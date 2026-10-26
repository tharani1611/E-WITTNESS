"""PostgreSQL integration tests for Phases 11-15 (Connectivity, Sessions, Migrations, Models & Identity Integrity).

All tests in this module execute against a genuine, isolated PostgreSQL test
database (`postgresql+asyncpg://`) managed by the `postgres_test_database_url`
and `postgres_db_manager` fixtures.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import text

from backend.app.api.dependencies import DbSessionDep
from backend.app.config.settings import Settings
from backend.app.core.exceptions import (
    BusinessRuleError,
    ConflictError,
    ResourceNotFoundError,
)
from backend.app.core.identity import AccountStatus, RoleCode, SessionStatus
from backend.app.infrastructure.database import (
    DatabaseSessionManager,
    create_db_engine,
    verify_database_connectivity,
)
from backend.app.infrastructure.migrations import (
    detect_schema_drift,
    get_current_database_revision,
    get_expected_head_revision,
    run_migrations_downgrade,
    run_migrations_upgrade,
)
from backend.app.main import create_app
from backend.app.models import Department, Session, User, utc_now
from backend.app.repositories.identity import (
    DepartmentRepository,
    RoleRepository,
    SessionRepository,
    UserRepository,
)


@pytest.mark.integration
class TestPostgreSQLConnectivityAndReadiness:
    """Phase 11 & 12: Verify real PostgreSQL connectivity, pooling, and readiness probes."""

    async def test_real_postgresql_connection_and_server_settings(
        self,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        assert await postgres_db_manager.verify_connectivity() is True

        async with postgres_db_manager.session() as session:
            dialect_name = session.bind.dialect.name if session.bind else ""
            assert dialect_name == "postgresql"

            version_res = await session.execute(text("SHOW server_version"))
            version_str = str(version_res.scalar())
            assert version_str != ""

            tz_res = await session.execute(text("SHOW timezone"))
            assert str(tz_res.scalar()).upper() == "UTC"

    async def test_health_ready_endpoint_with_live_postgresql_probe(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        app = create_app(
            postgres_settings,
            db_manager=postgres_db_manager,
            register_db_probe=True,
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            resp = await client.get("/api/v1/health/ready")
            assert resp.status_code == 200
            body = resp.json()
            assert body["checks"]["database"] == "ready"

    async def test_postgresql_connection_failure_is_handled_safely_without_leaking_secrets(
        self,
        settings_factory: Any,
    ) -> None:
        bad_settings = settings_factory(
            DATABASE_URL=(
                "postgresql+asyncpg://ewitness_test:UltraSecretPassword98765"
                "@127.0.0.1:1/ewitness_test"
            ),
            DB_CONNECT_TIMEOUT_SECONDS=1.0,
        )
        engine = create_db_engine(bad_settings)
        try:
            is_ok = await verify_database_connectivity(engine, timeout_seconds=1.0)
            assert is_ok is False
        finally:
            await engine.dispose()


@pytest.mark.integration
class TestAlembicMigrationsOnPostgreSQL:
    """Phase 13: Verify Alembic upgrade, downgrade, revision state, and zero schema drift on PostgreSQL."""

    async def test_alembic_upgrade_downgrade_and_zero_schema_drift_on_postgresql(
        self,
        postgres_settings: Settings,
    ) -> None:
        engine = create_db_engine(postgres_settings)
        try:
            expected_head = get_expected_head_revision()
            assert expected_head == "20261021_0015"

            # 1. Downgrade to base (clean slate)
            await run_migrations_downgrade(engine, "base")
            assert await get_current_database_revision(engine) is None

            # 2. Upgrade to head
            await run_migrations_upgrade(engine, "head")
            assert await get_current_database_revision(engine) == expected_head

            # 3. Verify zero schema drift between SQLAlchemy Base.metadata and PostgreSQL
            diffs = await detect_schema_drift(engine)
            assert diffs == [], f"Unexpected schema drift detected: {diffs}"
        finally:
            await engine.dispose()


@pytest.mark.integration
class TestAsyncSessionTransactionAndConcurrency:
    """Phase 12: Verify transaction commit, rollback, and concurrent session isolation on PostgreSQL."""

    async def test_transaction_commit_and_rollback_behavior(
        self,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        # 1. Successful transactional_session commits data
        async with postgres_db_manager.transactional_session() as session:
            dept_repo = DepartmentRepository(session)
            created = await dept_repo.create(
                Department(code="ACADEMIC-INTEGRITY", name="Academic Integrity Office")
            )
            dept_id = created.id

        # 2. Failed transactional_session rolls back uncommitted changes
        with pytest.raises(RuntimeError, match="Simulated service failure"):
            async with postgres_db_manager.transactional_session() as session:
                dept_repo = DepartmentRepository(session)
                await dept_repo.create(
                    Department(code="ROLLED-BACK-DEPT", name="Should Not Persist")
                )
                raise RuntimeError("Simulated service failure")

        # 3. Verify in a fresh session that committed row exists and rolled-back row does not
        async with postgres_db_manager.session() as verify_session:
            dept_repo = DepartmentRepository(verify_session)
            persisted = await dept_repo.get_by_id(dept_id)
            assert persisted is not None
            assert persisted.code == "ACADEMIC-INTEGRITY"
            assert await dept_repo.get_by_code("ROLLED-BACK-DEPT") is None

    async def test_concurrent_fastapi_requests_receive_isolated_database_sessions(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        app: FastAPI = create_app(postgres_settings, db_manager=postgres_db_manager)

        @app.get("/api/v1/_test/db-session-isolation")
        async def _probe_session(
            worker_idx: int,
            db_session: DbSessionDep,
        ) -> dict[str, Any]:
            result = await db_session.execute(
                text("SELECT CAST(:val AS INTEGER) AS worker_idx, pg_backend_pid() AS pid"),
                {"val": worker_idx},
            )
            row = result.mappings().one()
            return {
                "worker_idx": int(row["worker_idx"]),
                "session_obj_id": id(db_session),
                "backend_pid": int(row["pid"]),
            }

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            responses = await asyncio.gather(
                *(
                    client.get(
                        "/api/v1/_test/db-session-isolation",
                        params={"worker_idx": idx},
                    )
                    for idx in range(15)
                )
            )

        session_ids: set[int] = set()
        for idx, resp in enumerate(responses):
            assert resp.status_code == 200
            payload = resp.json()
            assert payload["worker_idx"] == idx
            session_ids.add(payload["session_obj_id"])

        # Every concurrent request must receive its own distinct AsyncSession instance
        assert len(session_ids) == 15


@pytest.mark.integration
class TestCoreModelsAndPostgreSQLIntegrity:
    """Phases 14 & 15: Verify relationships, uniqueness, foreign keys, check constraints, and concurrency."""

    async def test_department_role_user_and_session_full_lifecycle(
        self,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        async with postgres_db_manager.transactional_session() as session:
            dept_repo = DepartmentRepository(session)
            role_repo = RoleRepository(session)
            user_repo = UserRepository(session)
            sess_repo = SessionRepository(session)

            roles = await role_repo.ensure_default_roles()
            assert len(roles) == 5
            # Calling ensure_default_roles a second time is idempotent
            roles_again = await role_repo.ensure_default_roles()
            assert len(roles_again) == 5

            dept_a = await dept_repo.create(
                Department(
                    code="  campus-safety ",
                    name="Campus Safety Department",
                    description="Primary campus safety unit",
                )
            )
            dept_b = await dept_repo.create(
                Department(
                    code="STUDENT-AFFAIRS",
                    name="Student Affairs Department",
                )
            )
            assert len(await dept_repo.list_active()) == 2

            user_a = await user_repo.create(
                User(
                    email="  Investigator.Alpha@University.EDU ",
                    institutional_id=" inv-2026-01 ",
                    full_name="Alpha Investigator",
                    department_id=dept_a.id,
                    role_id=roles[RoleCode.INVESTIGATOR].id,
                )
            )
            assert user_a.email == "investigator.alpha@university.edu"
            assert user_a.institutional_id == "INV-2026-01"
            assert user_a.account_status == AccountStatus.PENDING_VERIFICATION.value
            assert user_a.is_active is False

            # Cannot create a session while user is still pending_verification
            now = utc_now()
            with pytest.raises(BusinessRuleError) as inactive_sess_err:
                await sess_repo.create(
                    Session(
                        user_id=user_a.id,
                        department_id=dept_a.id,
                        issued_at=now,
                        expires_at=now + timedelta(hours=2),
                    )
                )
            assert inactive_sess_err.value.code == "INACTIVE_USER_SESSION_FORBIDDEN"

            # Activate user account and create session
            activated_user = await user_repo.transition_account_status(
                user_a.id,
                AccountStatus.ACTIVE,
                department_id=dept_a.id,
            )
            assert activated_user.is_active is True
            assert activated_user.verified_at is not None

            # Cross-department session binding mismatch is rejected
            with pytest.raises(BusinessRuleError) as mismatch_err:
                await sess_repo.create(
                    Session(
                        user_id=user_a.id,
                        department_id=dept_b.id,
                        issued_at=now,
                        expires_at=now + timedelta(hours=2),
                    )
                )
            assert mismatch_err.value.code == "SESSION_DEPARTMENT_MISMATCH"

            created_session = await sess_repo.create(
                Session(
                    user_id=user_a.id,
                    department_id=dept_a.id,
                    client_ip="192.0.2.10",
                    user_agent="EWitnessTestClient/1.0",
                    issued_at=now,
                    expires_at=now + timedelta(hours=2),
                )
            )
            assert created_session.status == SessionStatus.ACTIVE.value

            active_sessions = await sess_repo.list_active_for_user(user_a.id)
            assert len(active_sessions) == 1
            assert active_sessions[0].id == created_session.id

            # Verify tenant scoping: Department B cannot read Department A's user
            assert await user_repo.get_by_id(user_a.id, department_id=dept_b.id) is None
            assert await user_repo.get_by_id(user_a.id, department_id=dept_a.id) is not None
            assert len(await user_repo.list_for_department(department_id=dept_a.id)) == 1
            assert len(await user_repo.list_for_department(department_id=dept_b.id)) == 0

            # Verify case-insensitive email & institutional_id lookups
            found_by_email = await user_repo.get_by_email(
                "INVESTIGATOR.ALPHA@UNIVERSITY.EDU",
                department_id=dept_a.id,
            )
            assert found_by_email is not None and found_by_email.id == user_a.id

            found_by_inst = await user_repo.get_by_institutional_id(
                "inv-2026-01",
                department_id=dept_a.id,
            )
            assert found_by_inst is not None and found_by_inst.id == user_a.id

            # Revoke session
            revoked = await sess_repo.revoke_session(
                created_session.id,
                reason="Session terminated by user",
            )
            assert revoked.status == SessionStatus.REVOKED.value
            assert revoked.revoked_at is not None
            assert await sess_repo.list_active_for_user(user_a.id) == []

    async def test_duplicate_identities_and_concurrent_registration_race_on_postgresql(
        self,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        async with postgres_db_manager.transactional_session() as setup_session:
            dept = await DepartmentRepository(setup_session).create(
                Department(code="CONCURRENCY-DEPT", name="Concurrency Test Department")
            )
            roles = await RoleRepository(setup_session).ensure_default_roles()
            student_role_id = roles[RoleCode.STUDENT].id
            dept_id = dept.id

        # Launch 10 concurrent registration tasks with case-varied versions of the same email
        async def _attempt_create(idx: int) -> str:
            async with postgres_db_manager.transactional_session() as worker_session:
                repo = UserRepository(worker_session)
                email_variant = (
                    "  Concurrent.Student@University.EDU "
                    if idx % 2 == 0
                    else "concurrent.student@university.edu"
                )
                await repo.create(
                    User(
                        email=email_variant,
                        institutional_id=f"STU-RACE-{idx:03d}",
                        full_name=f"Concurrent Student {idx}",
                        department_id=dept_id,
                        role_id=student_role_id,
                    )
                )
                return "created"

        outcomes = await asyncio.gather(
            *(_attempt_create(i) for i in range(10)),
            return_exceptions=True,
        )

        success_count = sum(1 for item in outcomes if item == "created")
        conflict_errors = [item for item in outcomes if isinstance(item, ConflictError)]

        assert success_count == 1
        assert len(conflict_errors) == 9
        for err in conflict_errors:
            assert err.code == "DATABASE_UNIQUE_CONFLICT"

        # Verify exactly 1 user row exists in PostgreSQL
        async with postgres_db_manager.session() as check_session:
            users = await UserRepository(check_session).list_for_department(department_id=dept_id)
            assert len(users) == 1
            assert users[0].email == "concurrent.student@university.edu"

    async def test_postgresql_foreign_keys_and_raw_sql_check_constraints(
        self,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        async with postgres_db_manager.transactional_session() as session:
            dept_repo = DepartmentRepository(session)
            role_repo = RoleRepository(session)
            user_repo = UserRepository(session)

            dept = await dept_repo.create(
                Department(code="FK-TEST-DEPT", name="FK Test Department")
            )
            roles = await role_repo.ensure_default_roles()
            staff_role = roles[RoleCode.STAFF]

            # 1. Invalid role_id or department_id is rejected
            with pytest.raises(BusinessRuleError) as bad_role_err:
                await user_repo.create(
                    User(
                        email="badrole@university.edu",
                        full_name="Bad Role User",
                        department_id=dept.id,
                        role_id=uuid4(),
                    )
                )
            assert bad_role_err.value.code == "INVALID_ROLE_ASSIGNMENT"

            with pytest.raises(BusinessRuleError) as bad_dept_err:
                await user_repo.create(
                    User(
                        email="baddept@university.edu",
                        full_name="Bad Dept User",
                        department_id=uuid4(),
                        role_id=staff_role.id,
                    )
                )
            assert bad_dept_err.value.code == "INVALID_DEPARTMENT_ASSIGNMENT"

            # 2. Deactivated department cannot accept new users
            await dept_repo.deactivate(dept.id)
            with pytest.raises(BusinessRuleError) as inactive_dept_err:
                await user_repo.create(
                    User(
                        email="inactivedept@university.edu",
                        full_name="Inactive Dept User",
                        department_id=dept.id,
                        role_id=staff_role.id,
                    )
                )
            assert inactive_dept_err.value.code == "INACTIVE_DEPARTMENT_ASSIGNMENT"

            # Reactivate department and create a valid user
            dept.activate()
            await session.flush()
            valid_user = await user_repo.create(
                User(
                    email="valid.staff@university.edu",
                    full_name="Valid Staff",
                    department_id=dept.id,
                    role_id=staff_role.id,
                )
            )
            dept_id = dept.id
            role_id = staff_role.id
            user_id = valid_user.id

        # 3. Verify PostgreSQL ON DELETE RESTRICT prevents deleting a department or role referenced by a user
        with pytest.raises(BusinessRuleError) as fk_delete_err:
            async with postgres_db_manager.transactional_session() as session:
                await session.execute(
                    text("DELETE FROM departments WHERE id = :id"),
                    {"id": dept_id},
                )
        assert fk_delete_err.value.code == "DATABASE_FOREIGN_KEY_VIOLATION"

        # 4. Verify PostgreSQL CHECK constraint rejects un-normalized email via raw SQL
        with pytest.raises(BusinessRuleError) as check_email_err:
            async with postgres_db_manager.transactional_session() as session:
                await session.execute(
                    text(
                        "INSERT INTO users (id, email, full_name, account_status, is_active, department_id, role_id) "
                        "VALUES (:id, 'UnNormalized@University.EDU', 'Raw SQL User', 'pending_verification', false, :dept_id, :role_id)"
                    ),
                    {"id": uuid4(), "dept_id": dept_id, "role_id": role_id},
                )
        assert check_email_err.value.code == "DATABASE_CONSTRAINT_VIOLATION"

        # 5. Verify PostgreSQL CHECK constraint rejects inconsistent (account_status='active', is_active=false)
        with pytest.raises(BusinessRuleError) as check_lifecycle_err:
            async with postgres_db_manager.transactional_session() as session:
                await session.execute(
                    text(
                        "UPDATE users SET account_status = 'active', is_active = false WHERE id = :id"
                    ),
                    {"id": user_id},
                )
        assert check_lifecycle_err.value.code == "DATABASE_CONSTRAINT_VIOLATION"

        # 6. Verify not-found error handling in repositories
        async with postgres_db_manager.session() as session:
            with pytest.raises(ResourceNotFoundError):
                await DepartmentRepository(session).deactivate(uuid4())
            with pytest.raises(ResourceNotFoundError):
                await UserRepository(session).transition_account_status(
                    uuid4(), AccountStatus.ACTIVE
                )
            with pytest.raises(ResourceNotFoundError):
                await SessionRepository(session).revoke_session(uuid4())
