"""PostgreSQL integration tests for Phases 16-20 (Password Security, Authentication, Sessions, Recovery).

All tests in this module execute against a genuine, isolated PostgreSQL test
database (`postgresql+asyncpg://`) managed by the `postgres_test_database_url`
and `postgres_db_manager` fixtures.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import text

from backend.app.config.settings import Settings
from backend.app.core.exceptions import (
    BusinessRuleError,
)
from backend.app.core.identity import (
    AccountStatus,
    RoleCode,
    SessionStatus,
)
from backend.app.core.rate_limit import InMemoryRateLimiter
from backend.app.core.tokens import (
    create_access_token,
    hash_token,
    verify_and_decode_access_token,
)
from backend.app.infrastructure.database import (
    DatabaseSessionManager,
    create_db_engine,
)
from backend.app.infrastructure.migrations import (
    detect_schema_drift,
    get_current_database_revision,
    get_expected_head_revision,
    run_migrations_downgrade,
    run_migrations_upgrade,
)
from backend.app.main import create_app
from backend.app.models import Department, User
from backend.app.repositories.identity import (
    AuthTokenRepository,
    DepartmentRepository,
    RoleRepository,
    SessionRepository,
    UserRepository,
)
from backend.app.services.email import FakeEmailDeliveryService
from backend.app.services.password import PasswordService


async def create_test_department_and_roles(
    postgres_db_manager: DatabaseSessionManager,
    *,
    code: str = "AUTH-DEPT",
    name: str = "Authentication Department",
) -> tuple[Department, dict[RoleCode, Any]]:
    """Helper fixture creating base Department and default roles."""
    async with postgres_db_manager.transactional_session() as session:
        dept_repo = DepartmentRepository(session)
        role_repo = RoleRepository(session)
        roles = await role_repo.ensure_default_roles()
        dept = await dept_repo.create(Department(code=code, name=name))
        return dept, roles


async def create_test_user(
    postgres_db_manager: DatabaseSessionManager,
    *,
    email: str,
    password: str | None = None,
    role_code: RoleCode = RoleCode.INVESTIGATOR,
    account_status: AccountStatus = AccountStatus.ACTIVE,
    is_active: bool = True,
    department: Department | None = None,
    roles_map: dict[RoleCode, Any] | None = None,
) -> tuple[User, Department, Any]:
    """Helper creating a test user with hashed password."""
    dept = department
    roles = roles_map
    if dept is None or roles is None:
        dept, roles = await create_test_department_and_roles(postgres_db_manager)

    role = roles[role_code]
    pw_service = PasswordService()
    pw_hash = pw_service.hash_password(password) if password is not None else None

    now = datetime.now(UTC)
    deactivated_at = (
        now if account_status in {AccountStatus.SUSPENDED, AccountStatus.DISABLED} else None
    )
    deactivation_reason = (
        "administrative_action"
        if account_status in {AccountStatus.SUSPENDED, AccountStatus.DISABLED}
        else None
    )
    async with postgres_db_manager.transactional_session() as session:
        user_repo = UserRepository(session)
        user = User(
            email=email,
            full_name="Auth Test Investigator",
            department_id=dept.id,
            role_id=role.id,
            account_status=account_status.value,
            is_active=is_active,
            password_hash=pw_hash,
            verified_at=now if account_status == AccountStatus.ACTIVE else None,
            deactivated_at=deactivated_at,
            deactivation_reason=deactivation_reason,
        )
        created_user = await user_repo.create(user)
        return created_user, dept, role


def make_auth_test_app(
    postgres_settings: Settings,
    postgres_db_manager: DatabaseSessionManager,
    *,
    email_service: FakeEmailDeliveryService | None = None,
    rate_limiter: InMemoryRateLimiter | None = None,
) -> FastAPI:
    """Helper to build a configured FastAPI application bound to test PostgreSQL."""
    app = create_app(postgres_settings, db_manager=postgres_db_manager)
    if email_service is not None:
        app.state.email_service = email_service
    if rate_limiter is not None:
        app.state.rate_limiter = rate_limiter
    return app


@pytest.mark.integration
class TestPasswordSecurityAndConstraintVerification:
    """Phase 16: Verify Argon2 password hashing, validation, and database constraints."""

    async def test_password_hash_model_helpers_and_usable_password(
        self,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        user, _, _ = await create_test_user(
            postgres_db_manager,
            email="argon.user@university.edu",
            password="Secure#Password123",
        )

        assert user.has_usable_password() is True
        assert user.password_hash is not None
        assert user.password_hash.startswith("$argon2id$")
        assert user.is_verified is True

        pw_service = PasswordService()
        assert pw_service.verify_password("Secure#Password123", user.password_hash) is True
        assert pw_service.verify_password("Wrong#Password999", user.password_hash) is False

    async def test_short_password_hash_rejected_by_model_and_postgresql_check_constraint(
        self,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        dept, roles = await create_test_department_and_roles(
            postgres_db_manager, code="CONSTRAINT-DEPT"
        )
        role = roles[RoleCode.STUDENT]

        # 1. Model set_password_hash rejects hashes shorter than 20 characters
        test_user = User(
            email="check.user@university.edu",
            full_name="Check User",
            department_id=dept.id,
            role_id=role.id,
        )
        with pytest.raises(ValueError, match="at least 20 characters"):
            test_user.set_password_hash("short_hash")

        # 2. PostgreSQL CHECK constraint rejects short password_hash via raw SQL
        with pytest.raises(BusinessRuleError) as exc_info:
            async with postgres_db_manager.transactional_session() as session:
                await session.execute(
                    text(
                        "INSERT INTO users (id, email, full_name, account_status, is_active, "
                        "department_id, role_id, password_hash) "
                        "VALUES (:id, 'raw.sql@university.edu', 'Raw User', 'active', true, "
                        ":dept_id, :role_id, 'too_short')"
                    ),
                    {"id": uuid4(), "dept_id": dept.id, "role_id": role.id},
                )
        assert exc_info.value.code == "DATABASE_CONSTRAINT_VIOLATION"


@pytest.mark.integration
class TestLoginAndSessionIssuance:
    """Phase 17: Verify user authentication, JWT issuance, and session creation."""

    async def test_successful_login_returns_valid_tokens_and_records_session(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        user, dept, _role = await create_test_user(
            postgres_db_manager,
            email="investigator.login@university.edu",
            password="Correct#Password2026",
            role_code=RoleCode.INVESTIGATOR,
        )

        app = make_auth_test_app(postgres_settings, postgres_db_manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
            headers={"User-Agent": "E-Witness-Audit-Client/1.0"},
        ) as client:
            resp = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": "investigator.login@university.edu",
                    "password": "Correct#Password2026",
                },
            )
            assert resp.status_code == 200
            data = resp.json()

            assert "access_token" in data
            assert "refresh_token" in data
            assert data["token_type"] == "bearer"
            assert data["expires_in"] == postgres_settings.AUTH_ACCESS_TOKEN_EXPIRE_MINUTES * 60

            # Verify JWT claims
            claims = verify_and_decode_access_token(
                data["access_token"],
                postgres_settings,
            )
            assert claims.sub == str(user.id)
            assert claims.role == RoleCode.INVESTIGATOR.value
            assert claims.dept_id == str(dept.id)
            assert claims.iss == postgres_settings.AUTH_ISSUER
            assert claims.aud == postgres_settings.AUTH_AUDIENCE

            # Verify session record in PostgreSQL
            session_uuid = UUID(claims.sid)
            async with postgres_db_manager.session() as session:
                sess_repo = SessionRepository(session)
                db_session = await sess_repo.get_by_id(session_uuid, user_id=user.id)
                assert db_session is not None
                assert db_session.status == SessionStatus.ACTIVE.value
                assert db_session.rotation_counter == 0
                assert db_session.refresh_token_hash == hash_token(data["refresh_token"])
                assert db_session.user_agent == "E-Witness-Audit-Client/1.0"

    async def test_login_invalid_password_returns_generic_error(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        await create_test_user(
            postgres_db_manager,
            email="valid.target@university.edu",
            password="Correct#Password2026",
        )

        app = make_auth_test_app(postgres_settings, postgres_db_manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            resp = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": "valid.target@university.edu",
                    "password": "WrongPassword999!",
                },
            )
            assert resp.status_code == 401
            data = resp.json()
            assert data["error"]["code"] == "INVALID_CREDENTIALS"
            assert "Invalid email or password" in data["error"]["message"]

    async def test_login_unknown_email_returns_identical_generic_error(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        app = make_auth_test_app(postgres_settings, postgres_db_manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            resp = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": "completely.unknown.user@university.edu",
                    "password": "SomeRandomPassword123!",
                },
            )
            assert resp.status_code == 401
            data = resp.json()
            assert data["error"]["code"] == "INVALID_CREDENTIALS"
            assert "Invalid email or password" in data["error"]["message"]

    async def test_login_rejection_for_pending_suspended_and_inactive_accounts(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        dept, roles = await create_test_department_and_roles(
            postgres_db_manager, code="STATUS-DEPT"
        )

        # 1. Pending verification
        await create_test_user(
            postgres_db_manager,
            email="pending.user@university.edu",
            password="ValidPassword123!",
            account_status=AccountStatus.PENDING_VERIFICATION,
            is_active=False,
            department=dept,
            roles_map=roles,
        )

        # 2. Suspended
        await create_test_user(
            postgres_db_manager,
            email="suspended.user@university.edu",
            password="ValidPassword123!",
            account_status=AccountStatus.SUSPENDED,
            is_active=False,
            department=dept,
            roles_map=roles,
        )

        # 3. Disabled
        await create_test_user(
            postgres_db_manager,
            email="disabled.user@university.edu",
            password="ValidPassword123!",
            account_status=AccountStatus.DISABLED,
            is_active=False,
            department=dept,
            roles_map=roles,
        )

        # 4. User without password hash
        await create_test_user(
            postgres_db_manager,
            email="nopassword.user@university.edu",
            password=None,
            account_status=AccountStatus.ACTIVE,
            is_active=True,
            department=dept,
            roles_map=roles,
        )

        app = make_auth_test_app(postgres_settings, postgres_db_manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            # Pending verification rejected
            resp_pending = await client.post(
                "/api/v1/auth/login",
                json={"email": "pending.user@university.edu", "password": "ValidPassword123!"},
            )
            assert resp_pending.status_code == 401
            assert resp_pending.json()["error"]["code"] == "ACCOUNT_PENDING_VERIFICATION"

            # Suspended rejected
            resp_susp = await client.post(
                "/api/v1/auth/login",
                json={"email": "suspended.user@university.edu", "password": "ValidPassword123!"},
            )
            assert resp_susp.status_code == 401
            assert resp_susp.json()["error"]["code"] == "ACCOUNT_INACTIVE"

            # Disabled rejected
            resp_dis = await client.post(
                "/api/v1/auth/login",
                json={"email": "disabled.user@university.edu", "password": "ValidPassword123!"},
            )
            assert resp_dis.status_code == 401
            assert resp_dis.json()["error"]["code"] == "ACCOUNT_INACTIVE"

            # No password hash rejected
            resp_nopw = await client.post(
                "/api/v1/auth/login",
                json={"email": "nopassword.user@university.edu", "password": "ValidPassword123!"},
            )
            assert resp_nopw.status_code == 401
            assert resp_nopw.json()["error"]["code"] == "INVALID_CREDENTIALS"


@pytest.mark.integration
class TestCurrentUserAndBearerAuthentication:
    """Phase 19: Verify protected endpoints, bearer authorization, and invalid token handling."""

    async def test_get_current_user_profile_success(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        user, dept, _role = await create_test_user(
            postgres_db_manager,
            email="profile.user@university.edu",
            password="Secure#Password123",
            role_code=RoleCode.DEPT_ADMIN,
        )

        app = make_auth_test_app(postgres_settings, postgres_db_manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            # Login
            login_resp = await client.post(
                "/api/v1/auth/login",
                json={"email": "profile.user@university.edu", "password": "Secure#Password123"},
            )
            token = login_resp.json()["access_token"]

            # Query /me
            me_resp = await client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert me_resp.status_code == 200
            profile = me_resp.json()
            assert profile["user"]["id"] == str(user.id)
            assert profile["user"]["email"] == "profile.user@university.edu"
            assert profile["role"]["code"] == RoleCode.DEPT_ADMIN.value
            assert profile["department"]["id"] == str(dept.id)
            assert "session_id" in profile

    async def test_get_current_user_profile_rejection_scenarios(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        user, dept, _role = await create_test_user(
            postgres_db_manager,
            email="tamper.test@university.edu",
            password="Secure#Password123",
        )

        app = make_auth_test_app(postgres_settings, postgres_db_manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            # 1. Missing Authorization header
            resp_missing = await client.get("/api/v1/auth/me")
            assert resp_missing.status_code == 401
            assert resp_missing.json()["error"]["code"] == "UNAUTHENTICATED"

            # 2. Malformed token
            resp_malformed = await client.get(
                "/api/v1/auth/me",
                headers={"Authorization": "Bearer malformed.jwt.token"},
            )
            assert resp_malformed.status_code == 401
            assert resp_malformed.json()["error"]["code"] == "TOKEN_INVALID"

            # 3. Expired token
            now = datetime.now(UTC) - timedelta(hours=2)
            expired_token, _ = create_access_token(
                user_id=user.id,
                session_id=uuid4(),
                role_code=RoleCode.INVESTIGATOR.value,
                department_id=dept.id,
                settings=postgres_settings,
                now=now,
            )
            resp_expired = await client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {expired_token}"},
            )
            assert resp_expired.status_code == 401
            assert resp_expired.json()["error"]["code"] == "TOKEN_EXPIRED"

            # 4. Token pointing to non-existent session
            phantom_token, _ = create_access_token(
                user_id=user.id,
                session_id=uuid4(),
                role_code=RoleCode.INVESTIGATOR.value,
                department_id=dept.id,
                settings=postgres_settings,
            )
            resp_phantom = await client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {phantom_token}"},
            )
            assert resp_phantom.status_code == 401
            assert resp_phantom.json()["error"]["code"] == "SESSION_NOT_FOUND"


@pytest.mark.integration
class TestRefreshTokenRotationAndReuseDetection:
    """Phases 17 & 19: Verify refresh token rotation, concurrency locking, and reuse revocation."""

    async def test_refresh_token_rotation_increments_counter_and_issues_new_token(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        user, _, _ = await create_test_user(
            postgres_db_manager,
            email="refresh.user@university.edu",
            password="Secure#Password123",
        )

        app = make_auth_test_app(postgres_settings, postgres_db_manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            login_resp = await client.post(
                "/api/v1/auth/login",
                json={"email": "refresh.user@university.edu", "password": "Secure#Password123"},
            )
            initial_tokens = login_resp.json()
            refresh_v1 = initial_tokens["refresh_token"]

            # Perform refresh rotation
            refresh_resp = await client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": refresh_v1},
            )
            assert refresh_resp.status_code == 200
            rotated_tokens = refresh_resp.json()
            refresh_v2 = rotated_tokens["refresh_token"]

            assert refresh_v2 != refresh_v1

            # Verify DB session state
            claims = verify_and_decode_access_token(
                rotated_tokens["access_token"], postgres_settings
            )
            async with postgres_db_manager.session() as session:
                sess_repo = SessionRepository(session)
                sess = await sess_repo.get_by_id(UUID(claims.sid), user_id=user.id)
                assert sess is not None
                assert sess.rotation_counter == 1
                assert sess.refresh_token_hash == hash_token(refresh_v2)
                assert sess.previous_refresh_token_hash == hash_token(refresh_v1)
                assert sess.status == SessionStatus.ACTIVE.value

    async def test_refresh_token_reuse_detection_revokes_entire_session(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        user, _, _ = await create_test_user(
            postgres_db_manager,
            email="reuse.user@university.edu",
            password="Secure#Password123",
        )

        app = make_auth_test_app(postgres_settings, postgres_db_manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            # Login
            login_resp = await client.post(
                "/api/v1/auth/login",
                json={"email": "reuse.user@university.edu", "password": "Secure#Password123"},
            )
            tokens = login_resp.json()
            token_v1 = tokens["refresh_token"]

            # Rotate once
            rot1_resp = await client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": token_v1},
            )
            assert rot1_resp.status_code == 200
            token_v2 = rot1_resp.json()["refresh_token"]

            # Attacker presents old token_v1 again (REUSE ATTACK)
            attack_resp = await client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": token_v1},
            )
            assert attack_resp.status_code == 401
            assert attack_resp.json()["error"]["code"] == "REFRESH_TOKEN_REUSE_DETECTED"

            # Verify session is revoked in PostgreSQL
            claims = verify_and_decode_access_token(
                rot1_resp.json()["access_token"], postgres_settings
            )
            async with postgres_db_manager.session() as session:
                sess_repo = SessionRepository(session)
                db_sess = await sess_repo.get_by_id(UUID(claims.sid), user_id=user.id)
                assert db_sess is not None
                assert db_sess.status == SessionStatus.REVOKED.value
                assert db_sess.revocation_reason == "refresh_token_reuse_detected"

            # Subsequent attempt with token_v2 also fails because session is revoked
            after_resp = await client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": token_v2},
            )
            assert after_resp.status_code == 401


@pytest.mark.integration
class TestLogoutAndSessionRevocation:
    """Phases 17 & 19: Verify user logout, session invalidation, and session management."""

    async def test_logout_revokes_current_session(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        user, _, _ = await create_test_user(
            postgres_db_manager,
            email="logout.user@university.edu",
            password="Secure#Password123",
        )

        app = make_auth_test_app(postgres_settings, postgres_db_manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            login_resp = await client.post(
                "/api/v1/auth/login",
                json={"email": "logout.user@university.edu", "password": "Secure#Password123"},
            )
            access_token = login_resp.json()["access_token"]
            claims = verify_and_decode_access_token(access_token, postgres_settings)

            # Call /logout
            logout_resp = await client.post(
                "/api/v1/auth/logout",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            assert logout_resp.status_code == 200
            assert logout_resp.json()["status"] == "success"

            # Subsequent /me call rejected
            me_resp = await client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            assert me_resp.status_code == 401
            assert me_resp.json()["error"]["code"] == "SESSION_REVOKED"

            # Verify in PostgreSQL
            async with postgres_db_manager.session() as session:
                sess_repo = SessionRepository(session)
                db_sess = await sess_repo.get_by_id(UUID(claims.sid), user_id=user.id)
                assert db_sess is not None
                assert db_sess.status == SessionStatus.REVOKED.value

    async def test_revoke_other_sessions_endpoint(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        _user, _, _ = await create_test_user(
            postgres_db_manager,
            email="multisess.user@university.edu",
            password="Secure#Password123",
        )

        app = make_auth_test_app(postgres_settings, postgres_db_manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            # Establish session 1
            s1_resp = await client.post(
                "/api/v1/auth/login",
                json={"email": "multisess.user@university.edu", "password": "Secure#Password123"},
            )
            token_1 = s1_resp.json()["access_token"]

            # Establish session 2
            s2_resp = await client.post(
                "/api/v1/auth/login",
                json={"email": "multisess.user@university.edu", "password": "Secure#Password123"},
            )
            token_2 = s2_resp.json()["access_token"]

            # From session 2, revoke all other sessions
            revoke_resp = await client.post(
                "/api/v1/auth/sessions/revoke",
                headers={"Authorization": f"Bearer {token_2}"},
                json={"all_other_sessions": True},
            )
            assert revoke_resp.status_code == 200
            assert "Revoked 1 other active session" in revoke_resp.json()["message"]

            # Session 1 is now rejected
            me_s1 = await client.get(
                "/api/v1/auth/me", headers={"Authorization": f"Bearer {token_1}"}
            )
            assert me_s1.status_code == 401
            assert me_s1.json()["error"]["code"] == "SESSION_REVOKED"

            # Session 2 is still active
            me_s2 = await client.get(
                "/api/v1/auth/me", headers={"Authorization": f"Bearer {token_2}"}
            )
            assert me_s2.status_code == 200


@pytest.mark.integration
class TestPasswordRecoveryFlow:
    """Phase 18: Verify self-service password recovery, single-use tokens, and session invalidation."""

    async def test_full_password_recovery_and_reset_lifecycle(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        _user, _, _ = await create_test_user(
            postgres_db_manager,
            email="recovery.user@university.edu",
            password="Original#Password123",
        )

        fake_email = FakeEmailDeliveryService()
        app = make_auth_test_app(
            postgres_settings,
            postgres_db_manager,
            email_service=fake_email,
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            # 1. Establish an active session prior to password reset
            login_resp = await client.post(
                "/api/v1/auth/login",
                json={"email": "recovery.user@university.edu", "password": "Original#Password123"},
            )
            pre_reset_token = login_resp.json()["access_token"]

            # 2. Request password reset
            forgot_resp = await client.post(
                "/api/v1/auth/forgot-password",
                json={"email": "recovery.user@university.edu"},
            )
            assert forgot_resp.status_code == 200
            assert "instructions have been sent" in forgot_resp.json()["message"]

            # Check dispatched email
            assert len(fake_email.sent_messages) == 1
            msg = fake_email.sent_messages[0]
            assert msg["to"] == "recovery.user@university.edu"
            assert msg["type"] == "password_reset"
            raw_reset_token = msg["token"]

            # 3. Reset password using valid token
            reset_resp = await client.post(
                "/api/v1/auth/reset-password",
                json={
                    "token": raw_reset_token,
                    "new_password": "BrandNew#Password2026",
                },
            )
            assert reset_resp.status_code == 200
            assert "successfully reset" in reset_resp.json()["message"]

            # 4. Invariant: Pre-reset session is revoked
            me_resp = await client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {pre_reset_token}"},
            )
            assert me_resp.status_code == 401
            assert me_resp.json()["error"]["code"] == "SESSION_REVOKED"

            # 5. Old password no longer authenticates
            old_login = await client.post(
                "/api/v1/auth/login",
                json={"email": "recovery.user@university.edu", "password": "Original#Password123"},
            )
            assert old_login.status_code == 401

            # 6. New password authenticates successfully
            new_login = await client.post(
                "/api/v1/auth/login",
                json={"email": "recovery.user@university.edu", "password": "BrandNew#Password2026"},
            )
            assert new_login.status_code == 200

            # 7. Token reuse is rejected
            reuse_reset = await client.post(
                "/api/v1/auth/reset-password",
                json={
                    "token": raw_reset_token,
                    "new_password": "Another#Password2026",
                },
            )
            assert reuse_reset.status_code == 401
            assert reuse_reset.json()["error"]["code"] == "INVALID_RESET_TOKEN"

    async def test_forgot_password_unknown_email_preserves_privacy_without_enumeration(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        fake_email = FakeEmailDeliveryService()
        app = make_auth_test_app(
            postgres_settings,
            postgres_db_manager,
            email_service=fake_email,
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            resp = await client.post(
                "/api/v1/auth/forgot-password",
                json={"email": "nobody.registered@university.edu"},
            )
            assert resp.status_code == 200
            assert "instructions have been sent" in resp.json()["message"]
            # No email sent for unknown accounts
            assert len(fake_email.sent_messages) == 0


@pytest.mark.integration
class TestEmailVerificationFlow:
    """Phase 18: Verify email verification token issuance, consumption, and account activation."""

    async def test_email_verification_lifecycle_and_account_activation(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        dept, roles = await create_test_department_and_roles(
            postgres_db_manager, code="VERIFY-DEPT"
        )
        user, _, _ = await create_test_user(
            postgres_db_manager,
            email="unverified.student@university.edu",
            password="Secure#Password123",
            role_code=RoleCode.STUDENT,
            account_status=AccountStatus.PENDING_VERIFICATION,
            is_active=False,
            department=dept,
            roles_map=roles,
        )

        fake_email = FakeEmailDeliveryService()
        app = make_auth_test_app(
            postgres_settings,
            postgres_db_manager,
            email_service=fake_email,
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            # 1. Login fails before verification
            unv_login = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": "unverified.student@university.edu",
                    "password": "Secure#Password123",
                },
            )
            assert unv_login.status_code == 401
            assert unv_login.json()["error"]["code"] == "ACCOUNT_PENDING_VERIFICATION"

            # 2. Request verification email
            req_resp = await client.post(
                "/api/v1/auth/verify-email/request",
                json={"email": "unverified.student@university.edu"},
            )
            assert req_resp.status_code == 200
            assert len(fake_email.sent_messages) == 1
            verify_token = fake_email.sent_messages[0]["token"]

            # 3. Confirm verification
            confirm_resp = await client.post(
                "/api/v1/auth/verify-email/confirm",
                json={"token": verify_token},
            )
            assert confirm_resp.status_code == 200
            assert "successfully verified" in confirm_resp.json()["message"]

            # 4. Verify account state in PostgreSQL
            async with postgres_db_manager.session() as session:
                user_repo = UserRepository(session)
                updated_user = await user_repo.get_by_id_unscoped(user.id)
                assert updated_user is not None
                assert updated_user.account_status == AccountStatus.ACTIVE.value
                assert updated_user.is_active is True
                assert updated_user.verified_at is not None

            # 5. User can now authenticate
            post_verify_login = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": "unverified.student@university.edu",
                    "password": "Secure#Password123",
                },
            )
            assert post_verify_login.status_code == 200

            # 6. Replay confirm verification fails
            replay_resp = await client.post(
                "/api/v1/auth/verify-email/confirm",
                json={"token": verify_token},
            )
            assert replay_resp.status_code == 401
            assert replay_resp.json()["error"]["code"] == "INVALID_VERIFICATION_TOKEN"


@pytest.mark.integration
class TestConcurrencyAndRateLimiting:
    """Phases 17-18: Verify atomic token consumption under concurrency and rate limiting."""

    async def test_concurrent_password_reset_token_redemption_race(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        _user, _, _ = await create_test_user(
            postgres_db_manager,
            email="race.user@university.edu",
            password="Original#Password123",
        )

        fake_email = FakeEmailDeliveryService()
        app = make_auth_test_app(
            postgres_settings,
            postgres_db_manager,
            email_service=fake_email,
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            # Generate token
            await client.post(
                "/api/v1/auth/forgot-password",
                json={"email": "race.user@university.edu"},
            )
            reset_token = fake_email.sent_messages[0]["token"]

            # Launch 5 concurrent reset attempts with the exact same token
            async def _attempt_reset(worker_id: int) -> int:
                resp = await client.post(
                    "/api/v1/auth/reset-password",
                    json={
                        "token": reset_token,
                        "new_password": f"NewPassWord#{worker_id:03d}!",
                    },
                )
                return resp.status_code

            status_codes = await asyncio.gather(*(_attempt_reset(i) for i in range(5)))

            # Exactly 1 request succeeds (200), remaining 4 are rejected (401)
            assert status_codes.count(200) == 1
            assert status_codes.count(401) == 4

            # Verify token consumed exactly once in database
            async with postgres_db_manager.session() as session:
                token_repo = AuthTokenRepository(session)
                token_record = await token_repo.get_by_token_hash(hash_token(reset_token))
                assert token_record is not None
                assert token_record.consumed_at is not None

    async def test_rate_limiting_enforcement_on_login(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        limiter = InMemoryRateLimiter()
        app = make_auth_test_app(
            postgres_settings,
            postgres_db_manager,
            rate_limiter=limiter,
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            responses = []
            # Max requests for login is 10/min
            for i in range(12):
                r = await client.post(
                    "/api/v1/auth/login",
                    json={"email": "nobody@university.edu", "password": f"Pass#{i}"},
                )
                responses.append(r.status_code)

            # First 10 get 401 (invalid creds), 11th and 12th get 429 (rate limited)
            assert responses[:10] == [401] * 10
            assert responses[10] == 429
            assert responses[11] == 429


@pytest.mark.integration
class TestAuthMigrationsAndSchemaVerification:
    """Phase 20: Verify Alembic migration 0002 applies cleanly, downgrades, and leaves zero schema drift."""

    async def test_migration_0002_upgrade_downgrade_and_zero_schema_drift(
        self,
        postgres_settings: Settings,
    ) -> None:
        engine = create_db_engine(postgres_settings)
        try:
            await run_migrations_upgrade(engine, "head")
            expected_head = get_expected_head_revision()
            assert expected_head == "20261015_0013"

            # Downgrade to 20261013_0001 (Phase 11-15 base)
            await run_migrations_downgrade(engine, "20261013_0001")
            assert await get_current_database_revision(engine) == "20261013_0001"

            # Re-upgrade to head (Phase 16-90)
            await run_migrations_upgrade(engine, "head")
            assert await get_current_database_revision(engine) == "20261015_0013"

            # Verify zero schema drift between metadata and PostgreSQL
            diffs = await detect_schema_drift(engine)
            assert diffs == [], f"Schema drift detected after 0002 upgrade: {diffs}"
        finally:
            await engine.dispose()
