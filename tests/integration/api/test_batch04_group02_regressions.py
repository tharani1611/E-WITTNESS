"""Integration and Regression Tests for Batch 04 Group 02 (Phases 36-40).

Executes against live PostgreSQL without mocks, validating:
- Phase 36: Investigator assignment, department scoping, eligibility validation.
- Phase 37: Super Admin global controls, Department Admin boundaries, escalation prevention.
- Phase 38: Search, pagination, filtering, allowlisted sorting, SQL injection immunity, safe responses.
- Phase 39: OpenAPI schema generation, unique operation IDs, schema examples, zero secret exposure.
- Phase 40: Duplicate record collisions, token replay defenses, user & department lifecycles.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest

from backend.app.config.settings import Settings
from backend.app.core.identity import AccountStatus, AuthTokenPurpose, RoleCode
from backend.app.core.tokens import generate_opaque_token, hash_token
from backend.app.infrastructure.database import DatabaseSessionManager
from backend.app.main import create_app
from backend.app.models.department import Department
from backend.app.models.token import AuthToken
from backend.app.models.user import User
from backend.app.repositories.identity import (
    DepartmentRepository,
    RoleRepository,
    UserRepository,
)
from backend.app.services.password import PasswordService


async def _setup_test_environment(
    postgres_db_manager: DatabaseSessionManager,
) -> dict[str, Any]:
    """Seed test departments, roles, and administrative principals in PostgreSQL."""
    pw_service = PasswordService()
    admin_pw = "AdminPass123456!"
    hashed_pw = pw_service.hash_password(admin_pw)

    async with postgres_db_manager.transactional_session() as session:
        dept_repo = DepartmentRepository(session)
        role_repo = RoleRepository(session)
        user_repo = UserRepository(session)

        roles = await role_repo.ensure_default_roles()

        suffix = uuid4().hex[:6].upper()
        dept_alpha = await dept_repo.create(
            Department(code=f"ALPHA-{suffix}", name="Department Alpha", is_active=True)
        )
        dept_beta = await dept_repo.create(
            Department(code=f"BETA-{suffix}", name="Department Beta", is_active=True)
        )
        dept_inactive = await dept_repo.create(
            Department(
                code=f"INACT-{suffix}",
                name="Department Inactive",
                is_active=False,
                deactivated_at=datetime.now(UTC),
            )
        )

        # 1. Super Admin
        super_admin = await user_repo.create(
            User(
                email=f"superadmin_{suffix.lower()}@ewitness.edu",
                full_name="Global Super Administrator",
                role_id=roles[RoleCode.SUPER_ADMIN].id,
                department_id=None,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        # 2. Dept Admin Alpha
        dept_admin_alpha = await user_repo.create(
            User(
                email=f"deptadmin_alpha_{suffix.lower()}@ewitness.edu",
                full_name="Alpha Department Administrator",
                role_id=roles[RoleCode.DEPT_ADMIN].id,
                department_id=dept_alpha.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        # 3. Dept Admin Beta
        dept_admin_beta = await user_repo.create(
            User(
                email=f"deptadmin_beta_{suffix.lower()}@ewitness.edu",
                full_name="Beta Department Administrator",
                role_id=roles[RoleCode.DEPT_ADMIN].id,
                department_id=dept_beta.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        # 4. Active Investigator in Alpha
        investigator_alpha = await user_repo.create(
            User(
                email=f"investigator_alpha_{suffix.lower()}@ewitness.edu",
                full_name="Detective Alpha Inspector",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_alpha.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        # 5. Active Investigator in Beta
        investigator_beta = await user_repo.create(
            User(
                email=f"investigator_beta_{suffix.lower()}@ewitness.edu",
                full_name="Detective Beta Inspector",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_beta.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        # 6. Active Student in Alpha
        student_alpha = await user_repo.create(
            User(
                email=f"student_alpha_{suffix.lower()}@ewitness.edu",
                full_name="Student Alpha Reporter",
                role_id=roles[RoleCode.STUDENT].id,
                department_id=dept_alpha.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        # 7. Suspended Investigator in Alpha
        suspended_investigator = await user_repo.create(
            User(
                email=f"suspended_inv_{suffix.lower()}@ewitness.edu",
                full_name="Suspended Investigator",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_alpha.id,
                account_status=AccountStatus.SUSPENDED.value,
                is_active=False,
                deactivated_at=datetime.now(UTC),
                password_hash=hashed_pw,
            )
        )

        return {
            "password": admin_pw,
            "roles": roles,
            "dept_alpha": dept_alpha,
            "dept_beta": dept_beta,
            "dept_inactive": dept_inactive,
            "super_admin": super_admin,
            "dept_admin_alpha": dept_admin_alpha,
            "dept_admin_beta": dept_admin_beta,
            "investigator_alpha": investigator_alpha,
            "investigator_beta": investigator_beta,
            "student_alpha": student_alpha,
            "suspended_investigator": suspended_investigator,
        }


async def _get_token(client: httpx.AsyncClient, email: str, password: str) -> str:
    """Helper to acquire JWT bearer access token."""
    resp = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, f"Login failed for {email}: {resp.text}"
    return str(resp.json()["access_token"])


@pytest.mark.integration
class TestInvestigatorAssignmentIntegration:
    """Phase 36: Investigator assignment, department responsibilities & prerequisites."""

    async def test_super_admin_assigns_investigator_to_department(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_test_environment(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver.local"
        ) as client:
            token = await _get_token(client, env["super_admin"].email, env["password"])
            dept_beta: Department = env["dept_beta"]
            inv_alpha: User = env["investigator_alpha"]

            # Reassign investigator from Alpha to Beta
            resp = await client.post(
                f"/api/v1/departments/{dept_beta.id}/investigators",
                headers={"Authorization": f"Bearer {token}"},
                json={"investigator_id": str(inv_alpha.id)},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["id"] == str(inv_alpha.id)
            assert data["department_id"] == str(dept_beta.id)

    async def test_super_admin_assigns_investigator_via_user_endpoint(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_test_environment(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver.local"
        ) as client:
            token = await _get_token(client, env["super_admin"].email, env["password"])
            dept_beta: Department = env["dept_beta"]
            inv_alpha: User = env["investigator_alpha"]

            resp = await client.post(
                f"/api/v1/users/{inv_alpha.id}/investigator-assignment",
                headers={"Authorization": f"Bearer {token}"},
                json={"department_id": str(dept_beta.id)},
            )
            assert resp.status_code == 200
            assert resp.json()["department_id"] == str(dept_beta.id)

    async def test_dept_admin_assigns_investigator_within_own_department(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_test_environment(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver.local"
        ) as client:
            token = await _get_token(client, env["dept_admin_alpha"].email, env["password"])
            dept_alpha: Department = env["dept_alpha"]
            inv_alpha: User = env["investigator_alpha"]

            resp = await client.post(
                f"/api/v1/departments/{dept_alpha.id}/investigators",
                headers={"Authorization": f"Bearer {token}"},
                json={"user_id": str(inv_alpha.id)},
            )
            assert resp.status_code == 200
            assert resp.json()["id"] == str(inv_alpha.id)

    async def test_dept_admin_cross_department_assignment_rejected(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_test_environment(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver.local"
        ) as client:
            token = await _get_token(client, env["dept_admin_alpha"].email, env["password"])
            dept_beta: Department = env["dept_beta"]
            inv_alpha: User = env["investigator_alpha"]

            # Dept Admin Alpha attempting to assign to Dept Beta -> 403 DEPARTMENT_MISMATCH
            resp = await client.post(
                f"/api/v1/departments/{dept_beta.id}/investigators",
                headers={"Authorization": f"Bearer {token}"},
                json={"investigator_id": str(inv_alpha.id)},
            )
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "DEPARTMENT_MISMATCH"

    async def test_dept_admin_cannot_steal_investigator_from_another_department(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_test_environment(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver.local"
        ) as client:
            token = await _get_token(client, env["dept_admin_alpha"].email, env["password"])
            dept_alpha: Department = env["dept_alpha"]
            inv_beta: User = env["investigator_beta"]

            # Dept Admin Alpha trying to pull Investigator Beta from Dept Beta -> 403 DEPARTMENT_MISMATCH
            resp = await client.post(
                f"/api/v1/departments/{dept_alpha.id}/investigators",
                headers={"Authorization": f"Bearer {token}"},
                json={"investigator_id": str(inv_beta.id)},
            )
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "DEPARTMENT_MISMATCH"

    async def test_assign_non_investigator_role_rejected(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_test_environment(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver.local"
        ) as client:
            token = await _get_token(client, env["super_admin"].email, env["password"])
            dept_alpha: Department = env["dept_alpha"]
            student_alpha: User = env["student_alpha"]

            # Student cannot be assigned as an investigator
            resp = await client.post(
                f"/api/v1/departments/{dept_alpha.id}/investigators",
                headers={"Authorization": f"Bearer {token}"},
                json={"investigator_id": str(student_alpha.id)},
            )
            assert resp.status_code == 422
            assert resp.json()["error"]["code"] == "INVALID_ROLE_ASSIGNMENT"

    async def test_assign_inactive_investigator_account_rejected(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_test_environment(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver.local"
        ) as client:
            token = await _get_token(client, env["super_admin"].email, env["password"])
            dept_alpha: Department = env["dept_alpha"]
            suspended_inv: User = env["suspended_investigator"]

            # Inactive investigator cannot receive assignment
            resp = await client.post(
                f"/api/v1/departments/{dept_alpha.id}/investigators",
                headers={"Authorization": f"Bearer {token}"},
                json={"investigator_id": str(suspended_inv.id)},
            )
            assert resp.status_code == 422
            assert resp.json()["error"]["code"] == "ACCOUNT_LIFECYCLE_RESTRICTED"

    async def test_assign_investigator_to_inactive_department_rejected(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_test_environment(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver.local"
        ) as client:
            token = await _get_token(client, env["super_admin"].email, env["password"])
            dept_inactive: Department = env["dept_inactive"]
            inv_alpha: User = env["investigator_alpha"]

            # Target department is inactive
            resp = await client.post(
                f"/api/v1/departments/{dept_inactive.id}/investigators",
                headers={"Authorization": f"Bearer {token}"},
                json={"investigator_id": str(inv_alpha.id)},
            )
            assert resp.status_code == 422
            assert resp.json()["error"]["code"] == "INACTIVE_DEPARTMENT_ASSIGNMENT"

    async def test_list_department_investigators_scoped_and_filtered(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_test_environment(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver.local"
        ) as client:
            # 1. Dept Admin Alpha listing own investigators -> OK
            token_alpha = await _get_token(client, env["dept_admin_alpha"].email, env["password"])
            dept_alpha: Department = env["dept_alpha"]
            resp1 = await client.get(
                f"/api/v1/departments/{dept_alpha.id}/investigators?page=1&page_size=10",
                headers={"Authorization": f"Bearer {token_alpha}"},
            )
            assert resp1.status_code == 200
            body1 = resp1.json()
            assert len(body1["items"]) >= 1
            assert any(item["id"] == str(env["investigator_alpha"].id) for item in body1["items"])

            # 2. Dept Admin Alpha listing Dept Beta investigators -> 403
            dept_beta: Department = env["dept_beta"]
            resp2 = await client.get(
                f"/api/v1/departments/{dept_beta.id}/investigators",
                headers={"Authorization": f"Bearer {token_alpha}"},
            )
            assert resp2.status_code == 403
            assert resp2.json()["error"]["code"] == "DEPARTMENT_MISMATCH"

            # 3. Super Admin listing any department investigators -> OK
            token_super = await _get_token(client, env["super_admin"].email, env["password"])
            resp3 = await client.get(
                f"/api/v1/departments/{dept_beta.id}/investigators",
                headers={"Authorization": f"Bearer {token_super}"},
            )
            assert resp3.status_code == 200
            body3 = resp3.json()
            assert any(item["id"] == str(env["investigator_beta"].id) for item in body3["items"])


@pytest.mark.integration
class TestSuperAdminAndPrivilegeBoundariesIntegration:
    """Phase 37: Super Admin global APIs and strict Department Admin privilege boundaries."""

    async def test_dept_admin_cannot_modify_super_admin(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_test_environment(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver.local"
        ) as client:
            token = await _get_token(client, env["dept_admin_alpha"].email, env["password"])
            super_admin: User = env["super_admin"]

            resp = await client.patch(
                f"/api/v1/users/{super_admin.id}",
                headers={"Authorization": f"Bearer {token}"},
                json={"full_name": "Tampered Name"},
            )
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] in {
                "PERMISSION_DENIED",
                "DEPARTMENT_MISMATCH",
                "PRIVILEGE_ESCALATION_FORBIDDEN",
            }

    async def test_dept_admin_cannot_deactivate_other_admins(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_test_environment(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver.local"
        ) as client:
            token = await _get_token(client, env["dept_admin_alpha"].email, env["password"])
            dept_admin_beta: User = env["dept_admin_beta"]

            resp = await client.post(
                f"/api/v1/users/{dept_admin_beta.id}/deactivate",
                headers={"Authorization": f"Bearer {token}"},
                json={"reason": "Hostile deactivation"},
            )
            assert resp.status_code == 403

    async def test_super_admin_cannot_deactivate_self(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_test_environment(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver.local"
        ) as client:
            token = await _get_token(client, env["super_admin"].email, env["password"])
            super_admin: User = env["super_admin"]

            resp = await client.post(
                f"/api/v1/users/{super_admin.id}/deactivate",
                headers={"Authorization": f"Bearer {token}"},
                json={"reason": "Accidental self deactivation"},
            )
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "SELF_DEACTIVATION_FORBIDDEN"

    async def test_super_admin_department_lifecycle(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_test_environment(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver.local"
        ) as client:
            token = await _get_token(client, env["super_admin"].email, env["password"])
            suffix = uuid4().hex[:6].upper()

            # 1. Create department
            create_resp = await client.post(
                "/api/v1/departments",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "code": f"LEGAL-{suffix}",
                    "name": "Legal Affairs",
                    "description": "Institutional legal representation",
                },
            )
            assert create_resp.status_code == 201
            dept_id = create_resp.json()["id"]

            # 2. Deactivate department
            deact_resp = await client.post(
                f"/api/v1/departments/{dept_id}/deactivate",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert deact_resp.status_code == 200
            assert deact_resp.json()["is_active"] is False

            # 3. Activate department
            act_resp = await client.post(
                f"/api/v1/departments/{dept_id}/activate",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert act_resp.status_code == 200
            assert act_resp.json()["is_active"] is True


@pytest.mark.integration
class TestSearchPaginationSortingSecurityIntegration:
    """Phase 38: Search, pagination, allowlisted sorting & SQL injection resistance."""

    async def test_sorting_allowlist_enforcement(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_test_environment(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver.local"
        ) as client:
            token = await _get_token(client, env["super_admin"].email, env["password"])

            # 1. Valid sort by email descending
            ok_resp = await client.get(
                "/api/v1/users?sort_by=email&sort_order=desc",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert ok_resp.status_code == 200
            assert len(ok_resp.json()["items"]) >= 1

            # 2. Invalid sort field -> 400 INVALID_SORT_FIELD
            bad_field_resp = await client.get(
                "/api/v1/users?sort_by=unauthorized_secret_column",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert bad_field_resp.status_code == 400
            assert bad_field_resp.json()["error"]["code"] == "INVALID_SORT_FIELD"

            # 3. Invalid sort order -> 422 (Pydantic StrEnum)
            bad_order_resp = await client.get(
                "/api/v1/users?sort_by=email&sort_order=backwards",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert bad_order_resp.status_code == 422

    async def test_sql_injection_resistance_in_search_and_filters(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_test_environment(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver.local"
        ) as client:
            token = await _get_token(client, env["super_admin"].email, env["password"])

            # Search with raw SQL injection attempt
            sqli_patterns = [
                "' OR '1'='1",
                "admin'--",
                "'; DROP TABLE users;--",
                "1' UNION SELECT * FROM users--",
            ]
            for pattern in sqli_patterns:
                resp = await client.get(
                    f"/api/v1/users?search={pattern}",
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert resp.status_code == 200, f"Query crashed with 500 on SQLi pattern: {pattern}"
                data = resp.json()
                assert isinstance(data["items"], list)

    async def test_zero_secret_leakage_in_responses(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_test_environment(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver.local"
        ) as client:
            token = await _get_token(client, env["super_admin"].email, env["password"])

            resp = await client.get(
                "/api/v1/users",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 200
            raw_text = resp.text

            # Crucial security invariants: password hashes and auth secrets never leaked
            assert "password_hash" not in raw_text
            assert "argon2" not in raw_text
            assert "token_hash" not in raw_text
            assert "secret_key" not in raw_text


@pytest.mark.integration
class TestOpenAPIContractValidation:
    """Phase 39: OpenAPI contract generation, unique operation IDs and example schemas."""

    def test_openapi_schema_generation_and_uniqueness(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        schema = app.openapi()

        # 1. Valid JSON serializable
        dumped = json.dumps(schema)
        assert len(dumped) > 1000

        # 2. Check operation IDs uniqueness
        paths = schema.get("paths", {})
        operation_ids: list[str] = []
        for path_item in paths.values():
            if isinstance(path_item, dict):
                for _method, op in path_item.items():
                    if isinstance(op, dict) and "operationId" in op:
                        operation_ids.append(op["operationId"])

        assert len(operation_ids) > 0
        duplicates = [op for op in operation_ids if operation_ids.count(op) > 1]
        assert not duplicates, f"Duplicate operation IDs detected: {duplicates}"

        # 3. Security: No secrets in schema descriptions or examples
        assert "password_hash" not in dumped
        assert "argon2" not in dumped
        assert postgres_settings.AUTH_SECRET_KEY.get_secret_value() not in dumped


@pytest.mark.integration
class TestLifecycleDuplicateAndConcurrencyRegressions:
    """Phase 40: Regressions for duplicates, token reuse, and lifecycle integrity."""

    async def test_duplicate_email_rejected_with_conflict(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_test_environment(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver.local"
        ) as client:
            token = await _get_token(client, env["super_admin"].email, env["password"])
            existing_user: User = env["investigator_alpha"]
            role_id = env["roles"][RoleCode.STAFF].id

            resp = await client.post(
                "/api/v1/users",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "email": existing_user.email,
                    "full_name": "Colliding User",
                    "role_id": str(role_id),
                    "department_id": str(env["dept_alpha"].id),
                    "password": "ValidPassword123!",
                    "account_status": "active",
                },
            )
            assert resp.status_code == 409
            assert resp.json()["error"]["code"] in {
                "EMAIL_ALREADY_EXISTS",
                "DATABASE_UNIQUE_CONFLICT",
            }

    async def test_token_replay_attack_rejected(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_test_environment(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        raw_token = generate_opaque_token(32)
        digest = hash_token(raw_token)
        student: User = env["student_alpha"]

        async with postgres_db_manager.transactional_session() as session:
            auth_token = AuthToken(
                user_id=student.id,
                token_hash=digest,
                purpose=AuthTokenPurpose.EMAIL_VERIFICATION.value,
                expires_at=datetime.now(UTC) + timedelta(hours=24),
            )
            session.add(auth_token)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver.local"
        ) as client:
            # 1. First consume succeeds
            resp1 = await client.post(
                "/api/v1/auth/verify-email/confirm",
                json={"token": raw_token},
            )
            assert resp1.status_code == 200

            # 2. Token replay attack rejected with 401
            resp2 = await client.post(
                "/api/v1/auth/verify-email/confirm",
                json={"token": raw_token},
            )
            assert resp2.status_code == 401
            assert resp2.json()["error"]["code"] in {
                "INVALID_VERIFICATION_TOKEN",
                "TOKEN_ALREADY_USED",
            }
