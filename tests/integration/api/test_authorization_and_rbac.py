"""PostgreSQL integration tests for Phases 21-25 (Authorization, RBAC, Scoping, and API Design).

All tests execute against real PostgreSQL (via `postgres_test_database_url` and `postgres_db_manager`),
verifying:
- Default-deny 401 Unauthenticated and 403 Unauthorized responses.
- Department-scoped access controls and horizontal privilege escalation prevention.
- Vertical privilege escalation prevention (Dept Admin cannot assign administrative roles).
- Self-modification guards (cannot alter own role, department, or account status).
- Super Admin global cross-department management.
- Pagination, allowlisted sorting, and domain filtering.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import httpx
import pytest

from backend.app.config.settings import Settings
from backend.app.core.identity import AccountStatus, RoleCode
from backend.app.infrastructure.database import DatabaseSessionManager
from backend.app.main import create_app
from backend.app.models.department import Department
from backend.app.models.user import User
from backend.app.repositories.identity import (
    DepartmentRepository,
    RoleRepository,
    UserRepository,
)
from backend.app.services.password import PasswordService


async def setup_departments_and_roles(
    postgres_db_manager: DatabaseSessionManager,
) -> tuple[Department, Department, dict[RoleCode, Any]]:
    """Helper to provision default roles and two isolated departments."""
    async with postgres_db_manager.transactional_session() as session:
        dept_repo = DepartmentRepository(session)
        role_repo = RoleRepository(session)
        roles = await role_repo.ensure_default_roles()
        dept_a = await dept_repo.create(
            Department(
                code=f"DEPT-A-{uuid4().hex[:6].upper()}",
                name="Department Alpha",
            )
        )
        dept_b = await dept_repo.create(
            Department(
                code=f"DEPT-B-{uuid4().hex[:6].upper()}",
                name="Department Beta",
            )
        )
        return dept_a, dept_b, roles


async def create_user_with_password(
    postgres_db_manager: DatabaseSessionManager,
    *,
    email: str,
    password: str,
    role: Any,
    department: Department | None = None,
    full_name: str = "Test User",
) -> User:
    """Create a user with hashed password in the PostgreSQL database."""
    pw_service = PasswordService()
    pw_hash = pw_service.hash_password(password)
    async with postgres_db_manager.transactional_session() as session:
        user_repo = UserRepository(session)
        user = User(
            email=email,
            full_name=full_name,
            department_id=department.id if department else None,
            role_id=role.id,
            account_status=AccountStatus.ACTIVE.value,
            is_active=True,
            password_hash=pw_hash,
        )
        return await user_repo.create(user)


async def login_and_get_token(
    client: httpx.AsyncClient,
    email: str,
    password: str,
) -> str:
    """Authenticate with credentials and return the JWT access token."""
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert resp.status_code == 200, f"Login failed for {email}: {resp.text}"
    data = resp.json()
    token = data["access_token"]
    assert isinstance(token, str) and len(token) > 20
    return token


@pytest.mark.integration
class TestAuthenticationAndBasicRBACRejections:
    """Phase 21 & 22: Verify 401 unauthenticated and 403 forbidden responses."""

    async def test_unauthenticated_requests_yield_401(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            resp1 = await client.get("/api/v1/users")
            assert resp1.status_code == 401
            assert resp1.json()["error"]["code"] == "UNAUTHENTICATED"

            resp2 = await client.post(
                "/api/v1/users",
                json={
                    "email": "test@test.edu",
                    "full_name": "Test",
                    "role_id": str(uuid4()),
                    "password": "Password123!",
                },
            )
            assert resp2.status_code == 401

            resp3 = await client.get("/api/v1/departments")
            assert resp3.status_code == 401

            resp4 = await client.post(
                "/api/v1/departments",
                json={"code": "MATH", "name": "Mathematics"},
            )
            assert resp4.status_code == 401

    async def test_student_lacks_permission_for_user_and_dept_management(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        dept_a, _, roles = await setup_departments_and_roles(postgres_db_manager)
        student_pw = "StudentPass123!"
        student = await create_user_with_password(
            postgres_db_manager,
            email=f"student_{uuid4().hex[:6]}@test.edu",
            password=student_pw,
            role=roles[RoleCode.STUDENT],
            department=dept_a,
        )

        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            token = await login_and_get_token(client, student.email, student_pw)
            headers = {"Authorization": f"Bearer {token}"}

            # Student cannot list users
            resp = await client.get("/api/v1/users", headers=headers)
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "PERMISSION_DENIED"

            # Student cannot create users
            resp = await client.post(
                "/api/v1/users",
                headers=headers,
                json={
                    "email": "intruder@test.edu",
                    "full_name": "Intruder",
                    "role_id": str(roles[RoleCode.STUDENT].id),
                    "password": "Password123!",
                },
            )
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "PERMISSION_DENIED"

            # Student cannot list departments
            resp = await client.get("/api/v1/departments", headers=headers)
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "PERMISSION_DENIED"

            # Student cannot create departments
            resp = await client.post(
                "/api/v1/departments",
                headers=headers,
                json={"code": "HACK", "name": "Hack Dept"},
            )
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "PERMISSION_DENIED"


@pytest.mark.integration
class TestHorizontalPrivilegeEscalationDefenses:
    """Phase 23 & 24: Department Administrators must not cross department boundaries."""

    async def test_department_admin_cannot_access_or_mutate_other_department(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        dept_a, dept_b, roles = await setup_departments_and_roles(postgres_db_manager)
        admin_a_pw = "DeptAdminA123!"
        admin_a = await create_user_with_password(
            postgres_db_manager,
            email=f"admin_a_{uuid4().hex[:6]}@test.edu",
            password=admin_a_pw,
            role=roles[RoleCode.DEPT_ADMIN],
            department=dept_a,
        )

        user_b = await create_user_with_password(
            postgres_db_manager,
            email=f"user_b_{uuid4().hex[:6]}@test.edu",
            password="UserBPassword123!",
            role=roles[RoleCode.STUDENT],
            department=dept_b,
            full_name="User In Dept B",
        )

        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            token_a = await login_and_get_token(client, admin_a.email, admin_a_pw)
            headers = {"Authorization": f"Bearer {token_a}"}

            # 1. Dept Admin A cannot list users filtering for Dept B
            resp = await client.get(
                f"/api/v1/users?department_id={dept_b.id}",
                headers=headers,
            )
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "DEPARTMENT_MISMATCH"

            # 2. Dept Admin A cannot get user in Dept B
            resp = await client.get(
                f"/api/v1/users/{user_b.id}",
                headers=headers,
            )
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "DEPARTMENT_MISMATCH"

            # 3. Dept Admin A cannot update user in Dept B
            resp = await client.patch(
                f"/api/v1/users/{user_b.id}",
                headers=headers,
                json={"full_name": "Tampered Name"},
            )
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "DEPARTMENT_MISMATCH"

            # 4. Dept Admin A cannot create user assigned to Dept B
            resp = await client.post(
                "/api/v1/users",
                headers=headers,
                json={
                    "email": f"new_cross_{uuid4().hex[:6]}@test.edu",
                    "full_name": "Cross Tenant User",
                    "role_id": str(roles[RoleCode.STUDENT].id),
                    "department_id": str(dept_b.id),
                    "password": "SecurePassword123!",
                },
            )
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "DEPARTMENT_MISMATCH"

            # 5. Dept Admin A cannot inspect Dept B details
            resp = await client.get(
                f"/api/v1/departments/{dept_b.id}",
                headers=headers,
            )
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "DEPARTMENT_MISMATCH"

            # But Dept Admin A CAN inspect Dept A details
            resp_own_dept = await client.get(
                f"/api/v1/departments/{dept_a.id}",
                headers=headers,
            )
            assert resp_own_dept.status_code == 200
            assert resp_own_dept.json()["id"] == str(dept_a.id)

    async def test_department_admin_cannot_reassign_user_department(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        dept_a, dept_b, roles = await setup_departments_and_roles(postgres_db_manager)
        admin_a_pw = "DeptAdminA123!"
        admin_a = await create_user_with_password(
            postgres_db_manager,
            email=f"admin_a2_{uuid4().hex[:6]}@test.edu",
            password=admin_a_pw,
            role=roles[RoleCode.DEPT_ADMIN],
            department=dept_a,
        )

        user_a = await create_user_with_password(
            postgres_db_manager,
            email=f"user_a_{uuid4().hex[:6]}@test.edu",
            password="UserAPassword123!",
            role=roles[RoleCode.STUDENT],
            department=dept_a,
        )

        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            token_a = await login_and_get_token(client, admin_a.email, admin_a_pw)
            headers = {"Authorization": f"Bearer {token_a}"}

            # Attempting to reassign user_a to dept_b
            resp = await client.patch(
                f"/api/v1/users/{user_a.id}",
                headers=headers,
                json={"department_id": str(dept_b.id)},
            )
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "DEPARTMENT_REASSIGNMENT_RESTRICTED"


@pytest.mark.integration
class TestVerticalPrivilegeEscalationDefenses:
    """Phase 23: Dept Admin must NOT create or assign Dept Admin or Super Admin roles."""

    async def test_department_admin_cannot_create_or_escalate_administrative_roles(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        dept_a, _, roles = await setup_departments_and_roles(postgres_db_manager)
        admin_a_pw = "DeptAdminA123!"
        admin_a = await create_user_with_password(
            postgres_db_manager,
            email=f"admin_escalate_{uuid4().hex[:6]}@test.edu",
            password=admin_a_pw,
            role=roles[RoleCode.DEPT_ADMIN],
            department=dept_a,
        )

        student_a = await create_user_with_password(
            postgres_db_manager,
            email=f"student_target_{uuid4().hex[:6]}@test.edu",
            password="StudentPass123!",
            role=roles[RoleCode.STUDENT],
            department=dept_a,
        )

        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            token_a = await login_and_get_token(client, admin_a.email, admin_a_pw)
            headers = {"Authorization": f"Bearer {token_a}"}

            # 1. Attempt to create a Dept Admin
            resp = await client.post(
                "/api/v1/users",
                headers=headers,
                json={
                    "email": f"new_admin_{uuid4().hex[:6]}@test.edu",
                    "full_name": "Rogue Admin",
                    "role_id": str(roles[RoleCode.DEPT_ADMIN].id),
                    "department_id": str(dept_a.id),
                    "password": "SecurePassword123!",
                },
            )
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "PRIVILEGE_ESCALATION_FORBIDDEN"

            # 2. Attempt to create a Super Admin
            resp = await client.post(
                "/api/v1/users",
                headers=headers,
                json={
                    "email": f"new_super_{uuid4().hex[:6]}@test.edu",
                    "full_name": "Rogue Super",
                    "role_id": str(roles[RoleCode.SUPER_ADMIN].id),
                    "department_id": str(dept_a.id),
                    "password": "SecurePassword123!",
                },
            )
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "PRIVILEGE_ESCALATION_FORBIDDEN"

            # 3. Attempt to escalate existing student to Dept Admin
            resp = await client.patch(
                f"/api/v1/users/{student_a.id}",
                headers=headers,
                json={"role_id": str(roles[RoleCode.DEPT_ADMIN].id)},
            )
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "PRIVILEGE_ESCALATION_FORBIDDEN"

            # 4. Attempt to escalate existing student to Super Admin
            resp = await client.patch(
                f"/api/v1/users/{student_a.id}",
                headers=headers,
                json={"role_id": str(roles[RoleCode.SUPER_ADMIN].id)},
            )
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "PRIVILEGE_ESCALATION_FORBIDDEN"

            # 5. But Dept Admin CAN assign permitted roles (e.g. Investigator)
            resp = await client.patch(
                f"/api/v1/users/{student_a.id}",
                headers=headers,
                json={"role_id": str(roles[RoleCode.INVESTIGATOR].id)},
            )
            assert resp.status_code == 200
            assert resp.json()["role_id"] == str(roles[RoleCode.INVESTIGATOR].id)


@pytest.mark.integration
class TestSelfModificationGuards:
    """Phase 24: Self-modification restrictions and self-service profile updates."""

    async def test_users_cannot_alter_own_role_or_status(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        dept_a, dept_b, roles = await setup_departments_and_roles(postgres_db_manager)
        admin_pw = "AdminSelf123!"
        admin = await create_user_with_password(
            postgres_db_manager,
            email=f"self_admin_{uuid4().hex[:6]}@test.edu",
            password=admin_pw,
            role=roles[RoleCode.DEPT_ADMIN],
            department=dept_a,
        )

        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            token = await login_and_get_token(client, admin.email, admin_pw)
            headers = {"Authorization": f"Bearer {token}"}

            # 1. Attempt to escalate own role
            resp = await client.patch(
                f"/api/v1/users/{admin.id}",
                headers=headers,
                json={"role_id": str(roles[RoleCode.SUPER_ADMIN].id)},
            )
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "SELF_ROLE_MODIFICATION_FORBIDDEN"

            # 2. Attempt to deactivate self
            resp = await client.patch(
                f"/api/v1/users/{admin.id}",
                headers=headers,
                json={"is_active": False},
            )
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "SELF_STATUS_MODIFICATION_FORBIDDEN"

            # 3. Attempt to change own account status
            resp = await client.patch(
                f"/api/v1/users/{admin.id}",
                headers=headers,
                json={"account_status": AccountStatus.SUSPENDED.value},
            )
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "SELF_STATUS_MODIFICATION_FORBIDDEN"

            # 4. Attempt to change own department
            resp = await client.patch(
                f"/api/v1/users/{admin.id}",
                headers=headers,
                json={"department_id": str(dept_b.id)},
            )
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "DEPARTMENT_REASSIGNMENT_RESTRICTED"

            # 5. Successfully update own profile name via /me/profile
            resp = await client.patch(
                "/api/v1/users/me/profile",
                headers=headers,
                json={"full_name": "Updated Self Name"},
            )
            assert resp.status_code == 200
            assert resp.json()["full_name"] == "Updated Self Name"


@pytest.mark.integration
class TestSuperAdminGlobalOperations:
    """Phases 23-25: Super Admin global operations across departments."""

    async def test_super_admin_full_lifecycle(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        dept_a, _dept_b, roles = await setup_departments_and_roles(postgres_db_manager)
        super_pw = "SuperAdminPassword123!"
        super_admin = await create_user_with_password(
            postgres_db_manager,
            email=f"super_{uuid4().hex[:6]}@test.edu",
            password=super_pw,
            role=roles[RoleCode.SUPER_ADMIN],
            department=None,
            full_name="Global Super Admin",
        )

        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            token = await login_and_get_token(client, super_admin.email, super_pw)
            headers = {"Authorization": f"Bearer {token}"}

            # 1. Super Admin lists all departments
            resp = await client.get("/api/v1/departments", headers=headers)
            assert resp.status_code == 200
            data = resp.json()
            assert "items" in data
            assert len(data["items"]) >= 2
            assert data["pagination"]["total_items"] >= 2

            # 2. Super Admin provisions a new department
            new_code = f"NEW-DEPT-{uuid4().hex[:6].upper()}"
            resp = await client.post(
                "/api/v1/departments",
                headers=headers,
                json={"code": new_code, "name": "Newly Created Department"},
            )
            assert resp.status_code == 201
            created_dept = resp.json()
            assert created_dept["code"] == new_code

            # 3. Duplicate department code rejection
            resp = await client.post(
                "/api/v1/departments",
                headers=headers,
                json={"code": new_code, "name": "Duplicate Department"},
            )
            assert resp.status_code == 409
            assert resp.json()["error"]["code"] == "DEPARTMENT_CODE_EXISTS"

            # 4. Super Admin modifies a department
            resp = await client.patch(
                f"/api/v1/departments/{created_dept['id']}",
                headers=headers,
                json={"name": "Renamed Department", "description": "Updated Description"},
            )
            assert resp.status_code == 200
            assert resp.json()["name"] == "Renamed Department"

            # 5. Super Admin creates user in any department with any role
            resp = await client.post(
                "/api/v1/users",
                headers=headers,
                json={
                    "email": f"provisioned_{uuid4().hex[:6]}@test.edu",
                    "full_name": "Provisioned Investigator",
                    "role_id": str(roles[RoleCode.INVESTIGATOR].id),
                    "department_id": created_dept["id"],
                    "password": "SecurePassword123!",
                },
            )
            assert resp.status_code == 201
            provisioned_user = resp.json()
            assert provisioned_user["department_id"] == created_dept["id"]

            # 6. Super Admin reassigns user across departments
            resp = await client.patch(
                f"/api/v1/users/{provisioned_user['id']}",
                headers=headers,
                json={"department_id": str(dept_a.id)},
            )
            assert resp.status_code == 200
            assert resp.json()["department_id"] == str(dept_a.id)


@pytest.mark.integration
class TestPaginationFilteringAndSorting:
    """Phase 25: Verification of query parameters, envelopes, sorting, and filtering."""

    async def test_pagination_and_sorting_on_users_collection(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        dept_a, _, roles = await setup_departments_and_roles(postgres_db_manager)
        admin_pw = "AdminPagination123!"
        admin = await create_user_with_password(
            postgres_db_manager,
            email=f"admin_page_{uuid4().hex[:6]}@test.edu",
            password=admin_pw,
            role=roles[RoleCode.DEPT_ADMIN],
            department=dept_a,
            full_name="Admin Page Tester",
        )

        # Seed 3 users in dept_a with specific names for sorting
        names = ["Alice Wonder", "Bob Builder", "Charlie Chaplin"]
        for name in names:
            await create_user_with_password(
                postgres_db_manager,
                email=f"{name.split()[0].lower()}_{uuid4().hex[:4]}@test.edu",
                password="TestPassword123!",
                role=roles[RoleCode.STUDENT],
                department=dept_a,
                full_name=name,
            )

        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            token = await login_and_get_token(client, admin.email, admin_pw)
            headers = {"Authorization": f"Bearer {token}"}

            # 1. Test pagination page_size=2
            resp = await client.get("/api/v1/users?page=1&page_size=2", headers=headers)
            assert resp.status_code == 200
            data = resp.json()
            assert len(data["items"]) == 2
            assert data["pagination"]["page"] == 1
            assert data["pagination"]["page_size"] == 2
            assert data["pagination"]["total_items"] >= 4  # 3 students + 1 admin
            assert data["pagination"]["has_next"] is True
            assert data["pagination"]["has_prev"] is False

            # 2. Test sorting asc
            resp_asc = await client.get(
                "/api/v1/users?sort_by=full_name&sort_order=asc",
                headers=headers,
            )
            assert resp_asc.status_code == 200
            items_asc = [u["full_name"] for u in resp_asc.json()["items"]]
            assert items_asc == sorted(items_asc)

            # 3. Test sorting desc
            resp_desc = await client.get(
                "/api/v1/users?sort_by=full_name&sort_order=desc",
                headers=headers,
            )
            assert resp_desc.status_code == 200
            items_desc = [u["full_name"] for u in resp_desc.json()["items"]]
            assert items_desc == sorted(items_desc, reverse=True)

            # 4. Reject unallowlisted sort field with 400 Bad Request
            resp_bad_sort = await client.get(
                "/api/v1/users?sort_by=password_hash",
                headers=headers,
            )
            assert resp_bad_sort.status_code == 400
            assert resp_bad_sort.json()["error"]["code"] == "INVALID_SORT_FIELD"

            # 5. Search substring match
            resp_search = await client.get(
                "/api/v1/users?search=Charlie",
                headers=headers,
            )
            assert resp_search.status_code == 200
            search_items = resp_search.json()["items"]
            assert len(search_items) == 1
            assert "Charlie" in search_items[0]["full_name"]

            # 6. Filter by role_code
            resp_role = await client.get(
                f"/api/v1/users?role_code={RoleCode.STUDENT.value}",
                headers=headers,
            )
            assert resp_role.status_code == 200
            for u in resp_role.json()["items"]:
                assert u["role_id"] == str(roles[RoleCode.STUDENT].id)
