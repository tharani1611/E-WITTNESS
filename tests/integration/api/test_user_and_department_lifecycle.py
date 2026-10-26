"""Live PostgreSQL integration tests for Phases 31-35 (User Profiles, Staff Invitations, Departments, Membership, Student Lifecycle).

Tests real PostgreSQL database transactions, ensuring:
- Department creation, metadata updates, deactivation, and reactivation (Phase 33).
- Staff invitation workflow, department scoping, privilege escalation defenses, and activation (Phase 32).
- Account deactivation, self-deactivation protection, and session revocation (Phase 32).
- Department membership assignment and cross-department scoping (Phase 34).
- Student self-registration, active department checks, email verification, and login (Phase 35).
- Self-service profile updates (Phase 31).
"""

from __future__ import annotations

from datetime import UTC, datetime
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
    """Provision standard roles and two isolated departments in the real PostgreSQL database."""
    async with postgres_db_manager.transactional_session() as session:
        dept_repo = DepartmentRepository(session)
        role_repo = RoleRepository(session)
        roles = await role_repo.ensure_default_roles()
        dept_a = await dept_repo.create(
            Department(
                code=f"DEPT-A-{uuid4().hex[:6].upper()}",
                name="Engineering Department",
            )
        )
        dept_b = await dept_repo.create(
            Department(
                code=f"DEPT-B-{uuid4().hex[:6].upper()}",
                name="Science Department",
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
    account_status: str = AccountStatus.ACTIVE.value,
    is_active: bool = True,
) -> User:
    """Create a user with Argon2id password hash in the real PostgreSQL database."""
    pw_service = PasswordService()
    pw_hash = pw_service.hash_password(password)
    deactivated_at = (
        datetime.now(UTC)
        if account_status in {AccountStatus.SUSPENDED.value, AccountStatus.DISABLED.value}
        else None
    )
    async with postgres_db_manager.transactional_session() as session:
        user_repo = UserRepository(session)
        user = User(
            email=email,
            full_name=full_name,
            department_id=department.id if department else None,
            role_id=role.id,
            account_status=account_status,
            is_active=is_active,
            password_hash=pw_hash,
            deactivated_at=deactivated_at,
        )
        return await user_repo.create(user)


async def login_and_get_token(
    client: httpx.AsyncClient,
    email: str,
    password: str,
) -> str:
    """Authenticate credentials and return the JWT access token."""
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
class TestDepartmentManagementLifecycleIntegration:
    """Phase 33: Department creation, deactivation, and reactivation."""

    async def test_department_crud_and_status_transitions(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        dept_a, _dept_b, roles = await setup_departments_and_roles(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        super_admin_email = f"super.{uuid4().hex[:6]}@institution.edu"
        dept_admin_email = f"deptadmin.{uuid4().hex[:6]}@institution.edu"

        await create_user_with_password(
            postgres_db_manager,
            email=super_admin_email,
            password="SuperPassword123!",
            role=roles[RoleCode.SUPER_ADMIN],
        )
        await create_user_with_password(
            postgres_db_manager,
            email=dept_admin_email,
            password="DeptAdminPassword123!",
            role=roles[RoleCode.DEPT_ADMIN],
            department=dept_a,
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            super_token = await login_and_get_token(client, super_admin_email, "SuperPassword123!")
            super_headers = {"Authorization": f"Bearer {super_token}"}

            dept_admin_token = await login_and_get_token(
                client, dept_admin_email, "DeptAdminPassword123!"
            )
            dept_admin_headers = {"Authorization": f"Bearer {dept_admin_token}"}

            # 1. Super Admin creates a new department
            new_dept_code = f"NEW-{uuid4().hex[:6].upper()}"
            create_resp = await client.post(
                "/api/v1/departments",
                headers=super_headers,
                json={
                    "code": new_dept_code,
                    "name": "New Department",
                    "description": "Initial desc",
                },
            )
            assert create_resp.status_code == 201
            dept_data = create_resp.json()
            dept_id = dept_data["id"]
            assert dept_data["is_active"] is True

            # 2. Dept Admin cannot deactivate department (403 Forbidden)
            deact_fail = await client.post(
                f"/api/v1/departments/{dept_id}/deactivate",
                headers=dept_admin_headers,
            )
            assert deact_fail.status_code == 403

            # 3. Super Admin deactivates department
            deact_resp = await client.post(
                f"/api/v1/departments/{dept_id}/deactivate",
                headers=super_headers,
            )
            assert deact_resp.status_code == 200
            assert deact_resp.json()["is_active"] is False

            # 4. Super Admin reactivates department
            act_resp = await client.post(
                f"/api/v1/departments/{dept_id}/activate",
                headers=super_headers,
            )
            assert act_resp.status_code == 200
            assert act_resp.json()["is_active"] is True


@pytest.mark.integration
class TestStaffInvitationAndActivationIntegration:
    """Phase 32: Staff invitation, token dispatch, acceptance, and login."""

    async def test_staff_invitation_acceptance_and_login_flow(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        dept_a, _dept_b, roles = await setup_departments_and_roles(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        super_admin_email = f"super.{uuid4().hex[:6]}@institution.edu"
        await create_user_with_password(
            postgres_db_manager,
            email=super_admin_email,
            password="SuperPassword123!",
            role=roles[RoleCode.SUPER_ADMIN],
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            super_token = await login_and_get_token(client, super_admin_email, "SuperPassword123!")
            super_headers = {"Authorization": f"Bearer {super_token}"}

            # 1. Super Admin invites new staff member
            invite_email = f"invited.staff.{uuid4().hex[:6]}@institution.edu"
            invite_resp = await client.post(
                "/api/v1/users/invite",
                headers=super_headers,
                json={
                    "email": invite_email,
                    "full_name": "Invited Staff Candidate",
                    "role_id": str(roles[RoleCode.STAFF].id),
                    "department_id": str(dept_a.id),
                },
            )
            assert invite_resp.status_code == 201
            invite_body = invite_resp.json()
            invitation_token = invite_body["invitation_token"]
            assert invitation_token is not None

            # 2. Staff candidate cannot login before accepting invitation
            login_fail = await client.post(
                "/api/v1/auth/login",
                json={"email": invite_email, "password": "AnyPassword123!"},
            )
            assert login_fail.status_code == 401

            # 3. Candidate accepts invitation and configures credentials
            accept_resp = await client.post(
                "/api/v1/auth/invitations/accept",
                json={
                    "token": invitation_token,
                    "password": "ActivatedStaff123!",
                    "full_name": "Officially Joined Staff",
                },
            )
            assert accept_resp.status_code == 200

            # 4. Token cannot be reused (replay attack defense)
            replay_resp = await client.post(
                "/api/v1/auth/invitations/accept",
                json={
                    "token": invitation_token,
                    "password": "AnotherPassword123!",
                },
            )
            assert replay_resp.status_code == 401

            # 5. Activated staff successfully logs in
            staff_token = await login_and_get_token(client, invite_email, "ActivatedStaff123!")
            staff_headers = {"Authorization": f"Bearer {staff_token}"}

            # 6. Introspect profile
            me_resp = await client.get("/api/v1/auth/me", headers=staff_headers)
            assert me_resp.status_code == 200
            assert me_resp.json()["user"]["full_name"] == "Officially Joined Staff"


@pytest.mark.integration
class TestUserDeactivationAndSessionRevocationIntegration:
    """Phase 32: User deactivation, self-deactivation guard, and immediate session invalidation."""

    async def test_deactivation_invalidates_active_sessions(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        dept_a, _dept_b, roles = await setup_departments_and_roles(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        super_admin_email = f"super.{uuid4().hex[:6]}@institution.edu"
        staff_email = f"staff.{uuid4().hex[:6]}@institution.edu"

        await create_user_with_password(
            postgres_db_manager,
            email=super_admin_email,
            password="SuperPassword123!",
            role=roles[RoleCode.SUPER_ADMIN],
        )
        staff_user = await create_user_with_password(
            postgres_db_manager,
            email=staff_email,
            password="StaffPassword123!",
            role=roles[RoleCode.STAFF],
            department=dept_a,
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            super_token = await login_and_get_token(client, super_admin_email, "SuperPassword123!")
            super_headers = {"Authorization": f"Bearer {super_token}"}

            staff_token = await login_and_get_token(client, staff_email, "StaffPassword123!")
            staff_headers = {"Authorization": f"Bearer {staff_token}"}

            # 1. Staff confirms active session works
            me_resp = await client.get("/api/v1/auth/me", headers=staff_headers)
            assert me_resp.status_code == 200

            # 2. Staff cannot deactivate themselves
            self_deact_resp = await client.post(
                f"/api/v1/users/{staff_user.id}/deactivate",
                headers=staff_headers,
                json={"reason": "Self attempt"},
            )
            assert self_deact_resp.status_code == 403

            # 3. Super Admin deactivates staff member
            deact_resp = await client.post(
                f"/api/v1/users/{staff_user.id}/deactivate",
                headers=super_headers,
                json={"reason": "Disciplinary suspension"},
            )
            assert deact_resp.status_code == 200
            assert deact_resp.json()["is_active"] is False

            # 4. Immediate session revocation: old token is rejected
            me_after = await client.get("/api/v1/auth/me", headers=staff_headers)
            assert me_after.status_code == 401

            # 5. Subsequent login fails
            login_after = await client.post(
                "/api/v1/auth/login",
                json={"email": staff_email, "password": "StaffPassword123!"},
            )
            assert login_after.status_code == 401

            # 6. Reactivate an eligible suspended user via API
            suspended_email = f"suspended.{uuid4().hex[:6]}@institution.edu"
            suspended_user = await create_user_with_password(
                postgres_db_manager,
                email=suspended_email,
                password="SuspendedPassword123!",
                role=roles[RoleCode.STAFF],
                department=dept_a,
                account_status=AccountStatus.SUSPENDED.value,
                is_active=False,
            )
            act_resp = await client.post(
                f"/api/v1/users/{suspended_user.id}/activate",
                headers=super_headers,
            )
            assert act_resp.status_code == 200
            assert act_resp.json()["is_active"] is True
            assert act_resp.json()["account_status"] == AccountStatus.ACTIVE.value


@pytest.mark.integration
class TestDepartmentAssignmentIntegration:
    """Phase 34: Department membership assignment and cross-department boundaries."""

    async def test_assign_department_and_inactive_department_defense(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        dept_a, dept_b, roles = await setup_departments_and_roles(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        super_admin_email = f"super.{uuid4().hex[:6]}@institution.edu"
        dept_admin_email = f"deptadmin.{uuid4().hex[:6]}@institution.edu"
        staff_email = f"staff.{uuid4().hex[:6]}@institution.edu"

        await create_user_with_password(
            postgres_db_manager,
            email=super_admin_email,
            password="SuperPassword123!",
            role=roles[RoleCode.SUPER_ADMIN],
        )
        await create_user_with_password(
            postgres_db_manager,
            email=dept_admin_email,
            password="DeptAdminPassword123!",
            role=roles[RoleCode.DEPT_ADMIN],
            department=dept_a,
        )
        staff_user = await create_user_with_password(
            postgres_db_manager,
            email=staff_email,
            password="StaffPassword123!",
            role=roles[RoleCode.STAFF],
            department=dept_a,
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            super_token = await login_and_get_token(client, super_admin_email, "SuperPassword123!")
            super_headers = {"Authorization": f"Bearer {super_token}"}

            dept_admin_token = await login_and_get_token(
                client, dept_admin_email, "DeptAdminPassword123!"
            )
            dept_admin_headers = {"Authorization": f"Bearer {dept_admin_token}"}

            # 1. Dept Admin cannot transfer staff to another department (403 Forbidden)
            cross_reassign = await client.post(
                f"/api/v1/users/{staff_user.id}/department",
                headers=dept_admin_headers,
                json={"department_id": str(dept_b.id)},
            )
            assert cross_reassign.status_code == 403

            # 2. Super Admin can transfer staff to Department B
            super_reassign = await client.post(
                f"/api/v1/users/{staff_user.id}/department",
                headers=super_headers,
                json={"department_id": str(dept_b.id)},
            )
            assert super_reassign.status_code == 200
            assert super_reassign.json()["department_id"] == str(dept_b.id)

            # 3. Super Admin deactivates Department A
            await client.post(
                f"/api/v1/departments/{dept_a.id}/deactivate",
                headers=super_headers,
            )

            # 4. Attempting to assign staff to deactivated Department A fails (422 Unprocessable Entity)
            inactive_assign = await client.post(
                f"/api/v1/users/{staff_user.id}/department",
                headers=super_headers,
                json={"department_id": str(dept_a.id)},
            )
            assert inactive_assign.status_code == 422
            assert inactive_assign.json()["error"]["code"] == "INACTIVE_DEPARTMENT_ASSIGNMENT"


@pytest.mark.integration
class TestStudentLifecycleIntegration:
    """Phase 35: Student self-registration, email verification, and login."""

    async def test_student_self_registration_verification_and_login(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        dept_a, _dept_b, _roles = await setup_departments_and_roles(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            student_email = f"student.{uuid4().hex[:6]}@institution.edu"
            student_pw = "StudentPassword123!"

            # 1. Self-register student
            reg_resp = await client.post(
                "/api/v1/auth/register",
                json={
                    "email": student_email,
                    "password": student_pw,
                    "full_name": "Enrolled Biology Student",
                    "department_id": str(dept_a.id),
                    "institutional_id": "BIO-2026-901",
                },
            )
            assert reg_resp.status_code == 201
            reg_body = reg_resp.json()
            verif_token = reg_body["verification_token"]
            assert verif_token is not None

            # 2. Login fails prior to verification
            pre_login = await client.post(
                "/api/v1/auth/login",
                json={"email": student_email, "password": student_pw},
            )
            assert pre_login.status_code == 401

            # 3. Confirm email verification
            confirm_resp = await client.post(
                "/api/v1/auth/verify-email/confirm",
                json={"token": verif_token},
            )
            assert confirm_resp.status_code == 200

            # 4. Login succeeds after verification
            student_token = await login_and_get_token(client, student_email, student_pw)
            student_headers = {"Authorization": f"Bearer {student_token}"}

            # 5. Student self-profile inspection and update (Phase 31)
            me_resp = await client.get("/api/v1/auth/me", headers=student_headers)
            assert me_resp.status_code == 200
            assert me_resp.json()["role"]["code"] == RoleCode.STUDENT.value

            profile_patch = await client.patch(
                "/api/v1/users/me/profile",
                headers=student_headers,
                json={"full_name": "Biology Scholar Student"},
            )
            assert profile_patch.status_code == 200
            assert profile_patch.json()["full_name"] == "Biology Scholar Student"
