"""Unit tests for user profiles, staff invitations, deactivation, and department assignments (Phases 31, 32, 34).

Validates:
- Self-service profile updates and immutable identity attributes (Phase 31).
- Staff invitation workflow, department scoping, privilege escalation guards, and email dispatch (Phase 32).
- Account deactivation, self-deactivation guards, session invalidation, and Super Admin protection (Phase 32).
- Account activation lifecycle and terminal status rules (Phase 32).
- Department membership assignment and cross-department transfer controls (Phase 34).
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from backend.app.config.settings import Settings
from backend.app.core.exceptions import (
    BusinessRuleError,
    ConflictError,
    PermissionDeniedError,
    ResourceNotFoundError,
)
from backend.app.core.identity import AccountStatus, RoleCode
from backend.app.models.department import Department
from backend.app.models.role import Role
from backend.app.models.user import User
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.identity import (
    StaffInviteRequest,
    UserProfileUpdate,
)
from backend.app.services.email import FakeEmailDeliveryService
from backend.app.services.password import PasswordService
from backend.app.services.user import UserService


def make_principal(
    role: RoleCode = RoleCode.STUDENT,
    department_id: UUID | None = None,
    user_id: UUID | None = None,
) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        user_id=user_id or uuid4(),
        email="principal@institution.edu",
        full_name="Principal User",
        account_status=AccountStatus.ACTIVE.value,
        is_active=True,
        role_code=role.value,
        department_id=department_id,
        session_id=uuid4(),
    )


def make_dummy_user(
    user_id: UUID | None = None,
    role_id: UUID | None = None,
    department_id: UUID | None = None,
    email: str = "user@institution.edu",
    full_name: str = "Test User",
    account_status: str = AccountStatus.ACTIVE.value,
    is_active: bool = True,
) -> User:
    now = datetime.now(UTC)
    user = User(
        email=email,
        full_name=full_name,
        role_id=role_id or uuid4(),
        department_id=department_id,
        account_status=account_status,
        is_active=is_active,
    )
    user.id = user_id or uuid4()
    user.created_at = now
    user.updated_at = now
    return user


def make_dummy_dept(
    dept_id: UUID | None = None,
    code: str = "DEPT-TEST",
    name: str = "Test Department",
    is_active: bool = True,
) -> Department:
    now = datetime.now(UTC)
    dept = Department(code=code, name=name, is_active=is_active)
    dept.id = dept_id or uuid4()
    dept.created_at = now
    dept.updated_at = now
    return dept


def make_dummy_role(role_id: UUID | None = None, code: RoleCode = RoleCode.STAFF) -> Role:
    role = Role(code=code.value, name=code.value.replace("_", " ").title())
    role.id = role_id or uuid4()
    return role


@pytest.fixture
def mock_user_repo() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def mock_role_repo() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def mock_dept_repo() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def mock_session_repo() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def mock_token_repo() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def fake_email_service() -> FakeEmailDeliveryService:
    return FakeEmailDeliveryService()


@pytest.fixture
def user_service(
    mock_user_repo: AsyncMock,
    mock_role_repo: AsyncMock,
    mock_dept_repo: AsyncMock,
    mock_session_repo: AsyncMock,
    mock_token_repo: AsyncMock,
    fake_email_service: FakeEmailDeliveryService,
    test_settings: Settings,
) -> UserService:
    return UserService(
        user_repo=mock_user_repo,
        role_repo=mock_role_repo,
        dept_repo=mock_dept_repo,
        session_repo=mock_session_repo,
        auth_token_repo=mock_token_repo,
        password_service=PasswordService(),
        email_service=fake_email_service,
        settings=test_settings,
    )


@pytest.mark.unit
class TestUserProfilesAndValidationUnit:
    """Phase 31: User profile inspection and update validations."""

    async def test_update_own_profile_success(
        self, user_service: UserService, mock_user_repo: AsyncMock
    ) -> None:
        principal = make_principal(RoleCode.STUDENT)
        user = make_dummy_user(user_id=principal.user_id, full_name="Original Name")
        mock_user_repo.get_by_id_unscoped.return_value = user
        mock_user_repo.update_profile.return_value = user

        payload = UserProfileUpdate(full_name="Updated Name")
        res = await user_service.update_own_profile(payload, principal)

        mock_user_repo.update_profile.assert_awaited_once_with(
            principal.user_id, full_name="Updated Name"
        )
        assert res.id == principal.user_id

    async def test_update_own_profile_not_found(
        self, user_service: UserService, mock_user_repo: AsyncMock
    ) -> None:
        principal = make_principal(RoleCode.STUDENT)
        mock_user_repo.update_profile.side_effect = ResourceNotFoundError(
            "User was not found.", code="USER_NOT_FOUND"
        )

        payload = UserProfileUpdate(full_name="New Name")
        with pytest.raises(ResourceNotFoundError) as exc_info:
            await user_service.update_own_profile(payload, principal)
        assert exc_info.value.code == "USER_NOT_FOUND"


@pytest.mark.unit
class TestStaffInvitationWorkflowUnit:
    """Phase 32: Staff invitation, token dispatch, and scoped authorization."""

    async def test_invite_staff_super_admin_success(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        mock_token_repo: AsyncMock,
        fake_email_service: FakeEmailDeliveryService,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        dept = make_dummy_dept(is_active=True)
        staff_role = make_dummy_role(code=RoleCode.STAFF)

        mock_dept_repo.get_by_id.return_value = dept
        mock_role_repo.get_by_id.return_value = staff_role
        mock_user_repo.get_by_email.return_value = None

        created_user = make_dummy_user(
            email="staff.invitee@institution.edu",
            full_name="Invited Staff",
            department_id=dept.id,
            role_id=staff_role.id,
            account_status=AccountStatus.PENDING_VERIFICATION.value,
            is_active=False,
        )
        mock_user_repo.create.return_value = created_user

        body = StaffInviteRequest(
            email="staff.invitee@institution.edu",
            full_name="Invited Staff",
            role_id=staff_role.id,
            department_id=dept.id,
        )
        response = await user_service.invite_staff(body, principal)

        assert response.user.email == "staff.invitee@institution.edu"
        assert response.invitation_token is not None
        assert (
            fake_email_service.get_last_token_for("staff.invitee@institution.edu", "invitation")
            is not None
        )
        mock_token_repo.create.assert_awaited_once()

    async def test_invite_staff_dept_admin_cannot_escalate_to_super_admin(
        self,
        user_service: UserService,
        mock_dept_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        super_role = make_dummy_role(code=RoleCode.SUPER_ADMIN)
        mock_dept_repo.get_by_id.return_value = make_dummy_dept(dept_id=dept_id, is_active=True)
        mock_role_repo.get_by_id.return_value = super_role

        body = StaffInviteRequest(
            email="new.super@institution.edu",
            full_name="Escalated User",
            role_id=super_role.id,
            department_id=dept_id,
        )
        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.invite_staff(body, principal)
        assert exc_info.value.code == "PRIVILEGE_ESCALATION_FORBIDDEN"

    async def test_invite_staff_dept_admin_cross_department_forbidden(
        self,
        user_service: UserService,
    ) -> None:
        principal_dept = uuid4()
        target_dept = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=principal_dept)

        body = StaffInviteRequest(
            email="staff@institution.edu",
            full_name="Staff Target",
            role_id=uuid4(),
            department_id=target_dept,
        )
        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.invite_staff(body, principal)
        assert exc_info.value.code == "DEPARTMENT_MISMATCH"

    async def test_invite_staff_inactive_department_rejected(
        self,
        user_service: UserService,
        mock_dept_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        dept = make_dummy_dept(is_active=False)
        staff_role = make_dummy_role(code=RoleCode.STAFF)
        principal = make_principal(RoleCode.SUPER_ADMIN)
        mock_dept_repo.get_by_id.return_value = dept
        mock_role_repo.get_by_id.return_value = staff_role

        body = StaffInviteRequest(
            email="staff@institution.edu",
            full_name="Staff Target",
            role_id=staff_role.id,
            department_id=dept.id,
        )
        with pytest.raises(BusinessRuleError) as exc_info:
            await user_service.invite_staff(body, principal)
        assert exc_info.value.code == "INACTIVE_DEPARTMENT_ASSIGNMENT"

    async def test_invite_staff_duplicate_email_rejected(
        self,
        user_service: UserService,
        mock_dept_repo: AsyncMock,
        mock_role_repo: AsyncMock,
        mock_user_repo: AsyncMock,
    ) -> None:
        dept = make_dummy_dept(is_active=True)
        staff_role = make_dummy_role(code=RoleCode.STAFF)
        principal = make_principal(RoleCode.SUPER_ADMIN)

        mock_dept_repo.get_by_id.return_value = dept
        mock_role_repo.get_by_id.return_value = staff_role
        mock_user_repo.get_by_email.return_value = make_dummy_user(email="staff@institution.edu")

        body = StaffInviteRequest(
            email="staff@institution.edu",
            full_name="Staff Member",
            role_id=staff_role.id,
            department_id=dept.id,
        )
        with pytest.raises(ConflictError) as exc_info:
            await user_service.invite_staff(body, principal)
        assert exc_info.value.code == "EMAIL_ALREADY_EXISTS"


@pytest.mark.unit
class TestUserDeactivationAndActivationUnit:
    """Phase 32: Account deactivation, self-deactivation guards, and session invalidation."""

    async def test_deactivate_user_self_deactivation_forbidden(
        self, user_service: UserService
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.deactivate_user(principal.user_id, principal)
        assert exc_info.value.code == "SELF_DEACTIVATION_FORBIDDEN"

    async def test_deactivate_user_dept_admin_cross_dept_forbidden(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=uuid4())
        target = make_dummy_user(department_id=uuid4())
        mock_user_repo.get_by_id_unscoped.return_value = target

        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.deactivate_user(target.id, principal)
        assert exc_info.value.code == "DEPARTMENT_MISMATCH"

    async def test_deactivate_user_super_admin_success(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
        mock_session_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        staff_role = make_dummy_role(code=RoleCode.STAFF)
        target = make_dummy_user(role_id=staff_role.id, account_status=AccountStatus.ACTIVE.value)

        mock_user_repo.get_by_id_unscoped.return_value = target
        mock_role_repo.get_by_id.return_value = staff_role

        result = await user_service.deactivate_user(
            target.id, principal, reason="Administrative audit"
        )

        assert result.account_status == AccountStatus.DISABLED.value
        assert result.is_active is False
        mock_session_repo.revoke_user_sessions.assert_awaited_once()

    async def test_activate_user_self_activation_forbidden(self, user_service: UserService) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.activate_user(principal.user_id, principal)
        assert exc_info.value.code == "SELF_STATUS_MODIFICATION_FORBIDDEN"

    async def test_activate_user_permanently_disabled_rejected(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        target = make_dummy_user(account_status=AccountStatus.DISABLED.value, is_active=False)
        mock_user_repo.get_by_id_unscoped.return_value = target

        with pytest.raises(BusinessRuleError) as exc_info:
            await user_service.activate_user(target.id, principal)
        assert exc_info.value.code == "ACCOUNT_LIFECYCLE_RESTRICTED"

    async def test_activate_user_suspended_success(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        staff_role = make_dummy_role(code=RoleCode.STAFF)
        target = make_dummy_user(
            role_id=staff_role.id,
            account_status=AccountStatus.SUSPENDED.value,
            is_active=False,
        )

        mock_user_repo.get_by_id_unscoped.return_value = target
        mock_role_repo.get_by_id.return_value = staff_role

        result = await user_service.activate_user(target.id, principal)
        assert result.account_status == AccountStatus.ACTIVE.value
        assert result.is_active is True

    async def test_activate_user_already_active_returns_immediately(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        target = make_dummy_user(account_status=AccountStatus.ACTIVE.value, is_active=True)
        mock_user_repo.get_by_id_unscoped.return_value = target

        result = await user_service.activate_user(target.id, principal)
        assert result.account_status == AccountStatus.ACTIVE.value

    async def test_activate_user_dept_admin_cross_dept_forbidden(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=uuid4())
        target = make_dummy_user(
            department_id=uuid4(), account_status=AccountStatus.SUSPENDED.value
        )
        mock_user_repo.get_by_id_unscoped.return_value = target

        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.activate_user(target.id, principal)
        assert exc_info.value.code == "DEPARTMENT_MISMATCH"

    async def test_activate_user_dept_admin_cannot_activate_admin(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        admin_role = make_dummy_role(code=RoleCode.DEPT_ADMIN)
        target = make_dummy_user(
            department_id=dept_id,
            role_id=admin_role.id,
            account_status=AccountStatus.SUSPENDED.value,
        )
        mock_user_repo.get_by_id_unscoped.return_value = target
        mock_role_repo.get_by_id.return_value = admin_role

        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.activate_user(target.id, principal)
        assert exc_info.value.code == "PRIVILEGE_ESCALATION_FORBIDDEN"

    async def test_deactivate_user_dept_admin_cannot_deactivate_admin(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        admin_role = make_dummy_role(code=RoleCode.DEPT_ADMIN)
        target = make_dummy_user(department_id=dept_id, role_id=admin_role.id)
        mock_user_repo.get_by_id_unscoped.return_value = target
        mock_role_repo.get_by_id.return_value = admin_role

        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.deactivate_user(target.id, principal)
        assert exc_info.value.code == "PRIVILEGE_ESCALATION_FORBIDDEN"


@pytest.mark.unit
class TestDepartmentAssignmentUnit:
    """Phase 34: Department membership assignment and cross-department boundaries."""

    async def test_assign_department_self_reassignment_forbidden(
        self, user_service: UserService
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        target_dept_id = uuid4()

        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.assign_department(principal.user_id, target_dept_id, principal)
        assert exc_info.value.code == "DEPARTMENT_REASSIGNMENT_RESTRICTED"

    async def test_assign_department_inactive_dept_rejected(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        target = make_dummy_user()
        inactive_dept = make_dummy_dept(is_active=False)

        mock_user_repo.get_by_id_unscoped.return_value = target
        mock_dept_repo.get_by_id.return_value = inactive_dept

        with pytest.raises(BusinessRuleError) as exc_info:
            await user_service.assign_department(target.id, inactive_dept.id, principal)
        assert exc_info.value.code == "INACTIVE_DEPARTMENT_ASSIGNMENT"

    async def test_assign_department_super_admin_success(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        target = make_dummy_user()
        active_dept = make_dummy_dept(is_active=True)

        mock_user_repo.get_by_id_unscoped.return_value = target
        mock_dept_repo.get_by_id.return_value = active_dept

        result = await user_service.assign_department(target.id, active_dept.id, principal)
        assert result.department_id == active_dept.id

    async def test_assign_department_dept_admin_transfer_from_other_dept_forbidden(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        other_dept = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        target = make_dummy_user(department_id=other_dept)
        mock_user_repo.get_by_id_unscoped.return_value = target

        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.assign_department(target.id, dept_id, principal)
        assert exc_info.value.code == "DEPARTMENT_MISMATCH"

    async def test_assign_department_dept_admin_cannot_reassign_admin(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        admin_role = make_dummy_role(code=RoleCode.DEPT_ADMIN)
        target = make_dummy_user(department_id=dept_id, role_id=admin_role.id)
        mock_user_repo.get_by_id_unscoped.return_value = target
        mock_role_repo.get_by_id.return_value = admin_role

        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.assign_department(target.id, dept_id, principal)
        assert exc_info.value.code == "PRIVILEGE_ESCALATION_FORBIDDEN"

    async def test_assign_department_caller_lacks_permission_rejected(
        self, user_service: UserService
    ) -> None:
        principal = make_principal(RoleCode.STUDENT)
        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.assign_department(uuid4(), uuid4(), principal)
        assert exc_info.value.code == "PERMISSION_DENIED"

    async def test_assign_department_target_not_found(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        mock_user_repo.get_by_id_unscoped.return_value = None

        with pytest.raises(ResourceNotFoundError) as exc_info:
            await user_service.assign_department(uuid4(), uuid4(), principal)
        assert exc_info.value.code == "USER_NOT_FOUND"

    async def test_assign_department_dept_not_found(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        target = make_dummy_user()
        mock_user_repo.get_by_id_unscoped.return_value = target
        mock_dept_repo.get_by_id.return_value = None

        with pytest.raises(ResourceNotFoundError) as exc_info:
            await user_service.assign_department(target.id, uuid4(), principal)
        assert exc_info.value.code == "DEPARTMENT_NOT_FOUND"


@pytest.mark.unit
class TestUserPermissionsAndEdgeCasesUnit:
    """Additional edge cases for user invitations, deactivations, and activations."""

    async def test_invite_staff_caller_lacks_permission_rejected(
        self, user_service: UserService
    ) -> None:
        principal = make_principal(RoleCode.STUDENT)
        body = StaffInviteRequest(
            email="staff@institution.edu",
            full_name="Staff Candidate",
            role_id=uuid4(),
            department_id=uuid4(),
        )
        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.invite_staff(body, principal)
        assert exc_info.value.code == "PERMISSION_DENIED"

    async def test_invite_staff_role_not_found_rejected(
        self,
        user_service: UserService,
        mock_role_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        mock_dept_repo.get_by_id.return_value = make_dummy_dept(dept_id=dept_id)
        mock_role_repo.get_by_id.return_value = None

        body = StaffInviteRequest(
            email="staff@institution.edu",
            full_name="Staff Candidate",
            role_id=uuid4(),
            department_id=dept_id,
        )
        with pytest.raises(BusinessRuleError) as exc_info:
            await user_service.invite_staff(body, principal)
        assert exc_info.value.code == "INVALID_ROLE_ASSIGNMENT"

    async def test_invite_staff_department_not_found_rejected(
        self,
        user_service: UserService,
        mock_role_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        staff_role = make_dummy_role(code=RoleCode.STAFF)
        mock_role_repo.get_by_id.return_value = staff_role
        mock_dept_repo.get_by_id.return_value = None

        body = StaffInviteRequest(
            email="staff@institution.edu",
            full_name="Staff Candidate",
            role_id=staff_role.id,
            department_id=uuid4(),
        )
        with pytest.raises(ResourceNotFoundError) as exc_info:
            await user_service.invite_staff(body, principal)
        assert exc_info.value.code == "DEPARTMENT_NOT_FOUND"

    async def test_deactivate_user_caller_lacks_permission_rejected(
        self, user_service: UserService
    ) -> None:
        principal = make_principal(RoleCode.STUDENT)
        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.deactivate_user(uuid4(), principal)
        assert exc_info.value.code == "PERMISSION_DENIED"

    async def test_deactivate_user_target_not_found_rejected(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        mock_user_repo.get_by_id_unscoped.return_value = None

        with pytest.raises(ResourceNotFoundError) as exc_info:
            await user_service.deactivate_user(uuid4(), principal)
        assert exc_info.value.code == "USER_NOT_FOUND"

    async def test_deactivate_user_non_super_admin_cannot_deactivate_super_admin(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.INVESTIGATOR)
        super_role = make_dummy_role(code=RoleCode.SUPER_ADMIN)
        target = make_dummy_user(role_id=super_role.id)
        mock_user_repo.get_by_id_unscoped.return_value = target
        mock_role_repo.get_by_id.return_value = super_role

        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.deactivate_user(target.id, principal)
        assert exc_info.value.code == "PERMISSION_DENIED"

    async def test_activate_user_caller_lacks_permission_rejected(
        self, user_service: UserService
    ) -> None:
        principal = make_principal(RoleCode.STUDENT)
        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.activate_user(uuid4(), principal)
        assert exc_info.value.code == "PERMISSION_DENIED"

    async def test_activate_user_target_not_found_rejected(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        mock_user_repo.get_by_id_unscoped.return_value = None

        with pytest.raises(ResourceNotFoundError) as exc_info:
            await user_service.activate_user(uuid4(), principal)
        assert exc_info.value.code == "USER_NOT_FOUND"
