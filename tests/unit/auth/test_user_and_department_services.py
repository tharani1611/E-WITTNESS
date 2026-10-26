"""Unit tests for UserService and DepartmentService domain logic (Phases 23-25).

Tests business rule validation, horizontal/vertical privilege escalation defenses,
self-modification restrictions, and error conditions using mock repositories.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
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
    DepartmentCreate,
    DepartmentUpdate,
    UserAdminCreate,
    UserProfileUpdate,
    UserUpdate,
)
from backend.app.schemas.pagination import PaginationParams
from backend.app.services.department import DepartmentService
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
    email: str = "user@test.edu",
    full_name: str = "Dummy User",
    account_status: str = "active",
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
    dept_id: UUID | None = None, code: str = "DEPT", name: str = "Dept"
) -> Department:
    now = datetime.now(UTC)
    dept = Department(code=code, name=name, is_active=True)
    dept.id = dept_id or uuid4()
    dept.created_at = now
    dept.updated_at = now
    return dept


@pytest.mark.unit
class TestUserServiceUnit:
    """Unit tests for UserService boundary checks and defenses."""

    @pytest.fixture
    def mock_user_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_role_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_dept_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def user_service(
        self,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        test_settings: Settings,
    ) -> UserService:
        return UserService(
            user_repo=mock_user_repo,
            role_repo=mock_role_repo,
            dept_repo=mock_dept_repo,
            password_service=PasswordService(),
            settings=test_settings,
        )

    async def test_get_user_by_id_self_not_found(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        user_id = uuid4()
        principal = make_principal(RoleCode.STUDENT, user_id=user_id)
        mock_user_repo.get_by_id_unscoped.return_value = None

        with pytest.raises(ResourceNotFoundError) as exc_info:
            await user_service.get_user_by_id(user_id, principal)
        assert exc_info.value.code == "USER_NOT_FOUND"

    async def test_get_user_by_id_super_admin_not_found(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        mock_user_repo.get_by_id_unscoped.return_value = None

        with pytest.raises(ResourceNotFoundError) as exc_info:
            await user_service.get_user_by_id(uuid4(), principal)
        assert exc_info.value.code == "USER_NOT_FOUND"

    async def test_get_user_by_id_dept_admin_not_found(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        mock_user_repo.get_by_id_unscoped.return_value = None

        with pytest.raises(ResourceNotFoundError) as exc_info:
            await user_service.get_user_by_id(uuid4(), principal)
        assert exc_info.value.code == "USER_NOT_FOUND"

    async def test_get_user_by_id_dept_admin_other_dept(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        dept_a = uuid4()
        dept_b = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_a)
        target = make_dummy_user(department_id=dept_b)
        mock_user_repo.get_by_id_unscoped.return_value = target

        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.get_user_by_id(target.id, principal)
        assert exc_info.value.code == "DEPARTMENT_MISMATCH"

    async def test_get_user_by_id_other_role_cross_user_denied(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.INVESTIGATOR)
        other_user_id = uuid4()

        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.get_user_by_id(other_user_id, principal)
        assert exc_info.value.code == "PERMISSION_DENIED"

    async def test_list_users_unauthorized_role(
        self,
        user_service: UserService,
    ) -> None:
        principal = make_principal(RoleCode.STAFF)
        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.list_users(principal, pagination=PaginationParams())
        assert exc_info.value.code == "PERMISSION_DENIED"

    async def test_create_user_unauthorized_role(
        self,
        user_service: UserService,
    ) -> None:
        principal = make_principal(RoleCode.STUDENT)
        dto = UserAdminCreate(
            email="new@test.edu",
            full_name="New User",
            role_id=uuid4(),
            password="SecurePassword123!",
        )
        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.create_user(dto, principal)
        assert exc_info.value.code == "PERMISSION_DENIED"

    async def test_create_user_dept_admin_role_not_found(
        self,
        user_service: UserService,
        mock_role_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        mock_role_repo.get_by_id.return_value = None

        dto = UserAdminCreate(
            email="new@test.edu",
            full_name="New User",
            role_id=uuid4(),
            department_id=dept_id,
            password="SecurePassword123!",
        )
        with pytest.raises(BusinessRuleError) as exc_info:
            await user_service.create_user(dto, principal)
        assert exc_info.value.code == "INVALID_ROLE_ASSIGNMENT"

    async def test_update_user_not_found(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        mock_user_repo.get_by_id_unscoped.return_value = None

        with pytest.raises(ResourceNotFoundError) as exc_info:
            await user_service.update_user(uuid4(), UserUpdate(full_name="Name"), principal)
        assert exc_info.value.code == "USER_NOT_FOUND"

    async def test_update_user_dept_admin_role_lookup_not_found(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        target = make_dummy_user(department_id=dept_id)
        mock_user_repo.get_by_id_unscoped.return_value = target
        mock_role_repo.get_by_id.return_value = None

        with pytest.raises(BusinessRuleError) as exc_info:
            await user_service.update_user(
                target.id,
                UserUpdate(role_id=uuid4()),
                principal,
            )
        assert exc_info.value.code == "INVALID_ROLE_ASSIGNMENT"

    async def test_get_user_by_id_self_success(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        user_id = uuid4()
        target = make_dummy_user(user_id=user_id)
        principal = make_principal(RoleCode.STUDENT, user_id=user_id)
        mock_user_repo.get_by_id_unscoped.return_value = target

        res = await user_service.get_user_by_id(user_id, principal)
        assert res.id == user_id

    async def test_get_user_by_id_super_admin_success(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        user_id = uuid4()
        target = make_dummy_user(user_id=user_id)
        principal = make_principal(RoleCode.SUPER_ADMIN)
        mock_user_repo.get_by_id_unscoped.return_value = target

        res = await user_service.get_user_by_id(user_id, principal)
        assert res.id == user_id

    async def test_get_user_by_id_dept_admin_own_dept_success(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        user_id = uuid4()
        target = make_dummy_user(user_id=user_id, department_id=dept_id)
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        mock_user_repo.get_by_id_unscoped.return_value = target

        res = await user_service.get_user_by_id(user_id, principal)
        assert res.id == user_id

    async def test_list_users_dept_admin_success(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        target = make_dummy_user(department_id=dept_id)
        mock_user_repo.list_paginated.return_value = ([target], 1)

        res = await user_service.list_users(
            principal,
            pagination=PaginationParams(),
            department_id=dept_id,
        )
        assert len(res.items) == 1
        assert res.pagination.total_items == 1

    async def test_list_users_super_admin_success(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        target = make_dummy_user()
        mock_user_repo.list_paginated.return_value = ([target], 1)

        res = await user_service.list_users(
            principal,
            pagination=PaginationParams(),
        )
        assert len(res.items) == 1
        assert res.pagination.total_items == 1

    async def test_create_user_dept_admin_success(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        role = Role(
            code=RoleCode.STUDENT.value,
            name="Student",
            description="Student role",
            requires_department_scope=True,
            is_system_role=True,
        )
        role.id = uuid4()
        mock_role_repo.get_by_id.return_value = role

        target = make_dummy_user(role_id=role.id, department_id=dept_id)
        mock_user_repo.create.return_value = target

        dto = UserAdminCreate(
            email="student@test.edu",
            full_name="Student User",
            role_id=role.id,
            password="SecurePassword123!",
        )
        res = await user_service.create_user(dto, principal)
        assert res.id == target.id

    async def test_create_user_super_admin_success(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        target = make_dummy_user()
        mock_user_repo.create.return_value = target

        dto = UserAdminCreate(
            email="super_user@test.edu",
            full_name="Super User",
            role_id=target.role_id,
            password="SecurePassword123!",
        )
        res = await user_service.create_user(dto, principal)
        assert res.id == target.id

    async def test_update_user_dept_admin_success(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        target = make_dummy_user(department_id=dept_id)
        mock_user_repo.get_by_id_unscoped.return_value = target

        role = Role(
            code=RoleCode.INVESTIGATOR.value,
            name="Investigator",
            description="Investigator role",
            requires_department_scope=True,
            is_system_role=True,
        )
        role.id = uuid4()
        mock_role_repo.get_by_id.return_value = role

        updated_target = make_dummy_user(
            user_id=target.id,
            role_id=role.id,
            department_id=dept_id,
            full_name="Updated Name",
        )
        mock_user_repo.update_admin.return_value = updated_target

        res = await user_service.update_user(
            target.id,
            UserUpdate(full_name="Updated Name", role_id=role.id),
            principal,
        )
        assert res.full_name == "Updated Name"

    async def test_update_user_super_admin_success(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        target = make_dummy_user()
        mock_user_repo.get_by_id_unscoped.return_value = target
        mock_user_repo.update_admin.return_value = target

        res = await user_service.update_user(
            target.id,
            UserUpdate(full_name="New Name"),
            principal,
        )
        assert res.id == target.id

    async def test_update_own_profile_success(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        user_id = uuid4()
        principal = make_principal(RoleCode.STUDENT, user_id=user_id)
        target = make_dummy_user(user_id=user_id, full_name="My New Name")
        mock_user_repo.update_profile.return_value = target

        res = await user_service.update_own_profile(
            UserProfileUpdate(full_name="My New Name"),
            principal,
        )
        assert res.full_name == "My New Name"

    async def test_list_users_dept_admin_other_department_denied(
        self,
        user_service: UserService,
    ) -> None:
        dept_id = uuid4()
        other_dept_id = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.list_users(
                principal=principal,
                pagination=PaginationParams(),
                department_id=other_dept_id,
            )
        assert exc_info.value.code == "DEPARTMENT_MISMATCH"

    async def test_create_user_dept_admin_other_department_denied(
        self,
        user_service: UserService,
    ) -> None:
        dept_id = uuid4()
        other_dept_id = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        dto = UserAdminCreate(
            email="new@test.edu",
            full_name="New User",
            role_id=uuid4(),
            password="SecurePassword123!",
            department_id=other_dept_id,
        )
        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.create_user(dto, principal)
        assert exc_info.value.code == "DEPARTMENT_MISMATCH"

    async def test_create_user_dept_admin_invalid_role_code_enum(
        self,
        user_service: UserService,
        mock_role_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        role = MagicMock()
        role.id = uuid4()
        role.code = "NON_EXISTENT_ENUM"
        mock_role_repo.get_by_id.return_value = role

        dto = UserAdminCreate(
            email="new@test.edu",
            full_name="New User",
            role_id=role.id,
            password="SecurePassword123!",
        )
        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.create_user(dto, principal)
        assert exc_info.value.code == "PRIVILEGE_ESCALATION_FORBIDDEN"

    async def test_update_user_self_role_modification_denied(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        user_id = uuid4()
        principal = make_principal(RoleCode.SUPER_ADMIN, user_id=user_id)
        target = make_dummy_user(user_id=user_id)
        mock_user_repo.get_by_id_unscoped.return_value = target

        new_role_id = uuid4()
        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.update_user(
                user_id,
                UserUpdate(role_id=new_role_id),
                principal,
            )
        assert exc_info.value.code == "SELF_ROLE_MODIFICATION_FORBIDDEN"

    async def test_update_user_self_status_modification_denied(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        user_id = uuid4()
        principal = make_principal(RoleCode.SUPER_ADMIN, user_id=user_id)
        target = make_dummy_user(user_id=user_id)
        mock_user_repo.get_by_id_unscoped.return_value = target

        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.update_user(
                user_id,
                UserUpdate(account_status=AccountStatus.SUSPENDED),
                principal,
            )
        assert exc_info.value.code == "SELF_STATUS_MODIFICATION_FORBIDDEN"

        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.update_user(
                user_id,
                UserUpdate(is_active=False),
                principal,
            )
        assert exc_info.value.code == "SELF_STATUS_MODIFICATION_FORBIDDEN"

    async def test_update_user_self_department_reassignment_denied(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        user_id = uuid4()
        dept_id = uuid4()
        principal = make_principal(RoleCode.SUPER_ADMIN, user_id=user_id, department_id=dept_id)
        target = make_dummy_user(user_id=user_id, department_id=dept_id)
        mock_user_repo.get_by_id_unscoped.return_value = target

        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.update_user(
                user_id,
                UserUpdate(department_id=uuid4()),
                principal,
            )
        assert exc_info.value.code == "DEPARTMENT_REASSIGNMENT_RESTRICTED"

    async def test_update_user_no_permission_denied(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.STUDENT)
        target = make_dummy_user()
        mock_user_repo.get_by_id_unscoped.return_value = target

        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.update_user(
                target.id,
                UserUpdate(full_name="New Name"),
                principal,
            )
        assert exc_info.value.code == "PERMISSION_DENIED"

    async def test_update_user_dept_admin_other_department_denied(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        dept_a = uuid4()
        dept_b = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_a)
        target = make_dummy_user(department_id=dept_b)
        mock_user_repo.get_by_id_unscoped.return_value = target

        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.update_user(
                target.id,
                UserUpdate(full_name="New Name"),
                principal,
            )
        assert exc_info.value.code == "DEPARTMENT_MISMATCH"

    async def test_update_user_dept_admin_department_reassignment_denied(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        dept_a = uuid4()
        other_dept = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_a)
        target = make_dummy_user(department_id=dept_a)
        mock_user_repo.get_by_id_unscoped.return_value = target

        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.update_user(
                target.id,
                UserUpdate(department_id=other_dept),
                principal,
            )
        assert exc_info.value.code == "DEPARTMENT_REASSIGNMENT_RESTRICTED"

    async def test_update_user_dept_admin_role_not_found(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        target = make_dummy_user(department_id=dept_id)
        mock_user_repo.get_by_id_unscoped.return_value = target
        mock_role_repo.get_by_id.return_value = None

        with pytest.raises(BusinessRuleError) as exc_info:
            await user_service.update_user(
                target.id,
                UserUpdate(role_id=uuid4()),
                principal,
            )
        assert exc_info.value.code == "INVALID_ROLE_ASSIGNMENT"

    async def test_update_user_dept_admin_escalation_denied(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        target = make_dummy_user(department_id=dept_id)
        mock_user_repo.get_by_id_unscoped.return_value = target

        admin_role = Role(
            code=RoleCode.SUPER_ADMIN.value,
            name="Super Admin",
            description="System super administrator",
            requires_department_scope=False,
            is_system_role=True,
        )
        admin_role.id = uuid4()
        mock_role_repo.get_by_id.return_value = admin_role

        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.update_user(
                target.id,
                UserUpdate(role_id=admin_role.id),
                principal,
            )
        assert exc_info.value.code == "PRIVILEGE_ESCALATION_FORBIDDEN"

    async def test_update_user_dept_admin_invalid_role_code_enum(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        principal = make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        target = make_dummy_user(department_id=dept_id)
        mock_user_repo.get_by_id_unscoped.return_value = target

        invalid_role = MagicMock()
        invalid_role.id = uuid4()
        invalid_role.code = "NOT_IN_ENUM"
        mock_role_repo.get_by_id.return_value = invalid_role

        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.update_user(
                target.id,
                UserUpdate(role_id=invalid_role.id),
                principal,
            )
        assert exc_info.value.code == "PRIVILEGE_ESCALATION_FORBIDDEN"

    async def test_from_session_factory(self, test_settings: Settings) -> None:
        mock_session = AsyncMock()
        service = UserService.from_session(mock_session, test_settings)
        assert isinstance(service, UserService)


@pytest.mark.unit
class TestDepartmentServiceUnit:
    """Unit tests for DepartmentService boundary checks and defenses."""

    @pytest.fixture
    def mock_dept_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def dept_service(
        self,
        mock_dept_repo: AsyncMock,
        test_settings: Settings,
    ) -> DepartmentService:
        return DepartmentService(dept_repo=mock_dept_repo, settings=test_settings)

    async def test_get_dept_not_found(
        self,
        dept_service: DepartmentService,
        mock_dept_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        mock_dept_repo.get_by_id.return_value = None

        with pytest.raises(ResourceNotFoundError) as exc_info:
            await dept_service.get_department_by_id(uuid4(), principal)
        assert exc_info.value.code == "DEPARTMENT_NOT_FOUND"

    async def test_get_dept_other_dept_denied(
        self,
        dept_service: DepartmentService,
        mock_dept_repo: AsyncMock,
    ) -> None:
        dept_a = uuid4()
        dept_b = uuid4()
        principal = make_principal(RoleCode.INVESTIGATOR, department_id=dept_a)
        dept_model = make_dummy_dept(dept_id=dept_b)
        mock_dept_repo.get_by_id.return_value = dept_model

        with pytest.raises(PermissionDeniedError) as exc_info:
            await dept_service.get_department_by_id(dept_b, principal)
        assert exc_info.value.code == "DEPARTMENT_MISMATCH"

    async def test_list_departments_unauthorized(
        self,
        dept_service: DepartmentService,
    ) -> None:
        principal = make_principal(RoleCode.DEPT_ADMIN)
        with pytest.raises(PermissionDeniedError) as exc_info:
            await dept_service.list_departments(principal, pagination=PaginationParams())
        assert exc_info.value.code == "PERMISSION_DENIED"

    async def test_create_department_unauthorized(
        self,
        dept_service: DepartmentService,
    ) -> None:
        principal = make_principal(RoleCode.DEPT_ADMIN)
        with pytest.raises(PermissionDeniedError) as exc_info:
            await dept_service.create_department(
                DepartmentCreate(code="NEW", name="New Dept"),
                principal,
            )
        assert exc_info.value.code == "PERMISSION_DENIED"

    async def test_update_department_unauthorized(
        self,
        dept_service: DepartmentService,
    ) -> None:
        principal = make_principal(RoleCode.DEPT_ADMIN)
        with pytest.raises(PermissionDeniedError) as exc_info:
            await dept_service.update_department(
                uuid4(),
                DepartmentUpdate(name="New Name"),
                principal,
            )
        assert exc_info.value.code == "PERMISSION_DENIED"

    async def test_get_dept_super_admin_success(
        self,
        dept_service: DepartmentService,
        mock_dept_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        dept = make_dummy_dept()
        mock_dept_repo.get_by_id.return_value = dept

        res = await dept_service.get_department_by_id(dept.id, principal)
        assert res.id == dept.id

    async def test_get_dept_own_dept_success(
        self,
        dept_service: DepartmentService,
        mock_dept_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        principal = make_principal(RoleCode.STAFF, department_id=dept_id)
        dept = make_dummy_dept(dept_id=dept_id)
        mock_dept_repo.get_by_id.return_value = dept

        res = await dept_service.get_department_by_id(dept_id, principal)
        assert res.id == dept_id

    async def test_list_departments_super_admin_success(
        self,
        dept_service: DepartmentService,
        mock_dept_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        dept = make_dummy_dept()
        mock_dept_repo.list_paginated.return_value = ([dept], 1)

        res = await dept_service.list_departments(
            principal,
            pagination=PaginationParams(),
        )
        assert len(res.items) == 1
        assert res.pagination.total_items == 1

    async def test_create_department_conflict(
        self,
        dept_service: DepartmentService,
        mock_dept_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        dept = make_dummy_dept(code="MATH")
        mock_dept_repo.get_by_code.return_value = dept

        with pytest.raises(ConflictError) as exc_info:
            await dept_service.create_department(
                DepartmentCreate(code="MATH", name="Math"),
                principal,
            )
        assert exc_info.value.code == "DEPARTMENT_CODE_EXISTS"

    async def test_create_department_success(
        self,
        dept_service: DepartmentService,
        mock_dept_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        dept = make_dummy_dept(code="MATH")
        mock_dept_repo.get_by_code.return_value = None
        mock_dept_repo.create.return_value = dept

        res = await dept_service.create_department(
            DepartmentCreate(code="MATH", name="Math"),
            principal,
        )
        assert res.id == dept.id

    async def test_update_department_success(
        self,
        dept_service: DepartmentService,
        mock_dept_repo: AsyncMock,
    ) -> None:
        principal = make_principal(RoleCode.SUPER_ADMIN)
        dept = make_dummy_dept()
        mock_dept_repo.update.return_value = dept

        res = await dept_service.update_department(
            dept.id,
            DepartmentUpdate(name="Renamed"),
            principal,
        )
        assert res.id == dept.id

    async def test_from_session_factory(self, test_settings: Settings) -> None:
        mock_session = AsyncMock()
        service = DepartmentService.from_session(mock_session, test_settings)
        assert isinstance(service, DepartmentService)


@pytest.mark.unit
class TestRepositoryMutationsUnit:
    """Unit tests for repository update and validation logic."""

    async def test_user_repo_update_profile_not_found(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from backend.app.repositories.identity import UserRepository

        session = AsyncMock()
        repo = UserRepository(session)
        monkeypatch.setattr(repo, "get_by_id_unscoped", AsyncMock(return_value=None))
        with pytest.raises(ResourceNotFoundError):
            await repo.update_profile(uuid4(), full_name="Name")

    async def test_user_repo_update_profile_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from backend.app.repositories.identity import UserRepository

        session = AsyncMock()
        repo = UserRepository(session)
        user = make_dummy_user()
        monkeypatch.setattr(repo, "get_by_id_unscoped", AsyncMock(return_value=user))
        res = await repo.update_profile(user.id, full_name="New Name")
        assert res.full_name == "New Name"

    async def test_user_repo_update_admin_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from backend.app.repositories.identity import UserRepository

        session = AsyncMock()
        repo = UserRepository(session)
        monkeypatch.setattr(repo, "get_by_id_unscoped", AsyncMock(return_value=None))
        with pytest.raises(ResourceNotFoundError):
            await repo.update_admin(uuid4(), full_name="Name")

    async def test_user_repo_update_admin_role_not_found(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from backend.app.repositories.identity import UserRepository

        session = AsyncMock()
        repo = UserRepository(session)
        user = make_dummy_user()
        monkeypatch.setattr(repo, "get_by_id_unscoped", AsyncMock(return_value=user))
        session.execute = AsyncMock(
            return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None))
        )
        with pytest.raises(BusinessRuleError):
            await repo.update_admin(user.id, role_id=uuid4())

    async def test_dept_repo_update_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from backend.app.repositories.identity import DepartmentRepository

        session = AsyncMock()
        repo = DepartmentRepository(session)
        monkeypatch.setattr(repo, "get_by_id", AsyncMock(return_value=None))
        with pytest.raises(ResourceNotFoundError):
            await repo.update(uuid4(), name="Name")

    async def test_dept_repo_update_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from backend.app.repositories.identity import DepartmentRepository

        session = AsyncMock()
        repo = DepartmentRepository(session)
        dept = make_dummy_dept()
        monkeypatch.setattr(repo, "get_by_id", AsyncMock(return_value=dept))
        res = await repo.update(
            dept.id,
            name="New Name",
            description="Desc",
            is_active=False,
        )
        assert res.name == "New Name"
        assert res.is_active is False

    async def test_dept_repo_deactivate_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from backend.app.repositories.identity import DepartmentRepository

        session = AsyncMock()
        repo = DepartmentRepository(session)
        monkeypatch.setattr(repo, "get_by_id", AsyncMock(return_value=None))
        with pytest.raises(ResourceNotFoundError):
            await repo.deactivate(uuid4())

    async def test_dept_repo_deactivate_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from backend.app.repositories.identity import DepartmentRepository

        session = AsyncMock()
        repo = DepartmentRepository(session)
        dept = make_dummy_dept()
        monkeypatch.setattr(repo, "get_by_id", AsyncMock(return_value=dept))
        res = await repo.deactivate(dept.id)
        assert res.is_active is False

    async def test_dept_repo_activate_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from backend.app.repositories.identity import DepartmentRepository

        session = AsyncMock()
        repo = DepartmentRepository(session)
        monkeypatch.setattr(repo, "get_by_id", AsyncMock(return_value=None))
        with pytest.raises(ResourceNotFoundError):
            await repo.activate(uuid4())

    async def test_dept_repo_activate_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from backend.app.repositories.identity import DepartmentRepository

        session = AsyncMock()
        repo = DepartmentRepository(session)
        dept = make_dummy_dept()
        dept.is_active = False
        monkeypatch.setattr(repo, "get_by_id", AsyncMock(return_value=dept))
        res = await repo.activate(dept.id)
        assert res.is_active is True
