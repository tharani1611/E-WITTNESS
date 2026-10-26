"""Unit tests for Investigator Assignment, Super Admin Controls & Repository Sorting (Phases 36-38).

Tests domain service logic, tenant isolation rules, administrative privilege
escalation boundaries, and repository query input validations.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

from backend.app.config.settings import Settings
from backend.app.core.exceptions import (
    BusinessRuleError,
    PermissionDeniedError,
    ResourceNotFoundError,
)
from backend.app.core.identity import AccountStatus, RoleCode
from backend.app.models.department import Department
from backend.app.models.role import Role
from backend.app.models.user import User
from backend.app.repositories.identity import (
    DepartmentRepository,
    UserRepository,
)
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.identity import UserUpdate
from backend.app.schemas.pagination import PaginationParams
from backend.app.services.password import PasswordService
from backend.app.services.user import UserService


def _make_principal(
    role: RoleCode = RoleCode.STUDENT,
    *,
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


def _make_user(
    *,
    role_id: UUID | None = None,
    department_id: UUID | None = None,
    account_status: AccountStatus = AccountStatus.ACTIVE,
    is_active: bool = True,
    email: str = "investigator.unit@ewitness.edu",
    full_name: str = "Detective Test Investigator",
) -> User:
    u = User(
        email=email,
        full_name=full_name,
        role_id=role_id or uuid4(),
        department_id=department_id,
        account_status=account_status.value,
        is_active=is_active,
    )
    u.id = uuid4()
    u.created_at = datetime.now(UTC)
    u.updated_at = datetime.now(UTC)
    return u


def _make_dept(
    *,
    dept_id: UUID | None = None,
    code: str = "FORENSICS",
    name: str = "Digital Forensics",
    is_active: bool = True,
) -> Department:
    d = Department(
        code=code,
        name=name,
        description="Department for forensics investigations",
        is_active=is_active,
    )
    d.id = dept_id or uuid4()
    d.created_at = datetime.now(UTC)
    d.updated_at = datetime.now(UTC)
    return d


def _make_role(
    *,
    role_id: UUID | None = None,
    code: RoleCode = RoleCode.INVESTIGATOR,
) -> Role:
    r = Role(
        code=code.value,
        name=code.value.title(),
        description=f"System {code.value} role",
        requires_department_scope=True,
        is_system_role=True,
    )
    r.id = role_id or uuid4()
    r.created_at = datetime.now(UTC)
    r.updated_at = datetime.now(UTC)
    return r


@pytest.fixture
def mock_user_repo() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def mock_dept_repo() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def mock_role_repo() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def user_service(
    mock_user_repo: AsyncMock,
    mock_dept_repo: AsyncMock,
    mock_role_repo: AsyncMock,
    test_settings: Settings,
) -> UserService:
    return UserService(
        user_repo=mock_user_repo,
        dept_repo=mock_dept_repo,
        role_repo=mock_role_repo,
        password_service=PasswordService(),
        settings=test_settings,
        session_repo=AsyncMock(),
        auth_token_repo=AsyncMock(),
        email_service=MagicMock(),
    )


class TestInvestigatorAssignmentUnit:
    """Unit tests for Phase 36: Investigator assignment and department scoping."""

    async def test_assign_investigator_success_super_admin(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        investigator_role = _make_role(code=RoleCode.INVESTIGATOR)
        old_dept = _make_dept(code="CYBER")
        new_dept = _make_dept(code="FORENSICS")
        target_user = _make_user(
            role_id=investigator_role.id,
            department_id=old_dept.id,
            account_status=AccountStatus.ACTIVE,
            is_active=True,
        )

        mock_user_repo.get_by_id_unscoped.return_value = target_user
        mock_role_repo.get_by_id.return_value = investigator_role
        mock_dept_repo.get_by_id.return_value = new_dept

        principal = _make_principal(RoleCode.SUPER_ADMIN)
        result = await user_service.assign_investigator(
            department_id=new_dept.id,
            investigator_id=target_user.id,
            principal=principal,
        )

        assert result.id == target_user.id
        assert target_user.department_id == new_dept.id

    async def test_assign_investigator_success_dept_admin(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        dept = _make_dept(code="FORENSICS")
        investigator_role = _make_role(code=RoleCode.INVESTIGATOR)
        target_user = _make_user(
            role_id=investigator_role.id,
            department_id=dept.id,
            account_status=AccountStatus.ACTIVE,
            is_active=True,
        )

        mock_user_repo.get_by_id_unscoped.return_value = target_user
        mock_role_repo.get_by_id.return_value = investigator_role
        mock_dept_repo.get_by_id.return_value = dept

        principal = _make_principal(RoleCode.DEPT_ADMIN, department_id=dept.id)
        result = await user_service.assign_investigator(
            department_id=dept.id,
            investigator_id=target_user.id,
            principal=principal,
        )

        assert result.id == target_user.id
        assert target_user.department_id == dept.id

    async def test_assign_investigator_idempotent(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        dept = _make_dept(code="FORENSICS")
        investigator_role = _make_role(code=RoleCode.INVESTIGATOR)
        target_user = _make_user(
            role_id=investigator_role.id,
            department_id=dept.id,
            account_status=AccountStatus.ACTIVE,
            is_active=True,
        )

        mock_user_repo.get_by_id_unscoped.return_value = target_user
        mock_role_repo.get_by_id.return_value = investigator_role
        mock_dept_repo.get_by_id.return_value = dept

        principal = _make_principal(RoleCode.SUPER_ADMIN)
        result = await user_service.assign_investigator(
            department_id=dept.id,
            investigator_id=target_user.id,
            principal=principal,
        )

        assert result.id == target_user.id
        assert target_user.department_id == dept.id

    async def test_assign_investigator_user_not_found(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
    ) -> None:
        mock_user_repo.get_by_id_unscoped.return_value = None
        principal = _make_principal(RoleCode.SUPER_ADMIN)

        with pytest.raises(ResourceNotFoundError) as exc_info:
            await user_service.assign_investigator(
                department_id=uuid4(),
                investigator_id=uuid4(),
                principal=principal,
            )
        assert exc_info.value.code == "USER_NOT_FOUND"

    async def test_assign_investigator_invalid_role(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        staff_role = _make_role(code=RoleCode.STAFF)
        target_user = _make_user(
            role_id=staff_role.id,
            account_status=AccountStatus.ACTIVE,
            is_active=True,
        )
        mock_user_repo.get_by_id_unscoped.return_value = target_user
        mock_role_repo.get_by_id.return_value = staff_role

        principal = _make_principal(RoleCode.SUPER_ADMIN)
        with pytest.raises(BusinessRuleError) as exc_info:
            await user_service.assign_investigator(
                department_id=uuid4(),
                investigator_id=target_user.id,
                principal=principal,
            )
        assert exc_info.value.code == "INVALID_ROLE_ASSIGNMENT"

    async def test_assign_investigator_inactive_account(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        investigator_role = _make_role(code=RoleCode.INVESTIGATOR)
        target_user = _make_user(
            role_id=investigator_role.id,
            account_status=AccountStatus.SUSPENDED,
            is_active=False,
        )
        mock_user_repo.get_by_id_unscoped.return_value = target_user
        mock_role_repo.get_by_id.return_value = investigator_role

        principal = _make_principal(RoleCode.SUPER_ADMIN)
        with pytest.raises(BusinessRuleError) as exc_info:
            await user_service.assign_investigator(
                department_id=uuid4(),
                investigator_id=target_user.id,
                principal=principal,
            )
        assert exc_info.value.code == "ACCOUNT_LIFECYCLE_RESTRICTED"

    async def test_assign_investigator_department_not_found(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        investigator_role = _make_role(code=RoleCode.INVESTIGATOR)
        target_user = _make_user(
            role_id=investigator_role.id,
            account_status=AccountStatus.ACTIVE,
            is_active=True,
        )
        mock_user_repo.get_by_id_unscoped.return_value = target_user
        mock_role_repo.get_by_id.return_value = investigator_role
        mock_dept_repo.get_by_id.return_value = None

        principal = _make_principal(RoleCode.SUPER_ADMIN)
        with pytest.raises(ResourceNotFoundError) as exc_info:
            await user_service.assign_investigator(
                department_id=uuid4(),
                investigator_id=target_user.id,
                principal=principal,
            )
        assert exc_info.value.code == "DEPARTMENT_NOT_FOUND"

    async def test_assign_investigator_inactive_department(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        investigator_role = _make_role(code=RoleCode.INVESTIGATOR)
        inactive_dept = _make_dept(code="OLD_DEPT", is_active=False)
        target_user = _make_user(
            role_id=investigator_role.id,
            account_status=AccountStatus.ACTIVE,
            is_active=True,
        )
        mock_user_repo.get_by_id_unscoped.return_value = target_user
        mock_role_repo.get_by_id.return_value = investigator_role
        mock_dept_repo.get_by_id.return_value = inactive_dept

        principal = _make_principal(RoleCode.SUPER_ADMIN)
        with pytest.raises(BusinessRuleError) as exc_info:
            await user_service.assign_investigator(
                department_id=inactive_dept.id,
                investigator_id=target_user.id,
                principal=principal,
            )
        assert exc_info.value.code == "INACTIVE_DEPARTMENT_ASSIGNMENT"

    async def test_assign_investigator_dept_admin_foreign_dept(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        my_dept = _make_dept(code="MY_DEPT")
        other_dept = _make_dept(code="OTHER_DEPT")
        investigator_role = _make_role(code=RoleCode.INVESTIGATOR)
        target_user = _make_user(
            role_id=investigator_role.id,
            department_id=my_dept.id,
            account_status=AccountStatus.ACTIVE,
            is_active=True,
        )
        mock_user_repo.get_by_id_unscoped.return_value = target_user
        mock_role_repo.get_by_id.return_value = investigator_role
        mock_dept_repo.get_by_id.return_value = other_dept

        principal = _make_principal(RoleCode.DEPT_ADMIN, department_id=my_dept.id)
        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.assign_investigator(
                department_id=other_dept.id,
                investigator_id=target_user.id,
                principal=principal,
            )
        assert exc_info.value.code == "DEPARTMENT_MISMATCH"

    async def test_assign_investigator_dept_admin_cannot_transfer_foreign_user(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        my_dept = _make_dept(code="MY_DEPT")
        other_dept = _make_dept(code="OTHER_DEPT")
        investigator_role = _make_role(code=RoleCode.INVESTIGATOR)
        target_user = _make_user(
            role_id=investigator_role.id,
            department_id=other_dept.id,
            account_status=AccountStatus.ACTIVE,
            is_active=True,
        )
        mock_user_repo.get_by_id_unscoped.return_value = target_user
        mock_role_repo.get_by_id.return_value = investigator_role
        mock_dept_repo.get_by_id.return_value = my_dept

        principal = _make_principal(RoleCode.DEPT_ADMIN, department_id=my_dept.id)
        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.assign_investigator(
                department_id=my_dept.id,
                investigator_id=target_user.id,
                principal=principal,
            )
        assert exc_info.value.code == "DEPARTMENT_MISMATCH"

    async def test_assign_investigator_permission_denied_ordinary_roles(
        self,
        user_service: UserService,
    ) -> None:
        student_principal = _make_principal(RoleCode.STUDENT)
        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.assign_investigator(
                department_id=uuid4(),
                investigator_id=uuid4(),
                principal=student_principal,
            )
        assert exc_info.value.code == "PERMISSION_DENIED"


class TestListDepartmentInvestigatorsUnit:
    """Unit tests for Phase 36: Listing department investigators with tenant boundaries."""

    async def test_list_department_investigators_dept_admin_own_dept(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
    ) -> None:
        dept = _make_dept(code="FORENSICS")
        mock_dept_repo.get_by_id.return_value = dept
        inv1 = _make_user(department_id=dept.id, full_name="Inv One")
        inv2 = _make_user(department_id=dept.id, full_name="Inv Two")
        mock_user_repo.list_paginated.return_value = ([inv1, inv2], 2)

        principal = _make_principal(RoleCode.DEPT_ADMIN, department_id=dept.id)
        result = await user_service.list_department_investigators(
            department_id=dept.id,
            principal=principal,
            pagination=PaginationParams(page=1, page_size=20),
        )

        assert len(result.items) == 2
        assert result.pagination.total_items == 2

    async def test_list_department_investigators_cross_dept_denied(
        self,
        user_service: UserService,
        mock_dept_repo: AsyncMock,
    ) -> None:
        dept1 = _make_dept(code="DEPT1")
        dept2 = _make_dept(code="DEPT2")
        mock_dept_repo.get_by_id.return_value = dept2

        principal = _make_principal(RoleCode.DEPT_ADMIN, department_id=dept1.id)
        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.list_department_investigators(
                department_id=dept2.id,
                principal=principal,
                pagination=PaginationParams(page=1, page_size=20),
            )
        assert exc_info.value.code == "DEPARTMENT_MISMATCH"

    async def test_list_department_investigators_super_admin_global(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
    ) -> None:
        dept = _make_dept(code="ANY_DEPT")
        mock_dept_repo.get_by_id.return_value = dept
        inv = _make_user(department_id=dept.id)
        mock_user_repo.list_paginated.return_value = ([inv], 1)

        principal = _make_principal(RoleCode.SUPER_ADMIN)
        result = await user_service.list_department_investigators(
            department_id=dept.id,
            principal=principal,
            pagination=PaginationParams(page=1, page_size=20),
        )

        assert len(result.items) == 1
        assert result.pagination.total_items == 1

    async def test_list_department_investigators_dept_not_found(
        self,
        user_service: UserService,
        mock_dept_repo: AsyncMock,
    ) -> None:
        mock_dept_repo.get_by_id.return_value = None
        principal = _make_principal(RoleCode.SUPER_ADMIN)

        with pytest.raises(ResourceNotFoundError) as exc_info:
            await user_service.list_department_investigators(
                department_id=uuid4(),
                principal=principal,
                pagination=PaginationParams(page=1, page_size=20),
            )
        assert exc_info.value.code == "DEPARTMENT_NOT_FOUND"


class TestSuperAdminPrivilegeBoundariesUnit:
    """Unit tests for Phase 37: Super Admin and Dept Admin privilege boundaries."""

    async def test_dept_admin_cannot_modify_super_admin_account(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        super_admin_role = _make_role(code=RoleCode.SUPER_ADMIN)
        super_admin_user = _make_user(
            role_id=super_admin_role.id,
            department_id=dept_id,
        )

        mock_user_repo.get_by_id_unscoped.return_value = super_admin_user
        mock_role_repo.get_by_id.return_value = super_admin_role

        dept_admin_principal = _make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.update_user(
                super_admin_user.id,
                UserUpdate(full_name="Compromised Name"),
                dept_admin_principal,
            )
        assert exc_info.value.code == "PRIVILEGE_ESCALATION_FORBIDDEN"

    async def test_dept_admin_cannot_modify_other_dept_admin_account(
        self,
        user_service: UserService,
        mock_user_repo: AsyncMock,
        mock_role_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        dept_admin_role = _make_role(code=RoleCode.DEPT_ADMIN)
        target_dept_admin = _make_user(
            role_id=dept_admin_role.id,
            department_id=dept_id,
        )

        mock_user_repo.get_by_id_unscoped.return_value = target_dept_admin
        mock_role_repo.get_by_id.return_value = dept_admin_role

        caller_dept_admin_principal = _make_principal(RoleCode.DEPT_ADMIN, department_id=dept_id)
        with pytest.raises(PermissionDeniedError) as exc_info:
            await user_service.update_user(
                target_dept_admin.id,
                UserUpdate(full_name="Target Name"),
                caller_dept_admin_principal,
            )
        assert exc_info.value.code == "PRIVILEGE_ESCALATION_FORBIDDEN"


class TestRepositorySortingAllowlistUnit:
    """Unit tests for Phase 38: Repository sorting allowlist and direction validation."""

    async def test_user_repository_invalid_sort_field(self) -> None:
        mock_session = AsyncMock()
        repo = UserRepository(mock_session)

        with pytest.raises(BusinessRuleError) as exc_info:
            await repo.list_paginated(sort_by="malicious_column; DROP TABLE users;--")
        assert exc_info.value.code == "INVALID_SORT_FIELD"

    async def test_user_repository_invalid_sort_order(self) -> None:
        mock_session = AsyncMock()
        repo = UserRepository(mock_session)

        with pytest.raises(BusinessRuleError) as exc_info:
            await repo.list_paginated(sort_by="email", sort_order="random_dir")
        assert exc_info.value.code == "INVALID_SORT_ORDER"

    async def test_department_repository_invalid_sort_field(self) -> None:
        mock_session = AsyncMock()
        repo = DepartmentRepository(mock_session)

        with pytest.raises(BusinessRuleError) as exc_info:
            await repo.list_paginated(sort_by="password_hash")
        assert exc_info.value.code == "INVALID_SORT_FIELD"

    async def test_department_repository_invalid_sort_order(self) -> None:
        mock_session = AsyncMock()
        repo = DepartmentRepository(mock_session)

        with pytest.raises(BusinessRuleError) as exc_info:
            await repo.list_paginated(sort_by="code", sort_order="descending")
        assert exc_info.value.code == "INVALID_SORT_ORDER"
