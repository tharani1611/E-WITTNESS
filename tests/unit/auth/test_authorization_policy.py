"""Unit tests for authorization matrix, RBAC dependencies, and pagination (Phases 21-25)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError

from backend.app.api.dependencies import (
    require_all_permissions,
    require_any_permission,
    require_permission,
)
from backend.app.core.authorization import (
    DEPT_ADMIN_ASSIGNABLE_ROLES,
    Permission,
    get_role_permissions,
    has_all_permissions,
    has_any_permission,
    has_permission,
)
from backend.app.core.exceptions import PermissionDeniedError
from backend.app.core.identity import AccountStatus, RoleCode
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.identity import (
    DepartmentUpdate,
    UserAdminCreate,
    UserProfileUpdate,
    UserUpdate,
)
from backend.app.schemas.pagination import (
    PaginatedResponse,
    PaginationMetadata,
    PaginationParams,
    SortOrder,
)


@pytest.mark.unit
class TestAuthorizationMatrix:
    """Verify granular role-to-permission mapping and default-deny policies (Phase 21)."""

    def test_all_five_roles_have_explicit_permission_mappings(self) -> None:
        for role in RoleCode:
            perms = get_role_permissions(role)
            assert isinstance(perms, frozenset)
            assert len(perms) > 0, f"Role {role} should have non-empty permissions"

    def test_student_and_staff_permissions_are_strictly_self_service(self) -> None:
        student_perms = get_role_permissions(RoleCode.STUDENT)
        staff_perms = get_role_permissions(RoleCode.STAFF)

        expected = frozenset(
            {
                Permission.USER_READ_OWN,
                Permission.USER_UPDATE_OWN,
                Permission.SESSION_READ_OWN,
                Permission.SESSION_REVOKE_OWN,
                Permission.INCIDENT_CREATE,
                Permission.INCIDENT_READ_OWN,
                Permission.INCIDENT_UPDATE_OWN,
                Permission.EVIDENCE_UPLOAD_OWN,
                Permission.EVIDENCE_READ_OWN,
                Permission.BIOMETRIC_REFERENCE_READ_OWN,
                Permission.BIOMETRIC_REFERENCE_MANAGE_OWN,
                Permission.NOTIFICATION_READ_OWN,
                Permission.NOTIFICATION_UPDATE_OWN,
                Permission.NOTIFICATION_PREFERENCE_MANAGE_OWN,
            }
        )
        assert student_perms == expected
        assert staff_perms == expected

    def test_investigator_has_department_read_in_addition_to_self(self) -> None:
        investigator_perms = get_role_permissions(RoleCode.INVESTIGATOR)
        assert Permission.DEPARTMENT_READ_OWN in investigator_perms
        assert Permission.USER_CREATE_DEPT not in investigator_perms
        assert Permission.USER_READ_GLOBAL not in investigator_perms

    def test_department_admin_has_department_scoped_permissions(self) -> None:
        dept_perms = get_role_permissions(RoleCode.DEPT_ADMIN)
        assert Permission.USER_CREATE_DEPT in dept_perms
        assert Permission.USER_READ_DEPT in dept_perms
        assert Permission.USER_UPDATE_DEPT in dept_perms
        assert Permission.USER_STATUS_UPDATE_DEPT in dept_perms
        assert Permission.USER_ROLE_ASSIGN_DEPT in dept_perms
        assert Permission.DEPARTMENT_READ_OWN in dept_perms

        # Must not have global permissions
        assert Permission.USER_CREATE_GLOBAL not in dept_perms
        assert Permission.USER_READ_GLOBAL not in dept_perms
        assert Permission.DEPARTMENT_CREATE_GLOBAL not in dept_perms
        assert Permission.SYSTEM_CONFIG_MANAGE not in dept_perms

    def test_super_admin_has_full_global_permissions(self) -> None:
        super_perms = get_role_permissions(RoleCode.SUPER_ADMIN)
        assert Permission.USER_CREATE_GLOBAL in super_perms
        assert Permission.USER_READ_GLOBAL in super_perms
        assert Permission.DEPARTMENT_CREATE_GLOBAL in super_perms
        assert Permission.SYSTEM_CONFIG_MANAGE in super_perms

    def test_dept_admin_assignable_roles_excludes_admins(self) -> None:
        assert RoleCode.STUDENT in DEPT_ADMIN_ASSIGNABLE_ROLES
        assert RoleCode.STAFF in DEPT_ADMIN_ASSIGNABLE_ROLES
        assert RoleCode.INVESTIGATOR in DEPT_ADMIN_ASSIGNABLE_ROLES
        assert RoleCode.DEPT_ADMIN not in DEPT_ADMIN_ASSIGNABLE_ROLES
        assert RoleCode.SUPER_ADMIN not in DEPT_ADMIN_ASSIGNABLE_ROLES

    def test_unknown_role_returns_empty_frozenset(self) -> None:
        assert get_role_permissions("unknown_role") == frozenset()
        assert get_role_permissions("") == frozenset()
        assert get_role_permissions("role_super_hacker") == frozenset()

    def test_has_permission_checks(self) -> None:
        assert has_permission(RoleCode.SUPER_ADMIN, Permission.SYSTEM_CONFIG_MANAGE) is True
        assert has_permission(RoleCode.STUDENT, Permission.SYSTEM_CONFIG_MANAGE) is False
        assert has_permission("invalid_role", Permission.USER_READ_OWN) is False
        assert has_permission(RoleCode.STUDENT, "invalid_perm") is False

    def test_has_any_permission_checks(self) -> None:
        assert (
            has_any_permission(
                RoleCode.STUDENT,
                [Permission.USER_READ_OWN, Permission.SYSTEM_CONFIG_MANAGE],
            )
            is True
        )
        assert (
            has_any_permission(
                RoleCode.STUDENT,
                [Permission.USER_CREATE_DEPT, Permission.SYSTEM_CONFIG_MANAGE],
            )
            is False
        )
        assert (
            has_any_permission(
                RoleCode.STUDENT,
                ["non_existent_perm"],
            )
            is False
        )

    def test_has_all_permissions_checks(self) -> None:
        assert (
            has_all_permissions(
                RoleCode.SUPER_ADMIN,
                [Permission.USER_CREATE_GLOBAL, Permission.USER_READ_GLOBAL],
            )
            is True
        )
        assert (
            has_all_permissions(
                RoleCode.DEPT_ADMIN,
                [Permission.USER_READ_DEPT, Permission.SYSTEM_CONFIG_MANAGE],
            )
            is False
        )
        assert (
            has_all_permissions(
                RoleCode.SUPER_ADMIN,
                ["non_existent_perm"],
            )
            is False
        )


@pytest.mark.unit
class TestRBACDependencies:
    """Verify FastAPI dependency factories enforce RBAC correctly (Phase 22)."""

    def _make_principal(self, role: RoleCode) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            user_id=uuid4(),
            email="test@institution.edu",
            full_name="Test Principal",
            account_status=AccountStatus.ACTIVE.value,
            is_active=True,
            role_code=role.value,
            department_id=uuid4(),
            session_id=uuid4(),
        )

    def test_require_permission_allows_authorized_role(self) -> None:
        dep = require_permission(Permission.USER_CREATE_GLOBAL)
        super_principal = self._make_principal(RoleCode.SUPER_ADMIN)
        result = dep(super_principal)
        assert result == super_principal

    def test_require_permission_raises_403_for_unauthorized_role(self) -> None:
        dep = require_permission(Permission.USER_CREATE_GLOBAL)
        student_principal = self._make_principal(RoleCode.STUDENT)
        with pytest.raises(PermissionDeniedError) as exc_info:
            dep(student_principal)
        assert exc_info.value.status_code == 403
        assert exc_info.value.code == "PERMISSION_DENIED"

    def test_require_any_permission_allows_if_at_least_one_matches(self) -> None:
        dep = require_any_permission(Permission.USER_READ_DEPT, Permission.USER_READ_GLOBAL)
        dept_admin = self._make_principal(RoleCode.DEPT_ADMIN)
        assert dep(dept_admin) == dept_admin

    def test_require_any_permission_denies_if_none_match(self) -> None:
        dep = require_any_permission(Permission.USER_READ_DEPT, Permission.USER_READ_GLOBAL)
        student = self._make_principal(RoleCode.STUDENT)
        with pytest.raises(PermissionDeniedError) as exc_info:
            dep(student)
        assert exc_info.value.status_code == 403
        assert exc_info.value.code == "PERMISSION_DENIED"

    def test_require_all_permissions_behavior(self) -> None:
        dep = require_all_permissions(Permission.USER_READ_OWN, Permission.USER_UPDATE_OWN)
        student = self._make_principal(RoleCode.STUDENT)
        assert dep(student) == student

        dep_fail = require_all_permissions(
            Permission.USER_READ_OWN,
            Permission.SYSTEM_CONFIG_MANAGE,
        )
        with pytest.raises(PermissionDeniedError) as exc_info:
            dep_fail(student)
        assert exc_info.value.status_code == 403
        assert exc_info.value.code == "PERMISSION_DENIED"


@pytest.mark.unit
class TestPaginationSchemas:
    """Verify pagination, sorting, and envelope schemas (Phase 25)."""

    def test_pagination_params_defaults_and_properties(self) -> None:
        params = PaginationParams()
        assert params.page == 1
        assert params.page_size == 20
        assert params.offset == 0
        assert params.limit == 20

    def test_pagination_params_custom_values(self) -> None:
        params = PaginationParams(page=3, page_size=50)
        assert params.page == 3
        assert params.page_size == 50
        assert params.offset == 100
        assert params.limit == 50

    def test_pagination_params_validation_bounds(self) -> None:
        with pytest.raises(ValidationError):
            PaginationParams(page=0)
        with pytest.raises(ValidationError):
            PaginationParams(page_size=0)
        with pytest.raises(ValidationError):
            PaginationParams(page_size=101)

    def test_sort_order_enum(self) -> None:
        assert SortOrder.ASC.value == "asc"
        assert SortOrder.DESC.value == "desc"

    def test_pagination_metadata_from_counts_empty_results(self) -> None:
        meta = PaginationMetadata.from_counts(page=1, page_size=20, total_items=0)
        assert meta.page == 1
        assert meta.page_size == 20
        assert meta.total_items == 0
        assert meta.total_pages == 0
        assert meta.has_next is False
        assert meta.has_prev is False

    def test_pagination_metadata_from_counts_multipage(self) -> None:
        meta = PaginationMetadata.from_counts(page=2, page_size=10, total_items=25)
        assert meta.page == 2
        assert meta.page_size == 10
        assert meta.total_items == 25
        assert meta.total_pages == 3
        assert meta.has_next is True
        assert meta.has_prev is True

    def test_pagination_metadata_last_page(self) -> None:
        meta = PaginationMetadata.from_counts(page=3, page_size=10, total_items=25)
        assert meta.has_next is False
        assert meta.has_prev is True

    def test_paginated_response_envelope(self) -> None:
        meta = PaginationMetadata.from_counts(page=1, page_size=2, total_items=3)
        response = PaginatedResponse[str](items=["item1", "item2"], pagination=meta)
        assert len(response.items) == 2
        assert response.pagination.total_items == 3
        assert response.pagination.has_next is True


@pytest.mark.unit
class TestIdentityDTOValidation:
    """Verify input DTO validation for administrative and self-service schemas."""

    def test_department_update_validation(self) -> None:
        update_dto = DepartmentUpdate(name="  Physics Department  ", is_active=True)
        assert update_dto.name == "Physics Department"
        assert update_dto.is_active is True

        with pytest.raises(ValidationError):
            DepartmentUpdate(name="   ")

    def test_user_profile_update_validation(self) -> None:
        profile = UserProfileUpdate(full_name="  Dr. Jane Doe  ")
        assert profile.full_name == "Dr. Jane Doe"

        with pytest.raises(ValidationError):
            UserProfileUpdate(full_name=" ")

    def test_user_admin_create_validation(self) -> None:
        role_id = uuid4()
        dept_id = uuid4()
        user_create = UserAdminCreate(
            email="  NEW_USER@INSTITUTION.EDU  ",
            full_name="  New User  ",
            role_id=role_id,
            department_id=dept_id,
            password="SecurePassword123!",
            account_status=AccountStatus.ACTIVE,
        )
        assert user_create.email == "new_user@institution.edu"
        assert user_create.full_name == "New User"
        assert user_create.role_id == role_id
        assert user_create.password == "SecurePassword123!"

        with pytest.raises(ValidationError):
            UserAdminCreate(
                email="invalid_email",
                full_name="Valid Name",
                role_id=role_id,
                password="short",
            )

    def test_user_update_validation(self) -> None:
        user_update = UserUpdate(full_name=" Updated Name ")
        assert user_update.full_name == "Updated Name"

        with pytest.raises(ValidationError):
            UserUpdate(full_name=" ")
