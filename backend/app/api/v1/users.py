"""User administration and self-service profile endpoints (Phases 21-25).

Provides RESTful operations for listing, retrieving, provisioning, and updating
user identities, protected by granular RBAC permissions and department boundaries.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from backend.app.api.dependencies import (
    CurrentUserDep,
    UserServiceDep,
    require_any_permission,
    require_permission,
)
from backend.app.core.authorization import Permission
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.identity import (
    StaffInviteRequest,
    StaffInviteResponse,
    UserAdminCreate,
    UserDeactivateRequest,
    UserDepartmentAssignRequest,
    UserProfileUpdate,
    UserRead,
    UserUpdate,
)
from backend.app.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    SortOrder,
)

router = APIRouter(prefix="/users", tags=["Users"])
v1_users_router = router


@router.get(
    "",
    response_model=PaginatedResponse[UserRead],
    summary="List users",
    description="Retrieve a paginated collection of users with filtering and sorting.",
)
async def list_users(
    user_service: UserServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.USER_READ_DEPT,
                Permission.USER_READ_GLOBAL,
            )
        ),
    ],
    page: Annotated[int, Query(ge=1, description="1-indexed page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
    department_id: Annotated[UUID | None, Query(description="Department filter")] = None,
    role_code: Annotated[str | None, Query(description="Role code filter")] = None,
    account_status: Annotated[str | None, Query(description="Account status filter")] = None,
    is_active: Annotated[bool | None, Query(description="Active status filter")] = None,
    search: Annotated[str | None, Query(description="Search term in email/name")] = None,
    sort_by: Annotated[str, Query(description="Field to sort by")] = "created_at",
    sort_order: Annotated[SortOrder, Query(description="Sort direction")] = SortOrder.ASC,
) -> PaginatedResponse[UserRead]:
    """List users matching criteria, strictly bounded by caller's department scope."""
    pagination = PaginationParams(page=page, page_size=page_size)
    return await user_service.list_users(
        principal=principal,
        pagination=pagination,
        department_id=department_id,
        role_code=role_code,
        account_status=account_status,
        is_active=is_active,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order.value,
    )


@router.post(
    "",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create user",
    description="Provision a new user record with credentials, role, and department assignment.",
)
async def create_user(
    body: UserAdminCreate,
    user_service: UserServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.USER_CREATE_DEPT,
                Permission.USER_CREATE_GLOBAL,
            )
        ),
    ],
) -> UserRead:
    """Provision a user identity with departmental and privilege escalation guards."""
    return await user_service.create_user(body, principal)


@router.post(
    "/invite",
    response_model=StaffInviteResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Invite staff member",
    description="Invite a new staff or investigator account with secure token delivery.",
)
async def invite_staff(
    body: StaffInviteRequest,
    user_service: UserServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.USER_CREATE_DEPT,
                Permission.USER_CREATE_GLOBAL,
            )
        ),
    ],
) -> StaffInviteResponse:
    """Invite a new staff or investigator with departmental and privilege escalation guards."""
    return await user_service.invite_staff(body, principal)


@router.patch(
    "/me/profile",
    response_model=UserRead,
    summary="Update own profile",
    description="Self-service profile modification for authenticated caller.",
)
async def update_own_profile(
    body: UserProfileUpdate,
    user_service: UserServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.USER_UPDATE_OWN)),
    ],
) -> UserRead:
    """Update authenticated caller's own display name."""
    return await user_service.update_own_profile(body, principal)


@router.get(
    "/{user_id}",
    response_model=UserRead,
    summary="Get user by ID",
    description="Retrieve a user's identity details by unique identifier.",
)
async def get_user_by_id(
    user_id: UUID,
    user_service: UserServiceDep,
    principal: CurrentUserDep,
) -> UserRead:
    """Retrieve user details by ID subject to ownership and departmental boundaries."""
    return await user_service.get_user_by_id(user_id, principal)


@router.patch(
    "/{user_id}",
    response_model=UserRead,
    summary="Update user",
    description="Update a user's profile, role, department, or account status.",
)
async def update_user(
    user_id: UUID,
    body: UserUpdate,
    user_service: UserServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.USER_UPDATE_DEPT,
                Permission.USER_UPDATE_GLOBAL,
            )
        ),
    ],
) -> UserRead:
    """Update user properties enforcing self-modification, department, and escalation guards."""
    return await user_service.update_user(user_id, body, principal)


@router.post(
    "/{user_id}/deactivate",
    response_model=UserRead,
    summary="Deactivate user",
    description="Deactivate a user account, revoke active sessions, and lock access.",
)
async def deactivate_user(
    user_id: UUID,
    body: UserDeactivateRequest,
    user_service: UserServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.USER_UPDATE_DEPT,
                Permission.USER_UPDATE_GLOBAL,
            )
        ),
    ],
) -> UserRead:
    """Deactivate user account and revoke all sessions."""
    return await user_service.deactivate_user(user_id, principal, reason=body.reason)


@router.post(
    "/{user_id}/activate",
    response_model=UserRead,
    summary="Activate user",
    description="Reactivate an eligible user account.",
)
async def activate_user(
    user_id: UUID,
    user_service: UserServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.USER_UPDATE_DEPT,
                Permission.USER_UPDATE_GLOBAL,
            )
        ),
    ],
) -> UserRead:
    """Activate an eligible user account."""
    return await user_service.activate_user(user_id, principal)


@router.post(
    "/{user_id}/department",
    response_model=UserRead,
    summary="Assign department",
    description="Assign or reassign a user's institutional department membership.",
)
async def assign_user_department(
    user_id: UUID,
    body: UserDepartmentAssignRequest,
    user_service: UserServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.USER_UPDATE_DEPT,
                Permission.USER_DEPT_REASSIGN_GLOBAL,
            )
        ),
    ],
) -> UserRead:
    """Assign or reassign a user's department."""
    return await user_service.assign_department(user_id, body.department_id, principal)


@router.post(
    "/{user_id}/investigator-assignment",
    response_model=UserRead,
    summary="Assign investigator to department",
    description="Assign an active, qualified investigator user to an active department (Phase 36).",
)
async def assign_investigator_department(
    user_id: UUID,
    body: UserDepartmentAssignRequest,
    user_service: UserServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.USER_UPDATE_DEPT,
                Permission.USER_DEPT_REASSIGN_GLOBAL,
            )
        ),
    ],
) -> UserRead:
    """Assign an investigator to an institutional department verifying investigator role and active account status."""
    return await user_service.assign_investigator(
        department_id=body.department_id,
        investigator_id=user_id,
        principal=principal,
    )
