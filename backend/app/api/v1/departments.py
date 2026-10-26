"""Department management endpoints (Phases 21-25).

Provides RESTful operations for listing, creating, and modifying institutional
departments, restricted to Super Admin or department members.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from backend.app.api.dependencies import (
    CurrentUserDep,
    DepartmentServiceDep,
    UserServiceDep,
    require_any_permission,
    require_permission,
)
from backend.app.core.authorization import Permission
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.identity import (
    DepartmentCreate,
    DepartmentRead,
    DepartmentUpdate,
    InvestigatorAssignRequest,
    UserRead,
)
from backend.app.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    SortOrder,
)

router = APIRouter(prefix="/departments", tags=["Departments"])
v1_departments_router = router


@router.get(
    "",
    response_model=PaginatedResponse[DepartmentRead],
    summary="List departments",
    description="Retrieve a paginated collection of departments (Super Admin only).",
)
async def list_departments(
    dept_service: DepartmentServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.DEPARTMENT_READ_GLOBAL)),
    ],
    page: Annotated[int, Query(ge=1, description="1-indexed page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
    is_active: Annotated[bool | None, Query(description="Active status filter")] = None,
    search: Annotated[str | None, Query(description="Search term in code/name")] = None,
    sort_by: Annotated[str, Query(description="Field to sort by")] = "code",
    sort_order: Annotated[SortOrder, Query(description="Sort direction")] = SortOrder.ASC,
) -> PaginatedResponse[DepartmentRead]:
    """List departments with pagination, filtering, and allowlisted sorting."""
    pagination = PaginationParams(page=page, page_size=page_size)
    return await dept_service.list_departments(
        principal=principal,
        pagination=pagination,
        is_active=is_active,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order.value,
    )


@router.post(
    "",
    response_model=DepartmentRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create department",
    description="Provision a new institutional department (Super Admin only).",
)
async def create_department(
    body: DepartmentCreate,
    dept_service: DepartmentServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.DEPARTMENT_CREATE_GLOBAL)),
    ],
) -> DepartmentRead:
    """Create a new institutional department."""
    return await dept_service.create_department(body, principal)


@router.get(
    "/{department_id}",
    response_model=DepartmentRead,
    summary="Get department by ID",
    description="Retrieve department details by ID (Super Admin or department member).",
)
async def get_department_by_id(
    department_id: UUID,
    dept_service: DepartmentServiceDep,
    principal: CurrentUserDep,
) -> DepartmentRead:
    """Retrieve department details by ID."""
    return await dept_service.get_department_by_id(department_id, principal)


@router.patch(
    "/{department_id}",
    response_model=DepartmentRead,
    summary="Update department",
    description="Update department properties (Super Admin only).",
)
async def update_department(
    department_id: UUID,
    body: DepartmentUpdate,
    dept_service: DepartmentServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.DEPARTMENT_UPDATE_GLOBAL)),
    ],
) -> DepartmentRead:
    """Update department properties."""
    return await dept_service.update_department(department_id, body, principal)


@router.post(
    "/{department_id}/deactivate",
    response_model=DepartmentRead,
    summary="Deactivate department",
    description="Soft-deactivate an institutional department (Super Admin only).",
)
async def deactivate_department(
    department_id: UUID,
    dept_service: DepartmentServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.DEPARTMENT_STATUS_UPDATE_GLOBAL,
                Permission.DEPARTMENT_UPDATE_GLOBAL,
            )
        ),
    ],
) -> DepartmentRead:
    """Soft-deactivate an institutional department."""
    return await dept_service.deactivate_department(department_id, principal)


@router.post(
    "/{department_id}/activate",
    response_model=DepartmentRead,
    summary="Activate department",
    description="Activate a previously deactivated institutional department (Super Admin only).",
)
async def activate_department(
    department_id: UUID,
    dept_service: DepartmentServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.DEPARTMENT_STATUS_UPDATE_GLOBAL,
                Permission.DEPARTMENT_UPDATE_GLOBAL,
            )
        ),
    ],
) -> DepartmentRead:
    """Activate an inactive institutional department."""
    return await dept_service.activate_department(department_id, principal)


@router.get(
    "/{department_id}/investigators",
    response_model=PaginatedResponse[UserRead],
    summary="List department investigators",
    description="Retrieve a paginated collection of active investigators assigned to this department (Phase 36).",
)
async def list_department_investigators(
    department_id: UUID,
    user_service: UserServiceDep,
    principal: CurrentUserDep,
    page: Annotated[int, Query(ge=1, description="1-indexed page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
    search: Annotated[str | None, Query(description="Search term in email/name")] = None,
    sort_by: Annotated[str, Query(description="Field to sort by")] = "created_at",
    sort_order: Annotated[SortOrder, Query(description="Sort direction")] = SortOrder.ASC,
) -> PaginatedResponse[UserRead]:
    """List investigators assigned to this department, strictly bounded by department scope."""
    pagination = PaginationParams(page=page, page_size=page_size)
    return await user_service.list_department_investigators(
        department_id=department_id,
        principal=principal,
        pagination=pagination,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order.value,
    )


@router.post(
    "/{department_id}/investigators",
    response_model=UserRead,
    summary="Assign investigator to department",
    description="Assign an active, qualified investigator account to this department (Phase 36).",
)
async def assign_investigator_to_department(
    department_id: UUID,
    body: InvestigatorAssignRequest,
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
    """Assign an investigator to an institutional department with privilege and scope guards."""
    return await user_service.assign_investigator(
        department_id=department_id,
        investigator_id=body.investigator_id,
        principal=principal,
    )
