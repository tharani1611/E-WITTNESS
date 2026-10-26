"""Department management and tenant scoping service (Phases 23-25).

Enforces Super Admin exclusive control over global department provisioning,
tenant visibility rules, and paginated department lookups.
"""

from __future__ import annotations

import logging
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config.settings import Settings
from backend.app.core.authorization import (
    Permission,
    has_permission,
)
from backend.app.core.exceptions import (
    ConflictError,
    PermissionDeniedError,
    ResourceNotFoundError,
)
from backend.app.core.identity import RoleCode
from backend.app.models.department import Department
from backend.app.repositories.identity import DepartmentRepository
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.identity import (
    DepartmentCreate,
    DepartmentRead,
    DepartmentUpdate,
)
from backend.app.schemas.pagination import (
    PaginatedResponse,
    PaginationMetadata,
    PaginationParams,
)

logger = logging.getLogger("ewitness.services.department")


class DepartmentService:
    """Domain service for managing institutional departments."""

    def __init__(
        self,
        *,
        dept_repo: DepartmentRepository,
        settings: Settings,
    ) -> None:
        self.dept_repo = dept_repo
        self.settings = settings

    @classmethod
    def from_session(
        cls,
        session: AsyncSession,
        settings: Settings,
    ) -> DepartmentService:
        """Construct a DepartmentService wired with repositories bound to ``session``."""
        return cls(
            dept_repo=DepartmentRepository(session),
            settings=settings,
        )

    async def get_department_by_id(
        self,
        department_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> DepartmentRead:
        """Retrieve department details by ID.

        - Super Admins may view any department.
        - Other stakeholders may view their own department (if assigned).
        - Attempting to inspect other departments yields 403 Forbidden.
        - Non-existent departments yield 404 Not Found.
        """
        dept = await self.dept_repo.get_by_id(department_id)
        if dept is None:
            raise ResourceNotFoundError(
                f"Department '{department_id}' was not found.",
                code="DEPARTMENT_NOT_FOUND",
            )

        if principal.role == RoleCode.SUPER_ADMIN:
            return DepartmentRead.model_validate(dept)

        if principal.department_id == department_id:
            return DepartmentRead.model_validate(dept)

        raise PermissionDeniedError(
            "Users cannot access department records outside their own assigned department.",
            code="DEPARTMENT_MISMATCH",
        )

    async def list_departments(
        self,
        principal: AuthenticatedPrincipal,
        *,
        pagination: PaginationParams,
        is_active: bool | None = None,
        search: str | None = None,
        sort_by: str = "code",
        sort_order: str = "asc",
    ) -> PaginatedResponse[DepartmentRead]:
        """List departments with pagination, filtering, and allowlisted sorting (Super Admin only)."""
        if not has_permission(principal.role, Permission.DEPARTMENT_READ_GLOBAL):
            raise PermissionDeniedError(
                f"User role '{principal.role}' lacks permission to list all departments.",
                code="PERMISSION_DENIED",
            )

        items, total_items = await self.dept_repo.list_paginated(
            limit=pagination.limit,
            offset=pagination.offset,
            is_active=is_active,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
        )

        return PaginatedResponse(
            items=[DepartmentRead.model_validate(d) for d in items],
            pagination=PaginationMetadata.from_counts(
                page=pagination.page,
                page_size=pagination.page_size,
                total_items=total_items,
            ),
        )

    async def create_department(
        self,
        data: DepartmentCreate,
        principal: AuthenticatedPrincipal,
    ) -> DepartmentRead:
        """Create a new institutional department (Super Admin only)."""
        if not has_permission(principal.role, Permission.DEPARTMENT_CREATE_GLOBAL):
            raise PermissionDeniedError(
                f"User role '{principal.role}' lacks permission to create departments.",
                code="PERMISSION_DENIED",
            )

        existing = await self.dept_repo.get_by_code(data.code)
        if existing is not None:
            raise ConflictError(
                f"Department with code '{data.code}' already exists.",
                code="DEPARTMENT_CODE_EXISTS",
            )

        dept = Department(
            code=data.code,
            name=data.name,
            description=data.description,
            is_active=True,
        )
        created = await self.dept_repo.create(dept)
        return DepartmentRead.model_validate(created)

    async def update_department(
        self,
        department_id: UUID,
        data: DepartmentUpdate,
        principal: AuthenticatedPrincipal,
    ) -> DepartmentRead:
        """Update department properties (Super Admin only)."""
        if not has_permission(principal.role, Permission.DEPARTMENT_UPDATE_GLOBAL):
            raise PermissionDeniedError(
                f"User role '{principal.role}' lacks permission to modify departments.",
                code="PERMISSION_DENIED",
            )

        updated = await self.dept_repo.update(
            department_id=department_id,
            name=data.name,
            description=data.description,
            is_active=data.is_active,
        )
        return DepartmentRead.model_validate(updated)

    async def deactivate_department(
        self,
        department_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> DepartmentRead:
        """Soft-deactivate an institutional department (Super Admin only, Phase 33)."""
        if not (
            has_permission(principal.role, Permission.DEPARTMENT_STATUS_UPDATE_GLOBAL)
            or has_permission(principal.role, Permission.DEPARTMENT_UPDATE_GLOBAL)
        ):
            raise PermissionDeniedError(
                f"User role '{principal.role}' lacks permission to deactivate departments.",
                code="PERMISSION_DENIED",
            )

        updated = await self.dept_repo.deactivate(department_id)
        return DepartmentRead.model_validate(updated)

    async def activate_department(
        self,
        department_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> DepartmentRead:
        """Activate an inactive institutional department (Super Admin only, Phase 33)."""
        if not (
            has_permission(principal.role, Permission.DEPARTMENT_STATUS_UPDATE_GLOBAL)
            or has_permission(principal.role, Permission.DEPARTMENT_UPDATE_GLOBAL)
        ):
            raise PermissionDeniedError(
                f"User role '{principal.role}' lacks permission to activate departments.",
                code="PERMISSION_DENIED",
            )

        updated = await self.dept_repo.activate(department_id)
        return DepartmentRead.model_validate(updated)
