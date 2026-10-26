"""Operational Dashboard service for aggregated metrics (Phase 95).

Enforces:
- Tenant and department isolation: Department-level roles are strictly confined to their department.
- Cross-department denial by default.
- Global aggregation restricted to authorized SUPER_ADMIN roles.
- Bounded time ranges with UTC normalization.
- Immutable audit event logging upon dashboard access.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config.settings import Settings
from backend.app.core.audit import AuditAction, AuditOutcome, AuditTargetType
from backend.app.core.authorization import Permission, has_permission
from backend.app.core.exceptions import PermissionDeniedError
from backend.app.core.logging import get_logger
from backend.app.repositories.audit import AuditRepository
from backend.app.repositories.dashboard import DashboardRepository
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.dashboard import (
    CaseDashboardRead,
    DashboardDateFilter,
    IncidentDashboardRead,
    OperationsDashboardRead,
)

logger = get_logger("services.dashboard")


class DashboardService:
    """Service orchestrating operational dashboard aggregations and access controls."""

    def __init__(
        self,
        dashboard_repo: DashboardRepository,
        audit_repo: AuditRepository,
        settings: Settings,
    ) -> None:
        self.dashboard_repo = dashboard_repo
        self.audit_repo = audit_repo
        self.settings = settings

    @classmethod
    def from_session(cls, session: AsyncSession, settings: Settings) -> DashboardService:
        """Construct a DashboardService wired with session repositories."""
        return cls(
            dashboard_repo=DashboardRepository(session),
            audit_repo=AuditRepository(session),
            settings=settings,
        )

    def _resolve_effective_department_id(
        self,
        requested_dept_id: UUID | None,
        principal: AuthenticatedPrincipal,
    ) -> UUID | None:
        """Resolve and validate department scope against caller permissions.

        - Global dashboard viewers (SUPER_ADMIN) may view global (None) or filter by any department.
        - Department-scoped viewers (DEPT_ADMIN, INVESTIGATOR) can ONLY view their own department.
        - Cross-department access attempts are denied.
        """
        can_global = has_permission(principal.role_code, Permission.DASHBOARD_VIEW_GLOBAL)
        can_dept = has_permission(principal.role_code, Permission.DASHBOARD_VIEW_DEPT)

        if not can_global and not can_dept:
            raise PermissionDeniedError(
                "You do not have permission to view operational dashboards.",
                code="DASHBOARD_ACCESS_DENIED",
            )

        if not can_global:
            # Department-scoped user: strictly confined to own department
            if requested_dept_id is not None and requested_dept_id != principal.department_id:
                raise PermissionDeniedError(
                    "Cross-department dashboard access is forbidden.",
                    code="CROSS_DEPARTMENT_FORBIDDEN",
                )
            if principal.department_id is None:
                raise PermissionDeniedError(
                    "User has no assigned department for department-scoped dashboards.",
                    code="DEPARTMENT_NOT_ASSIGNED",
                )
            return principal.department_id

        # Global admin: can query specific department or None for global
        return requested_dept_id

    async def get_incident_dashboard(
        self,
        filter_params: DashboardDateFilter,
        principal: AuthenticatedPrincipal,
        actor_ip: str | None = None,
        actor_user_agent: str | None = None,
    ) -> IncidentDashboardRead:
        """Fetch aggregated incident operational metrics."""
        effective_dept_id = self._resolve_effective_department_id(
            filter_params.department_id, principal
        )

        start_date = filter_params.start_date or (datetime.now(UTC) - timedelta(days=30))
        end_date = filter_params.end_date or datetime.now(UTC)

        result = await self.dashboard_repo.get_incident_metrics(
            start_date=start_date,
            end_date=end_date,
            department_id=effective_dept_id,
        )

        await self.audit_repo.append_event(
            action=AuditAction.DASHBOARD_ACCESSED,
            actor_id=principal.user_id,
            actor_role=principal.role_code,
            target_type=AuditTargetType.DASHBOARD,
            target_id="incidents",
            outcome=AuditOutcome.SUCCESS,
            actor_ip=actor_ip,
            actor_user_agent=actor_user_agent,
            department_id=effective_dept_id,
            details={
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "department_id": str(effective_dept_id) if effective_dept_id else None,
            },
        )

        return IncidentDashboardRead.model_validate(result)

    async def get_case_dashboard(
        self,
        filter_params: DashboardDateFilter,
        principal: AuthenticatedPrincipal,
        actor_ip: str | None = None,
        actor_user_agent: str | None = None,
    ) -> CaseDashboardRead:
        """Fetch aggregated investigation case operational metrics."""
        effective_dept_id = self._resolve_effective_department_id(
            filter_params.department_id, principal
        )

        start_date = filter_params.start_date or (datetime.now(UTC) - timedelta(days=30))
        end_date = filter_params.end_date or datetime.now(UTC)

        result = await self.dashboard_repo.get_case_metrics(
            start_date=start_date,
            end_date=end_date,
            department_id=effective_dept_id,
        )

        await self.audit_repo.append_event(
            action=AuditAction.DASHBOARD_ACCESSED,
            actor_id=principal.user_id,
            actor_role=principal.role_code,
            target_type=AuditTargetType.DASHBOARD,
            target_id="cases",
            outcome=AuditOutcome.SUCCESS,
            actor_ip=actor_ip,
            actor_user_agent=actor_user_agent,
            department_id=effective_dept_id,
            details={
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "department_id": str(effective_dept_id) if effective_dept_id else None,
            },
        )

        return CaseDashboardRead.model_validate(result)

    async def get_operations_dashboard(
        self,
        filter_params: DashboardDateFilter,
        principal: AuthenticatedPrincipal,
        actor_ip: str | None = None,
        actor_user_agent: str | None = None,
    ) -> OperationsDashboardRead:
        """Fetch aggregated system operations metrics for AI and notifications."""
        effective_dept_id = self._resolve_effective_department_id(
            filter_params.department_id, principal
        )

        start_date = filter_params.start_date or (datetime.now(UTC) - timedelta(days=30))
        end_date = filter_params.end_date or datetime.now(UTC)

        result = await self.dashboard_repo.get_operations_metrics(
            start_date=start_date,
            end_date=end_date,
            department_id=effective_dept_id,
        )

        await self.audit_repo.append_event(
            action=AuditAction.DASHBOARD_ACCESSED,
            actor_id=principal.user_id,
            actor_role=principal.role_code,
            target_type=AuditTargetType.DASHBOARD,
            target_id="operations",
            outcome=AuditOutcome.SUCCESS,
            actor_ip=actor_ip,
            actor_user_agent=actor_user_agent,
            department_id=effective_dept_id,
            details={
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "department_id": str(effective_dept_id) if effective_dept_id else None,
            },
        )

        return OperationsDashboardRead.model_validate(result)
