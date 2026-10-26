"""Reviewer workload and background processing metrics service (Phase 97).

Enforces:
- Department isolation on reviewer workload and queue processing metrics:
  - `CASE_WORKLOAD_READ_GLOBAL` / `OPERATIONS_METRICS_READ_GLOBAL`: Global access.
  - `CASE_WORKLOAD_READ_DEPT` / `OPERATIONS_METRICS_READ_DEPT`: Department-scoped access.
- Calculation of logical job totals distinct from retry attempts.
- Average and p95 processing duration reporting with safe missing-data handling.
- Append-only security audit logging for workload and processing inquiries.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config.settings import Settings
from backend.app.core.audit import AuditAction, AuditOutcome, AuditTargetType
from backend.app.core.authorization import Permission, has_permission
from backend.app.core.exceptions import BusinessRuleError, PermissionDeniedError
from backend.app.repositories.analytics import AnalyticsRepository
from backend.app.repositories.audit import AuditRepository
from backend.app.schemas.analytics import AnalyticsFilter
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.workload import (
    ProcessingMetricsRead,
    ReviewerWorkloadSummaryRead,
)


class WorkloadService:
    """Domain service for reviewer assignment transparency and worker throughput metrics."""

    def __init__(
        self,
        analytics_repo: AnalyticsRepository,
        audit_repo: AuditRepository | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.analytics_repo = analytics_repo
        self.audit_repo = audit_repo
        self.settings = settings

    @classmethod
    def from_session(cls, session: AsyncSession, settings: Settings) -> WorkloadService:
        """Construct a WorkloadService wired with session repositories."""
        return cls(
            analytics_repo=AnalyticsRepository(session),
            audit_repo=AuditRepository(session),
            settings=settings,
        )

    def _resolve_workload_department_scope(
        self,
        principal: AuthenticatedPrincipal,
        requested_dept_id: UUID | None,
    ) -> UUID | None:
        """Enforce department scoping on reviewer workload queries."""
        has_global = has_permission(principal.role, Permission.CASE_WORKLOAD_READ_GLOBAL)
        has_dept = has_permission(principal.role, Permission.CASE_WORKLOAD_READ_DEPT)

        if not has_global and not has_dept:
            raise PermissionDeniedError(
                "You do not possess permission to view reviewer workloads.",
                code="PERMISSION_DENIED",
            )

        if has_global:
            return requested_dept_id

        user_dept_id = principal.department_id
        if user_dept_id is None:
            raise PermissionDeniedError(
                "User has no assigned department for department-scoped workload.",
                code="DEPARTMENT_REQUIRED",
            )

        if requested_dept_id is not None and requested_dept_id != user_dept_id:
            raise PermissionDeniedError(
                "Cross-department workload queries are strictly forbidden.",
                code="CROSS_DEPARTMENT_ACCESS_FORBIDDEN",
            )

        return user_dept_id

    def _resolve_operations_department_scope(
        self,
        principal: AuthenticatedPrincipal,
        requested_dept_id: UUID | None,
    ) -> UUID | None:
        """Enforce department scoping on background processing queries."""
        has_global = has_permission(principal.role, Permission.OPERATIONS_METRICS_READ_GLOBAL)
        has_dept = has_permission(principal.role, Permission.OPERATIONS_METRICS_READ_DEPT)

        if not has_global and not has_dept:
            raise PermissionDeniedError(
                "You do not possess permission to view background processing metrics.",
                code="PERMISSION_DENIED",
            )

        if has_global:
            return requested_dept_id

        user_dept_id = principal.department_id
        if user_dept_id is None:
            raise PermissionDeniedError(
                "User has no assigned department for department-scoped processing metrics.",
                code="DEPARTMENT_REQUIRED",
            )

        if requested_dept_id is not None and requested_dept_id != user_dept_id:
            raise PermissionDeniedError(
                "Cross-department processing metric queries are strictly forbidden.",
                code="CROSS_DEPARTMENT_ACCESS_FORBIDDEN",
            )

        return user_dept_id

    async def _audit(
        self,
        principal: AuthenticatedPrincipal,
        action: AuditAction,
        details: dict[str, Any],
        department_id: UUID | None = None,
    ) -> None:
        """Record immutable append-only audit log entry."""
        if self.audit_repo is None:
            return
        await self.audit_repo.append_event(
            action=action.value,
            actor_id=principal.id,
            actor_role=principal.role,
            target_type=AuditTargetType.WORKLOAD.value,
            target_id=str(department_id or "global"),
            outcome=AuditOutcome.SUCCESS.value,
            department_id=department_id or principal.department_id,
            details=details,
        )

    async def get_reviewer_workload(
        self,
        principal: AuthenticatedPrincipal,
        department_id: UUID | None = None,
    ) -> ReviewerWorkloadSummaryRead:
        """Fetch active review assignments and workload distributions."""
        resolved_dept_id = self._resolve_workload_department_scope(principal, department_id)

        raw = await self.analytics_repo.get_reviewer_workload(
            department_id=resolved_dept_id,
        )

        await self._audit(
            principal,
            AuditAction.WORKLOAD_ACCESSED,
            {
                "query": "reviewer_workload",
                "reviewers_count": raw["total_reviewers"],
            },
            department_id=resolved_dept_id,
        )

        return ReviewerWorkloadSummaryRead.model_validate(raw)

    async def get_processing_metrics(
        self,
        principal: AuthenticatedPrincipal,
        filter_params: AnalyticsFilter,
    ) -> ProcessingMetricsRead:
        """Fetch background job and notification delivery processing metrics."""
        resolved_dept_id = self._resolve_operations_department_scope(
            principal, filter_params.department_id
        )
        if filter_params.start_date is None or filter_params.end_date is None:
            raise BusinessRuleError(
                "Processing metrics date range must be specified.", code="INVALID_DATE_RANGE"
            )
        start_date = filter_params.start_date
        end_date = filter_params.end_date

        raw = await self.analytics_repo.get_background_processing_metrics(
            start_date=start_date,
            end_date=end_date,
            department_id=resolved_dept_id,
        )

        await self._audit(
            principal,
            AuditAction.WORKLOAD_ACCESSED,
            {
                "query": "processing_metrics",
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
            },
            department_id=resolved_dept_id,
        )

        return ProcessingMetricsRead.model_validate(raw)
