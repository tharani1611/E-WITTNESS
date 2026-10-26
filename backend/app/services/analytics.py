"""Authorized analytics and aggregate statistics domain service (Phase 96).

Enforces:
- Strict department and tenant scoping based on caller role permissions:
  - `ANALYTICS_VIEW_GLOBAL`: Global query access across all departments.
  - `ANALYTICS_VIEW_DEPT`: Confined strictly to caller's own department; cross-department access denied.
- UTC normalization and query window limit enforcement (<= 365 days).
- Append-only security audit logging for all analytical queries.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config.settings import Settings
from backend.app.core.audit import AuditAction, AuditOutcome, AuditTargetType
from backend.app.core.authorization import Permission, has_permission
from backend.app.core.exceptions import BusinessRuleError, PermissionDeniedError
from backend.app.repositories.analytics import AnalyticsRepository
from backend.app.repositories.audit import AuditRepository
from backend.app.schemas.analytics import (
    AnalyticsFilter,
    AnalyticsOverviewRead,
    CaseAnalyticsRead,
    IncidentAnalyticsRead,
    ReviewOutcomeAnalyticsRead,
)
from backend.app.schemas.auth import AuthenticatedPrincipal


class AnalyticsService:
    """Domain service for aggregated statistical reporting and trends."""

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
    def from_session(cls, session: AsyncSession, settings: Settings) -> AnalyticsService:
        """Construct an AnalyticsService wired with session repositories."""
        return cls(
            analytics_repo=AnalyticsRepository(session),
            audit_repo=AuditRepository(session),
            settings=settings,
        )

    def _resolve_department_scope(
        self,
        principal: AuthenticatedPrincipal,
        requested_dept_id: UUID | None,
    ) -> UUID | None:
        """Enforce strict department scoping and cross-department protection."""
        has_global = has_permission(principal.role, Permission.ANALYTICS_VIEW_GLOBAL)
        has_dept = has_permission(principal.role, Permission.ANALYTICS_VIEW_DEPT)

        if not has_global and not has_dept:
            raise PermissionDeniedError(
                "You do not possess permission to view analytical metrics.",
                code="PERMISSION_DENIED",
            )

        if has_global:
            return requested_dept_id

        # User is restricted to own department
        user_dept_id = principal.department_id
        if user_dept_id is None:
            raise PermissionDeniedError(
                "User has no assigned department for department-scoped analytics.",
                code="DEPARTMENT_REQUIRED",
            )

        if requested_dept_id is not None and requested_dept_id != user_dept_id:
            raise PermissionDeniedError(
                "Cross-department analytics queries are strictly forbidden.",
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
            target_type=AuditTargetType.ANALYTICS.value,
            target_id=str(department_id or "global"),
            outcome=AuditOutcome.SUCCESS.value,
            department_id=department_id or principal.department_id,
            details=details,
        )

    @staticmethod
    def _extract_bounds(filter_params: AnalyticsFilter) -> tuple[datetime, datetime]:
        if filter_params.start_date is None or filter_params.end_date is None:
            raise BusinessRuleError(
                "Analytics filter date range must be specified.", code="INVALID_DATE_RANGE"
            )
        return filter_params.start_date, filter_params.end_date

    async def get_incident_analytics(
        self,
        principal: AuthenticatedPrincipal,
        filter_params: AnalyticsFilter,
    ) -> IncidentAnalyticsRead:
        """Fetch incident statistics and time-series histograms."""
        resolved_dept_id = self._resolve_department_scope(principal, filter_params.department_id)
        start_date, end_date = self._extract_bounds(filter_params)

        raw = await self.analytics_repo.get_incident_analytics(
            start_date=start_date,
            end_date=end_date,
            bucket=filter_params.bucket,
            department_id=resolved_dept_id,
        )

        await self._audit(
            principal,
            AuditAction.ANALYTICS_ACCESSED,
            {
                "analytics_type": "incidents",
                "bucket": filter_params.bucket.value,
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
            },
            department_id=resolved_dept_id,
        )

        return IncidentAnalyticsRead.model_validate(raw)

    async def get_case_analytics(
        self,
        principal: AuthenticatedPrincipal,
        filter_params: AnalyticsFilter,
    ) -> CaseAnalyticsRead:
        """Fetch case investigation analytics and status trends."""
        resolved_dept_id = self._resolve_department_scope(principal, filter_params.department_id)
        start_date, end_date = self._extract_bounds(filter_params)

        raw = await self.analytics_repo.get_case_analytics(
            start_date=start_date,
            end_date=end_date,
            bucket=filter_params.bucket,
            department_id=resolved_dept_id,
        )

        await self._audit(
            principal,
            AuditAction.ANALYTICS_ACCESSED,
            {
                "analytics_type": "cases",
                "bucket": filter_params.bucket.value,
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
            },
            department_id=resolved_dept_id,
        )

        return CaseAnalyticsRead.model_validate(raw)

    async def get_review_outcome_analytics(
        self,
        principal: AuthenticatedPrincipal,
        filter_params: AnalyticsFilter,
    ) -> ReviewOutcomeAnalyticsRead:
        """Fetch AI candidate review outcomes and false-positive reasons."""
        resolved_dept_id = self._resolve_department_scope(principal, filter_params.department_id)
        start_date, end_date = self._extract_bounds(filter_params)

        raw = await self.analytics_repo.get_review_outcome_analytics(
            start_date=start_date,
            end_date=end_date,
            bucket=filter_params.bucket,
            department_id=resolved_dept_id,
        )

        await self._audit(
            principal,
            AuditAction.ANALYTICS_ACCESSED,
            {
                "analytics_type": "review_outcomes",
                "bucket": filter_params.bucket.value,
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
            },
            department_id=resolved_dept_id,
        )

        return ReviewOutcomeAnalyticsRead.model_validate(raw)

    async def get_analytics_overview(
        self,
        principal: AuthenticatedPrincipal,
        filter_params: AnalyticsFilter,
    ) -> AnalyticsOverviewRead:
        """Fetch combined cross-domain analytical summary overview."""
        resolved_dept_id = self._resolve_department_scope(principal, filter_params.department_id)
        start_date, end_date = self._extract_bounds(filter_params)

        inc_raw = await self.analytics_repo.get_incident_analytics(
            start_date=start_date,
            end_date=end_date,
            bucket=filter_params.bucket,
            department_id=resolved_dept_id,
        )
        case_raw = await self.analytics_repo.get_case_analytics(
            start_date=start_date,
            end_date=end_date,
            bucket=filter_params.bucket,
            department_id=resolved_dept_id,
        )
        rev_raw = await self.analytics_repo.get_review_outcome_analytics(
            start_date=start_date,
            end_date=end_date,
            bucket=filter_params.bucket,
            department_id=resolved_dept_id,
        )

        overview_dict = {
            "total_incidents": inc_raw["total_incidents"],
            "total_cases": case_raw["total_cases"],
            "total_reviews": rev_raw["total_reviews"],
            "active_investigations": case_raw["active_investigations_count"],
            "incidents_trend": inc_raw["time_series"],
            "cases_trend": case_raw["time_series"],
            "time_range_start": start_date,
            "time_range_end": end_date,
            "department_id": resolved_dept_id,
            "generated_at": inc_raw["generated_at"],
        }

        await self._audit(
            principal,
            AuditAction.ANALYTICS_ACCESSED,
            {
                "analytics_type": "overview",
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
            },
            department_id=resolved_dept_id,
        )

        return AnalyticsOverviewRead.model_validate(overview_dict)
