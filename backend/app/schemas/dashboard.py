"""Pydantic v2 schemas for Operational Dashboards (Phase 95).

Enforces:
- Strict department and tenant scoping.
- Bounded time ranges with UTC normalization to prevent unbounded DB scans.
- Aggregation models for Incident, Case, and System Operations metrics.
- Read-only data presentation (no client mutations allowed).
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class DashboardDateFilter(BaseModel):
    """Query parameter validator for bounded dashboard queries."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    start_date: datetime | None = Field(
        default=None,
        description="Start time (UTC). Defaults to 30 days prior if omitted.",
    )
    end_date: datetime | None = Field(
        default=None,
        description="End time (UTC). Defaults to current time if omitted.",
    )
    department_id: UUID | None = Field(
        default=None,
        description="Optional department scope. Required for non-superadmins to match their tenant.",
    )

    @model_validator(mode="after")
    def validate_and_bound_dates(self) -> DashboardDateFilter:
        """Enforce start_date <= end_date and bounded range."""
        now = datetime.now(UTC)
        if self.end_date is not None and self.end_date.tzinfo is None:
            self.end_date = self.end_date.replace(tzinfo=UTC)
        if self.start_date is not None and self.start_date.tzinfo is None:
            self.start_date = self.start_date.replace(tzinfo=UTC)

        if self.end_date is None:
            self.end_date = now

        if self.start_date is None:
            # Default to 30 days prior
            from datetime import timedelta

            self.start_date = self.end_date - timedelta(days=30)

        if self.start_date > self.end_date:
            raise ValueError("start_date cannot be greater than end_date")

        # Maximum lookback range: 365 days
        from datetime import timedelta

        if (self.end_date - self.start_date) > timedelta(days=366):
            raise ValueError("Time range cannot exceed 366 days.")

        return self


class IncidentDashboardRead(BaseModel):
    """Aggregated operational metrics for incidents."""

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )

    total_incidents: int
    incidents_by_status: dict[str, int]
    incidents_by_severity: dict[str, int]
    incidents_by_department: dict[str, int]
    total_evidence_items: int
    time_range_start: datetime
    time_range_end: datetime
    department_id: UUID | None = None
    generated_at: datetime


class CaseDashboardRead(BaseModel):
    """Aggregated operational metrics for investigation cases."""

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )

    total_cases: int
    cases_by_status: dict[str, int]
    cases_by_priority: dict[str, int]
    cases_by_escalation: dict[str, int]
    active_investigations_count: int
    legal_hold_cases_count: int
    time_range_start: datetime
    time_range_end: datetime
    department_id: UUID | None = None
    generated_at: datetime


class OperationsDashboardRead(BaseModel):
    """Aggregated metrics for AI jobs, notifications, and delivery infrastructure."""

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )

    ai_jobs_total: int
    ai_jobs_by_status: dict[str, int]
    ai_jobs_by_task_type: dict[str, int]
    notifications_total: int
    notifications_by_channel: dict[str, int]
    notifications_by_status: dict[str, int]
    delivery_attempts_total: int
    delivery_failures_total: int
    time_range_start: datetime
    time_range_end: datetime
    department_id: UUID | None = None
    generated_at: datetime
