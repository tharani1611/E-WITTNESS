"""Pydantic v2 schemas for authorized analytics and aggregate statistics (Phase 96).

Enforces:
- UTC normalization and bounded date range validation (max 365 days).
- Flexible time-series aggregation buckets (day, week, month).
- Aggregation consistency without leaking confidential evidence or restricted notes.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.app.core.analytics import MAX_ANALYTICS_RANGE_DAYS, TimeBucket
from backend.app.core.exceptions import BusinessRuleError


class AnalyticsFilter(BaseModel):
    """Query parameter filter for analytical metrics with bounded date ranges."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    start_date: datetime | None = Field(
        default=None,
        description="Filter range start timestamp (UTC). Defaults to 30 days prior to end_date.",
    )
    end_date: datetime | None = Field(
        default=None,
        description="Filter range end timestamp (UTC). Defaults to current UTC time.",
    )
    bucket: TimeBucket = Field(
        default=TimeBucket.DAY,
        description="Time bucket interval for trend series.",
    )
    department_id: UUID | None = Field(
        default=None,
        description="Optional department filter. Subordinated to role permissions.",
    )

    @model_validator(mode="after")
    def validate_and_normalize_dates(self) -> AnalyticsFilter:
        """Enforce UTC normalization, default dates, and max range bounds."""
        now = datetime.now(UTC)
        end = self.end_date or now
        if end.tzinfo is None:
            end = end.replace(tzinfo=UTC)

        start = self.start_date or (end - timedelta(days=30))
        if start.tzinfo is None:
            start = start.replace(tzinfo=UTC)

        if start > end:
            raise BusinessRuleError(
                "Analytics start_date must not be after end_date.",
                code="INVALID_DATE_RANGE",
            )

        if (end - start).days > MAX_ANALYTICS_RANGE_DAYS:
            raise BusinessRuleError(
                f"Analytics date range exceeds maximum allowed limit of {MAX_ANALYTICS_RANGE_DAYS} days.",
                code="RANGE_EXCEEDS_MAXIMUM_DAYS",
            )

        object.__setattr__(self, "start_date", start)
        object.__setattr__(self, "end_date", end)
        return self


class TimeSeriesBucket(BaseModel):
    """Single point in a time-series histogram."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    bucket_start: datetime = Field(..., description="Start of time bucket interval (UTC).")
    bucket_end: datetime = Field(..., description="End of time bucket interval (UTC).")
    count: int = Field(..., ge=0, description="Count of entities recorded in this bucket.")


class IncidentAnalyticsRead(BaseModel):
    """Analytical summary and time trends for incident reporting."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_incidents: int = Field(..., ge=0)
    incidents_by_category: dict[str, int] = Field(default_factory=dict)
    incidents_by_severity: dict[str, int] = Field(default_factory=dict)
    incidents_by_status: dict[str, int] = Field(default_factory=dict)
    incidents_by_department: dict[str, int] = Field(default_factory=dict)
    time_series: list[TimeSeriesBucket] = Field(default_factory=list)
    avg_resolution_hours: float | None = Field(default=None)
    time_range_start: datetime
    time_range_end: datetime
    department_id: UUID | None = None
    generated_at: datetime


class CaseAnalyticsRead(BaseModel):
    """Analytical summary and time trends for case investigations."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_cases: int = Field(..., ge=0)
    cases_by_status: dict[str, int] = Field(default_factory=dict)
    cases_by_priority: dict[str, int] = Field(default_factory=dict)
    cases_by_escalation: dict[str, int] = Field(default_factory=dict)
    active_investigations_count: int = Field(..., ge=0)
    closed_cases_count: int = Field(..., ge=0)
    time_series: list[TimeSeriesBucket] = Field(default_factory=list)
    time_range_start: datetime
    time_range_end: datetime
    department_id: UUID | None = None
    generated_at: datetime


class ReviewOutcomeAnalyticsRead(BaseModel):
    """Analytical metrics for AI candidate segment reviews and human oversight."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_reviews: int = Field(..., ge=0)
    reviews_by_status: dict[str, int] = Field(default_factory=dict)
    acceptance_rate: float = Field(..., ge=0.0, le=1.0)
    rejection_rate: float = Field(..., ge=0.0, le=1.0)
    false_positive_reasons: dict[str, int] = Field(default_factory=dict)
    time_series: list[TimeSeriesBucket] = Field(default_factory=list)
    time_range_start: datetime
    time_range_end: datetime
    department_id: UUID | None = None
    generated_at: datetime


class AnalyticsOverviewRead(BaseModel):
    """Cross-domain analytical overview dashboard."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_incidents: int = Field(..., ge=0)
    total_cases: int = Field(..., ge=0)
    total_reviews: int = Field(..., ge=0)
    active_investigations: int = Field(..., ge=0)
    incidents_trend: list[TimeSeriesBucket] = Field(default_factory=list)
    cases_trend: list[TimeSeriesBucket] = Field(default_factory=list)
    time_range_start: datetime
    time_range_end: datetime
    department_id: UUID | None = None
    generated_at: datetime
