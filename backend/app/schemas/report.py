"""Pydantic v2 schemas for controlled report generation and exports (Phase 98).

Enforces:
- Supported report types (incidents, cases, operational_summary, human_reviews).
- Supported formats (CSV, PDF).
- Bounded date filter validation and maximum row limitations.
- Metadata and download response models.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.app.core.analytics import (
    MAX_ANALYTICS_RANGE_DAYS,
    MAX_EXPORT_ROWS,
    ReportFormat,
    ReportType,
)
from backend.app.core.exceptions import BusinessRuleError


class ReportExportRequest(BaseModel):
    """Request payload to initiate or download a controlled report export."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    report_type: ReportType = Field(
        ...,
        description="Type of report to export (incidents, cases, operational_summary, human_reviews).",
    )
    export_format: ReportFormat = Field(
        ...,
        description="Desired document format (csv or pdf).",
    )
    start_date: datetime | None = Field(
        default=None,
        description="Start timestamp for report data (UTC). Defaults to 30 days prior to end_date.",
    )
    end_date: datetime | None = Field(
        default=None,
        description="End timestamp for report data (UTC). Defaults to current UTC time.",
    )
    department_id: UUID | None = Field(
        default=None,
        description="Optional department filter. Subordinated to role permissions.",
    )
    limit: int = Field(
        default=MAX_EXPORT_ROWS,
        description="Maximum rows to include in export (clamped to MAX_EXPORT_ROWS).",
    )

    @model_validator(mode="after")
    def validate_dates(self) -> ReportExportRequest:
        """Enforce UTC normalization, date range bounds, and row limit clamping."""
        now = datetime.now(UTC)
        end = self.end_date or now
        if end.tzinfo is None:
            end = end.replace(tzinfo=UTC)

        start = self.start_date or (end - timedelta(days=30))
        if start.tzinfo is None:
            start = start.replace(tzinfo=UTC)

        if start > end:
            raise BusinessRuleError(
                "Export start_date must not be after end_date.",
                code="INVALID_DATE_RANGE",
            )

        if (end - start).days > MAX_ANALYTICS_RANGE_DAYS:
            raise BusinessRuleError(
                f"Export date range exceeds maximum allowed limit of {MAX_ANALYTICS_RANGE_DAYS} days.",
                code="RANGE_EXCEEDS_MAXIMUM_DAYS",
            )

        row_limit = self.limit
        if row_limit <= 0 or row_limit > MAX_EXPORT_ROWS:
            row_limit = MAX_EXPORT_ROWS

        object.__setattr__(self, "start_date", start)
        object.__setattr__(self, "end_date", end)
        object.__setattr__(self, "limit", row_limit)
        return self


class ReportExportRead(BaseModel):
    """Persisted report export metadata."""

    model_config = ConfigDict(from_attributes=True, frozen=True, extra="forbid")

    id: UUID
    report_type: str
    export_format: str
    file_name: str
    status: str
    file_size_bytes: int | None = None
    content_sha256: str | None = None
    parameters_json: str = "{}"
    download_count: int
    expires_at: datetime
    created_at: datetime

    @property
    def file_hash_sha256(self) -> str | None:
        return self.content_sha256

    @property
    def record_count(self) -> int:
        try:
            import json

            return int(json.loads(self.parameters_json).get("record_count", 0))
        except Exception:
            return 0
