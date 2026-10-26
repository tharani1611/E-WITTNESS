"""Pydantic v2 schemas for reviewer workloads and background processing metrics (Phase 97).

Enforces:
- Reviewer workload transparency based on real assignments and pending reviews.
- Logical job counting distinct from retry attempts.
- Explicit observation windows, denominators, and p95 duration reporting.
- Stale background worker job detection.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ReviewerWorkloadItem(BaseModel):
    """Workload distribution metrics for an individual reviewer or investigator."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    reviewer_id: UUID
    reviewer_name: str
    reviewer_email: str
    department_id: UUID
    active_cases_count: int = Field(..., ge=0)
    assigned_incidents_count: int = Field(..., ge=0)
    completed_case_reviews_count: int = Field(..., ge=0)
    completed_ai_segment_reviews_count: int = Field(..., ge=0)
    pending_ai_segment_reviews_count: int = Field(..., ge=0)


class ReviewerWorkloadSummaryRead(BaseModel):
    """Authorized summary of reviewer workloads across a department or globally."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    reviewers: list[ReviewerWorkloadItem] = Field(default_factory=list)
    total_reviewers: int = Field(..., ge=0)
    unassigned_incidents_count: int = Field(..., ge=0)
    unassigned_cases_count: int = Field(..., ge=0)
    department_id: UUID | None = None
    generated_at: datetime


class AIJobProcessingMetricsRead(BaseModel):
    """Operational metrics for AI analysis video jobs."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_logical_jobs: int = Field(..., ge=0)
    pending_count: int = Field(..., ge=0)
    running_count: int = Field(..., ge=0)
    completed_count: int = Field(..., ge=0)
    failed_count: int = Field(..., ge=0)
    cancelled_count: int = Field(..., ge=0)
    retry_attempts_count: int = Field(..., ge=0)
    completion_rate: float = Field(..., ge=0.0, le=1.0)
    failure_rate: float = Field(..., ge=0.0, le=1.0)
    avg_processing_duration_seconds: float | None = None
    p95_processing_duration_seconds: float | None = None
    avg_queue_wait_seconds: float | None = None
    stale_running_count: int = Field(..., ge=0)


class NotificationProcessingMetricsRead(BaseModel):
    """Operational metrics for notification delivery attempts and retries."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_logical_notifications: int = Field(..., ge=0)
    total_delivery_attempts: int = Field(..., ge=0)
    delivered_count: int = Field(..., ge=0)
    failed_count: int = Field(..., ge=0)
    pending_count: int = Field(..., ge=0)
    retry_exhausted_count: int = Field(..., ge=0)
    delivery_success_rate: float = Field(..., ge=0.0, le=1.0)


class ProcessingMetricsRead(BaseModel):
    """Aggregated operational processing metrics across all asynchronous services."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ai_jobs: AIJobProcessingMetricsRead
    notifications: NotificationProcessingMetricsRead
    observation_window_start: datetime
    observation_window_end: datetime
    department_id: UUID | None = None
    generated_at: datetime
