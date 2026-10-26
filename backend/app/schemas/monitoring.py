"""Pydantic v2 schemas for health endpoints, worker status, queue monitoring, and operational alerts (Phase 99).

Enforces:
- Separation of public liveness from detailed operational health.
- Worker heartbeat tracking and staleness visibility.
- Queue backlog and oldest pending-job age monitoring.
- Operational anomaly alerts with severity and resolution metadata.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from backend.app.schemas.health import LivenessResponse, ReadinessResponse


class WorkerHeartbeatCreate(BaseModel):
    """Payload submitted by a background worker to record a periodic heartbeat."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    worker_id: str = Field(
        ..., min_length=3, max_length=64, description="Unique worker instance identifier."
    )
    hostname: str = Field(
        ..., min_length=1, max_length=128, description="Host/container name running worker."
    )
    task_types: list[str] = Field(
        default_factory=lambda: ["all"], description="Task types processed by worker."
    )
    current_job_id: UUID | None = Field(
        default=None, description="Active job ID currently being processed."
    )
    metrics: dict[str, Any] = Field(
        default_factory=dict, description="Worker telemetry statistics."
    )


class WorkerHeartbeatRead(BaseModel):
    """Status snapshot of a registered background worker."""

    model_config = ConfigDict(from_attributes=True, frozen=True, extra="forbid")

    id: UUID
    worker_id: str
    hostname: str
    task_types: list[str]
    status: str
    last_heartbeat_at: datetime
    is_stale: bool
    current_job_id: UUID | None = None
    metrics: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class QueueMonitoringRead(BaseModel):
    """Real-time queue depth and backlog statistics."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ai_job_queue_depth: int = Field(
        ..., ge=0, description="Count of queued AI analysis jobs waiting for execution."
    )
    oldest_queued_job_age_seconds: float | None = Field(
        default=None, description="Age in seconds of the oldest queued job."
    )
    notification_queue_depth: int = Field(
        ..., ge=0, description="Count of pending notification delivery attempts."
    )
    retry_exhausted_count: int = Field(
        ..., ge=0, description="Count of failed jobs or notifications with retries exhausted."
    )


class OperationalAlertRead(BaseModel):
    """Operational anomaly or threshold alert."""

    model_config = ConfigDict(from_attributes=True, frozen=True, extra="forbid")

    id: UUID
    alert_type: str
    severity: str
    title: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    is_active: bool
    triggered_at: datetime
    resolved_at: datetime | None = None


class SystemHealthDetailedRead(BaseModel):
    """Comprehensive system health and operational monitoring response."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    liveness: LivenessResponse
    readiness: ReadinessResponse
    database_status: str
    queue_monitoring: QueueMonitoringRead
    workers_total: int = Field(..., ge=0)
    workers_active: int = Field(..., ge=0)
    workers_stale: int = Field(..., ge=0)
    workers: list[WorkerHeartbeatRead] = Field(default_factory=list)
    active_alerts: list[OperationalAlertRead] = Field(default_factory=list)
    generated_at: datetime
