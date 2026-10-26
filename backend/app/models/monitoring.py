"""Operational worker health, heartbeat, and alert persistence models (Phase 99).

Enforces:
- Deterministic tracking of background workers across distributed application nodes.
- Heartbeat staleness detection and active job execution monitoring.
- Deduplicated operational system alerts with cooldown and resolution tracking.
- Linkage to generated system notifications for auditability and operator alerting.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.analytics import (
    OperationalAlertSeverity,
    OperationalAlertType,
    WorkerStatus,
)
from backend.app.models.base import (
    Base,
    TimestampMixin,
    UTCDateTime,
    UUIDPrimaryKeyMixin,
)

if TYPE_CHECKING:
    from backend.app.models.notification import Notification


_WORKER_STATUS_VALUES = ", ".join(f"'{s.value}'" for s in WorkerStatus)
_ALERT_SEVERITY_VALUES = ", ".join(f"'{s.value}'" for s in OperationalAlertSeverity)
_ALERT_TYPE_VALUES = ", ".join(f"'{s.value}'" for s in OperationalAlertType)


class WorkerHeartbeat(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Heartbeat and state tracker for background workers (AI processors, notification dispatchers)."""

    __tablename__ = "worker_heartbeats"
    __table_args__ = (
        UniqueConstraint("worker_id", name="uq_worker_heartbeats_worker_id"),
        CheckConstraint(
            f"status IN ({_WORKER_STATUS_VALUES})",
            name="ck_worker_heartbeats_status",
        ),
        Index("ix_worker_heartbeats_status", "status"),
        Index("ix_worker_heartbeats_last_heartbeat", "last_heartbeat_at"),
    )

    worker_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    hostname: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    task_types: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        default="all",
        server_default="all",
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=WorkerStatus.ACTIVE.value,
        server_default=WorkerStatus.ACTIVE.value,
    )
    last_heartbeat_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
    )
    current_job_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    metrics_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        default="{}",
        server_default="{}",
    )

    @property
    def metrics(self) -> dict[str, Any]:
        """Safely parse worker telemetry metrics dictionary."""
        try:
            return json.loads(self.metrics_json) if self.metrics_json else {}
        except Exception:
            return {}

    def __repr__(self) -> str:
        return f"<WorkerHeartbeat worker_id={self.worker_id} status={self.status} host={self.hostname}>"


class OperationalAlert(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Operational anomaly or failure alert tracking with deduplication cooldowns."""

    __tablename__ = "operational_alerts"
    __table_args__ = (
        CheckConstraint(
            f"alert_type IN ({_ALERT_TYPE_VALUES})",
            name="ck_operational_alerts_type",
        ),
        CheckConstraint(
            f"severity IN ({_ALERT_SEVERITY_VALUES})",
            name="ck_operational_alerts_severity",
        ),
        Index("ix_operational_alerts_type", "alert_type"),
        Index("ix_operational_alerts_severity", "severity"),
        Index("ix_operational_alerts_is_active", "is_active"),
        Index("ix_operational_alerts_triggered_at", "triggered_at"),
    )

    alert_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=OperationalAlertSeverity.WARNING.value,
        server_default=OperationalAlertSeverity.WARNING.value,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    details_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        default="{}",
        server_default="{}",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    triggered_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
    )
    notification_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("notifications.id", ondelete="SET NULL"),
        nullable=True,
    )

    notification: Mapped[Notification | None] = relationship(
        "Notification",
        foreign_keys=[notification_id],
        lazy="selectin",
    )

    @property
    def details(self) -> dict[str, Any]:
        """Safely parse alert details dictionary."""
        try:
            return json.loads(self.details_json) if self.details_json else {}
        except Exception:
            return {}

    def __repr__(self) -> str:
        return f"<OperationalAlert type={self.alert_type} severity={self.severity} active={self.is_active}>"
