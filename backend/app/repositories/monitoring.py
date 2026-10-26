"""Operational monitoring, worker heartbeats, and alert repository (Phase 99).

Enforces:
- Distributed background worker heartbeat tracking and staleness transitions.
- Queue depth, oldest-job latency, and retry exhaustion monitoring queries.
- Operational alert creation, cooldown deduplication, and resolution.
- Layer boundary compliance (no schema imports).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.ai import AIJobStatus
from backend.app.core.analytics import WorkerStatus
from backend.app.core.notification import DeliveryStatus
from backend.app.models.ai import AIAnalysisJob
from backend.app.models.monitoring import OperationalAlert, WorkerHeartbeat
from backend.app.models.notification import NotificationDeliveryAttempt


class OperationalMonitoringRepository:
    """Async database repository for worker heartbeats, queue backlogs, and alerts."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # =========================================================================
    # Worker Heartbeats
    # =========================================================================

    async def upsert_worker_heartbeat(
        self,
        worker_id: str,
        hostname: str,
        task_types: list[str],
        status: str = WorkerStatus.ACTIVE.value,
        current_job_id: UUID | None = None,
        metrics: dict[str, Any] | None = None,
    ) -> WorkerHeartbeat:
        """Register or update an active worker heartbeat."""
        now = datetime.now(UTC)
        stmt = select(WorkerHeartbeat).where(WorkerHeartbeat.worker_id == worker_id)
        result = await self.session.execute(stmt)
        record = result.scalars().first()

        metrics_str = json.dumps(metrics or {}, default=str)
        task_types_str = ",".join(task_types) if task_types else "all"

        if record is None:
            record = WorkerHeartbeat(
                worker_id=worker_id,
                hostname=hostname,
                task_types=task_types_str,
                status=status,
                last_heartbeat_at=now,
                current_job_id=current_job_id,
                metrics_json=metrics_str,
            )
            self.session.add(record)
        else:
            record.hostname = hostname
            record.task_types = task_types_str
            record.status = status
            record.last_heartbeat_at = now
            record.current_job_id = current_job_id
            record.metrics_json = metrics_str
            record.updated_at = now

        await self.session.flush()
        return record

    async def list_worker_heartbeats(self) -> Sequence[WorkerHeartbeat]:
        """Fetch all registered worker heartbeats ordered by last heartbeat."""
        stmt = select(WorkerHeartbeat).order_by(WorkerHeartbeat.last_heartbeat_at.desc())
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def mark_stale_workers(self, threshold_seconds: int = 300) -> int:
        """Mark workers whose last heartbeat exceeds threshold as 'stale'."""
        cutoff = datetime.now(UTC) - timedelta(seconds=threshold_seconds)
        stmt = (
            update(WorkerHeartbeat)
            .where(
                WorkerHeartbeat.status == WorkerStatus.ACTIVE.value,
                WorkerHeartbeat.last_heartbeat_at <= cutoff,
            )
            .values(
                status=WorkerStatus.STALE.value,
                updated_at=datetime.now(UTC),
            )
        )
        res = await self.session.execute(stmt)
        await self.session.flush()
        rowcount = getattr(res, "rowcount", 0)
        return int(rowcount) if rowcount is not None else 0

    # =========================================================================
    # Queue Depth & Backlog Monitoring
    # =========================================================================

    async def get_queue_depth_metrics(self) -> dict[str, Any]:
        """Retrieve real-time queue depths and oldest pending job latency."""
        now = datetime.now(UTC)

        # 1. Queued AI jobs
        stmt_ai_queue = select(func.count(AIAnalysisJob.id)).where(
            AIAnalysisJob.status == AIJobStatus.QUEUED.value
        )
        r_ai_q = await self.session.execute(stmt_ai_queue)
        ai_job_queue_depth = int(r_ai_q.scalar_one_or_none() or 0)

        # 2. Oldest queued job age in seconds
        stmt_oldest = (
            select(AIAnalysisJob.created_at)
            .where(AIAnalysisJob.status == AIJobStatus.QUEUED.value)
            .order_by(AIAnalysisJob.created_at.asc())
            .limit(1)
        )
        r_oldest = await self.session.execute(stmt_oldest)
        oldest_ts = r_oldest.scalar_one_or_none()
        oldest_queued_job_age_seconds: float | None = None
        if oldest_ts:
            if oldest_ts.tzinfo is None:
                oldest_ts = oldest_ts.replace(tzinfo=UTC)
            oldest_queued_job_age_seconds = round((now - oldest_ts).total_seconds(), 2)

        # 3. Pending notification delivery attempts
        stmt_notif_q = select(func.count(NotificationDeliveryAttempt.id)).where(
            NotificationDeliveryAttempt.status == DeliveryStatus.PENDING.value
        )
        r_n_q = await self.session.execute(stmt_notif_q)
        notification_queue_depth = int(r_n_q.scalar_one_or_none() or 0)

        # 4. Retry exhausted AI jobs or notifications
        stmt_ai_exhausted = select(func.count(AIAnalysisJob.id)).where(
            AIAnalysisJob.status == AIJobStatus.FAILED.value,
            AIAnalysisJob.retry_count >= AIAnalysisJob.max_retries,
        )
        r_ai_ex = await self.session.execute(stmt_ai_exhausted)
        retry_exhausted_count = int(r_ai_ex.scalar_one_or_none() or 0)

        return {
            "ai_job_queue_depth": ai_job_queue_depth,
            "oldest_queued_job_age_seconds": oldest_queued_job_age_seconds,
            "notification_queue_depth": notification_queue_depth,
            "retry_exhausted_count": retry_exhausted_count,
        }

    # =========================================================================
    # Operational Alerts & Cooldown Deduplication
    # =========================================================================

    async def create_operational_alert(self, alert: OperationalAlert) -> OperationalAlert:
        """Record an active operational system alert."""
        self.session.add(alert)
        await self.session.flush()
        return alert

    async def get_active_operational_alerts(self) -> Sequence[OperationalAlert]:
        """Fetch all currently active (unresolved) operational alerts."""
        stmt = (
            select(OperationalAlert)
            .where(OperationalAlert.is_active.is_(True))
            .order_by(OperationalAlert.triggered_at.desc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_recent_alert_by_type(
        self,
        alert_type: str,
        cooldown_seconds: int = 900,
    ) -> OperationalAlert | None:
        """Check if an alert of this type was triggered within the cooldown window."""
        cutoff = datetime.now(UTC) - timedelta(seconds=cooldown_seconds)
        stmt = (
            select(OperationalAlert)
            .where(
                OperationalAlert.alert_type == alert_type,
                OperationalAlert.triggered_at >= cutoff,
            )
            .order_by(OperationalAlert.triggered_at.desc())
            .limit(1)
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def resolve_operational_alert(self, alert_id: UUID) -> None:
        """Mark an active operational alert as resolved."""
        now = datetime.now(UTC)
        stmt = (
            update(OperationalAlert)
            .where(OperationalAlert.id == alert_id)
            .values(
                is_active=False,
                resolved_at=now,
                updated_at=now,
            )
        )
        await self.session.execute(stmt)
        await self.session.flush()

    # Repository method aliases
    get_latest_alert_by_type = get_recent_alert_by_type
    list_workers = list_worker_heartbeats
    list_active_alerts = get_active_operational_alerts
