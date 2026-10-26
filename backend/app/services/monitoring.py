"""Operational monitoring, worker heartbeats, and alert evaluation service (Phase 99).

Enforces:
- Separation of public liveness/readiness from detailed operational health metrics:
  - `HEALTH_VIEW_DETAILED` or `DASHBOARD_VIEW_GLOBAL` required for deep diagnostics.
- Worker heartbeat recording and automated staleness detection.
- Real-time queue depth and latency monitoring.
- Alert threshold evaluation with 15-minute cooldown deduplication to prevent alert storms.
- Fail-safe alert dispatch via `NotificationService` without masking underlying failures.
- Append-only security audit logging for operational diagnostics and alert triggers.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config.settings import Settings
from backend.app.core.analytics import (
    ALERT_COOLDOWN_SECONDS,
    WORKER_STALE_THRESHOLD_SECONDS,
    OperationalAlertSeverity,
    OperationalAlertType,
    WorkerStatus,
)
from backend.app.core.audit import AuditAction, AuditOutcome, AuditTargetType
from backend.app.core.authorization import Permission, has_permission
from backend.app.core.exceptions import PermissionDeniedError
from backend.app.core.notification import (
    NotificationChannel,
    NotificationPriority,
)
from backend.app.models.monitoring import OperationalAlert
from backend.app.repositories.audit import AuditRepository
from backend.app.repositories.monitoring import OperationalMonitoringRepository
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.monitoring import (
    OperationalAlertRead,
    QueueMonitoringRead,
    SystemHealthDetailedRead,
    WorkerHeartbeatCreate,
    WorkerHeartbeatRead,
)
from backend.app.services.health import HealthService
from backend.app.services.notification import NotificationService

logger = logging.getLogger(__name__)


class OperationalMonitoringService:
    """Domain service for deep system telemetry, background workers, and operational alerts."""

    def __init__(
        self,
        monitoring_repo: OperationalMonitoringRepository,
        health_service: HealthService,
        notification_service: NotificationService | None = None,
        audit_repo: AuditRepository | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.monitoring_repo = monitoring_repo
        self.health_service = health_service
        self.notification_service = notification_service
        self.audit_repo = audit_repo
        self.settings = settings

    @classmethod
    def from_session(
        cls,
        session: AsyncSession,
        settings: Settings,
        health_service: HealthService,
    ) -> OperationalMonitoringService:
        """Construct an OperationalMonitoringService wired with session repositories."""
        return cls(
            monitoring_repo=OperationalMonitoringRepository(session),
            health_service=health_service,
            notification_service=NotificationService.from_session(session, settings),
            audit_repo=AuditRepository(session),
            settings=settings,
        )

    async def _audit(
        self,
        principal: AuthenticatedPrincipal,
        action: AuditAction,
        target_id: str,
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
            target_type=AuditTargetType.HEALTH.value,
            target_id=target_id,
            outcome=AuditOutcome.SUCCESS.value,
            department_id=department_id or principal.department_id,
            details=details,
        )

    def _require_detailed_access(self, principal: AuthenticatedPrincipal) -> None:
        """Enforce HEALTH_VIEW_DETAILED or DASHBOARD_VIEW_GLOBAL permissions."""
        has_health_perm = has_permission(principal.role, Permission.HEALTH_VIEW_DETAILED)
        has_dash_perm = has_permission(principal.role, Permission.DASHBOARD_VIEW_GLOBAL)
        if not has_health_perm and not has_dash_perm:
            raise PermissionDeniedError(
                "You are not authorized to access detailed operational health diagnostics.",
                code="PERMISSION_DENIED",
            )

    async def get_detailed_health(
        self,
        principal: AuthenticatedPrincipal,
    ) -> SystemHealthDetailedRead:
        """Assemble comprehensive system health, worker statuses, and queue depths."""
        self._require_detailed_access(principal)

        # 1. Base liveness and readiness
        liveness = self.health_service.get_liveness()
        readiness = await self.health_service.evaluate_readiness()

        # 2. Mark stale workers
        await self.monitoring_repo.mark_stale_workers(WORKER_STALE_THRESHOLD_SECONDS)

        # 3. Fetch workers
        raw_workers = await self.monitoring_repo.list_worker_heartbeats()
        now = datetime.now(UTC)
        worker_reads: list[WorkerHeartbeatRead] = []
        active_count = 0
        stale_count = 0

        for w in raw_workers:
            lh = w.last_heartbeat_at
            if lh.tzinfo is None:
                lh = lh.replace(tzinfo=UTC)
            is_stale = (
                w.status == WorkerStatus.STALE.value
                or (now - lh).total_seconds() > WORKER_STALE_THRESHOLD_SECONDS
            )
            if is_stale:
                stale_count += 1
            else:
                active_count += 1

            task_types_list = [t.strip() for t in w.task_types.split(",") if t.strip()]
            worker_reads.append(
                WorkerHeartbeatRead(
                    id=w.id,
                    worker_id=w.worker_id,
                    hostname=w.hostname,
                    task_types=task_types_list,
                    status=WorkerStatus.STALE.value if is_stale else w.status,
                    last_heartbeat_at=w.last_heartbeat_at,
                    is_stale=is_stale,
                    current_job_id=w.current_job_id,
                    metrics=w.metrics,
                    created_at=w.created_at or datetime.now(UTC),
                )
            )

        # 4. Fetch queue depth metrics
        raw_queue = await self.monitoring_repo.get_queue_depth_metrics()
        queue_monitoring = QueueMonitoringRead.model_validate(raw_queue)

        # 5. Fetch active operational alerts
        raw_alerts = await self.monitoring_repo.get_active_operational_alerts()
        alert_reads = [OperationalAlertRead.model_validate(a) for a in raw_alerts]

        # 6. Audit
        await self._audit(
            principal=principal,
            action=AuditAction.HEALTH_DETAILED_ACCESSED,
            target_id="system_health",
            details={
                "readiness_status": readiness.status,
                "workers_count": len(worker_reads),
                "ai_queue_depth": queue_monitoring.ai_job_queue_depth,
                "notification_queue_depth": queue_monitoring.notification_queue_depth,
            },
        )

        return SystemHealthDetailedRead(
            liveness=liveness,
            readiness=readiness,
            database_status="healthy" if readiness.ready else "degraded",
            queue_monitoring=queue_monitoring,
            workers_total=len(worker_reads),
            workers_active=active_count,
            workers_stale=stale_count,
            workers=worker_reads,
            active_alerts=alert_reads,
            generated_at=now,
        )

    get_system_health_detailed = get_detailed_health

    async def list_active_workers(
        self,
        principal: AuthenticatedPrincipal,
        status_filter: str | None = None,
    ) -> list[WorkerHeartbeatRead]:
        """List registered background workers with optional status filtering."""
        self._require_detailed_access(principal)
        detailed = await self.get_detailed_health(principal)
        if status_filter is not None:
            return [w for w in detailed.workers if w.status == status_filter]
        return detailed.workers

    async def record_worker_heartbeat(
        self,
        payload: WorkerHeartbeatCreate,
    ) -> WorkerHeartbeatRead:
        """Register or refresh an active worker heartbeat."""
        record = await self.monitoring_repo.upsert_worker_heartbeat(
            worker_id=payload.worker_id,
            hostname=payload.hostname,
            task_types=payload.task_types,
            status=WorkerStatus.ACTIVE.value,
            current_job_id=payload.current_job_id,
            metrics=payload.metrics,
        )
        task_types_list = [t.strip() for t in record.task_types.split(",") if t.strip()]
        return WorkerHeartbeatRead(
            id=record.id,
            worker_id=record.worker_id,
            hostname=record.hostname,
            task_types=task_types_list,
            status=record.status,
            last_heartbeat_at=record.last_heartbeat_at,
            is_stale=False,
            current_job_id=record.current_job_id,
            metrics=record.metrics,
            created_at=record.created_at or datetime.now(UTC),
        )

    async def evaluate_operational_alerts(
        self,
        principal: AuthenticatedPrincipal,
    ) -> list[OperationalAlertRead]:
        """Evaluate operational health conditions and emit deduplicated alerts with cooldowns."""
        has_manage = has_permission(principal.role, Permission.OPERATIONAL_ALERT_MANAGE)
        has_global = has_permission(principal.role, Permission.DASHBOARD_VIEW_GLOBAL)
        if not has_manage and not has_global:
            raise PermissionDeniedError(
                "You do not possess permission to evaluate operational alerts.",
                code="PERMISSION_DENIED",
            )

        now = datetime.now(UTC)
        await self.monitoring_repo.mark_stale_workers(WORKER_STALE_THRESHOLD_SECONDS)
        queue_metrics = await self.monitoring_repo.get_queue_depth_metrics()
        workers = await self.monitoring_repo.list_worker_heartbeats()

        stale_workers = [w for w in workers if w.status == WorkerStatus.STALE.value]
        triggered_alerts: list[OperationalAlert] = []

        # Condition 1: Queue Backlog (queued AI jobs > 50)
        ai_queue_depth = queue_metrics["ai_job_queue_depth"]
        if ai_queue_depth > 50:
            existing = await self.monitoring_repo.get_recent_alert_by_type(
                OperationalAlertType.QUEUE_BACKLOG.value,
                cooldown_seconds=ALERT_COOLDOWN_SECONDS,
            )
            if existing is None:
                alert = OperationalAlert(
                    id=uuid4(),
                    created_at=now,
                    alert_type=OperationalAlertType.QUEUE_BACKLOG.value,
                    severity=OperationalAlertSeverity.WARNING.value,
                    title="Elevated AI Analysis Job Queue Backlog",
                    message=f"Queue backlog has reached {ai_queue_depth} jobs waiting for worker pickup.",
                    details_json=json.dumps({"queue_depth": ai_queue_depth}),
                    is_active=True,
                    triggered_at=now,
                )
                saved = await self.monitoring_repo.create_operational_alert(alert)
                triggered_alerts.append(saved)

        # Condition 2: Stale Workers
        if stale_workers:
            existing = await self.monitoring_repo.get_recent_alert_by_type(
                OperationalAlertType.WORKER_STALE.value,
                cooldown_seconds=ALERT_COOLDOWN_SECONDS,
            )
            if existing is None:
                stale_ids = [w.worker_id for w in stale_workers]
                alert = OperationalAlert(
                    id=uuid4(),
                    created_at=now,
                    alert_type=OperationalAlertType.WORKER_STALE.value,
                    severity=OperationalAlertSeverity.CRITICAL.value,
                    title="Background Worker Heartbeat Lost",
                    message=f"{len(stale_workers)} worker(s) have failed to report heartbeats within threshold: {stale_ids}",
                    details_json=json.dumps({"stale_workers": stale_ids}),
                    is_active=True,
                    triggered_at=now,
                )
                saved = await self.monitoring_repo.create_operational_alert(alert)
                triggered_alerts.append(saved)

        # Condition 3: Retry Exhaustion
        exhausted_count = queue_metrics["retry_exhausted_count"]
        if exhausted_count > 0:
            existing = await self.monitoring_repo.get_recent_alert_by_type(
                OperationalAlertType.RETRY_EXHAUSTION.value,
                cooldown_seconds=ALERT_COOLDOWN_SECONDS,
            )
            if existing is None:
                alert = OperationalAlert(
                    id=uuid4(),
                    created_at=now,
                    alert_type=OperationalAlertType.RETRY_EXHAUSTION.value,
                    severity=OperationalAlertSeverity.WARNING.value,
                    title="Background Job Retry Exhaustion Detected",
                    message=f"{exhausted_count} job(s) have exhausted maximum retry attempts and moved to permanent failure.",
                    details_json=json.dumps({"exhausted_count": exhausted_count}),
                    is_active=True,
                    triggered_at=now,
                )
                saved = await self.monitoring_repo.create_operational_alert(alert)
                triggered_alerts.append(saved)

        # Fail-safe notification dispatch for new alerts
        if self.notification_service is not None and triggered_alerts:
            for alt in triggered_alerts:
                try:
                    await self.notification_service.dispatch(
                        template_name="system_notice",
                        template_vars={
                            "notice_title": f"[ALERT: {alt.severity.upper()}] {alt.title}",
                            "notice_message": alt.message,
                        },
                        recipient_id=principal.user_id,
                        department_id=principal.department_id,
                        channel=NotificationChannel.IN_APP,
                        priority=NotificationPriority.HIGH,
                        correlation_id=f"alert-{alt.id}",
                    )
                except Exception:
                    # Fail-safe: An alert delivery failure must never conceal the underlying operational failure
                    logger.warning(
                        "Fail-safe: alert notification dispatch failed for alert %s",
                        alt.id,
                        exc_info=True,
                    )

        # Audit if new alerts triggered
        if triggered_alerts:
            await self._audit(
                principal=principal,
                action=AuditAction.OPERATIONAL_ALERT_TRIGGERED,
                target_id="operational_alerts",
                details={
                    "alerts_triggered_count": len(triggered_alerts),
                    "alert_types": [a.alert_type for a in triggered_alerts],
                },
            )

        return [OperationalAlertRead.model_validate(a) for a in triggered_alerts]
