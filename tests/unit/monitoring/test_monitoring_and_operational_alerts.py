"""Unit tests for Phase 99 Operational Monitoring, Worker Heartbeats, and Alert Evaluation.

Verifies:
- Authorization gate: HEALTH_VIEW_DETAILED / DASHBOARD_VIEW_GLOBAL required for deep diagnostics.
- Liveness and readiness probe separation from internal operational health metrics.
- Worker heartbeat ingestion, automated staleness detection, and status updates.
- Real-time queue depth and latency telemetry.
- Operational alert rule evaluation:
  - Worker staleness threshold breaches (> 60s).
  - Queue depth backlogs (> 100 items).
- 15-minute cooldown deduplication preventing alert storms.
- Fail-safe alert notification dispatch via NotificationService.
- Append-only security audit trail.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from backend.app.config.settings import Settings
from backend.app.core.analytics import (
    OperationalAlertSeverity,
    OperationalAlertType,
    WorkerStatus,
)
from backend.app.core.audit import AuditAction
from backend.app.core.authorization import RoleCode
from backend.app.core.exceptions import PermissionDeniedError
from backend.app.models.monitoring import OperationalAlert, WorkerHeartbeat
from backend.app.repositories.monitoring import OperationalMonitoringRepository
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.health import (
    DependencyCheckStatus,
    LivenessResponse,
    ReadinessResponse,
)
from backend.app.schemas.monitoring import (
    SystemHealthDetailedRead,
    WorkerHeartbeatCreate,
    WorkerHeartbeatRead,
)
from backend.app.services.health import HealthService
from backend.app.services.monitoring import OperationalMonitoringService
from backend.app.services.notification import NotificationService


@pytest.fixture
def mock_monitoring_repo() -> MagicMock:
    repo = MagicMock(spec=OperationalMonitoringRepository)
    now = datetime.now(UTC)

    # Worker heartbeats
    hb1 = WorkerHeartbeat(
        id=uuid4(),
        created_at=now,
        worker_id="worker-node-01",
        hostname="worker-01.local",
        status=WorkerStatus.ACTIVE.value,
        task_types='["ai_analysis"]',
        current_job_id=None,
        metrics_json="{}",
        last_heartbeat_at=now,
    )
    hb2 = WorkerHeartbeat(
        id=uuid4(),
        created_at=now,
        worker_id="worker-node-02",
        hostname="worker-02.local",
        status=WorkerStatus.STALE.value,
        task_types='["notifications"]',
        current_job_id=None,
        metrics_json="{}",
        last_heartbeat_at=now - timedelta(seconds=120),
    )

    repo.upsert_worker_heartbeat = AsyncMock(return_value=hb1)
    repo.list_workers = AsyncMock(return_value=[hb1, hb2])
    repo.mark_stale_workers = AsyncMock(return_value=1)

    # Queue metrics
    repo.get_queue_depth_metrics = AsyncMock(
        return_value={
            "ai_job_queue_depth": 5,
            "oldest_queued_job_age_seconds": 12.0,
            "notification_queue_depth": 2,
            "retry_exhausted_count": 0,
        }
    )

    # Alerts
    alt1 = OperationalAlert(
        id=uuid4(),
        created_at=now,
        alert_type=OperationalAlertType.QUEUE_BACKLOG.value,
        severity=OperationalAlertSeverity.WARNING.value,
        title="AI Job Queue Backlog",
        message="Queued AI jobs exceed normal operating thresholds.",
        details_json="{}",
        is_active=True,
        triggered_at=now - timedelta(minutes=5),
        resolved_at=None,
    )
    repo.list_active_alerts = AsyncMock(return_value=[alt1])
    repo.get_active_operational_alerts = repo.list_active_alerts
    repo.get_latest_alert_by_type = AsyncMock(return_value=None)
    repo.get_recent_alert_by_type = repo.get_latest_alert_by_type
    repo.list_workers = AsyncMock(return_value=[hb1, hb2])
    repo.list_worker_heartbeats = repo.list_workers
    repo.create_operational_alert = AsyncMock(side_effect=lambda a: a)

    return repo


@pytest.fixture
def mock_health_service() -> MagicMock:
    service = MagicMock(spec=HealthService)

    live_resp = LivenessResponse(
        status="ok",
        service="e-witness",
        version="1.0.0",
        environment="test",
    )
    ready_resp = ReadinessResponse(
        status="ok",
        ready=True,
        checks={"database": DependencyCheckStatus.READY},
        message="Database connection healthy",
    )
    service.get_liveness = MagicMock(return_value=live_resp)
    service.evaluate_readiness = AsyncMock(return_value=ready_resp)
    service.check_liveness = AsyncMock(return_value=live_resp)
    service.check_readiness = AsyncMock(return_value=ready_resp)
    return service


@pytest.fixture
def mock_notification_service() -> MagicMock:
    service = MagicMock(spec=NotificationService)
    service.dispatch = AsyncMock()
    return service


@pytest.fixture
def mock_audit_repo() -> MagicMock:
    repo = MagicMock()
    repo.append_event = AsyncMock()
    return repo


@pytest.fixture
def monitoring_service(
    mock_monitoring_repo: MagicMock,
    mock_health_service: MagicMock,
    mock_notification_service: MagicMock,
    mock_audit_repo: MagicMock,
    test_settings: Settings,
) -> OperationalMonitoringService:
    return OperationalMonitoringService(
        monitoring_repo=mock_monitoring_repo,
        health_service=mock_health_service,
        notification_service=mock_notification_service,
        audit_repo=mock_audit_repo,
        settings=test_settings,
    )


def test_detailed_health_access_control(monitoring_service: OperationalMonitoringService) -> None:
    """Detailed operational health requires HEALTH_VIEW_DETAILED or DASHBOARD_VIEW_GLOBAL."""
    # Super Admin has access
    sa = AuthenticatedPrincipal(
        user_id=uuid4(),
        email="superadmin@campus.edu",
        full_name="Super Admin",
        account_status="active",
        is_active=True,
        role_code=RoleCode.SUPER_ADMIN.value,
        department_id=None,
        session_id=uuid4(),
    )
    monitoring_service._require_detailed_access(sa)

    # Student denied
    student = AuthenticatedPrincipal(
        user_id=uuid4(),
        email="student@campus.edu",
        full_name="Student",
        account_status="active",
        is_active=True,
        role_code=RoleCode.STUDENT.value,
        department_id=uuid4(),
        session_id=uuid4(),
    )
    with pytest.raises(
        PermissionDeniedError, match="not authorized to access detailed operational"
    ):
        monitoring_service._require_detailed_access(student)


@pytest.mark.asyncio
async def test_get_system_health_detailed(
    monitoring_service: OperationalMonitoringService,
    mock_monitoring_repo: MagicMock,
    mock_health_service: MagicMock,
    mock_audit_repo: MagicMock,
) -> None:
    """Verify deep diagnostic telemetry aggregation and audit recording."""
    sa = AuthenticatedPrincipal(
        user_id=uuid4(),
        email="superadmin@campus.edu",
        full_name="Super Admin",
        account_status="active",
        is_active=True,
        role_code=RoleCode.SUPER_ADMIN.value,
        department_id=None,
        session_id=uuid4(),
    )

    res = await monitoring_service.get_system_health_detailed(sa)

    assert isinstance(res, SystemHealthDetailedRead)
    assert res.liveness.status == "ok"
    assert res.readiness.status == "ok"
    assert res.workers_total == 2
    assert res.workers_active == 1
    assert res.workers_stale == 1
    assert res.queue_monitoring.ai_job_queue_depth == 5
    assert len(res.active_alerts) == 1

    mock_monitoring_repo.mark_stale_workers.assert_awaited_once()
    mock_audit_repo.append_event.assert_awaited_once()
    assert (
        mock_audit_repo.append_event.call_args[1]["action"]
        == AuditAction.HEALTH_DETAILED_ACCESSED.value
    )


@pytest.mark.asyncio
async def test_record_worker_heartbeat(
    monitoring_service: OperationalMonitoringService,
    mock_monitoring_repo: MagicMock,
) -> None:
    """Verify worker heartbeat recording."""
    payload = WorkerHeartbeatCreate(
        worker_id="worker-node-01",
        hostname="worker-01.local",
        task_types=["ai_analysis"],
        current_job_id=None,
        metrics={"cpu_pct": 15.2, "ram_mb": 512},
    )

    res = await monitoring_service.record_worker_heartbeat(payload)

    assert isinstance(res, WorkerHeartbeatRead)
    assert res.worker_id == "worker-node-01"
    assert res.status == WorkerStatus.ACTIVE
    mock_monitoring_repo.upsert_worker_heartbeat.assert_awaited_once_with(
        worker_id=payload.worker_id,
        hostname=payload.hostname,
        task_types=payload.task_types,
        status="active",
        current_job_id=None,
        metrics=payload.metrics,
    )


@pytest.mark.asyncio
async def test_list_active_workers(
    monitoring_service: OperationalMonitoringService,
    mock_monitoring_repo: MagicMock,
) -> None:
    """Verify worker list retrieval with automatic staleness detection."""
    sa = AuthenticatedPrincipal(
        user_id=uuid4(),
        email="superadmin@campus.edu",
        full_name="Super Admin",
        account_status="active",
        is_active=True,
        role_code=RoleCode.SUPER_ADMIN.value,
        department_id=None,
        session_id=uuid4(),
    )

    workers = await monitoring_service.list_active_workers(sa, status_filter=None)
    assert len(workers) == 2
    mock_monitoring_repo.mark_stale_workers.assert_awaited_once()


@pytest.mark.asyncio
async def test_evaluate_operational_alerts_trigger_and_cooldown(
    monitoring_service: OperationalMonitoringService,
    mock_monitoring_repo: MagicMock,
    mock_notification_service: MagicMock,
    mock_audit_repo: MagicMock,
) -> None:
    """Verify threshold evaluation, 15-minute cooldown deduplication, and fail-safe dispatch."""
    sa = AuthenticatedPrincipal(
        user_id=uuid4(),
        email="superadmin@campus.edu",
        full_name="Super Admin",
        account_status="active",
        is_active=True,
        role_code=RoleCode.SUPER_ADMIN.value,
        department_id=None,
        session_id=uuid4(),
    )

    # Set queue backlog threshold breach
    mock_monitoring_repo.get_queue_depth_metrics = AsyncMock(
        return_value={
            "ai_job_queue_depth": 150,  # > 100 triggers alert
            "oldest_queued_job_age_seconds": 950.0,  # > 900s triggers alert
            "notification_queue_depth": 5,
            "retry_exhausted_count": 0,
        }
    )

    # 1. No prior alert -> Triggered
    mock_monitoring_repo.get_recent_alert_by_type = AsyncMock(return_value=None)
    mock_monitoring_repo.get_latest_alert_by_type = mock_monitoring_repo.get_recent_alert_by_type

    triggered = await monitoring_service.evaluate_operational_alerts(sa)
    assert len(triggered) >= 1
    mock_monitoring_repo.create_operational_alert.assert_awaited()
    mock_notification_service.dispatch.assert_awaited()
    mock_audit_repo.append_event.assert_awaited()

    # 2. Within cooldown (< 15 mins) -> Suppressed
    recent_alert = OperationalAlert(
        id=uuid4(),
        created_at=datetime.now(UTC),
        alert_type=OperationalAlertType.QUEUE_BACKLOG.value,
        severity=OperationalAlertSeverity.WARNING.value,
        title="AI Job Queue Backlog",
        message="Queued jobs exceed 100",
        details_json="{}",
        is_active=True,
        triggered_at=datetime.now(UTC) - timedelta(minutes=5),  # only 5 mins ago
        resolved_at=None,
    )
    mock_monitoring_repo.get_recent_alert_by_type = AsyncMock(return_value=recent_alert)
    mock_monitoring_repo.get_latest_alert_by_type = mock_monitoring_repo.get_recent_alert_by_type
    mock_monitoring_repo.create_operational_alert.reset_mock()

    triggered_cooldown = await monitoring_service.evaluate_operational_alerts(sa)
    # Should be empty because it is within cooldown period
    assert len(triggered_cooldown) == 0
    mock_monitoring_repo.create_operational_alert.assert_not_awaited()


@pytest.mark.asyncio
async def test_alert_dispatch_fail_safe(
    monitoring_service: OperationalMonitoringService,
    mock_monitoring_repo: MagicMock,
    mock_notification_service: MagicMock,
) -> None:
    """Verify notification dispatch failure does not interrupt operational alert creation."""
    sa = AuthenticatedPrincipal(
        user_id=uuid4(),
        email="superadmin@campus.edu",
        full_name="Super Admin",
        account_status="active",
        is_active=True,
        role_code=RoleCode.SUPER_ADMIN.value,
        department_id=None,
        session_id=uuid4(),
    )

    mock_monitoring_repo.get_queue_depth_metrics = AsyncMock(
        return_value={
            "ai_job_queue_depth": 200,
            "oldest_queued_job_age_seconds": 1000.0,
            "notification_queue_depth": 0,
            "retry_exhausted_count": 0,
        }
    )
    mock_monitoring_repo.get_recent_alert_by_type = AsyncMock(return_value=None)
    mock_monitoring_repo.get_latest_alert_by_type = mock_monitoring_repo.get_recent_alert_by_type
    # Notification delivery throws network/system error
    mock_notification_service.dispatch = AsyncMock(side_effect=RuntimeError("SMTP Outage"))

    # Must complete cleanly without raising exception
    triggered = await monitoring_service.evaluate_operational_alerts(sa)
    assert len(triggered) >= 1
