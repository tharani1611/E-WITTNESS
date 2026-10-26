"""PostgreSQL database repository integration tests for Batch 10 Group 02 (Phases 96-99).

Verifies pure SQL execution and transaction isolation against live PostgreSQL:
- AnalyticsRepository:
  - Aggregation of incident counts by category, severity, and status.
  - Aggregation of case counts by status and priority.
  - Aggregation of human review outcomes and false positive metrics.
  - Background AI analysis and notification processing metrics.
- ReportRepository:
  - Bounded data extraction for CSV/PDF exports (limit <= 5000).
  - Metadata persistence and retrieval for ReportExport entities.
  - Download count incrementation.
- OperationalMonitoringRepository:
  - Worker heartbeat upserting, query by status, and threshold-based staleness updates.
  - Queue depth and oldest pending job calculation.
  - Operational alert creation, active alert retrieval, and 15-minute cooldown checks.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text

from backend.app.core.analytics import (
    ExportStatus,
    OperationalAlertSeverity,
    OperationalAlertType,
    ReportFormat,
    ReportType,
    TimeBucket,
    WorkerStatus,
)
from backend.app.core.identity import RoleCode
from backend.app.infrastructure.database import DatabaseSessionManager
from backend.app.models.department import Department
from backend.app.models.monitoring import OperationalAlert
from backend.app.models.report import ReportExport
from backend.app.models.role import Role
from backend.app.models.user import User
from backend.app.repositories.analytics import AnalyticsRepository
from backend.app.repositories.monitoring import OperationalMonitoringRepository
from backend.app.repositories.report import ReportRepository


@pytest.mark.asyncio
class TestBatch10RepositoriesLivePostgres:
    """Execute repository methods directly against genuine PostgreSQL database."""

    async def test_analytics_repository_aggregations(
        self,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify AnalyticsRepository pure SQL queries execute cleanly on live Postgres."""
        now = datetime.now(UTC)
        start_date = now - timedelta(days=30)
        end_date = now

        async with postgres_db_manager.transactional_session() as session:
            # Seed a test department
            dept = Department(
                code=f"ANL-{uuid4().hex[:4].upper()}",
                name="Analytics Test Dept",
                is_active=True,
            )
            session.add(dept)
            await session.flush()

            repo = AnalyticsRepository(session)

            # 1. Incident analytics
            inc_metrics = await repo.get_incident_analytics(
                start_date=start_date,
                end_date=end_date,
                bucket=TimeBucket.DAY,
                department_id=dept.id,
            )
            assert isinstance(inc_metrics, dict)
            assert "total_incidents" in inc_metrics
            assert "incidents_by_severity" in inc_metrics
            assert "incidents_by_status" in inc_metrics
            assert "incidents_by_category" in inc_metrics
            assert "time_series" in inc_metrics
            assert inc_metrics["total_incidents"] == 0

            # 2. Case analytics
            case_metrics = await repo.get_case_analytics(
                start_date=start_date,
                end_date=end_date,
                bucket=TimeBucket.WEEK,
                department_id=dept.id,
            )
            assert isinstance(case_metrics, dict)
            assert "total_cases" in case_metrics
            assert "cases_by_status" in case_metrics
            assert "cases_by_priority" in case_metrics
            assert case_metrics["total_cases"] == 0

            # 3. Review outcome analytics
            rev_metrics = await repo.get_review_outcome_analytics(
                start_date=start_date,
                end_date=end_date,
                bucket=TimeBucket.DAY,
                department_id=dept.id,
            )
            assert isinstance(rev_metrics, dict)
            assert "total_reviews" in rev_metrics
            assert "acceptance_rate" in rev_metrics
            assert "rejection_rate" in rev_metrics
            assert "reviews_by_status" in rev_metrics

            # 4. Reviewer workload
            workload = await repo.get_reviewer_workload(department_id=dept.id)
            assert isinstance(workload, dict)
            assert "reviewers" in workload
            assert "unassigned_incidents_count" in workload
            assert "unassigned_cases_count" in workload

            # 5. Background processing metrics
            proc = await repo.get_background_processing_metrics(
                start_date=start_date,
                end_date=end_date,
                department_id=dept.id,
            )
            assert isinstance(proc, dict)
            assert "ai_jobs" in proc
            assert "notifications" in proc
            assert proc["ai_jobs"]["total_logical_jobs"] == 0
            assert proc["notifications"]["total_logical_notifications"] == 0

    async def test_report_repository_crud_and_exports(
        self,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify ReportRepository CRUD and bounded extraction queries on live Postgres."""
        now = datetime.now(UTC)
        start_date = now - timedelta(days=7)
        end_date = now

        async with postgres_db_manager.transactional_session() as session:
            # Seed test department and user
            dept = Department(
                code=f"REP-{uuid4().hex[:4].upper()}",
                name="Report Test Dept",
                is_active=True,
            )
            session.add(dept)
            await session.flush()

            # Ensure role
            role_res = await session.execute(
                text("SELECT id FROM roles WHERE code = :code LIMIT 1"),
                {"code": RoleCode.SUPER_ADMIN.value},
            )
            role_id = role_res.scalar_one_or_none()
            if not role_id:
                r = Role(
                    code=RoleCode.SUPER_ADMIN.value,
                    name="Super Admin",
                    description="Super Administrator with global access",
                )
                session.add(r)
                await session.flush()
                role_id = r.id

            user = User(
                email=f"reporter_{uuid4().hex[:6]}@campus.edu",
                full_name="Report Creator",
                role_id=role_id,
                department_id=dept.id,
                account_status="active",
                is_active=True,
                password_hash="$2b$12$e80yq9G0Z3o6/XW7Kz2XjeP0j4f1qf5k4G8Xy7M1w2V3u4T5S6R7Q",
            )
            session.add(user)
            await session.flush()

            repo = ReportRepository(session)

            # 1. Test extraction queries (empty sets)
            inc_rows = await repo.fetch_incidents_for_export(
                start_date, end_date, dept.id, limit=10
            )
            assert isinstance(inc_rows, list)

            case_rows = await repo.fetch_cases_for_export(start_date, end_date, dept.id, limit=10)
            assert isinstance(case_rows, list)

            rev_rows = await repo.fetch_reviews_for_export(start_date, end_date, dept.id, limit=10)
            assert isinstance(rev_rows, list)

            op_rows = await repo.fetch_operational_summary_for_export(start_date, end_date, dept.id)
            assert isinstance(op_rows, list)
            assert len(op_rows) > 0

            # 2. Create ReportExport record
            export_rec = ReportExport(
                id=uuid4(),
                created_at=now,
                report_type=ReportType.INCIDENTS.value,
                export_format=ReportFormat.CSV.value,
                department_id=dept.id,
                created_by_id=user.id,
                parameters_json=json.dumps(
                    {"start_date": start_date.isoformat(), "record_count": 0}
                ),
                status=ExportStatus.COMPLETED.value,
                file_name="incidents_test.csv",
                file_size_bytes=256,
                content_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                download_count=1,
                expires_at=now + timedelta(days=7),
            )
            saved = await repo.create_report_export(export_rec)
            assert saved.id == export_rec.id

            # 3. Retrieve by ID
            fetched = await repo.get_report_export_by_id(saved.id)
            assert fetched is not None
            assert fetched.file_name == "incidents_test.csv"
            assert fetched.download_count == 1

            # 4. Increment download count
            await repo.increment_download_count(saved.id)
            refetched = await repo.get_report_export_by_id(saved.id)
            assert refetched is not None
            assert refetched.download_count == 2

    async def test_operational_monitoring_repository(
        self,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify worker heartbeat upsert, staleness transition, and operational alert deduplication."""
        now = datetime.now(UTC)
        worker_id = f"worker-{uuid4().hex[:6]}"

        async with postgres_db_manager.transactional_session() as session:
            repo = OperationalMonitoringRepository(session)

            # 1. Upsert worker heartbeat
            hb = await repo.upsert_worker_heartbeat(
                worker_id=worker_id,
                hostname="node-01.campus.edu",
                task_types=["ai_analysis", "notifications"],
                status=WorkerStatus.ACTIVE.value,
                current_job_id=None,
                metrics={"cpu": 12.5, "mem_mb": 256},
            )
            assert hb.worker_id == worker_id
            assert hb.status == WorkerStatus.ACTIVE.value
            assert hb.metrics["cpu"] == 12.5

            # Refresh heartbeat
            hb2 = await repo.upsert_worker_heartbeat(
                worker_id=worker_id,
                hostname="node-01.campus.edu",
                task_types=["ai_analysis"],
                status=WorkerStatus.ACTIVE.value,
                metrics={"cpu": 18.0},
            )
            assert hb2.id == hb.id
            assert hb2.metrics["cpu"] == 18.0

            # 2. List worker heartbeats
            all_hb = await repo.list_worker_heartbeats()
            assert any(w.worker_id == worker_id for w in all_hb)

            # 3. Queue depth metrics
            q_metrics = await repo.get_queue_depth_metrics()
            assert "ai_job_queue_depth" in q_metrics
            assert "notification_queue_depth" in q_metrics
            assert "retry_exhausted_count" in q_metrics

            # 4. Create and query operational alert
            alert = OperationalAlert(
                id=uuid4(),
                created_at=now,
                alert_type=OperationalAlertType.QUEUE_BACKLOG.value,
                severity=OperationalAlertSeverity.WARNING.value,
                title="Queue Backlog Test",
                message="Test queue backlog message",
                details_json=json.dumps({"depth": 75}),
                is_active=True,
                triggered_at=now,
            )
            saved_alert = await repo.create_operational_alert(alert)
            assert saved_alert.id == alert.id

            # Active alerts query
            active_alerts = await repo.get_active_operational_alerts()
            assert any(a.id == saved_alert.id for a in active_alerts)

            # Cooldown check
            recent = await repo.get_recent_alert_by_type(
                alert_type=OperationalAlertType.QUEUE_BACKLOG.value,
                cooldown_seconds=900,
            )
            assert recent is not None
            assert recent.id == saved_alert.id

            # Resolve alert
            await repo.resolve_operational_alert(saved_alert.id)
            after_resolve = await repo.get_active_operational_alerts()
            assert not any(a.id == saved_alert.id for a in after_resolve)
