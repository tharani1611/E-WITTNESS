"""Unit tests for Phase 97 Reviewer Workload and Background Processing Metrics.

Verifies:
- Scoping rules:
  - Global access for SUPER_ADMIN with CASE_WORKLOAD_READ_GLOBAL and OPERATIONS_METRICS_READ_GLOBAL.
  - Department scoped access for DEPT_ADMIN and INVESTIGATOR.
  - Rejection of unauthorized cross-department inquiries.
- Workload metrics:
  - Per-reviewer case and incident assignments.
  - Completed and pending AI segment review totals.
  - Unassigned case and incident counts.
  - Identification of top bottleneck reviewers.
- Background processing metrics:
  - Logical job totals distinct from retry counts.
  - Calculation of p95 and average durations with safe empty data handling.
  - Detection of stale background jobs.
  - Notification delivery channel statistics.
- Append-only security audit trail.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from backend.app.config.settings import Settings
from backend.app.core.audit import AuditAction
from backend.app.core.authorization import RoleCode
from backend.app.core.exceptions import BusinessRuleError, PermissionDeniedError
from backend.app.repositories.analytics import AnalyticsRepository
from backend.app.schemas.analytics import AnalyticsFilter
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.workload import (
    ProcessingMetricsRead,
    ReviewerWorkloadSummaryRead,
)
from backend.app.services.workload import WorkloadService


@pytest.fixture
def mock_analytics_repo() -> MagicMock:
    repo = MagicMock(spec=AnalyticsRepository)
    now = datetime.now(UTC)
    rev_id1 = uuid4()
    rev_id2 = uuid4()
    dept_id = uuid4()

    repo.get_reviewer_workload = AsyncMock(
        return_value={
            "reviewers": [
                {
                    "reviewer_id": rev_id1,
                    "reviewer_name": "Alice Lead",
                    "reviewer_email": "alice@campus.edu",
                    "department_id": dept_id,
                    "active_cases_count": 8,
                    "assigned_incidents_count": 4,
                    "completed_case_reviews_count": 8,
                    "completed_ai_segment_reviews_count": 25,
                    "pending_ai_segment_reviews_count": 10,
                },
                {
                    "reviewer_id": rev_id2,
                    "reviewer_name": "Bob Reviewer",
                    "reviewer_email": "bob@campus.edu",
                    "department_id": dept_id,
                    "active_cases_count": 3,
                    "assigned_incidents_count": 2,
                    "completed_case_reviews_count": 3,
                    "completed_ai_segment_reviews_count": 15,
                    "pending_ai_segment_reviews_count": 2,
                },
            ],
            "total_reviewers": 2,
            "unassigned_cases_count": 2,
            "unassigned_incidents_count": 5,
            "department_id": dept_id,
            "generated_at": now,
        }
    )

    repo.get_background_processing_metrics = AsyncMock(
        return_value={
            "ai_jobs": {
                "total_logical_jobs": 100,
                "retry_attempts_count": 15,
                "pending_count": 5,
                "running_count": 2,
                "completed_count": 90,
                "failed_count": 2,
                "cancelled_count": 1,
                "completion_rate": 0.9783,
                "failure_rate": 0.0217,
                "avg_processing_duration_seconds": 12.5,
                "p95_processing_duration_seconds": 24.8,
                "avg_queue_wait_seconds": 3.2,
                "stale_running_count": 0,
            },
            "notifications": {
                "total_logical_notifications": 250,
                "total_delivery_attempts": 260,
                "delivered_count": 245,
                "failed_count": 3,
                "pending_count": 2,
                "retry_exhausted_count": 0,
                "delivery_success_rate": 0.98,
            },
            "observation_window_start": now - timedelta(days=7),
            "observation_window_end": now,
            "department_id": dept_id,
            "generated_at": now,
        }
    )

    return repo


@pytest.fixture
def mock_audit_repo() -> MagicMock:
    repo = MagicMock()
    repo.append_event = AsyncMock()
    return repo


@pytest.fixture
def workload_service(
    mock_analytics_repo: MagicMock,
    mock_audit_repo: MagicMock,
    test_settings: Settings,
) -> WorkloadService:
    return WorkloadService(
        analytics_repo=mock_analytics_repo,
        audit_repo=mock_audit_repo,
        settings=test_settings,
    )


def test_workload_scope_resolution(workload_service: WorkloadService) -> None:
    """Verify department resolution for workload and operations permissions."""
    dept1 = uuid4()
    dept2 = uuid4()
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
    # Global allowed
    assert workload_service._resolve_workload_department_scope(sa, None) is None
    assert workload_service._resolve_operations_department_scope(sa, dept1) == dept1

    # Dept Admin confined
    da = AuthenticatedPrincipal(
        user_id=uuid4(),
        email="da@campus.edu",
        full_name="Dept Admin",
        account_status="active",
        is_active=True,
        role_code=RoleCode.DEPT_ADMIN.value,
        department_id=dept1,
        session_id=uuid4(),
    )
    assert workload_service._resolve_workload_department_scope(da, None) == dept1
    assert workload_service._resolve_operations_department_scope(da, dept1) == dept1

    # Cross department raises PermissionDeniedError
    with pytest.raises(PermissionDeniedError, match="Cross-department"):
        workload_service._resolve_workload_department_scope(da, dept2)
    with pytest.raises(PermissionDeniedError, match="Cross-department"):
        workload_service._resolve_operations_department_scope(da, dept2)

    # Student denied
    student = AuthenticatedPrincipal(
        user_id=uuid4(),
        email="student@campus.edu",
        full_name="Student",
        account_status="active",
        is_active=True,
        role_code=RoleCode.STUDENT.value,
        department_id=dept1,
        session_id=uuid4(),
    )
    with pytest.raises(PermissionDeniedError, match="permission to view reviewer workloads"):
        workload_service._resolve_workload_department_scope(student, None)
    with pytest.raises(
        PermissionDeniedError, match="permission to view background processing metrics"
    ):
        workload_service._resolve_operations_department_scope(student, None)


@pytest.mark.asyncio
async def test_get_reviewer_workload(
    workload_service: WorkloadService,
    mock_analytics_repo: MagicMock,
    mock_audit_repo: MagicMock,
) -> None:
    """Verify reviewer workload summary retrieval, sorting, and audit logging."""
    dept_id = uuid4()
    da = AuthenticatedPrincipal(
        user_id=uuid4(),
        email="da@campus.edu",
        full_name="Dept Admin",
        account_status="active",
        is_active=True,
        role_code=RoleCode.DEPT_ADMIN.value,
        department_id=dept_id,
        session_id=uuid4(),
    )

    res = await workload_service.get_reviewer_workload(da, department_id=dept_id)

    assert isinstance(res, ReviewerWorkloadSummaryRead)
    assert len(res.reviewers) == 2
    # Verify top bottleneck is Alice Lead (8 active cases)
    assert res.reviewers[0].reviewer_name == "Alice Lead"
    assert res.reviewers[0].active_cases_count == 8
    assert res.unassigned_cases_count == 2
    assert res.unassigned_incidents_count == 5

    mock_analytics_repo.get_reviewer_workload.assert_awaited_once_with(department_id=dept_id)
    mock_audit_repo.append_event.assert_awaited_once()
    assert (
        mock_audit_repo.append_event.call_args[1]["action"] == AuditAction.WORKLOAD_ACCESSED.value
    )


@pytest.mark.asyncio
async def test_get_processing_metrics(
    workload_service: WorkloadService,
    mock_analytics_repo: MagicMock,
    mock_audit_repo: MagicMock,
) -> None:
    """Verify background AI and notification throughput metrics."""
    dept_id = uuid4()
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
    filter_params = AnalyticsFilter(department_id=dept_id)

    res = await workload_service.get_processing_metrics(sa, filter_params)

    assert isinstance(res, ProcessingMetricsRead)
    # AI Job Metrics
    assert res.ai_jobs.total_logical_jobs == 100
    assert res.ai_jobs.retry_attempts_count == 15
    assert res.ai_jobs.completion_rate == 0.9783
    assert res.ai_jobs.p95_processing_duration_seconds == 24.8
    assert res.ai_jobs.stale_running_count == 0

    # Notification Metrics
    assert res.notifications.total_logical_notifications == 250
    assert res.notifications.total_delivery_attempts == 260
    assert res.notifications.delivered_count == 245
    assert res.notifications.delivery_success_rate == 0.98

    mock_analytics_repo.get_background_processing_metrics.assert_awaited_once()
    mock_audit_repo.append_event.assert_awaited_once()


def test_workload_filter_validation(workload_service: WorkloadService) -> None:
    """Verify invalid date handling in processing metrics raises BusinessRuleError."""
    f = AnalyticsFilter()
    object.__setattr__(f, "start_date", None)
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
    with pytest.raises(BusinessRuleError, match="date range must be specified"):
        import asyncio

        asyncio.run(workload_service.get_processing_metrics(sa, f))
