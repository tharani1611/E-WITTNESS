"""Unit tests for Phase 96 Authorized Analytics, Aggregate Statistics, and Scoping.

Verifies:
- Scoping rules:
  - SUPER_ADMIN with ANALYTICS_VIEW_GLOBAL can query any department or global scope.
  - DEPT_ADMIN and INVESTIGATOR with ANALYTICS_VIEW_DEPT are strictly bound to their department.
  - Cross-department queries by non-global roles are strictly rejected with 403 PermissionDeniedError.
  - Users without analytics permissions are rejected.
- Aggregation workflows for:
  - Incident analytics and time-series histograms.
  - Case analytics and status/priority trends.
  - AI review outcomes, confirmation vs rejection rates, and false-positive reasons.
  - Combined analytical summary overview.
- Append-only security audit logging for all analytical queries.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from backend.app.config.settings import Settings
from backend.app.core.analytics import TimeBucket
from backend.app.core.audit import AuditAction
from backend.app.core.authorization import RoleCode
from backend.app.core.exceptions import BusinessRuleError, PermissionDeniedError
from backend.app.repositories.analytics import AnalyticsRepository
from backend.app.schemas.analytics import (
    AnalyticsFilter,
    AnalyticsOverviewRead,
    CaseAnalyticsRead,
    IncidentAnalyticsRead,
    ReviewOutcomeAnalyticsRead,
    TimeSeriesBucket,
)
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.services.analytics import AnalyticsService


@pytest.fixture
def mock_analytics_repo() -> MagicMock:
    now = datetime.now(UTC)
    repo = MagicMock(spec=AnalyticsRepository)

    bucket = TimeSeriesBucket(
        bucket_start=now - timedelta(days=1),
        bucket_end=now,
        count=5,
    )

    repo.get_incident_analytics = AsyncMock(
        return_value={
            "total_incidents": 20,
            "incidents_by_status": {"submitted": 10, "under_review": 10},
            "incidents_by_category": {"property": 15, "safety": 5},
            "incidents_by_severity": {"low": 12, "high": 8},
            "incidents_by_department": {"Security": 20},
            "avg_resolution_hours": 4.5,
            "time_series": [bucket.model_dump()],
            "time_range_start": now - timedelta(days=30),
            "time_range_end": now,
            "department_id": None,
            "generated_at": now,
        }
    )

    repo.get_case_analytics = AsyncMock(
        return_value={
            "total_cases": 12,
            "cases_by_status": {"open": 6, "closed": 6},
            "cases_by_priority": {"medium": 8, "high": 4},
            "cases_by_escalation": {},
            "active_investigations_count": 6,
            "closed_cases_count": 6,
            "time_series": [bucket.model_dump()],
            "time_range_start": now - timedelta(days=30),
            "time_range_end": now,
            "department_id": None,
            "generated_at": now,
        }
    )

    repo.get_review_outcome_analytics = AsyncMock(
        return_value={
            "total_reviews": 50,
            "reviews_by_status": {"confirmed": 40, "rejected": 10},
            "acceptance_rate": 0.8,
            "rejection_rate": 0.2,
            "false_positive_reasons": {"occlusion": 6, "camera_shake": 4},
            "time_series": [bucket.model_dump()],
            "time_range_start": now - timedelta(days=30),
            "time_range_end": now,
            "department_id": None,
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
def analytics_service(
    mock_analytics_repo: MagicMock,
    mock_audit_repo: MagicMock,
    test_settings: Settings,
) -> AnalyticsService:
    return AnalyticsService(
        analytics_repo=mock_analytics_repo,
        audit_repo=mock_audit_repo,
        settings=test_settings,
    )


def test_resolve_department_scope_global(analytics_service: AnalyticsService) -> None:
    """Super admin can query all or specific department."""
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
    # Query all
    assert analytics_service._resolve_department_scope(sa, None) is None
    # Query specific
    dept_id = uuid4()
    assert analytics_service._resolve_department_scope(sa, dept_id) == dept_id


def test_resolve_department_scope_department_bound(analytics_service: AnalyticsService) -> None:
    """Department admin or investigator is restricted to their own department."""
    my_dept = uuid4()
    da = AuthenticatedPrincipal(
        user_id=uuid4(),
        email="deptadmin@campus.edu",
        full_name="Dept Admin",
        account_status="active",
        is_active=True,
        role_code=RoleCode.DEPT_ADMIN.value,
        department_id=my_dept,
        session_id=uuid4(),
    )
    # None requested -> defaults to my_dept
    assert analytics_service._resolve_department_scope(da, None) == my_dept
    # my_dept requested -> allowed
    assert analytics_service._resolve_department_scope(da, my_dept) == my_dept


def test_resolve_department_scope_cross_department_forbidden(
    analytics_service: AnalyticsService,
) -> None:
    """Investigator attempting to query another department is rejected."""
    my_dept = uuid4()
    other_dept = uuid4()
    inv = AuthenticatedPrincipal(
        user_id=uuid4(),
        email="inv@campus.edu",
        full_name="Investigator One",
        account_status="active",
        is_active=True,
        role_code=RoleCode.INVESTIGATOR.value,
        department_id=my_dept,
        session_id=uuid4(),
    )
    with pytest.raises(PermissionDeniedError, match="Cross-department"):
        analytics_service._resolve_department_scope(inv, other_dept)


def test_resolve_department_scope_no_permission(analytics_service: AnalyticsService) -> None:
    """Student or external role without analytics permission is denied."""
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
    with pytest.raises(PermissionDeniedError, match="permission to view analytical metrics"):
        analytics_service._resolve_department_scope(student, None)


@pytest.mark.asyncio
async def test_get_incident_analytics(
    analytics_service: AnalyticsService,
    mock_analytics_repo: MagicMock,
    mock_audit_repo: MagicMock,
) -> None:
    """Verify incident analytics aggregation and audit trail generation."""
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
    filter_params = AnalyticsFilter(bucket=TimeBucket.WEEK, department_id=dept_id)

    res = await analytics_service.get_incident_analytics(sa, filter_params)

    assert isinstance(res, IncidentAnalyticsRead)
    assert res.total_incidents == 20
    assert len(res.time_series) == 1
    mock_analytics_repo.get_incident_analytics.assert_awaited_once()
    mock_audit_repo.append_event.assert_awaited_once()
    assert (
        mock_audit_repo.append_event.call_args[1]["action"] == AuditAction.ANALYTICS_ACCESSED.value
    )


@pytest.mark.asyncio
async def test_get_case_analytics(
    analytics_service: AnalyticsService,
    mock_analytics_repo: MagicMock,
    mock_audit_repo: MagicMock,
) -> None:
    """Verify case analytics aggregation and trends."""
    dept_id = uuid4()
    inv = AuthenticatedPrincipal(
        user_id=uuid4(),
        email="inv@campus.edu",
        full_name="Investigator One",
        account_status="active",
        is_active=True,
        role_code=RoleCode.INVESTIGATOR.value,
        department_id=dept_id,
        session_id=uuid4(),
    )
    filter_params = AnalyticsFilter(bucket=TimeBucket.DAY)

    res = await analytics_service.get_case_analytics(inv, filter_params)

    assert isinstance(res, CaseAnalyticsRead)
    assert res.total_cases == 12
    assert res.active_investigations_count == 6
    mock_analytics_repo.get_case_analytics.assert_awaited_once()
    mock_audit_repo.append_event.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_review_outcome_analytics(
    analytics_service: AnalyticsService,
    mock_analytics_repo: MagicMock,
    mock_audit_repo: MagicMock,
) -> None:
    """Verify AI candidate human review outcomes and false-positive reasons."""
    dept_id = uuid4()
    da = AuthenticatedPrincipal(
        user_id=uuid4(),
        email="deptadmin@campus.edu",
        full_name="Dept Admin",
        account_status="active",
        is_active=True,
        role_code=RoleCode.DEPT_ADMIN.value,
        department_id=dept_id,
        session_id=uuid4(),
    )
    filter_params = AnalyticsFilter(bucket=TimeBucket.MONTH)

    res = await analytics_service.get_review_outcome_analytics(da, filter_params)

    assert isinstance(res, ReviewOutcomeAnalyticsRead)
    assert res.total_reviews == 50
    assert res.acceptance_rate == 0.8
    assert res.rejection_rate == 0.2
    assert res.false_positive_reasons["occlusion"] == 6
    mock_analytics_repo.get_review_outcome_analytics.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_analytics_overview(
    analytics_service: AnalyticsService,
    mock_analytics_repo: MagicMock,
    mock_audit_repo: MagicMock,
) -> None:
    """Verify combined analytical overview across incidents, cases, and reviews."""
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
    filter_params = AnalyticsFilter()

    res = await analytics_service.get_analytics_overview(sa, filter_params)

    assert isinstance(res, AnalyticsOverviewRead)
    assert res.total_incidents == 20
    assert res.total_cases == 12
    assert res.total_reviews == 50
    assert res.active_investigations == 6
    assert mock_audit_repo.append_event.call_count == 1


def test_extract_bounds_missing_raises_business_rule_error() -> None:
    """Verify _extract_bounds handles unpopulated filter dates safely."""
    # Create an unvalidated or manually modified object to verify type-guard behavior
    f = AnalyticsFilter()
    object.__setattr__(f, "start_date", None)
    with pytest.raises(BusinessRuleError, match="must be specified"):
        AnalyticsService._extract_bounds(f)
