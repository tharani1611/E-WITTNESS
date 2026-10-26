"""Unit tests for Operational Dashboards, Scoping, and Validations (Phase 95).

Tests:
- Bounded date range filtering with UTC normalization and range limits.
- Department isolation and tenant protection:
  - Department administrators and investigators are confined to their own department.
  - Cross-department access attempts are denied.
  - Global dashboard viewing is restricted to SUPER_ADMIN.
- Metric aggregation flows for incidents, cases, and operations.
- Immutable audit trail generation on dashboard access.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

from backend.app.config.settings import Settings
from backend.app.core.audit import AuditAction
from backend.app.core.authorization import RoleCode
from backend.app.core.exceptions import PermissionDeniedError
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.dashboard import (
    CaseDashboardRead,
    DashboardDateFilter,
    IncidentDashboardRead,
    OperationsDashboardRead,
)
from backend.app.services.dashboard import DashboardService


@pytest.fixture
def mock_dashboard_repo() -> MagicMock:
    now = datetime.now(UTC)
    repo = MagicMock()
    repo.get_incident_metrics = AsyncMock(
        return_value=IncidentDashboardRead(
            total_incidents=10,
            incidents_by_status={"submitted": 4, "under_review": 6},
            incidents_by_severity={"medium": 7, "high": 3},
            incidents_by_department={"Safety": 10},
            total_evidence_items=15,
            time_range_start=now - timedelta(days=30),
            time_range_end=now,
            department_id=None,
            generated_at=now,
        )
    )
    repo.get_case_metrics = AsyncMock(
        return_value=CaseDashboardRead(
            total_cases=5,
            cases_by_status={"open": 3, "in_progress": 2},
            cases_by_priority={"medium": 4, "high": 1},
            cases_by_escalation={},
            active_investigations_count=5,
            legal_hold_cases_count=1,
            time_range_start=now - timedelta(days=30),
            time_range_end=now,
            department_id=None,
            generated_at=now,
        )
    )
    repo.get_operations_metrics = AsyncMock(
        return_value=OperationsDashboardRead(
            ai_jobs_total=8,
            ai_jobs_by_status={"completed": 6, "queued": 2},
            ai_jobs_by_task_type={"face_detection": 8},
            notifications_total=25,
            notifications_by_channel={"in_app": 20, "email": 5},
            notifications_by_status={"delivered": 24, "failed": 1},
            delivery_attempts_total=26,
            delivery_failures_total=1,
            time_range_start=now - timedelta(days=30),
            time_range_end=now,
            department_id=None,
            generated_at=now,
        )
    )
    return repo


@pytest.fixture
def mock_audit_repo() -> MagicMock:
    repo = MagicMock()
    repo.append_event = AsyncMock()
    return repo


@pytest.fixture
def dashboard_service(
    mock_dashboard_repo: MagicMock,
    mock_audit_repo: MagicMock,
    test_settings: Settings,
) -> DashboardService:
    return DashboardService(
        dashboard_repo=mock_dashboard_repo,
        audit_repo=mock_audit_repo,
        settings=test_settings,
    )


class TestDashboardDateFilter:
    """Verifies bounded date range validation and UTC normalization."""

    def test_default_dates_assigned(self) -> None:
        """When omitted, end_date is now (UTC) and start_date is 30 days prior."""
        filter_params = DashboardDateFilter()
        assert filter_params.start_date is not None
        assert filter_params.end_date is not None
        assert filter_params.start_date.tzinfo == UTC
        assert filter_params.end_date.tzinfo == UTC
        diff = filter_params.end_date - filter_params.start_date
        assert 29 <= diff.days <= 31

    def test_start_greater_than_end_raises(self) -> None:
        """start_date after end_date must raise ValueError."""
        now = datetime.now(UTC)
        with pytest.raises(ValueError, match="start_date cannot be greater than end_date"):
            DashboardDateFilter(start_date=now, end_date=now - timedelta(days=1))

    def test_range_exceeding_max_days_raises(self) -> None:
        """Query windows exceeding 366 days are rejected."""
        now = datetime.now(UTC)
        with pytest.raises(ValueError, match="Time range cannot exceed 366 days"):
            DashboardDateFilter(start_date=now - timedelta(days=400), end_date=now)


def _make_principal(
    role_code: str,
    department_id: UUID | None = None,
    user_id: UUID | None = None,
) -> AuthenticatedPrincipal:
    """Helper to construct valid AuthenticatedPrincipal instances for tests."""
    return AuthenticatedPrincipal(
        user_id=user_id or uuid4(),
        email=f"user_{uuid4().hex[:6]}@ewitness.edu",
        full_name="Test Principal",
        account_status="active",
        is_active=True,
        role_code=role_code,
        department_id=department_id,
        session_id=uuid4(),
    )


class TestDashboardScopingAndAccessControl:
    """Verifies tenant isolation and permission enforcement."""

    @pytest.mark.asyncio
    async def test_unauthorized_role_denied(
        self,
        dashboard_service: DashboardService,
    ) -> None:
        """Users without dashboard permissions (e.g. STUDENT) are rejected."""
        student_principal = _make_principal(
            role_code=RoleCode.STUDENT.value,
            department_id=uuid4(),
        )
        filter_params = DashboardDateFilter()

        with pytest.raises(PermissionDeniedError) as exc_info:
            await dashboard_service.get_incident_dashboard(filter_params, student_principal)
        assert exc_info.value.code == "DASHBOARD_ACCESS_DENIED"

    @pytest.mark.asyncio
    async def test_dept_admin_cannot_query_cross_department(
        self,
        dashboard_service: DashboardService,
    ) -> None:
        """Dept admin querying another department's ID is rejected."""
        sec_dept_id = uuid4()
        other_dept_id = uuid4()

        dept_admin_principal = _make_principal(
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=sec_dept_id,
        )
        filter_params = DashboardDateFilter(department_id=other_dept_id)

        with pytest.raises(PermissionDeniedError) as exc_info:
            await dashboard_service.get_incident_dashboard(filter_params, dept_admin_principal)
        assert exc_info.value.code == "CROSS_DEPARTMENT_FORBIDDEN"

    @pytest.mark.asyncio
    async def test_dept_admin_scoped_to_own_department(
        self,
        dashboard_service: DashboardService,
        mock_dashboard_repo: MagicMock,
        mock_audit_repo: MagicMock,
    ) -> None:
        """Dept admin without explicit department filter automatically scopes to own department."""
        sec_dept_id = uuid4()
        dept_admin_principal = _make_principal(
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=sec_dept_id,
        )
        filter_params = DashboardDateFilter(department_id=None)

        res = await dashboard_service.get_incident_dashboard(filter_params, dept_admin_principal)
        assert res is not None

        # Verify repo was called with effective dept id
        mock_dashboard_repo.get_incident_metrics.assert_called_once()
        call_kwargs = mock_dashboard_repo.get_incident_metrics.call_args[1]
        assert call_kwargs["department_id"] == sec_dept_id

        # Verify audit event
        mock_audit_repo.append_event.assert_called_once()
        audit_call = mock_audit_repo.append_event.call_args[1]
        assert audit_call["action"] == AuditAction.DASHBOARD_ACCESSED
        assert audit_call["target_id"] == "incidents"
        assert audit_call["department_id"] == sec_dept_id

    @pytest.mark.asyncio
    async def test_super_admin_global_and_specific_department(
        self,
        dashboard_service: DashboardService,
        mock_dashboard_repo: MagicMock,
    ) -> None:
        """Super admin can view global metrics (dept=None) or any specific department."""
        super_admin_principal = _make_principal(
            role_code=RoleCode.SUPER_ADMIN.value,
            department_id=None,
        )

        # 1. Global case dashboard
        global_filter = DashboardDateFilter(department_id=None)
        await dashboard_service.get_case_dashboard(global_filter, super_admin_principal)
        call_kwargs = mock_dashboard_repo.get_case_metrics.call_args[1]
        assert call_kwargs["department_id"] is None

        # 2. Specific department case dashboard
        target_dept = uuid4()
        specific_filter = DashboardDateFilter(department_id=target_dept)
        await dashboard_service.get_case_dashboard(specific_filter, super_admin_principal)
        call_kwargs = mock_dashboard_repo.get_case_metrics.call_args[1]
        assert call_kwargs["department_id"] == target_dept

    @pytest.mark.asyncio
    async def test_operations_dashboard_metrics(
        self,
        dashboard_service: DashboardService,
        mock_dashboard_repo: MagicMock,
        mock_audit_repo: MagicMock,
    ) -> None:
        """Operations dashboard aggregates AI and notification queues."""
        super_admin_principal = _make_principal(
            role_code=RoleCode.SUPER_ADMIN.value,
            department_id=None,
        )
        filter_params = DashboardDateFilter()

        res = await dashboard_service.get_operations_dashboard(filter_params, super_admin_principal)
        assert res.ai_jobs_total == 8
        assert res.notifications_total == 25
        assert res.delivery_failures_total == 1

        mock_audit_repo.append_event.assert_called_once()
        audit_call = mock_audit_repo.append_event.call_args[1]
        assert audit_call["action"] == AuditAction.DASHBOARD_ACCESSED
        assert audit_call["target_id"] == "operations"
