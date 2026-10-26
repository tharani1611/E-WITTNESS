"""Unit tests for Phase 55: Incident severity, deterministic routing, and authorized overrides."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from backend.app.config.settings import Settings
from backend.app.core.exceptions import (
    BusinessRuleError,
    PermissionDeniedError,
    ResourceNotFoundError,
)
from backend.app.core.identity import RoleCode
from backend.app.core.incident import (
    IncidentCategory,
    IncidentRoutingType,
    IncidentSeverity,
    IncidentStatus,
    evaluate_deterministic_routing,
    parse_incident_severity,
)
from backend.app.models.department import Department
from backend.app.models.incident import Incident, IncidentRoutingDecision
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.incident import (
    IncidentCreate,
    IncidentRouteOverrideRequest,
    IncidentUpdate,
)
from backend.app.schemas.pagination import PaginationParams
from backend.app.services.incident import IncidentService


class TestIncidentSeverityAndDomainRouting:
    """Phase 55: Severity enum parsing and deterministic routing engine tests."""

    def test_parse_incident_severity_valid(self) -> None:
        assert parse_incident_severity("low") == IncidentSeverity.LOW
        assert parse_incident_severity("  MEDIUM  ") == IncidentSeverity.MEDIUM
        assert parse_incident_severity("High") == IncidentSeverity.HIGH
        assert parse_incident_severity("CRITICAL") == IncidentSeverity.CRITICAL

    def test_parse_incident_severity_invalid(self) -> None:
        with pytest.raises(BusinessRuleError) as exc_info:
            parse_incident_severity("catastrophic")
        assert exc_info.value.code == "INVALID_INCIDENT_SEVERITY"

    def test_evaluate_deterministic_routing_critical_safety(self) -> None:
        safety_id = uuid4()
        academic_id = uuid4()
        reporter_dept = uuid4()
        depts = [(safety_id, "CAMPUS_SAFETY"), (academic_id, "ACADEMIC_AFFAIRS")]

        # Critical severity routes to safety regardless of category
        target, rule = evaluate_deterministic_routing(
            category=IncidentCategory.ACADEMIC_MISCONDUCT,
            severity=IncidentSeverity.CRITICAL,
            available_departments=depts,
            reporter_department_id=reporter_dept,
        )
        assert target == safety_id
        assert "CRITICAL_SAFETY_ROUTING" in rule

    def test_evaluate_deterministic_routing_physical_assault(self) -> None:
        safety_id = uuid4()
        academic_id = uuid4()
        depts = [(safety_id, "SAFETY"), (academic_id, "ACADEMIC")]

        target, rule = evaluate_deterministic_routing(
            category=IncidentCategory.PHYSICAL_ASSAULT,
            severity=IncidentSeverity.LOW,
            available_departments=depts,
            reporter_department_id=academic_id,
        )
        assert target == safety_id
        assert "CRITICAL_SAFETY_ROUTING:SAFETY" in rule

    def test_evaluate_deterministic_routing_academic_misconduct(self) -> None:
        safety_id = uuid4()
        conduct_id = uuid4()
        depts = [(safety_id, "SAFETY"), (conduct_id, "STUDENT_CONDUCT")]

        target, rule = evaluate_deterministic_routing(
            category=IncidentCategory.ACADEMIC_MISCONDUCT,
            severity=IncidentSeverity.MEDIUM,
            available_departments=depts,
            reporter_department_id=safety_id,
        )
        assert target == conduct_id
        assert "ACADEMIC_AFFAIRS_ROUTING" in rule

    def test_evaluate_deterministic_routing_harassment(self) -> None:
        title_ix_id = uuid4()
        depts = [(title_ix_id, "TITLE_IX")]

        target, rule = evaluate_deterministic_routing(
            category=IncidentCategory.HARASSMENT_DISCRIMINATION,
            severity=IncidentSeverity.MEDIUM,
            available_departments=depts,
            reporter_department_id=uuid4(),
        )
        assert target == title_ix_id
        assert "CONDUCT_TITLE_IX_ROUTING:TITLE_IX" in rule

    def test_evaluate_deterministic_routing_property_damage(self) -> None:
        facilities_id = uuid4()
        depts = [(facilities_id, "FACILITIES")]

        target, rule = evaluate_deterministic_routing(
            category=IncidentCategory.PROPERTY_DAMAGE_THEFT,
            severity=IncidentSeverity.MEDIUM,
            available_departments=depts,
            reporter_department_id=uuid4(),
        )
        assert target == facilities_id
        assert "FACILITIES_SAFETY_ROUTING:FACILITIES" in rule

    def test_evaluate_deterministic_routing_fallback_reporter_home(self) -> None:
        reporter_dept_id = uuid4()
        other_dept_id = uuid4()
        depts = [(other_dept_id, "CHEMISTRY"), (reporter_dept_id, "BIOLOGY")]

        target, rule = evaluate_deterministic_routing(
            category=IncidentCategory.OTHER,
            severity=IncidentSeverity.LOW,
            available_departments=depts,
            reporter_department_id=reporter_dept_id,
        )
        assert target == reporter_dept_id
        assert rule == "DEFAULT_REPORTER_HOME_DEPARTMENT"

    def test_evaluate_deterministic_routing_fallback_first_available(self) -> None:
        first_dept_id = uuid4()
        reporter_dept_id = uuid4()
        depts = [(first_dept_id, "MATH")]

        target, rule = evaluate_deterministic_routing(
            category=IncidentCategory.OTHER,
            severity=IncidentSeverity.LOW,
            available_departments=depts,
            reporter_department_id=reporter_dept_id,
        )
        assert target == first_dept_id
        assert "DEFAULT_FIRST_AVAILABLE" in rule

    def test_evaluate_deterministic_routing_empty_departments_fallback(self) -> None:
        reporter_dept_id = uuid4()
        target, rule = evaluate_deterministic_routing(
            category=IncidentCategory.OTHER,
            severity=IncidentSeverity.LOW,
            available_departments=[],
            reporter_department_id=reporter_dept_id,
        )
        assert target == reporter_dept_id
        assert rule == "DEFAULT_FALLBACK"


class TestIncidentSeverityAndRoutingSchemas:
    """Phase 55: Schema validation for severity and routing decisions."""

    def test_incident_create_defaults_severity_medium(self) -> None:
        payload = IncidentCreate(
            title="Suspicious activity reported",
            description="Detailed narrative of observed unauthorized access.",
            category=IncidentCategory.OTHER,
            location="Library 3rd floor",
            occurred_at=datetime.now(UTC) - timedelta(hours=1),
        )
        assert payload.severity == IncidentSeverity.MEDIUM

    def test_incident_create_custom_severity(self) -> None:
        payload = IncidentCreate(
            title="Critical security vulnerability",
            description="Server room door left open unattended with alarms silenced.",
            category=IncidentCategory.SAFETY_HAZARD,
            severity=IncidentSeverity.CRITICAL,
            location="Main Data Center",
            occurred_at=datetime.now(UTC) - timedelta(hours=1),
        )
        assert payload.severity == IncidentSeverity.CRITICAL

    def test_incident_create_invalid_severity_raises(self) -> None:
        with pytest.raises(ValidationError):
            IncidentCreate(
                title="Suspicious activity reported",
                description="Detailed narrative of observed unauthorized access.",
                category=IncidentCategory.OTHER,
                severity="ultra-critical",  # type: ignore[arg-type]
                location="Library 3rd floor",
                occurred_at=datetime.now(UTC) - timedelta(hours=1),
            )

    def test_incident_route_override_request_validation(self) -> None:
        target_id = uuid4()
        req = IncidentRouteOverrideRequest(
            target_department_id=target_id,
            reason="Case involves cross-department academic fraud.",
        )
        assert req.target_department_id == target_id
        assert req.reason == "Case involves cross-department academic fraud."

        with pytest.raises(ValidationError):
            IncidentRouteOverrideRequest(
                target_department_id=target_id,
                reason="abc",  # min_length 5
            )


class TestIncidentRoutingService:
    """Phase 55: Incident service routing logic, deterministic evaluation, and overrides."""

    @pytest.fixture
    def mock_incident_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_dept_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def service(
        self,
        mock_incident_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        test_settings: Settings,
    ) -> IncidentService:
        return IncidentService(mock_incident_repo, mock_dept_repo, test_settings)

    @pytest.fixture
    def dept_id(self) -> UUID:
        return uuid4()

    @pytest.fixture
    def student_principal(self, dept_id: UUID) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            user_id=uuid4(),
            email="student@university.edu",
            full_name="Student Reporter",
            account_status="active",
            is_active=True,
            role_code=RoleCode.STUDENT.value,
            department_id=dept_id,
            session_id=uuid4(),
        )

    @pytest.fixture
    def dept_admin_principal(self, dept_id: UUID) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            user_id=uuid4(),
            email="admin@university.edu",
            full_name="Department Admin",
            account_status="active",
            is_active=True,
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=dept_id,
            session_id=uuid4(),
        )

    @pytest.fixture
    def super_admin_principal(self) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            user_id=uuid4(),
            email="superadmin@university.edu",
            full_name="Super Admin",
            account_status="active",
            is_active=True,
            role_code=RoleCode.SUPER_ADMIN.value,
            department_id=None,
            session_id=uuid4(),
        )

    @pytest.mark.asyncio
    async def test_create_incident_deterministic_routing_emits_decision(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        student_principal: AuthenticatedPrincipal,
        dept_id: UUID,
    ) -> None:
        safety_dept_id = uuid4()
        active_depts = [
            Department(id=dept_id, code="BIOLOGY", name="Biology Dept", is_active=True),
            Department(id=safety_dept_id, code="SAFETY", name="Campus Safety", is_active=True),
        ]
        mock_dept_repo.list_active.return_value = active_depts
        mock_incident_repo.get_by_reference_number.return_value = None

        created_incident = Incident(
            id=uuid4(),
            reference_number="INC-2026-TEST1234",
            title="Lab hazard detected",
            description="Hazardous chemical container leaking in Lab 202.",
            category=IncidentCategory.SAFETY_HAZARD.value,
            severity=IncidentSeverity.HIGH.value,
            status=IncidentStatus.SUBMITTED.value,
            location="Science Hall Lab 202",
            occurred_at=datetime.now(UTC) - timedelta(hours=2),
            reporter_id=student_principal.user_id,
            department_id=safety_dept_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.create.return_value = created_incident
        mock_incident_repo.create_routing_decision.return_value = None

        payload = IncidentCreate(
            title="Lab hazard detected",
            description="Hazardous chemical container leaking in Lab 202.",
            category=IncidentCategory.SAFETY_HAZARD,
            severity=IncidentSeverity.HIGH,
            location="Science Hall Lab 202",
            occurred_at=datetime.now(UTC) - timedelta(hours=2),
            department_id=None,  # triggers deterministic routing
        )

        result = await service.create_incident(payload, student_principal)

        assert result.category == IncidentCategory.SAFETY_HAZARD.value
        assert result.severity == IncidentSeverity.HIGH.value
        assert result.department_id == safety_dept_id

        # Verify routing decision was persisted
        mock_incident_repo.create_routing_decision.assert_called_once()
        decision_arg = mock_incident_repo.create_routing_decision.call_args[0][0]
        assert decision_arg.routing_type == IncidentRoutingType.SYSTEM_RULE.value
        assert decision_arg.target_department_id == safety_dept_id
        assert "CRITICAL_SAFETY_ROUTING:SAFETY" in decision_arg.rule_applied

    @pytest.mark.asyncio
    async def test_override_incident_routing_dept_admin_success(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        dept_admin_principal: AuthenticatedPrincipal,
        dept_id: UUID,
    ) -> None:
        incident_id = uuid4()
        target_dept_id = uuid4()

        incident = Incident(
            id=incident_id,
            reference_number="INC-2026-REF1234",
            title="Student cheating complaint",
            description="Observed sharing test answers during final exam.",
            category=IncidentCategory.ACADEMIC_MISCONDUCT.value,
            severity=IncidentSeverity.MEDIUM.value,
            status=IncidentStatus.SUBMITTED.value,
            location="Lecture Hall 1",
            occurred_at=datetime.now(UTC) - timedelta(days=1),
            reporter_id=uuid4(),
            department_id=dept_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = incident
        mock_dept_repo.get_by_id.return_value = Department(
            id=target_dept_id, code="ACADEMIC", name="Academic Affairs", is_active=True
        )
        mock_incident_repo.update.return_value = incident
        mock_incident_repo.create_routing_decision.return_value = None

        result = await service.override_incident_routing(
            incident_id=incident_id,
            target_department_id=target_dept_id,
            reason="Re-routing to Academic Affairs for student honor code inquiry.",
            principal=dept_admin_principal,
        )

        assert result.department_id == target_dept_id
        mock_incident_repo.create_routing_decision.assert_called_once()
        decision = mock_incident_repo.create_routing_decision.call_args[0][0]
        assert decision.routing_type == IncidentRoutingType.AUTHORIZED_OVERRIDE.value
        assert decision.source_department_id == dept_id
        assert decision.target_department_id == target_dept_id
        assert decision.assigned_by_id == dept_admin_principal.user_id

    @pytest.mark.asyncio
    async def test_override_incident_routing_forbidden_roles(
        self,
        service: IncidentService,
        student_principal: AuthenticatedPrincipal,
    ) -> None:
        with pytest.raises(PermissionDeniedError) as exc_info:
            await service.override_incident_routing(
                incident_id=uuid4(),
                target_department_id=uuid4(),
                reason="Student trying to reroute",
                principal=student_principal,
            )
        assert exc_info.value.code == "PERMISSION_DENIED"

    @pytest.mark.asyncio
    async def test_override_incident_routing_dept_mismatch(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        dept_admin_principal: AuthenticatedPrincipal,
    ) -> None:
        other_dept_id = uuid4()
        incident = Incident(
            id=uuid4(),
            reference_number="INC-2026-REF1234",
            title="Complaint",
            description="Detail",
            category=IncidentCategory.OTHER.value,
            severity=IncidentSeverity.LOW.value,
            status=IncidentStatus.SUBMITTED.value,
            location="Room 1",
            occurred_at=datetime.now(UTC),
            reporter_id=uuid4(),
            department_id=other_dept_id,  # not admin's dept
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = incident

        with pytest.raises(PermissionDeniedError) as exc_info:
            await service.override_incident_routing(
                incident_id=incident.id,
                target_department_id=uuid4(),
                reason="Trying to reroute another department's incident",
                principal=dept_admin_principal,
            )
        assert exc_info.value.code == "DEPARTMENT_MISMATCH"

    @pytest.mark.asyncio
    async def test_override_incident_routing_locked_status(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        dept_admin_principal: AuthenticatedPrincipal,
        dept_id: UUID,
    ) -> None:
        incident = Incident(
            id=uuid4(),
            reference_number="INC-2026-REF1234",
            title="Closed Complaint",
            description="Detail",
            category=IncidentCategory.OTHER.value,
            severity=IncidentSeverity.LOW.value,
            status=IncidentStatus.CLOSED.value,
            location="Room 1",
            occurred_at=datetime.now(UTC),
            reporter_id=uuid4(),
            department_id=dept_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = incident

        with pytest.raises(BusinessRuleError) as exc_info:
            await service.override_incident_routing(
                incident_id=incident.id,
                target_department_id=uuid4(),
                reason="Trying to reroute closed incident",
                principal=dept_admin_principal,
            )
        assert exc_info.value.code == "INCIDENT_ROUTING_LOCKED"

    @pytest.mark.asyncio
    async def test_override_incident_routing_same_department(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        dept_admin_principal: AuthenticatedPrincipal,
        dept_id: UUID,
    ) -> None:
        incident = Incident(
            id=uuid4(),
            reference_number="INC-2026-REF1234",
            title="Complaint",
            description="Detail",
            category=IncidentCategory.OTHER.value,
            severity=IncidentSeverity.LOW.value,
            status=IncidentStatus.SUBMITTED.value,
            location="Room 1",
            occurred_at=datetime.now(UTC),
            reporter_id=uuid4(),
            department_id=dept_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = incident

        with pytest.raises(BusinessRuleError) as exc_info:
            await service.override_incident_routing(
                incident_id=incident.id,
                target_department_id=dept_id,
                reason="Reroute to same department",
                principal=dept_admin_principal,
            )
        assert exc_info.value.code == "SAME_DEPARTMENT_ROUTING"

    @pytest.mark.asyncio
    async def test_override_incident_routing_inactive_department(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        dept_admin_principal: AuthenticatedPrincipal,
        dept_id: UUID,
    ) -> None:
        target_dept_id = uuid4()
        incident = Incident(
            id=uuid4(),
            reference_number="INC-2026-REF1234",
            title="Complaint",
            description="Detail",
            category=IncidentCategory.OTHER.value,
            severity=IncidentSeverity.LOW.value,
            status=IncidentStatus.SUBMITTED.value,
            location="Room 1",
            occurred_at=datetime.now(UTC),
            reporter_id=uuid4(),
            department_id=dept_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = incident
        mock_dept_repo.get_by_id.return_value = Department(
            id=target_dept_id, code="INACTIVE", name="Old Dept", is_active=False
        )

        with pytest.raises(BusinessRuleError) as exc_info:
            await service.override_incident_routing(
                incident_id=incident.id,
                target_department_id=target_dept_id,
                reason="Reroute to inactive",
                principal=dept_admin_principal,
            )
        assert exc_info.value.code == "INACTIVE_DEPARTMENT_TARGET"

    @pytest.mark.asyncio
    async def test_get_incident_routing_history_visibility(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        student_principal: AuthenticatedPrincipal,
        dept_admin_principal: AuthenticatedPrincipal,
        dept_id: UUID,
    ) -> None:
        incident_id = uuid4()
        other_user_id = uuid4()
        incident = Incident(
            id=incident_id,
            reference_number="INC-2026-REF1234",
            title="Complaint",
            description="Detail",
            category=IncidentCategory.OTHER.value,
            severity=IncidentSeverity.LOW.value,
            status=IncidentStatus.SUBMITTED.value,
            location="Room 1",
            occurred_at=datetime.now(UTC),
            reporter_id=other_user_id,
            department_id=dept_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = incident
        decision = IncidentRoutingDecision(
            id=uuid4(),
            incident_id=incident_id,
            source_department_id=None,
            target_department_id=dept_id,
            assigned_by_id=None,
            routing_type=IncidentRoutingType.SYSTEM_RULE.value,
            rule_applied="DEFAULT_REPORTER_HOME_DEPARTMENT",
            reason="Initial intake",
            created_at=datetime.now(UTC),
        )
        mock_incident_repo.get_routing_history.return_value = [decision]

        # Student cannot see other user's incident routing history (404)
        with pytest.raises(ResourceNotFoundError):
            await service.get_incident_routing_history(incident_id, student_principal)

        # Department admin for this department can view history
        history = await service.get_incident_routing_history(incident_id, dept_admin_principal)
        assert len(history) == 1
        assert history[0].routing_type == IncidentRoutingType.SYSTEM_RULE.value
        assert history[0].rule_applied == "DEFAULT_REPORTER_HOME_DEPARTMENT"

    @pytest.mark.asyncio
    async def test_list_incidents_with_severity_filter(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        dept_admin_principal: AuthenticatedPrincipal,
    ) -> None:
        mock_incident_repo.list_paginated.return_value = ([], 0)
        pagination = PaginationParams(page=1, page_size=10)

        await service.list_incidents(
            dept_admin_principal,
            pagination,
            severity="critical",
        )

        mock_incident_repo.list_paginated.assert_called_once()
        kwargs = mock_incident_repo.list_paginated.call_args[1]
        assert kwargs["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_update_incident_severity(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        student_principal: AuthenticatedPrincipal,
        dept_id: UUID,
    ) -> None:
        incident = Incident(
            id=uuid4(),
            reference_number="INC-2026-REF1234",
            title="Original title",
            description="Original description",
            category=IncidentCategory.OTHER.value,
            severity=IncidentSeverity.LOW.value,
            status=IncidentStatus.SUBMITTED.value,
            location="Room 1",
            occurred_at=datetime.now(UTC) - timedelta(hours=1),
            reporter_id=student_principal.user_id,
            department_id=dept_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = incident
        mock_incident_repo.update.return_value = incident

        update_payload = IncidentUpdate(severity=IncidentSeverity.HIGH)
        res = await service.update_incident(incident.id, update_payload, student_principal)

        assert incident.severity == IncidentSeverity.HIGH.value
        assert res.severity == IncidentSeverity.HIGH.value
