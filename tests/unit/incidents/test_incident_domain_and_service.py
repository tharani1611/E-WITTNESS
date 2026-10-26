"""Unit tests for incident domain models, schemas, and service layer (Phases 41-42)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

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
    IncidentStatus,
    generate_incident_reference_number,
    parse_incident_category,
    parse_incident_status,
    validate_incident_status_transition,
)
from backend.app.models.department import Department
from backend.app.models.incident import Incident
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.incident import (
    IncidentCreate,
    IncidentStatusTransitionRequest,
    IncidentUpdate,
)
from backend.app.schemas.pagination import PaginationParams
from backend.app.services.incident import IncidentService


class TestIncidentDomainPrimitives:
    """Phase 41: Unit tests for core incident enums, parsers, and transition validators."""

    def test_incident_category_enum_and_parser(self) -> None:
        assert (
            parse_incident_category("academic_misconduct") == IncidentCategory.ACADEMIC_MISCONDUCT
        )
        assert (
            parse_incident_category("  HARASSMENT_DISCRIMINATION  ")
            == IncidentCategory.HARASSMENT_DISCRIMINATION
        )
        assert (
            parse_incident_category("Property_Damage_Theft")
            == IncidentCategory.PROPERTY_DAMAGE_THEFT
        )
        assert parse_incident_category("SAFETY_HAZARD") == IncidentCategory.SAFETY_HAZARD
        assert parse_incident_category("physical_assault") == IncidentCategory.PHYSICAL_ASSAULT
        assert parse_incident_category("other") == IncidentCategory.OTHER

        with pytest.raises(BusinessRuleError) as exc_info:
            parse_incident_category("invalid_category")
        assert exc_info.value.code == "INVALID_INCIDENT_CATEGORY"
        assert exc_info.value.status_code == 422

    def test_incident_status_enum_and_parser(self) -> None:
        assert parse_incident_status("submitted") == IncidentStatus.SUBMITTED
        assert parse_incident_status("  TRIAGED  ") == IncidentStatus.TRIAGED
        assert parse_incident_status("under_investigation") == IncidentStatus.UNDER_INVESTIGATION
        assert parse_incident_status("closed") == IncidentStatus.CLOSED
        assert parse_incident_status("dismissed") == IncidentStatus.DISMISSED

        with pytest.raises(BusinessRuleError) as exc_info:
            parse_incident_status("unknown_status")
        assert exc_info.value.code == "INVALID_INCIDENT_STATUS"
        assert exc_info.value.status_code == 422

    def test_validate_incident_status_transition_rules(self) -> None:
        # Same status is permitted (idempotent, returns None without raising)
        validate_incident_status_transition(IncidentStatus.SUBMITTED, IncidentStatus.SUBMITTED)
        validate_incident_status_transition(IncidentStatus.TRIAGED, IncidentStatus.TRIAGED)

        # Valid forward transitions
        validate_incident_status_transition(IncidentStatus.SUBMITTED, IncidentStatus.TRIAGED)
        validate_incident_status_transition(IncidentStatus.SUBMITTED, IncidentStatus.DISMISSED)
        validate_incident_status_transition(
            IncidentStatus.TRIAGED, IncidentStatus.UNDER_INVESTIGATION
        )
        validate_incident_status_transition(IncidentStatus.TRIAGED, IncidentStatus.DISMISSED)
        validate_incident_status_transition(
            IncidentStatus.UNDER_INVESTIGATION, IncidentStatus.CLOSED
        )
        validate_incident_status_transition(
            IncidentStatus.UNDER_INVESTIGATION, IncidentStatus.DISMISSED
        )

        # Closed incidents cannot be transitioned anywhere
        with pytest.raises(BusinessRuleError) as exc_closed:
            validate_incident_status_transition(IncidentStatus.CLOSED, IncidentStatus.SUBMITTED)
        assert exc_closed.value.code == "INVALID_STATUS_TRANSITION"
        assert exc_closed.value.status_code == 422

        # Dismissed incidents cannot be transitioned anywhere
        with pytest.raises(BusinessRuleError) as exc_dismissed:
            validate_incident_status_transition(IncidentStatus.DISMISSED, IncidentStatus.TRIAGED)
        assert exc_dismissed.value.code == "INVALID_STATUS_TRANSITION"

        # Disallowed jumps (e.g., submitted directly to closed without investigation or triage)
        with pytest.raises(BusinessRuleError) as exc_jump:
            validate_incident_status_transition(IncidentStatus.SUBMITTED, IncidentStatus.CLOSED)
        assert exc_jump.value.code == "INVALID_STATUS_TRANSITION"

    def test_generate_incident_reference_number_format(self) -> None:
        year = datetime.now(UTC).year
        ref1 = generate_incident_reference_number()
        ref2 = generate_incident_reference_number()

        assert ref1.startswith(f"INC-{year}-")
        assert ref2.startswith(f"INC-{year}-")
        assert len(ref1) == 17  # INC-YYYY-XXXXXXXX
        assert ref1 != ref2
        suffix = ref1.split("-")[2]
        assert len(suffix) == 8
        int(suffix, 16)  # Must parse as valid hex


class TestIncidentSchemasValidation:
    """Phase 41 & 42: Pydantic schema validation unit tests."""

    def test_valid_incident_create(self) -> None:
        now = datetime.now(UTC) - timedelta(minutes=10)
        payload = IncidentCreate(
            title="Lab equipment vandalism",
            description="Found broken microscope in science lab room 204.",
            category=IncidentCategory.PROPERTY_DAMAGE_THEFT,
            location="Science Hall, Room 204",
            occurred_at=now,
        )
        assert payload.title == "Lab equipment vandalism"
        assert payload.category == IncidentCategory.PROPERTY_DAMAGE_THEFT
        assert payload.location == "Science Hall, Room 204"

    def test_incident_create_rejects_future_occurred_at(self) -> None:
        future_time = datetime.now(UTC) + timedelta(days=2)
        with pytest.raises(ValidationError) as exc_info:
            IncidentCreate(
                title="Future misconduct",
                description="This hasn't happened yet.",
                category=IncidentCategory.OTHER,
                location="Main Quad",
                occurred_at=future_time,
            )
        assert "cannot be in the future" in str(exc_info.value)

    def test_incident_create_rejects_short_title(self) -> None:
        now = datetime.now(UTC)
        with pytest.raises(ValidationError) as exc_info:
            IncidentCreate(
                title="Abc",
                description="Long enough description for the report.",
                category=IncidentCategory.OTHER,
                location="Main Quad",
                occurred_at=now,
            )
        assert "at least 5 characters" in str(exc_info.value)

    def test_incident_create_rejects_empty_whitespace_title(self) -> None:
        now = datetime.now(UTC)
        with pytest.raises(ValidationError) as exc_info:
            IncidentCreate(
                title="     ",
                description="Valid description for the report.",
                category=IncidentCategory.OTHER,
                location="Main Quad",
                occurred_at=now,
            )
        assert "at least 5 characters" in str(exc_info.value)

    def test_incident_create_rejects_invalid_category(self) -> None:
        now = datetime.now(UTC)
        with pytest.raises(ValidationError) as exc_info:
            IncidentCreate(
                title="Valid Incident Title",
                description="Valid description for the report.",
                category="not_a_category",  # type: ignore[arg-type]
                location="Main Quad",
                occurred_at=now,
            )
        assert "Invalid incident category" in str(exc_info.value)

    def test_incident_update_validation(self) -> None:
        update = IncidentUpdate(
            title="Updated title text",
            description="Updated description with more details.",
            location="Building B, Room 101",
        )
        assert update.title == "Updated title text"
        assert update.location == "Building B, Room 101"

    def test_incident_status_transition_request(self) -> None:
        req = IncidentStatusTransitionRequest(
            status=IncidentStatus.UNDER_INVESTIGATION,
            reason="Investigation assigned to detective.",
        )
        assert req.status == IncidentStatus.UNDER_INVESTIGATION
        assert req.reason == "Investigation assigned to detective."

        with pytest.raises(ValidationError):
            IncidentStatusTransitionRequest(status="invalid_status")  # type: ignore[arg-type]


class TestIncidentServiceUnit:
    """Phase 42: Service layer business logic unit tests with mocked repositories."""

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
    def student_principal(self) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            user_id=uuid4(),
            email="student@university.edu",
            full_name="Student User",
            account_status="active",
            is_active=True,
            role_code=RoleCode.STUDENT.value,
            department_id=uuid4(),
            session_id=uuid4(),
        )

    @pytest.fixture
    def dept_admin_principal(self) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            user_id=uuid4(),
            email="deptadmin@university.edu",
            full_name="Dept Admin User",
            account_status="active",
            is_active=True,
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=uuid4(),
            session_id=uuid4(),
        )

    @pytest.fixture
    def super_admin_principal(self) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            user_id=uuid4(),
            email="superadmin@university.edu",
            full_name="Super Admin User",
            account_status="active",
            is_active=True,
            role_code=RoleCode.SUPER_ADMIN.value,
            department_id=uuid4(),
            session_id=uuid4(),
        )

    async def test_create_incident_success(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        student_principal: AuthenticatedPrincipal,
    ) -> None:
        dept = Department(
            id=student_principal.department_id, code="CS", name="Computer Science", is_active=True
        )
        mock_dept_repo.get_by_id.return_value = dept

        def _mock_create(inc: Incident) -> Incident:
            inc.id = uuid4()
            inc.created_at = datetime.now(UTC)
            inc.updated_at = datetime.now(UTC)
            return inc

        mock_incident_repo.create.side_effect = _mock_create

        payload = IncidentCreate(
            title="Cheating during exam",
            description="Student was seen using notes during finals exam.",
            category=IncidentCategory.ACADEMIC_MISCONDUCT,
            location="Hall 101",
            occurred_at=datetime.now(UTC) - timedelta(hours=1),
        )

        result = await service.create_incident(payload, student_principal)
        assert result.title == payload.title
        assert result.status == IncidentStatus.SUBMITTED.value
        assert result.reporter_id == student_principal.user_id
        assert result.department_id == student_principal.department_id
        assert result.reference_number.startswith("INC-")

    async def test_create_incident_rejects_inactive_department(
        self,
        service: IncidentService,
        mock_dept_repo: AsyncMock,
        student_principal: AuthenticatedPrincipal,
    ) -> None:
        dept = Department(
            id=student_principal.department_id, code="CS", name="Computer Science", is_active=False
        )
        mock_dept_repo.get_by_id.return_value = dept

        payload = IncidentCreate(
            title="Cheating during exam",
            description="Student was seen using notes during finals exam.",
            category=IncidentCategory.ACADEMIC_MISCONDUCT,
            location="Hall 101",
            occurred_at=datetime.now(UTC) - timedelta(hours=1),
        )

        with pytest.raises(BusinessRuleError) as exc_info:
            await service.create_incident(payload, student_principal)
        assert exc_info.value.code == "INACTIVE_DEPARTMENT_TARGET"

    async def test_create_incident_rejects_cross_department_for_student(
        self,
        service: IncidentService,
        mock_dept_repo: AsyncMock,
        student_principal: AuthenticatedPrincipal,
    ) -> None:
        other_dept_id = uuid4()
        other_dept = Department(
            id=other_dept_id, code="OTHER", name="Other Department", is_active=True
        )
        mock_dept_repo.get_by_id.return_value = other_dept

        payload = IncidentCreate(
            title="Cheating during exam",
            description="Student was seen using notes during finals exam.",
            category=IncidentCategory.ACADEMIC_MISCONDUCT,
            location="Hall 101",
            occurred_at=datetime.now(UTC) - timedelta(hours=1),
            department_id=other_dept_id,
        )

        with pytest.raises(BusinessRuleError) as exc_info:
            await service.create_incident(payload, student_principal)
        assert exc_info.value.code == "CROSS_DEPARTMENT_REPORT_FORBIDDEN"

    async def test_get_incident_scoping_and_enumeration_resistance(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        student_principal: AuthenticatedPrincipal,
    ) -> None:
        other_user_id = uuid4()
        other_dept_id = uuid4()
        incident = Incident(
            id=uuid4(),
            reference_number="INC-2026-ABCDEF12",
            title="Another student's report",
            description="Details about another report.",
            category="other",
            location="Gym",
            occurred_at=datetime.now(UTC),
            status=IncidentStatus.SUBMITTED.value,
            reporter_id=other_user_id,
            department_id=other_dept_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = incident

        with pytest.raises(ResourceNotFoundError) as exc_info:
            await service.get_incident(incident.id, student_principal)
        assert exc_info.value.code == "INCIDENT_NOT_FOUND"

    async def test_submitter_can_update_incident_while_submitted(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        student_principal: AuthenticatedPrincipal,
    ) -> None:
        incident = Incident(
            id=uuid4(),
            reference_number="INC-2026-ABCDEF12",
            title="Original title",
            description="Original description.",
            category="other",
            location="Gym",
            occurred_at=datetime.now(UTC),
            status=IncidentStatus.SUBMITTED.value,
            reporter_id=student_principal.user_id,
            department_id=student_principal.department_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = incident
        mock_incident_repo.update.side_effect = lambda inc: inc

        update_payload = IncidentUpdate(
            title="Updated title by reporter",
            location="Basketball Court",
        )
        updated = await service.update_incident(incident.id, update_payload, student_principal)
        assert updated.title == "Updated title by reporter"
        assert updated.location == "Basketball Court"

    async def test_submitter_cannot_update_incident_after_triage(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        student_principal: AuthenticatedPrincipal,
    ) -> None:
        incident = Incident(
            id=uuid4(),
            reference_number="INC-2026-ABCDEF12",
            title="Original title",
            description="Original description.",
            category="other",
            location="Gym",
            occurred_at=datetime.now(UTC),
            status=IncidentStatus.TRIAGED.value,
            reporter_id=student_principal.user_id,
            department_id=student_principal.department_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = incident

        update_payload = IncidentUpdate(title="Should fail update")
        with pytest.raises(BusinessRuleError) as exc_info:
            await service.update_incident(incident.id, update_payload, student_principal)
        assert exc_info.value.code == "INCIDENT_UPDATE_LOCKED"

    async def test_dept_admin_can_transition_incident_status(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        dept_admin_principal: AuthenticatedPrincipal,
    ) -> None:
        incident = Incident(
            id=uuid4(),
            reference_number="INC-2026-ABCDEF12",
            title="Report to triage",
            description="Report description.",
            category="other",
            location="Library",
            occurred_at=datetime.now(UTC),
            status=IncidentStatus.SUBMITTED.value,
            reporter_id=uuid4(),
            department_id=dept_admin_principal.department_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = incident
        mock_incident_repo.update.side_effect = lambda inc: inc

        req = IncidentStatusTransitionRequest(
            status=IncidentStatus.TRIAGED,
            reason="Reviewed and triaged by department admin.",
        )
        transitioned = await service.transition_status(
            incident.id,
            req.status,
            dept_admin_principal,
            reason=req.reason,
        )
        assert transitioned.status == IncidentStatus.TRIAGED.value

    async def test_student_cannot_transition_incident_status(
        self,
        service: IncidentService,
        student_principal: AuthenticatedPrincipal,
    ) -> None:
        req = IncidentStatusTransitionRequest(status=IncidentStatus.CLOSED)
        with pytest.raises(PermissionDeniedError):
            await service.transition_status(uuid4(), req.status, student_principal)

    async def test_service_from_session(self, test_settings: Settings) -> None:
        mock_session = AsyncMock()
        srv = IncidentService.from_session(mock_session, test_settings)
        assert isinstance(srv, IncidentService)
        assert srv.settings == test_settings

    async def test_get_incident_not_found(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        student_principal: AuthenticatedPrincipal,
    ) -> None:
        mock_incident_repo.get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError) as exc:
            await service.get_incident(uuid4(), student_principal)
        assert exc.value.code == "INCIDENT_NOT_FOUND"

    async def test_get_incident_by_reference_success(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        student_principal: AuthenticatedPrincipal,
    ) -> None:
        incident = Incident(
            id=uuid4(),
            reference_number="INC-2026-REF12345",
            title="Referenced report",
            description="Found by reference number.",
            category="other",
            location="Library",
            occurred_at=datetime.now(UTC),
            status=IncidentStatus.SUBMITTED.value,
            reporter_id=student_principal.user_id,
            department_id=student_principal.department_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_reference_number.return_value = incident
        read = await service.get_incident_by_reference("INC-2026-REF12345", student_principal)
        assert read.reference_number == "INC-2026-REF12345"

    async def test_get_incident_by_reference_not_found(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        student_principal: AuthenticatedPrincipal,
    ) -> None:
        mock_incident_repo.get_by_reference_number.return_value = None
        with pytest.raises(ResourceNotFoundError) as exc:
            await service.get_incident_by_reference("INC-2026-NONEXIST", student_principal)
        assert exc.value.code == "INCIDENT_NOT_FOUND"

    async def test_create_incident_permission_denied(
        self,
        service: IncidentService,
    ) -> None:
        no_perm_principal = AuthenticatedPrincipal(
            user_id=uuid4(),
            email="noperm@univ.edu",
            full_name="No Perm",
            account_status="active",
            is_active=True,
            role_code="ROLE_UNKNOWN",
            department_id=uuid4(),
            session_id=uuid4(),
        )
        payload = IncidentCreate(
            title="Test report",
            description="Description for report.",
            category=IncidentCategory.OTHER,
            location="Lab 1",
            occurred_at=datetime.now(UTC),
        )
        with pytest.raises(PermissionDeniedError) as exc:
            await service.create_incident(payload, no_perm_principal)
        assert exc.value.code == "PERMISSION_DENIED"

    async def test_create_incident_no_department(
        self,
        service: IncidentService,
    ) -> None:
        super_admin_no_dept = AuthenticatedPrincipal(
            user_id=uuid4(),
            email="super@univ.edu",
            full_name="Super Admin",
            account_status="active",
            is_active=True,
            role_code=RoleCode.SUPER_ADMIN.value,
            department_id=None,
            session_id=uuid4(),
        )
        payload = IncidentCreate(
            title="Test report",
            description="Description for report.",
            category=IncidentCategory.OTHER,
            location="Lab 1",
            occurred_at=datetime.now(UTC),
            department_id=None,
        )
        with pytest.raises(BusinessRuleError) as exc:
            await service.create_incident(payload, super_admin_no_dept)
        assert exc.value.code == "DEPARTMENT_REQUIRED"

    async def test_create_incident_target_dept_inactive(
        self,
        service: IncidentService,
        mock_dept_repo: AsyncMock,
        dept_admin_principal: AuthenticatedPrincipal,
    ) -> None:
        dept = Department(
            id=dept_admin_principal.department_id, code="INACT", name="Inactive", is_active=False
        )
        mock_dept_repo.get_by_id.return_value = dept
        payload = IncidentCreate(
            title="Test report",
            description="Description for report.",
            category=IncidentCategory.OTHER,
            location="Lab 1",
            occurred_at=datetime.now(UTC),
            department_id=dept_admin_principal.department_id,
        )
        with pytest.raises(BusinessRuleError) as exc:
            await service.create_incident(payload, dept_admin_principal)
        assert exc.value.code == "INACTIVE_DEPARTMENT_TARGET"

    async def test_create_incident_ref_collision_handled(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        mock_dept_repo: AsyncMock,
        dept_admin_principal: AuthenticatedPrincipal,
    ) -> None:
        dept = Department(
            id=dept_admin_principal.department_id, code="ENG", name="Engineering", is_active=True
        )
        mock_dept_repo.get_by_id.return_value = dept

        existing_incident = Incident(id=uuid4(), reference_number="INC-2026-COLLIDE")
        # First check finds collision, second check returns None
        mock_incident_repo.get_by_reference_number.side_effect = [existing_incident, None]

        created_incident = Incident(
            id=uuid4(),
            reference_number="INC-2026-FRESH123",
            title="Valid title for report",
            description="Detailed report description here.",
            category="academic_misconduct",
            location="Room 101",
            occurred_at=datetime.now(UTC),
            status=IncidentStatus.SUBMITTED.value,
            reporter_id=dept_admin_principal.user_id,
            department_id=dept_admin_principal.department_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.create.return_value = created_incident

        payload = IncidentCreate(
            title="Valid title for report",
            description="Detailed report description here.",
            category=IncidentCategory.ACADEMIC_MISCONDUCT,
            location="Room 101",
            occurred_at=datetime.now(UTC),
            department_id=dept_admin_principal.department_id,
        )
        result = await service.create_incident(payload, dept_admin_principal)
        assert result.id == created_incident.id
        assert mock_incident_repo.get_by_reference_number.call_count >= 1

    async def test_list_incidents_by_roles(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        dept_admin_principal: AuthenticatedPrincipal,
        super_admin_principal: AuthenticatedPrincipal,
    ) -> None:
        mock_incident_repo.list_paginated.return_value = ([], 0)
        params = PaginationParams(page=1, page_size=20)

        # Super admin
        resp_super = await service.list_incidents(super_admin_principal, params)
        assert resp_super.pagination.total_items == 0

        # Dept admin
        resp_dept = await service.list_incidents(dept_admin_principal, params)
        assert resp_dept.pagination.total_items == 0

        # Unknown role denied
        unknown_principal = AuthenticatedPrincipal(
            user_id=uuid4(),
            email="unk@univ.edu",
            full_name="Unknown",
            account_status="active",
            is_active=True,
            role_code="ROLE_UNKNOWN",
            department_id=uuid4(),
            session_id=uuid4(),
        )
        with pytest.raises(PermissionDeniedError):
            await service.list_incidents(unknown_principal, params)

    async def test_update_incident_dept_admin_and_super_admin(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        dept_admin_principal: AuthenticatedPrincipal,
        super_admin_principal: AuthenticatedPrincipal,
    ) -> None:
        incident = Incident(
            id=uuid4(),
            reference_number="INC-2026-UPDATE01",
            title="Original title",
            description="Original description text.",
            category="other",
            location="Main Hall",
            occurred_at=datetime.now(UTC),
            status=IncidentStatus.SUBMITTED.value,
            reporter_id=uuid4(),
            department_id=dept_admin_principal.department_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = incident
        mock_incident_repo.update.side_effect = lambda inc: inc

        # Dept Admin can update incident in their department
        update_data = IncidentUpdate(
            title="Updated by dept admin",
            description="New details added.",
            category=IncidentCategory.SAFETY_HAZARD,
            location="Room 200",
            occurred_at=datetime.now(UTC) - timedelta(hours=2),
        )
        res = await service.update_incident(incident.id, update_data, dept_admin_principal)
        assert res.title == "Updated by dept admin"
        assert res.category == "safety_hazard"

        # Dept Admin receives 404 for incident in another department
        other_dept_principal = AuthenticatedPrincipal(
            user_id=uuid4(),
            email="otheradmin@univ.edu",
            full_name="Other Dept Admin",
            account_status="active",
            is_active=True,
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=uuid4(),
            session_id=uuid4(),
        )
        with pytest.raises(ResourceNotFoundError):
            await service.update_incident(incident.id, update_data, other_dept_principal)

        # Super Admin can update
        res_super = await service.update_incident(incident.id, update_data, super_admin_principal)
        assert res_super.title == "Updated by dept admin"

    async def test_transition_status_edge_cases(
        self,
        service: IncidentService,
        mock_incident_repo: AsyncMock,
        dept_admin_principal: AuthenticatedPrincipal,
        super_admin_principal: AuthenticatedPrincipal,
    ) -> None:
        # Not found
        mock_incident_repo.get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await service.transition_status(uuid4(), IncidentStatus.TRIAGED, dept_admin_principal)

        incident = Incident(
            id=uuid4(),
            reference_number="INC-2026-TRANS01",
            title="Incident to transition",
            description="Description for transition.",
            category="other",
            location="Lab",
            occurred_at=datetime.now(UTC),
            status=IncidentStatus.TRIAGED.value,
            reporter_id=uuid4(),
            department_id=dept_admin_principal.department_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = incident
        mock_incident_repo.update.side_effect = lambda inc: inc

        # Invalid transition: TRIAGED cannot go back to SUBMITTED
        with pytest.raises(BusinessRuleError):
            await service.transition_status(
                incident.id, IncidentStatus.SUBMITTED, dept_admin_principal
            )

        # Dept Admin from other dept gets DEPARTMENT_MISMATCH
        other_dept_principal = AuthenticatedPrincipal(
            user_id=uuid4(),
            email="otheradmin@univ.edu",
            full_name="Other Dept Admin",
            account_status="active",
            is_active=True,
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=uuid4(),
            session_id=uuid4(),
        )
        with pytest.raises(PermissionDeniedError) as exc:
            await service.transition_status(
                incident.id, IncidentStatus.UNDER_INVESTIGATION, other_dept_principal
            )
        assert exc.value.code == "DEPARTMENT_MISMATCH"

        # Super admin can transition
        res = await service.transition_status(
            incident.id, IncidentStatus.UNDER_INVESTIGATION, super_admin_principal
        )
        assert res.status == IncidentStatus.UNDER_INVESTIGATION.value


class TestIncidentSchemasValidationEdgeCases:
    """Tests for edge cases in incident schema validators."""

    def test_incident_create_category_variants(self) -> None:
        now = datetime.now(UTC) - timedelta(minutes=5)
        # Using IncidentCategory directly
        c1 = IncidentCreate(
            title="Valid title here",
            description="Long enough description.",
            category=IncidentCategory.PROPERTY_DAMAGE_THEFT,
            location="Gate 1",
            occurred_at=now,
        )
        assert c1.category == IncidentCategory.PROPERTY_DAMAGE_THEFT

        # Using invalid type
        with pytest.raises(ValidationError):
            IncidentCreate(
                title="Valid title here",
                description="Long enough description.",
                category=12345,  # type: ignore[arg-type]
                location="Gate 1",
                occurred_at=now,
            )

    def test_incident_update_category_and_datetime_variants(self) -> None:
        # Category None
        u1 = IncidentUpdate(category=None)
        assert u1.category is None

        # Category enum
        u2 = IncidentUpdate(category=IncidentCategory.SAFETY_HAZARD)
        assert u2.category == IncidentCategory.SAFETY_HAZARD

        # Category string
        u3 = IncidentUpdate(category="safety_hazard")  # type: ignore[arg-type]
        assert u3.category == IncidentCategory.SAFETY_HAZARD

        # Invalid category string
        with pytest.raises(ValidationError):
            IncidentUpdate(category="invalid_category_xyz")  # type: ignore[arg-type]

        # Invalid category non-str
        with pytest.raises(ValidationError):
            IncidentUpdate(category=999)  # type: ignore[arg-type]

        # Future occurred_at
        future = datetime.now(UTC) + timedelta(days=2)
        with pytest.raises(ValidationError):
            IncidentUpdate(occurred_at=future)

        # Valid past occurred_at without tzinfo
        naive_past = datetime(2026, 1, 1, 12, 0, 0)
        u4 = IncidentUpdate(occurred_at=naive_past)
        assert u4.occurred_at is not None
        assert u4.occurred_at.tzinfo == UTC
