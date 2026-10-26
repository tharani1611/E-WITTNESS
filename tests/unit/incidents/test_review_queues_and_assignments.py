"""Unit tests for Phase 56 & 57: Review queues, workload views, and reviewer assignment."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
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
    AssignmentStatus,
    IncidentCategory,
    IncidentSeverity,
    IncidentStatus,
    parse_assignment_status,
    validate_reviewer_assignment,
)
from backend.app.models.incident import Incident
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.incident import (
    IncidentRead,
    ReviewerAssignRequest,
    ReviewerReassignRequest,
    ReviewQueueWorkloadSummary,
)
from backend.app.schemas.pagination import PaginationParams
from backend.app.services.incident import IncidentService


class TestAssignmentPrimitivesAndValidation:
    """Phase 57: Unit tests for assignment status parser and reviewer eligibility validator."""

    def test_parse_assignment_status_valid(self) -> None:
        assert parse_assignment_status("unassigned") == AssignmentStatus.UNASSIGNED
        assert parse_assignment_status("assigned") == AssignmentStatus.ASSIGNED
        assert parse_assignment_status("acknowledged") == AssignmentStatus.ACKNOWLEDGED
        assert parse_assignment_status("under_review") == AssignmentStatus.UNDER_REVIEW
        assert parse_assignment_status("reassigned") == AssignmentStatus.REASSIGNED

    def test_parse_assignment_status_invalid(self) -> None:
        with pytest.raises(BusinessRuleError) as exc_info:
            parse_assignment_status("unknown_status")
        assert exc_info.value.code == "INVALID_ASSIGNMENT_STATUS"

    def test_validate_reviewer_assignment_success_investigator(self) -> None:
        reporter_id = uuid4()
        reviewer_id = uuid4()
        dept_id = uuid4()

        validate_reviewer_assignment(
            incident_reporter_id=reporter_id,
            reviewer_id=reviewer_id,
            reviewer_role=RoleCode.INVESTIGATOR.value,
            reviewer_dept_id=dept_id,
            incident_dept_id=dept_id,
            is_active=True,
            account_status="active",
        )

    def test_validate_reviewer_assignment_success_super_admin_cross_dept(self) -> None:
        reporter_id = uuid4()
        reviewer_id = uuid4()
        dept1 = uuid4()
        dept2 = uuid4()

        validate_reviewer_assignment(
            incident_reporter_id=reporter_id,
            reviewer_id=reviewer_id,
            reviewer_role=RoleCode.SUPER_ADMIN.value,
            reviewer_dept_id=dept1,
            incident_dept_id=dept2,
            is_active=True,
            account_status="active",
        )

    def test_validate_reviewer_assignment_inactive_account(self) -> None:
        reporter_id = uuid4()
        reviewer_id = uuid4()
        dept_id = uuid4()

        with pytest.raises(BusinessRuleError) as exc_info:
            validate_reviewer_assignment(
                incident_reporter_id=reporter_id,
                reviewer_id=reviewer_id,
                reviewer_role=RoleCode.INVESTIGATOR.value,
                reviewer_dept_id=dept_id,
                incident_dept_id=dept_id,
                is_active=False,
                account_status="active",
            )
        assert exc_info.value.code == "INACTIVE_REVIEWER"

    def test_validate_reviewer_assignment_conflict_of_interest(self) -> None:
        same_person_id = uuid4()
        dept_id = uuid4()

        with pytest.raises(BusinessRuleError) as exc_info:
            validate_reviewer_assignment(
                incident_reporter_id=same_person_id,
                reviewer_id=same_person_id,
                reviewer_role=RoleCode.INVESTIGATOR.value,
                reviewer_dept_id=dept_id,
                incident_dept_id=dept_id,
                is_active=True,
                account_status="active",
            )
        assert exc_info.value.code == "CONFLICT_OF_INTEREST"

    def test_validate_reviewer_assignment_ineligible_role(self) -> None:
        reporter_id = uuid4()
        reviewer_id = uuid4()
        dept_id = uuid4()

        with pytest.raises(BusinessRuleError) as exc_info:
            validate_reviewer_assignment(
                incident_reporter_id=reporter_id,
                reviewer_id=reviewer_id,
                reviewer_role=RoleCode.STUDENT.value,
                reviewer_dept_id=dept_id,
                incident_dept_id=dept_id,
                is_active=True,
                account_status="active",
            )
        assert exc_info.value.code == "INELIGIBLE_REVIEWER_ROLE"

    def test_validate_reviewer_assignment_cross_department_for_investigator(self) -> None:
        reporter_id = uuid4()
        reviewer_id = uuid4()
        dept1 = uuid4()
        dept2 = uuid4()

        with pytest.raises(BusinessRuleError) as exc_info:
            validate_reviewer_assignment(
                incident_reporter_id=reporter_id,
                reviewer_id=reviewer_id,
                reviewer_role=RoleCode.INVESTIGATOR.value,
                reviewer_dept_id=dept1,
                incident_dept_id=dept2,
                is_active=True,
                account_status="active",
            )
        assert exc_info.value.code == "DEPARTMENT_MISMATCH"


class TestReviewQueueSchemas:
    """Phase 56: Schema validation for queue requests and workload summaries."""

    def test_workload_summary_defaults(self) -> None:
        summary = ReviewQueueWorkloadSummary()
        assert summary.pending == 0
        assert summary.assigned == 0
        assert summary.unassigned == 0
        assert summary.overdue == 0
        assert summary.completed == 0
        assert summary.total == 0

    def test_workload_summary_populated(self) -> None:
        summary = ReviewQueueWorkloadSummary(
            pending=5, assigned=10, unassigned=3, overdue=2, completed=20, total=38
        )
        assert summary.pending == 5
        assert summary.total == 38

    def test_reviewer_reassign_request_validation(self) -> None:
        req = ReviewerReassignRequest(reviewer_id=uuid4(), reason="Case overload")
        assert req.reason == "Case overload"

        with pytest.raises(ValidationError):
            ReviewerReassignRequest(reviewer_id=uuid4(), reason="  ")

    def test_incident_read_with_assignment_fields(self) -> None:
        inc_id = uuid4()
        rep_id = uuid4()
        dept_id = uuid4()
        rev_id = uuid4()
        now = datetime.now(UTC)

        read = IncidentRead(
            id=inc_id,
            reference_number="INC-2026-TEST",
            title="Test Incident Title",
            description="Detailed test narrative of incident.",
            category="academic_misconduct",
            severity="high",
            status="submitted",
            location="Library Hall",
            occurred_at=now,
            reporter_id=rep_id,
            department_id=dept_id,
            assigned_reviewer_id=rev_id,
            assignment_status="assigned",
            assigned_at=now,
            acknowledged_at=None,
            created_at=now,
            updated_at=now,
        )
        assert read.assigned_reviewer_id == rev_id
        assert read.assignment_status == "assigned"
        assert read.assigned_at == now
        assert read.acknowledged_at is None


def _make_principal(
    *,
    user_id: UUID | None = None,
    role_code: str = RoleCode.INVESTIGATOR.value,
    department_id: UUID | None = None,
    email: str = "user@test.edu",
    full_name: str = "Test User",
) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        user_id=user_id or uuid4(),
        role_code=role_code,
        department_id=department_id,
        email=email,
        full_name=full_name,
        account_status="active",
        is_active=True,
        session_id=uuid4(),
    )


class TestReviewQueueAndAssignmentService:
    """Phase 56 & 57: Service orchestration tests for review queues and assignments."""

    @pytest.fixture
    def mock_incident_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_department_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_user_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_audit_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def incident_service(
        self,
        mock_incident_repo: AsyncMock,
        mock_department_repo: AsyncMock,
        mock_user_repo: AsyncMock,
        mock_audit_repo: AsyncMock,
        test_settings: Settings,
    ) -> IncidentService:
        return IncidentService(
            incident_repo=mock_incident_repo,
            department_repo=mock_department_repo,
            settings=test_settings,
            user_repo=mock_user_repo,
            audit_repo=mock_audit_repo,
        )

    @pytest.mark.asyncio
    async def test_get_review_queue_investigator_scoped(
        self,
        incident_service: IncidentService,
        mock_incident_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        principal = _make_principal(
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=dept_id,
            email="investigator@test.edu",
        )
        mock_incident_repo.list_review_queue_paginated.return_value = ([], 0)

        res = await incident_service.get_review_queue(
            principal=principal,
            pagination=PaginationParams(page=1, page_size=20),
        )

        assert res.items == []
        mock_incident_repo.list_review_queue_paginated.assert_awaited_once()
        _, kwargs = mock_incident_repo.list_review_queue_paginated.call_args
        assert kwargs["department_id"] == dept_id

    @pytest.mark.asyncio
    async def test_get_review_queue_student_forbidden(
        self,
        incident_service: IncidentService,
    ) -> None:
        principal = _make_principal(
            role_code=RoleCode.STUDENT.value,
            department_id=uuid4(),
            email="student@test.edu",
        )
        with pytest.raises(PermissionDeniedError):
            await incident_service.get_review_queue(
                principal=principal,
                pagination=PaginationParams(page=1, page_size=20),
            )

    @pytest.mark.asyncio
    async def test_get_workload_summary_dept_admin(
        self,
        incident_service: IncidentService,
        mock_incident_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        principal = _make_principal(
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=dept_id,
            email="admin@test.edu",
        )
        mock_incident_repo.get_workload_summary.return_value = {
            "total": 12,
            "pending": 4,
            "assigned": 5,
            "unassigned": 3,
            "overdue": 1,
            "completed": 2,
        }

        workload = await incident_service.get_workload_summary(principal)
        assert workload.total == 12
        assert workload.pending == 4
        assert workload.assigned == 5
        assert workload.unassigned == 3

    @pytest.mark.asyncio
    async def test_assign_reviewer_success(
        self,
        incident_service: IncidentService,
        mock_incident_repo: AsyncMock,
        mock_user_repo: AsyncMock,
        mock_audit_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        reporter_id = uuid4()
        reviewer_id = uuid4()
        admin_id = uuid4()

        incident = Incident(
            id=uuid4(),
            reference_number="INC-2026-ASSIGN",
            title="Assignment Test Incident",
            description="Testing reviewer assignment orchestration.",
            category=IncidentCategory.ACADEMIC_MISCONDUCT.value,
            severity=IncidentSeverity.HIGH.value,
            status=IncidentStatus.SUBMITTED.value,
            location="Room 101",
            occurred_at=datetime.now(UTC),
            reporter_id=reporter_id,
            department_id=dept_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = incident
        mock_incident_repo.update.side_effect = lambda inc: inc

        reviewer_role = MagicMock()
        reviewer_role.code = RoleCode.INVESTIGATOR.value
        reviewer = MagicMock()
        reviewer.id = reviewer_id
        reviewer.role = reviewer_role
        reviewer.department_id = dept_id
        reviewer.is_active = True
        reviewer.account_status = "active"
        mock_user_repo.get_by_id_unscoped.return_value = reviewer

        principal = _make_principal(
            user_id=admin_id,
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=dept_id,
            email="admin@test.edu",
        )

        res = await incident_service.assign_reviewer(
            incident_id=incident.id,
            payload=ReviewerAssignRequest(reviewer_id=reviewer_id, reason="Assigned for intake"),
            principal=principal,
        )

        assert res.assigned_reviewer_id == reviewer_id
        assert res.assignment_status == "assigned"
        assert res.status == "triaged"
        mock_incident_repo.create_assignment.assert_awaited_once()
        mock_audit_repo.append_event.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_reassign_reviewer_success(
        self,
        incident_service: IncidentService,
        mock_incident_repo: AsyncMock,
        mock_user_repo: AsyncMock,
        mock_audit_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        reporter_id = uuid4()
        old_reviewer_id = uuid4()
        new_reviewer_id = uuid4()
        admin_id = uuid4()

        incident = Incident(
            id=uuid4(),
            reference_number="INC-2026-REASSIGN",
            title="Reassign Test Incident",
            description="Testing reviewer reassignment orchestration.",
            category=IncidentCategory.SAFETY_HAZARD.value,
            severity=IncidentSeverity.MEDIUM.value,
            status=IncidentStatus.TRIAGED.value,
            location="Room 102",
            occurred_at=datetime.now(UTC),
            reporter_id=reporter_id,
            department_id=dept_id,
            assigned_reviewer_id=old_reviewer_id,
            assignment_status="assigned",
            assigned_at=datetime.now(UTC) - timedelta(days=2),
            acknowledged_at=datetime.now(UTC) - timedelta(days=1),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = incident
        mock_incident_repo.update.side_effect = lambda inc: inc

        new_role = MagicMock()
        new_role.code = RoleCode.INVESTIGATOR.value
        new_rev = MagicMock()
        new_rev.id = new_reviewer_id
        new_rev.role = new_role
        new_rev.department_id = dept_id
        new_rev.is_active = True
        new_rev.account_status = "active"
        mock_user_repo.get_by_id_unscoped.return_value = new_rev

        principal = _make_principal(
            user_id=admin_id,
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=dept_id,
            email="admin@test.edu",
        )

        res = await incident_service.reassign_reviewer(
            incident_id=incident.id,
            payload=ReviewerReassignRequest(
                reviewer_id=new_reviewer_id, reason="Previous investigator on medical leave."
            ),
            principal=principal,
        )

        assert res.assigned_reviewer_id == new_reviewer_id
        assert res.assignment_status == "reassigned"
        assert res.acknowledged_at is None
        mock_incident_repo.create_assignment.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_reassign_same_reviewer_fails(
        self,
        incident_service: IncidentService,
        mock_incident_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        reviewer_id = uuid4()

        incident = Incident(
            id=uuid4(),
            reference_number="INC-2026-REASSIGN-FAIL",
            title="Reassign Same Reviewer",
            description="Testing same reviewer rejection.",
            category=IncidentCategory.SAFETY_HAZARD.value,
            severity=IncidentSeverity.MEDIUM.value,
            status=IncidentStatus.TRIAGED.value,
            location="Room 102",
            occurred_at=datetime.now(UTC),
            reporter_id=uuid4(),
            department_id=dept_id,
            assigned_reviewer_id=reviewer_id,
            assignment_status="assigned",
        )
        mock_incident_repo.get_by_id.return_value = incident

        principal = _make_principal(
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=dept_id,
            email="admin@test.edu",
        )

        with pytest.raises(BusinessRuleError) as exc_info:
            await incident_service.reassign_reviewer(
                incident_id=incident.id,
                payload=ReviewerReassignRequest(
                    reviewer_id=reviewer_id, reason="Reassigning same person"
                ),
                principal=principal,
            )
        assert exc_info.value.code == "SAME_REVIEWER_ASSIGNMENT"

    @pytest.mark.asyncio
    async def test_acknowledge_assignment_success(
        self,
        incident_service: IncidentService,
        mock_incident_repo: AsyncMock,
        mock_audit_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        reviewer_id = uuid4()

        incident = Incident(
            id=uuid4(),
            reference_number="INC-2026-ACK",
            title="Ack Test Incident",
            description="Testing assignment acknowledgement.",
            category=IncidentCategory.ACADEMIC_MISCONDUCT.value,
            severity=IncidentSeverity.LOW.value,
            status=IncidentStatus.TRIAGED.value,
            location="Room 103",
            occurred_at=datetime.now(UTC),
            reporter_id=uuid4(),
            department_id=dept_id,
            assigned_reviewer_id=reviewer_id,
            assignment_status="assigned",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = incident
        mock_incident_repo.update.side_effect = lambda inc: inc

        principal = _make_principal(
            user_id=reviewer_id,
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=dept_id,
            email="reviewer@test.edu",
        )

        res = await incident_service.acknowledge_assignment(incident.id, principal)
        assert res.assignment_status == "acknowledged"
        assert res.acknowledged_at is not None
        mock_incident_repo.create_assignment.assert_awaited_once()
        mock_audit_repo.append_event.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_acknowledge_assignment_by_wrong_user_fails(
        self,
        incident_service: IncidentService,
        mock_incident_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        reviewer_id = uuid4()
        imposter_id = uuid4()

        incident = Incident(
            id=uuid4(),
            reference_number="INC-2026-ACK-FAIL",
            title="Ack Wrong User Incident",
            description="Testing wrong user acknowledgement denial.",
            category=IncidentCategory.ACADEMIC_MISCONDUCT.value,
            severity=IncidentSeverity.LOW.value,
            status=IncidentStatus.TRIAGED.value,
            location="Room 103",
            occurred_at=datetime.now(UTC),
            reporter_id=uuid4(),
            department_id=dept_id,
            assigned_reviewer_id=reviewer_id,
            assignment_status="assigned",
        )
        mock_incident_repo.get_by_id.return_value = incident

        imposter = _make_principal(
            user_id=imposter_id,
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=dept_id,
            email="imposter@test.edu",
        )

        with pytest.raises(PermissionDeniedError) as exc_info:
            await incident_service.acknowledge_assignment(incident.id, imposter)
        assert exc_info.value.code == "NOT_ASSIGNED_REVIEWER"

    @pytest.mark.asyncio
    async def test_assign_reviewer_edge_cases(
        self,
        incident_service: IncidentService,
        mock_incident_repo: AsyncMock,
        mock_user_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        reviewer_id = uuid4()
        admin = _make_principal(role_code=RoleCode.DEPT_ADMIN.value, department_id=dept_id)

        # 1. Closed incident cannot be assigned
        closed_inc = Incident(
            id=uuid4(),
            reference_number="INC-CLOSED",
            title="Closed Incident",
            description="Testing closed incident assignment block.",
            category=IncidentCategory.SAFETY_HAZARD.value,
            severity=IncidentSeverity.LOW.value,
            status=IncidentStatus.CLOSED.value,
            location="Room 1",
            occurred_at=datetime.now(UTC),
            reporter_id=uuid4(),
            department_id=dept_id,
        )
        mock_incident_repo.get_by_id.return_value = closed_inc
        with pytest.raises(BusinessRuleError) as exc_locked:
            await incident_service.assign_reviewer(
                closed_inc.id, ReviewerAssignRequest(reviewer_id=reviewer_id), admin
            )
        assert exc_locked.value.code == "INCIDENT_ASSIGNMENT_LOCKED"

        # 2. Reviewer not found
        open_inc = Incident(
            id=uuid4(),
            reference_number="INC-OPEN",
            title="Open Incident",
            description="Testing missing reviewer user.",
            category=IncidentCategory.SAFETY_HAZARD.value,
            severity=IncidentSeverity.LOW.value,
            status=IncidentStatus.SUBMITTED.value,
            location="Room 1",
            occurred_at=datetime.now(UTC),
            reporter_id=uuid4(),
            department_id=dept_id,
        )
        mock_incident_repo.get_by_id.return_value = open_inc
        mock_user_repo.get_by_id_unscoped.return_value = None
        with pytest.raises(ResourceNotFoundError) as exc_rev:
            await incident_service.assign_reviewer(
                open_inc.id, ReviewerAssignRequest(reviewer_id=reviewer_id), admin
            )
        assert exc_rev.value.code == "REVIEWER_NOT_FOUND"

    @pytest.mark.asyncio
    async def test_get_assignment_history_edge_cases(
        self,
        incident_service: IncidentService,
        mock_incident_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        inc_id = uuid4()
        admin = _make_principal(role_code=RoleCode.DEPT_ADMIN.value, department_id=dept_id)

        # 1. Incident not found
        mock_incident_repo.get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await incident_service.get_assignment_history(inc_id, admin)

        # 2. Incident in different department denied for dept admin
        other_dept_inc = Incident(
            id=inc_id,
            reference_number="INC-OTHER",
            title="Other Dept Inc",
            description="Testing cross dept visibility denial.",
            category=IncidentCategory.SAFETY_HAZARD.value,
            severity=IncidentSeverity.LOW.value,
            status=IncidentStatus.SUBMITTED.value,
            location="Room 2",
            occurred_at=datetime.now(UTC),
            reporter_id=uuid4(),
            department_id=uuid4(),
        )
        mock_incident_repo.get_by_id.return_value = other_dept_inc
        with pytest.raises(ResourceNotFoundError):
            await incident_service.get_assignment_history(inc_id, admin)
