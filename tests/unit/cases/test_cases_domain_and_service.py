"""Comprehensive unit tests for Investigation Cases domain, core rules, and service (Phases 81-85).

Tests:
- Phase 81: State transitions, reference number generation, department scoping, case CRUD, incident linkage.
- Phase 82: Investigator assignment history, optimistic concurrency version_id checks, workload capacity limits (max 10).
- Phase 83: Evidence inventory integrity metadata, zero storage credential leakage, legal hold protections.
- Phase 84: AI candidate segment integration, department validation, mandatory advisory disclaimers.
- Phase 85: Human review workflow, reviewer conflict-of-interest check (reporter cannot review), classification corrections.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from backend.app.config.settings import Settings
from backend.app.core.case import (
    AI_ADVISORY_DISCLAIMER,
    INVESTIGATOR_DEFAULT_MAX_ACTIVE_CASES,
    CasePriority,
    CaseStatus,
    IncidentLinkType,
    InvestigativeRelevance,
    generate_case_reference_number,
    parse_case_priority,
    parse_case_status,
    validate_case_status_transition,
)
from backend.app.core.exceptions import (
    BusinessRuleError,
    PermissionDeniedError,
    ResourceNotFoundError,
)
from backend.app.core.identity import RoleCode
from backend.app.models.ai import AICandidateSegment
from backend.app.models.case import (
    Case,
    CaseAISegment,
    CaseAssignment,
    CaseEvidence,
    CaseIncident,
)
from backend.app.models.department import Department
from backend.app.models.evidence import EvidenceAttachment
from backend.app.models.incident import Incident
from backend.app.models.user import User
from backend.app.repositories.case import CaseRepository
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.case import (
    CaseAISegmentReviewRequest,
    CaseAssignRequest,
    CaseCreate,
    CaseLinkAISegmentRequest,
    CaseLinkEvidenceRequest,
    CaseLinkIncidentRequest,
    CaseUpdate,
)
from backend.app.services.case import CaseService

# =============================================================================
# Domain Core Logic Tests (Phase 81)
# =============================================================================


class TestCaseDomainCore:
    """Unit tests for core case domain rules and state machine."""

    def test_generate_case_reference_number_format(self) -> None:
        ref = generate_case_reference_number()
        assert ref.startswith("CASE-")
        parts = ref.split("-")
        assert len(parts) == 3
        assert parts[1] == str(datetime.now(UTC).year)
        assert len(parts[2]) == 8
        assert ref == ref.upper()

    def test_parse_case_status_valid_and_invalid(self) -> None:
        assert parse_case_status("open") == CaseStatus.OPEN
        assert parse_case_status("UNDER_INVESTIGATION") == CaseStatus.UNDER_INVESTIGATION
        assert parse_case_status("resolved") == CaseStatus.RESOLVED

        with pytest.raises(BusinessRuleError) as exc:
            parse_case_status("nonexistent_status")
        assert exc.value.code == "INVALID_CASE_STATUS"

    def test_parse_case_priority_valid_and_invalid(self) -> None:
        assert parse_case_priority("low") == CasePriority.LOW
        assert parse_case_priority("CRITICAL") == CasePriority.CRITICAL

        with pytest.raises(BusinessRuleError) as exc:
            parse_case_priority("ultra_urgent")
        assert exc.value.code == "INVALID_CASE_PRIORITY"

    def test_validate_case_status_transition_valid_paths(self) -> None:
        # Same status is no-op
        validate_case_status_transition("open", "open")
        # Standard lifecycle
        validate_case_status_transition("draft", "open")
        validate_case_status_transition("open", "under_investigation")
        validate_case_status_transition("under_investigation", "pending_review")
        validate_case_status_transition("pending_review", "resolved")
        validate_case_status_transition("resolved", "closed")
        validate_case_status_transition("under_investigation", "suspended")
        validate_case_status_transition("suspended", "under_investigation")

    def test_validate_case_status_transition_invalid_paths(self) -> None:
        with pytest.raises(BusinessRuleError) as exc:
            validate_case_status_transition("closed", "open")
        assert exc.value.code == "INVALID_CASE_TRANSITION"

        with pytest.raises(BusinessRuleError) as exc:
            validate_case_status_transition("draft", "resolved")
        assert exc.value.code == "INVALID_CASE_TRANSITION"


# =============================================================================
# CaseService Tests (Phases 81 - 85)
# =============================================================================


def make_principal(
    role_code: str,
    department_id: UUID | None = None,
    user_id: UUID | None = None,
    email: str = "user@ewitness.edu",
) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        user_id=user_id or uuid4(),
        email=email,
        full_name="Test Principal",
        role_code=role_code,
        account_status="active",
        is_active=True,
        session_id=uuid4(),
        department_id=department_id,
    )


def make_case_entity(
    *,
    case_id: UUID | None = None,
    department_id: UUID | None = None,
    title: str = "Test Case",
    summary: str = "Investigation case summary details",
    status: str = "open",
    priority: str = "medium",
    reference_number: str | None = None,
    version_id: int = 1,
    is_legal_hold: bool = False,
    legal_hold_reason: str | None = None,
    created_by_id: UUID | None = None,
    lead_investigator_id: UUID | None = None,
) -> Case:
    now = datetime.now(UTC)
    return Case(
        id=case_id or uuid4(),
        reference_number=reference_number or generate_case_reference_number(),
        title=title,
        summary=summary,
        status=status,
        priority=priority,
        department_id=department_id or uuid4(),
        created_by_id=created_by_id or uuid4(),
        lead_investigator_id=lead_investigator_id,
        version_id=version_id,
        is_legal_hold=is_legal_hold,
        legal_hold_reason=legal_hold_reason,
        created_at=now,
        updated_at=now,
    )


@pytest.fixture
def mock_case_service(test_settings: Settings) -> tuple[CaseService, dict[str, AsyncMock]]:
    case_repo = AsyncMock()
    incident_repo = AsyncMock()
    evidence_repo = AsyncMock()
    ai_segment_repo = AsyncMock()
    department_repo = AsyncMock()
    user_repo = AsyncMock()
    audit_repo = AsyncMock()

    service = CaseService(
        case_repo=case_repo,
        incident_repo=incident_repo,
        evidence_repo=evidence_repo,
        ai_segment_repo=ai_segment_repo,
        department_repo=department_repo,
        user_repo=user_repo,
        audit_repo=audit_repo,
        settings=test_settings,
        max_active_cases=INVESTIGATOR_DEFAULT_MAX_ACTIVE_CASES,
    )
    mocks = {
        "case_repo": case_repo,
        "incident_repo": incident_repo,
        "evidence_repo": evidence_repo,
        "ai_segment_repo": ai_segment_repo,
        "department_repo": department_repo,
        "user_repo": user_repo,
        "audit_repo": audit_repo,
    }
    return service, mocks


@pytest.mark.asyncio
class TestCaseServiceUnit:
    """Unit tests for CaseService business logic, isolation, capacity, and human review."""

    # -------------------------------------------------------------------------
    # Phase 81: Case Creation & Isolation
    # -------------------------------------------------------------------------

    async def test_create_case_permission_denied_for_student(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, _ = mock_case_service
        student_principal = make_principal(
            role_code=RoleCode.STUDENT.value,
            department_id=uuid4(),
            email="student@ewitness.edu",
        )
        payload = CaseCreate(
            title="Unauthorized Case Attempt",
            summary="Attempting to create case without permission.",
        )
        with pytest.raises(PermissionDeniedError) as exc:
            await service.create_case(payload, student_principal)
        assert exc.value.code == "PERMISSION_DENIED"

    async def test_create_case_cross_department_forbidden_for_dept_admin(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, _ = mock_case_service
        my_dept = uuid4()
        other_dept = uuid4()
        dept_admin_principal = make_principal(
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=my_dept,
            email="deptadmin@ewitness.edu",
        )
        payload = CaseCreate(
            title="Cross Dept Case",
            summary="Attempting cross-department case creation.",
            department_id=other_dept,
        )
        with pytest.raises(PermissionDeniedError) as exc:
            await service.create_case(payload, dept_admin_principal)
        assert exc.value.code == "CROSS_DEPARTMENT_FORBIDDEN"

    async def test_create_case_success_with_investigator_and_initial_incident(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, mocks = mock_case_service
        dept_id = uuid4()
        lead_id = uuid4()
        inc_id = uuid4()
        principal = make_principal(
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=dept_id,
            email="admin@ewitness.edu",
        )

        # Mocks
        dept = Department(id=dept_id, code="SEC", name="Security", is_active=True)
        investigator = User(
            id=lead_id, department_id=dept_id, is_active=True, full_name="Investigator Lead"
        )
        incident = Incident(
            id=inc_id,
            department_id=dept_id,
            title="Test Incident",
            reference_number="INC-2026-0001",
            status="triaged",
        )

        mocks["department_repo"].get_by_id.return_value = dept
        mocks["user_repo"].get_by_id.return_value = investigator
        mocks["case_repo"].count_active_cases_for_investigator.return_value = 2  # under 10
        mocks["incident_repo"].get_by_id.return_value = incident
        mocks["case_repo"].get_by_reference_number.return_value = None

        def fake_create(c: Case) -> Case:
            c.id = uuid4()
            c.department = dept
            c.lead_investigator = investigator
            c.created_at = datetime.now(UTC)
            c.updated_at = datetime.now(UTC)
            c.incidents = []
            c.evidence = []
            c.ai_segments = []
            return c

        mocks["case_repo"].create.side_effect = fake_create

        payload = CaseCreate(
            title="Academic Integrity Investigation",
            summary="Formal inquiry into unauthorized material.",
            priority=CasePriority.HIGH,
            lead_investigator_id=lead_id,
            initial_incident_id=inc_id,
        )
        created = await service.create_case(payload, principal)

        assert created.title == "Academic Integrity Investigation"
        assert created.priority == CasePriority.HIGH
        assert created.department_id == dept_id
        assert created.lead_investigator_id == lead_id
        assert created.version_id == 1
        assert created.is_legal_hold is False

        # Verify initial assignment and incident link recorded
        assert mocks["case_repo"].record_assignment.called
        assert mocks["case_repo"].link_incident.called
        assert mocks["audit_repo"].append_event.called

    # -------------------------------------------------------------------------
    # Phase 82: Assignment, Capacity & Optimistic Concurrency
    # -------------------------------------------------------------------------

    async def test_assign_case_capacity_limit_exceeded_rejects_with_422(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, mocks = mock_case_service
        dept_id = uuid4()
        case_id = uuid4()
        overloaded_investigator_id = uuid4()

        principal = make_principal(
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=dept_id,
            email="admin@ewitness.edu",
        )

        existing_case = Case(
            id=case_id,
            department_id=dept_id,
            title="Existing Case",
            summary="Case details",
            status="open",
            priority="medium",
            version_id=1,
            is_legal_hold=False,
        )
        investigator = User(
            id=overloaded_investigator_id,
            department_id=dept_id,
            is_active=True,
            full_name="Overworked Investigator",
        )

        mocks["case_repo"].get_by_id.return_value = existing_case
        mocks["user_repo"].get_by_id.return_value = investigator
        # Exactly at max capacity (10)
        mocks["case_repo"].count_active_cases_for_investigator.return_value = 10

        payload = CaseAssignRequest(
            new_investigator_id=overloaded_investigator_id,
            assignment_reason="Assigning heavy workload",
            expected_version=1,
        )

        with pytest.raises(BusinessRuleError) as exc:
            await service.assign_case(case_id, payload, principal)
        assert exc.value.code == "INVESTIGATOR_CAPACITY_EXCEEDED"
        assert exc.value.status_code == 422

    async def test_update_case_optimistic_locking_conflict_rejects_with_409(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, mocks = mock_case_service
        dept_id = uuid4()
        case_id = uuid4()

        principal = make_principal(
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=dept_id,
            email="investigator@ewitness.edu",
        )

        existing_case = Case(
            id=case_id,
            department_id=dept_id,
            title="Current Title",
            summary="Current Summary",
            status="open",
            priority="medium",
            version_id=3,  # Already updated to version 3
            is_legal_hold=False,
        )
        mocks["case_repo"].get_by_id.return_value = existing_case

        # Caller sends stale version 2
        payload = CaseUpdate(
            title="Stale Update Title",
            expected_version=2,
        )

        with pytest.raises(BusinessRuleError) as exc:
            await service.update_case(case_id, payload, principal)
        assert exc.value.code == "CONCURRENCY_CONFLICT"
        assert exc.value.status_code == 409

    async def test_update_case_terminal_status_requires_rationale(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, mocks = mock_case_service
        dept_id = uuid4()
        case_id = uuid4()

        principal = make_principal(
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=dept_id,
            email="admin@ewitness.edu",
        )

        existing_case = Case(
            id=case_id,
            department_id=dept_id,
            title="Resolved Case",
            summary="Case details",
            status="pending_review",
            priority="medium",
            version_id=1,
            is_legal_hold=False,
        )
        mocks["case_repo"].get_by_id.return_value = existing_case

        # Missing status_reason
        payload = CaseUpdate(
            status=CaseStatus.RESOLVED,
            status_reason=None,
            expected_version=1,
        )

        with pytest.raises(BusinessRuleError) as exc:
            await service.update_case(case_id, payload, principal)
        assert exc.value.code == "STATUS_REASON_REQUIRED"

    # -------------------------------------------------------------------------
    # Phase 83: Evidence Inventory & Legal Hold Protections
    # -------------------------------------------------------------------------

    async def test_unlink_evidence_blocked_under_legal_hold(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, mocks = mock_case_service
        dept_id = uuid4()
        case_id = uuid4()
        ev_id = uuid4()

        principal = make_principal(
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=dept_id,
            email="investigator@ewitness.edu",
        )

        existing_case = Case(
            id=case_id,
            department_id=dept_id,
            title="Legal Hold Case",
            summary="Summary",
            status="under_investigation",
            version_id=1,
            is_legal_hold=True,  # Legal hold is ACTIVE
            legal_hold_reason="Court subpoena received.",
        )
        existing_link = CaseEvidence(
            case_id=case_id,
            evidence_id=ev_id,
            linked_by_id=principal.user_id,
        )

        mocks["case_repo"].get_by_id.return_value = existing_case
        mocks["case_repo"].get_evidence_link.return_value = existing_link

        with pytest.raises(BusinessRuleError) as exc:
            await service.unlink_evidence(case_id, ev_id, principal)
        assert exc.value.code == "LEGAL_HOLD_ACTIVE"
        assert exc.value.status_code == 409

    # -------------------------------------------------------------------------
    # Phase 84: AI Candidate Segment Linkage & Advisory Disclaimers
    # -------------------------------------------------------------------------

    async def test_link_ai_segment_department_mismatch_rejected(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, mocks = mock_case_service
        case_dept = uuid4()
        other_dept = uuid4()
        case_id = uuid4()
        segment_id = uuid4()

        principal = make_principal(
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=case_dept,
            email="investigator@ewitness.edu",
        )

        existing_case = Case(
            id=case_id,
            department_id=case_dept,
            title="Dept Case",
            summary="Summary",
            status="under_investigation",
            version_id=1,
        )
        ai_segment = AICandidateSegment(
            id=segment_id,
            department_id=other_dept,  # Different department!
            job_id=uuid4(),
            evidence_id=uuid4(),
            incident_id=uuid4(),
            start_seconds=0.0,
            end_seconds=5.0,
            duration_seconds=5.0,
            raw_score=0.88,
            raw_label="violence",
            model_name="violence_v1",
            model_version="1.0.0",
            review_status="pending_review",
        )

        mocks["case_repo"].get_by_id.return_value = existing_case
        mocks["ai_segment_repo"].get_by_id.return_value = ai_segment

        payload = CaseLinkAISegmentRequest(
            segment_id=segment_id,
            investigative_relevance=InvestigativeRelevance.CANDIDATE_LEAD,
        )

        with pytest.raises(BusinessRuleError) as exc:
            await service.link_ai_segment(case_id, payload, principal)
        assert exc.value.code == "DEPARTMENT_MISMATCH"

    # -------------------------------------------------------------------------
    # Phase 85: Human Review & Conflict of Interest Prevention
    # -------------------------------------------------------------------------

    async def test_review_ai_segment_conflict_of_interest_fails_closed(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, mocks = mock_case_service
        dept_id = uuid4()
        case_id = uuid4()
        segment_id = uuid4()
        ev_id = uuid4()
        inc_id = uuid4()
        investigator_user_id = uuid4()

        # The principal is the investigator
        principal = make_principal(
            user_id=investigator_user_id,
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=dept_id,
            email="investigator@ewitness.edu",
        )

        existing_case = Case(
            id=case_id,
            department_id=dept_id,
            title="Conflict Case",
            summary="Summary",
            status="under_investigation",
            version_id=1,
        )
        ai_segment = AICandidateSegment(
            id=segment_id,
            department_id=dept_id,
            job_id=uuid4(),
            evidence_id=ev_id,
            incident_id=inc_id,
            start_seconds=0.0,
            end_seconds=5.0,
            duration_seconds=5.0,
            raw_score=0.85,
            raw_label="violence",
            model_name="violence_v1",
            model_version="1.0.0",
            review_status="pending_review",
        )
        existing_link = CaseAISegment(
            case_id=case_id,
            segment_id=segment_id,
            linked_by_id=investigator_user_id,
            investigative_relevance=InvestigativeRelevance.CANDIDATE_LEAD.value,
        )
        evidence = EvidenceAttachment(
            id=ev_id,
            incident_id=inc_id,
            uploader_id=uuid4(),
            department_id=dept_id,
            original_filename="video.mp4",
            declared_mime_type="video/mp4",
            file_size_bytes=1000,
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            storage_key="sec/video.mp4",
        )
        # CRUCIAL: The incident was reported by the SAME investigator!
        incident = Incident(
            id=inc_id,
            department_id=dept_id,
            title="Reported Incident",
            reference_number="INC-2026-0002",
            reporter_id=investigator_user_id,  # Conflict of interest!
        )

        mocks["case_repo"].get_by_id.return_value = existing_case
        mocks["case_repo"].get_ai_segment_link.return_value = existing_link
        mocks["ai_segment_repo"].get_by_id.return_value = ai_segment
        mocks["evidence_repo"].get_attachment_by_id.return_value = evidence
        mocks["incident_repo"].get_by_id.return_value = incident

        payload = CaseAISegmentReviewRequest(
            review_status="confirmed",
            review_rationale="I observed this firsthand and confirm it.",
        )

        # Must fail closed with 403 Forbidden!
        with pytest.raises(PermissionDeniedError) as exc:
            await service.review_ai_segment(case_id, segment_id, payload, principal)
        assert exc.value.code == "REVIEWER_CONFLICT_OF_INTEREST"

    async def test_review_ai_segment_success_with_correction(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, mocks = mock_case_service
        dept_id = uuid4()
        case_id = uuid4()
        segment_id = uuid4()
        ev_id = uuid4()
        inc_id = uuid4()
        reviewer_id = uuid4()
        different_reporter_id = uuid4()

        principal = make_principal(
            user_id=reviewer_id,
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=dept_id,
            email="reviewer@ewitness.edu",
        )

        existing_case = Case(
            id=case_id,
            department_id=dept_id,
            title="Valid Review Case",
            summary="Summary",
            status="under_investigation",
            version_id=1,
        )
        ai_segment = AICandidateSegment(
            id=segment_id,
            department_id=dept_id,
            job_id=uuid4(),
            evidence_id=ev_id,
            incident_id=inc_id,
            start_seconds=12.5,
            end_seconds=17.5,
            duration_seconds=5.0,
            raw_score=0.74,
            raw_label="violence",
            model_name="violence_v1",
            model_version="1.0.0",
            review_status="pending_review",
        )
        existing_link = CaseAISegment(
            id=uuid4(),
            case_id=case_id,
            segment_id=segment_id,
            linked_by_id=reviewer_id,
            investigative_relevance=InvestigativeRelevance.CANDIDATE_LEAD.value,
            created_at=datetime.now(UTC),
        )
        evidence = EvidenceAttachment(
            id=ev_id,
            incident_id=inc_id,
            uploader_id=uuid4(),
            department_id=dept_id,
            original_filename="surveillance.mp4",
            declared_mime_type="video/mp4",
            file_size_bytes=5000000,
            sha256_hash="abc123hash",
            storage_key="sec/surveillance.mp4",
        )
        # Incident reporter is independent
        incident = Incident(
            id=inc_id,
            department_id=dept_id,
            title="Campus Incident",
            reference_number="INC-2026-0003",
            reporter_id=different_reporter_id,
        )

        mocks["case_repo"].get_by_id.return_value = existing_case
        mocks["case_repo"].get_ai_segment_link.return_value = existing_link
        mocks["ai_segment_repo"].get_by_id.return_value = ai_segment
        mocks["evidence_repo"].get_attachment_by_id.return_value = evidence
        mocks["incident_repo"].get_by_id.return_value = incident

        payload = CaseAISegmentReviewRequest(
            review_status="confirmed",
            review_rationale="Carefully reviewed video frame-by-frame; candidate segment confirmed as physical altercation.",
            corrected_label="physical_altercation",
        )

        result = await service.review_ai_segment(case_id, segment_id, payload, principal)

        assert result.review_status == "confirmed"
        assert result.reviewed_by_id == reviewer_id
        assert result.label == "physical_altercation"
        assert result.review_notes == payload.review_rationale
        assert result.advisory_disclaimer == AI_ADVISORY_DISCLAIMER
        assert mocks["audit_repo"].append_event.called

    async def test_list_cases_dept_and_global_filtering(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, mocks = mock_case_service
        dept_id = uuid4()
        user_id = uuid4()
        c1 = make_case_entity(department_id=dept_id, title="Case 1", status="open", priority="high")
        c2 = make_case_entity(
            department_id=dept_id, title="Case 2", status="closed", priority="low"
        )
        mocks["case_repo"].list_paginated.return_value = ([c1, c2], 2)

        # Investigator (dept-scoped)
        inv = make_principal(RoleCode.INVESTIGATOR.value, department_id=dept_id, user_id=user_id)
        res = await service.list_cases(inv, limit=10, offset=0, status="open", priority="high")
        assert len(res.items) == 2
        assert res.total == 2
        mocks["case_repo"].list_paginated.assert_called_with(
            limit=10,
            offset=0,
            department_id=dept_id,
            lead_investigator_id=None,
            created_by_id=None,
            status="open",
            priority="high",
            is_legal_hold=None,
            search=None,
            sort_by="created_at",
            sort_order="desc",
        )

        # Super admin (global) with search keyword
        admin = make_principal(RoleCode.SUPER_ADMIN.value, department_id=None)
        await service.list_cases(
            admin,
            limit=5,
            offset=5,
            search="theft",
            is_legal_hold=True,
            sort_by="priority",
            sort_order="asc",
        )
        mocks["case_repo"].list_paginated.assert_called_with(
            limit=5,
            offset=5,
            department_id=None,
            lead_investigator_id=None,
            created_by_id=None,
            status=None,
            priority=None,
            is_legal_hold=True,
            search="theft",
            sort_by="priority",
            sort_order="asc",
        )

    async def test_get_case_by_id_and_reference_scenarios(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, mocks = mock_case_service
        dept_id = uuid4()
        other_dept = uuid4()
        case_id = uuid4()
        user_id = uuid4()
        c = make_case_entity(
            case_id=case_id, reference_number="CASE-2026-TEST0001", department_id=dept_id, title="C"
        )

        mocks["case_repo"].get_by_id.return_value = c
        mocks["case_repo"].get_by_reference_number.return_value = c

        inv = make_principal(RoleCode.INVESTIGATOR.value, department_id=dept_id, user_id=user_id)
        # Success by ID
        r1 = await service.get_case(case_id, inv)
        assert r1.id == case_id

        # Success by ref
        r2 = await service.get_case_by_reference("CASE-2026-TEST0001", inv)
        assert r2.reference_number == "CASE-2026-TEST0001"

        # Cross department masked as 404
        other_inv = make_principal(RoleCode.INVESTIGATOR.value, department_id=other_dept)
        with pytest.raises(ResourceNotFoundError) as exc1:
            await service.get_case(case_id, other_inv)
        assert exc1.value.code == "CASE_NOT_FOUND"

        with pytest.raises(ResourceNotFoundError) as exc2:
            await service.get_case_by_reference("CASE-2026-TEST0001", other_inv)
        assert exc2.value.code == "CASE_NOT_FOUND"

        # Not found
        mocks["case_repo"].get_by_id.return_value = None
        mocks["case_repo"].get_by_reference_number.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await service.get_case(uuid4(), inv)
        with pytest.raises(ResourceNotFoundError):
            await service.get_case_by_reference("CASE-2026-NONEXIST", inv)

    async def test_create_case_validation_and_permissions(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, mocks = mock_case_service
        dept_id = uuid4()
        other_dept = uuid4()

        # Student lacks permission
        student = make_principal(RoleCode.STUDENT.value, department_id=dept_id)
        with pytest.raises(PermissionDeniedError):
            await service.create_case(
                CaseCreate(title="Test Case", summary="Summary text"), student
            )

        # Cross department forbidden for non-global
        inv = make_principal(RoleCode.INVESTIGATOR.value, department_id=dept_id)
        with pytest.raises(PermissionDeniedError) as exc_cross:
            await service.create_case(
                CaseCreate(title="Test Case", summary="Summary text", department_id=other_dept), inv
            )
        assert exc_cross.value.code == "CROSS_DEPARTMENT_FORBIDDEN"

        # Missing department when principal has none
        admin_no_dept = make_principal(RoleCode.SUPER_ADMIN.value, department_id=None)
        with pytest.raises(BusinessRuleError) as exc_dept:
            await service.create_case(
                CaseCreate(title="Test Case", summary="Summary text"), admin_no_dept
            )
        assert exc_dept.value.code == "DEPARTMENT_REQUIRED"

        # Inactive department
        mocks["department_repo"].get_by_id.return_value = Department(
            id=dept_id, code="INACT", name="Inactive", is_active=False
        )
        with pytest.raises(BusinessRuleError) as exc_inact:
            await service.create_case(CaseCreate(title="Test Case", summary="Summary text"), inv)
        assert exc_inact.value.code == "INACTIVE_DEPARTMENT"

        # Active department
        mocks["department_repo"].get_by_id.return_value = Department(
            id=dept_id, code="ACT", name="Active", is_active=True
        )

        # Initial incident not found
        inc_id = uuid4()
        mocks["incident_repo"].get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError) as exc_inc:
            await service.create_case(
                CaseCreate(title="Test Case", summary="Summary text", initial_incident_id=inc_id),
                inv,
            )
        assert exc_inc.value.code == "INCIDENT_NOT_FOUND"

        # Initial incident department mismatch
        mocks["incident_repo"].get_by_id.return_value = Incident(
            id=inc_id,
            reference_number="INC-2026-0099",
            department_id=other_dept,
            title="Diff Dept",
            reporter_id=uuid4(),
        )
        with pytest.raises(BusinessRuleError) as exc_inc_mismatch:
            await service.create_case(
                CaseCreate(title="Test Case", summary="Summary text", initial_incident_id=inc_id),
                inv,
            )
        assert exc_inc_mismatch.value.code == "DEPARTMENT_MISMATCH"

    async def test_update_case_status_and_legal_hold_transitions(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, mocks = mock_case_service
        dept_id = uuid4()
        case_id = uuid4()
        inv = make_principal(RoleCode.INVESTIGATOR.value, department_id=dept_id)

        # Case not found
        mocks["case_repo"].get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await service.update_case(
                case_id, CaseUpdate(title="New Title", expected_version=1), inv
            )

        # Case cross department
        existing = make_case_entity(
            case_id=case_id,
            department_id=uuid4(),
            title="Existing",
            status="open",
            priority="low",
            version_id=1,
        )
        mocks["case_repo"].get_by_id.return_value = existing
        with pytest.raises(ResourceNotFoundError):
            await service.update_case(
                case_id, CaseUpdate(title="New Title", expected_version=1), inv
            )

        # Optimistic locking concurrency conflict
        existing.department_id = dept_id
        with pytest.raises(BusinessRuleError) as exc_ver:
            await service.update_case(
                case_id, CaseUpdate(title="New Title", expected_version=99), inv
            )
        assert exc_ver.value.code == "CONCURRENCY_CONFLICT"

        # Invalid status transition (open -> resolved)
        with pytest.raises(BusinessRuleError) as exc_trans:
            await service.update_case(
                case_id, CaseUpdate(status="resolved", expected_version=1), inv
            )
        assert exc_trans.value.code == "INVALID_CASE_TRANSITION"

        # Terminal status requires status_reason
        existing.status = "pending_review"
        with pytest.raises(BusinessRuleError) as exc_reason:
            await service.update_case(
                case_id, CaseUpdate(status="resolved", expected_version=1), inv
            )
        assert exc_reason.value.code == "STATUS_REASON_REQUIRED"

        # Setting legal hold requires legal_hold_reason
        existing.status = "open"
        with pytest.raises(BusinessRuleError) as exc_lh:
            await service.update_case(
                case_id, CaseUpdate(is_legal_hold=True, expected_version=1), inv
            )
        assert exc_lh.value.code == "LEGAL_HOLD_REASON_REQUIRED"

        # Attempt to modify a closed case
        existing.status = "closed"
        with pytest.raises(BusinessRuleError) as exc_closed:
            await service.update_case(
                case_id, CaseUpdate(title="New Title", expected_version=1), inv
            )
        assert exc_closed.value.code == "CASE_TERMINAL_IMMUTABLE"

        # Valid update
        existing.status = "open"
        mocks["case_repo"].update.return_value = existing
        res = await service.update_case(
            case_id,
            CaseUpdate(title="Updated Title", priority="critical", expected_version=1),
            inv,
        )
        assert res.title == "Updated Title"
        assert res.priority == CasePriority.CRITICAL

        # Valid legal hold enable
        res_lh = await service.update_case(
            case_id,
            CaseUpdate(
                is_legal_hold=True,
                legal_hold_reason="Pending preservation notice",
                expected_version=2,
            ),
            inv,
        )
        assert res_lh.is_legal_hold is True
        assert res_lh.legal_hold_reason == "Pending preservation notice"

        # Release legal hold
        res_rel = await service.update_case(
            case_id,
            CaseUpdate(is_legal_hold=False, expected_version=3),
            inv,
        )
        assert res_rel.is_legal_hold is False

        # Update summary and status transition to under_investigation
        res_stat = await service.update_case(
            case_id,
            CaseUpdate(
                summary="Updated detailed case summary",
                status="under_investigation",
                expected_version=4,
            ),
            inv,
        )
        assert res_stat.status == CaseStatus.UNDER_INVESTIGATION

    async def test_link_unlink_incident_scenarios(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, mocks = mock_case_service
        dept_id = uuid4()
        case_id = uuid4()
        inc_id = uuid4()
        inv = make_principal(RoleCode.INVESTIGATOR.value, department_id=dept_id)

        existing_case = make_case_entity(
            case_id=case_id,
            department_id=dept_id,
            title="Case",
            status="open",
            priority="low",
            version_id=1,
        )
        mocks["case_repo"].get_by_id.return_value = existing_case

        # Incident not found
        mocks["incident_repo"].get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await service.link_incident(case_id, CaseLinkIncidentRequest(incident_id=inc_id), inv)

        # Cross department incident
        inc = Incident(
            id=inc_id,
            reference_number="INC-2026-1111",
            department_id=uuid4(),
            title="Inc",
            reporter_id=uuid4(),
        )
        mocks["incident_repo"].get_by_id.return_value = inc
        with pytest.raises(BusinessRuleError) as exc_inc_dept:
            await service.link_incident(case_id, CaseLinkIncidentRequest(incident_id=inc_id), inv)
        assert exc_inc_dept.value.code == "DEPARTMENT_MISMATCH"

        # Duplicate link
        inc.department_id = dept_id
        mocks["case_repo"].get_incident_link.return_value = CaseIncident(
            case_id=case_id, incident_id=inc_id
        )
        with pytest.raises(BusinessRuleError) as exc_dup:
            await service.link_incident(case_id, CaseLinkIncidentRequest(incident_id=inc_id), inv)
        assert exc_dup.value.code == "INCIDENT_ALREADY_LINKED"

        # Unlink incident not found link
        mocks["case_repo"].get_incident_link.return_value = None
        with pytest.raises(ResourceNotFoundError) as exc_unl:
            await service.unlink_incident(case_id, inc_id, inv)
        assert exc_unl.value.code == "LINK_NOT_FOUND"

        # Unlink under legal hold
        existing_case.is_legal_hold = True
        mocks["case_repo"].get_incident_link.return_value = CaseIncident(
            case_id=case_id, incident_id=inc_id
        )
        with pytest.raises(BusinessRuleError) as exc_lh_unl:
            await service.unlink_incident(case_id, inc_id, inv)
        assert exc_lh_unl.value.code == "LEGAL_HOLD_ACTIVE"

        # List incidents
        existing_case.is_legal_hold = False
        link = CaseIncident(
            case_id=case_id, incident_id=inc_id, link_type="primary", created_at=datetime.now(UTC)
        )
        link.incident = inc
        mocks["case_repo"].list_case_incidents.return_value = [link]
        inc_list = await service.list_case_incidents(case_id, inv)
        assert len(inc_list) == 1
        assert inc_list[0].incident_id == inc_id

        # Successful link
        mocks["case_repo"].get_incident_link.return_value = None
        linked_inc = await service.link_incident(
            case_id, CaseLinkIncidentRequest(incident_id=inc_id), inv
        )
        assert linked_inc.incident_id == inc_id

        # Successful unlink
        mocks["case_repo"].get_incident_link.return_value = CaseIncident(
            case_id=case_id, incident_id=inc_id
        )
        mocks["case_repo"].unlink_incident.return_value = True
        unlinked = await service.unlink_incident(case_id, inc_id, inv)
        assert unlinked is True

    async def test_link_unlink_evidence_scenarios(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, mocks = mock_case_service
        dept_id = uuid4()
        case_id = uuid4()
        ev_id = uuid4()
        inv = make_principal(RoleCode.INVESTIGATOR.value, department_id=dept_id)

        existing_case = make_case_entity(
            case_id=case_id,
            department_id=dept_id,
            title="Case",
            status="open",
            priority="low",
            version_id=1,
        )
        mocks["case_repo"].get_by_id.return_value = existing_case

        # Evidence not found
        mocks["evidence_repo"].get_attachment_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await service.link_evidence(case_id, CaseLinkEvidenceRequest(evidence_id=ev_id), inv)

        # Cross department evidence
        inc_cross = Incident(
            id=uuid4(),
            reference_number="INC-2026-9999",
            department_id=uuid4(),
            title="Inc",
            reporter_id=uuid4(),
        )
        ev = EvidenceAttachment(
            id=ev_id,
            incident_id=inc_cross.id,
            uploader_id=uuid4(),
            department_id=uuid4(),
            original_filename="doc.pdf",
            declared_mime_type="application/pdf",
            file_size_bytes=1000,
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            storage_key="sec/doc.pdf",
        )
        mocks["evidence_repo"].get_attachment_by_id.return_value = ev
        mocks["incident_repo"].get_by_id.return_value = inc_cross
        with pytest.raises(BusinessRuleError) as exc_ev_dept:
            await service.link_evidence(case_id, CaseLinkEvidenceRequest(evidence_id=ev_id), inv)
        assert exc_ev_dept.value.code == "DEPARTMENT_MISMATCH"

        # Duplicate link
        inc_same = Incident(
            id=ev.incident_id,
            reference_number="INC-2026-1111",
            department_id=dept_id,
            title="Inc",
            reporter_id=uuid4(),
        )
        mocks["incident_repo"].get_by_id.return_value = inc_same
        ev.department_id = dept_id
        mocks["case_repo"].get_evidence_link.return_value = CaseEvidence(
            case_id=case_id, evidence_id=ev_id
        )
        with pytest.raises(BusinessRuleError) as exc_dup_ev:
            await service.link_evidence(case_id, CaseLinkEvidenceRequest(evidence_id=ev_id), inv)
        assert exc_dup_ev.value.code == "EVIDENCE_ALREADY_LINKED"

        # Corrupt sha256 detected
        mocks["case_repo"].get_evidence_link.return_value = None
        ev.sha256_hash = "not_a_valid_64_hex_string"
        with pytest.raises(BusinessRuleError) as exc_corrupt:
            await service.link_evidence(case_id, CaseLinkEvidenceRequest(evidence_id=ev_id), inv)
        assert exc_corrupt.value.code == "EVIDENCE_INTEGRITY_COMPROMISED"

        # Unlink not found
        mocks["case_repo"].get_evidence_link.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await service.unlink_evidence(case_id, ev_id, inv)

        # List evidence items
        ev.sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        link = CaseEvidence(
            case_id=case_id,
            evidence_id=ev_id,
            notes="Ex A",
            is_exhibiting=True,
            created_at=datetime.now(UTC),
        )
        link.evidence = ev
        mocks["case_repo"].list_case_evidence.return_value = [link]
        ev_items = await service.list_case_evidence(case_id, inv)
        assert len(ev_items) == 1
        assert ev_items[0].sha256_hash == ev.sha256_hash
        assert ev_items[0].integrity_status == "verified"

        # Successful link
        mocks["case_repo"].get_evidence_link.return_value = None
        ev.sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        linked_ev = await service.link_evidence(
            case_id, CaseLinkEvidenceRequest(evidence_id=ev_id, notes="Ex 1"), inv
        )
        assert linked_ev.evidence_id == ev_id

        # Successful unlink
        mocks["case_repo"].get_evidence_link.return_value = CaseEvidence(
            case_id=case_id, evidence_id=ev_id
        )
        mocks["case_repo"].unlink_evidence.return_value = True
        unlinked_ev = await service.unlink_evidence(case_id, ev_id, inv)
        assert unlinked_ev is True

        # Unlink blocked under legal hold
        existing_case.is_legal_hold = True
        with pytest.raises(BusinessRuleError) as exc_ev_lh:
            await service.unlink_evidence(case_id, ev_id, inv)
        assert exc_ev_lh.value.code == "LEGAL_HOLD_ACTIVE"
        existing_case.is_legal_hold = False

    async def test_link_unlink_ai_segment_scenarios(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, mocks = mock_case_service
        dept_id = uuid4()
        case_id = uuid4()
        seg_id = uuid4()
        inv = make_principal(RoleCode.INVESTIGATOR.value, department_id=dept_id)

        existing_case = make_case_entity(
            case_id=case_id,
            department_id=dept_id,
            title="Case",
            status="open",
            priority="low",
            version_id=1,
        )
        mocks["case_repo"].get_by_id.return_value = existing_case

        # Segment not found
        mocks["ai_segment_repo"].get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await service.link_ai_segment(case_id, CaseLinkAISegmentRequest(segment_id=seg_id), inv)

        # Cross department segment
        seg = AICandidateSegment(
            id=seg_id,
            job_id=uuid4(),
            evidence_id=uuid4(),
            incident_id=uuid4(),
            department_id=uuid4(),
            start_seconds=1.0,
            end_seconds=3.0,
            duration_seconds=2.0,
            raw_score=0.8,
            raw_label="violence",
            model_name="m",
            model_version="1",
            review_status="pending_review",
        )
        mocks["ai_segment_repo"].get_by_id.return_value = seg
        with pytest.raises(BusinessRuleError) as exc_seg_dept:
            await service.link_ai_segment(case_id, CaseLinkAISegmentRequest(segment_id=seg_id), inv)
        assert exc_seg_dept.value.code == "DEPARTMENT_MISMATCH"

        # Duplicate link
        seg.department_id = dept_id
        mocks["case_repo"].get_ai_segment_link.return_value = CaseAISegment(
            case_id=case_id, segment_id=seg_id
        )
        with pytest.raises(BusinessRuleError) as exc_dup_seg:
            await service.link_ai_segment(case_id, CaseLinkAISegmentRequest(segment_id=seg_id), inv)
        assert exc_dup_seg.value.code == "SEGMENT_ALREADY_LINKED"

        # Unlink not found
        mocks["case_repo"].get_ai_segment_link.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await service.unlink_ai_segment(case_id, seg_id, inv)

        # List ai segments
        link = CaseAISegment(
            case_id=case_id,
            segment_id=seg_id,
            investigative_relevance="candidate_lead",
            created_at=datetime.now(UTC),
        )
        link.segment = seg
        mocks["case_repo"].list_case_ai_segments.return_value = [link]
        seg_items = await service.list_case_ai_segments(case_id, inv)
        assert len(seg_items) == 1
        assert seg_items[0].advisory_disclaimer == AI_ADVISORY_DISCLAIMER

        # Successful link
        mocks["case_repo"].get_ai_segment_link.return_value = None
        linked_seg = await service.link_ai_segment(
            case_id,
            CaseLinkAISegmentRequest(
                segment_id=seg_id, investigative_relevance=InvestigativeRelevance.CANDIDATE_LEAD
            ),
            inv,
        )
        assert linked_seg.segment_id == seg_id

        # Successful unlink
        mocks["case_repo"].get_ai_segment_link.return_value = CaseAISegment(
            case_id=case_id, segment_id=seg_id
        )
        mocks["case_repo"].unlink_ai_segment.return_value = True
        unlinked_seg = await service.unlink_ai_segment(case_id, seg_id, inv)
        assert unlinked_seg is True

        # Unlink blocked under legal hold
        existing_case.is_legal_hold = True
        with pytest.raises(BusinessRuleError) as exc_seg_lh:
            await service.unlink_ai_segment(case_id, seg_id, inv)
        assert exc_seg_lh.value.code == "LEGAL_HOLD_ACTIVE"
        existing_case.is_legal_hold = False

    async def test_get_workload_and_list_assignments_scenarios(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, mocks = mock_case_service
        dept_id = uuid4()
        inv_id = uuid4()

        # Student cannot read workload
        student = make_principal(RoleCode.STUDENT.value, department_id=dept_id)
        with pytest.raises(PermissionDeniedError):
            await service.get_investigator_workload(inv_id, student)

        # Investigator cannot read workload (management only)
        inv = make_principal(RoleCode.INVESTIGATOR.value, department_id=dept_id)
        with pytest.raises(PermissionDeniedError):
            await service.get_investigator_workload(inv_id, inv)

        # Dept Admin cross department / not found
        admin = make_principal(RoleCode.DEPT_ADMIN.value, department_id=dept_id)
        mocks["user_repo"].get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await service.get_investigator_workload(inv_id, admin)

        # Valid workload query by Dept Admin
        target_user = User(
            id=inv_id,
            department_id=dept_id,
            is_active=True,
            email="inv@ewitness.edu",
            full_name="Inv",
        )
        mocks["user_repo"].get_by_id.return_value = target_user
        mocks["case_repo"].count_active_cases_for_investigator.return_value = 3

        wl = await service.get_investigator_workload(inv_id, admin)
        assert wl.active_cases_count == 3
        assert wl.capacity_available is True

        # Valid workload query by Super Admin (can_global=True)
        super_admin = make_principal(RoleCode.SUPER_ADMIN.value, department_id=None)
        mocks["user_repo"].get_by_id_unscoped.return_value = target_user
        wl_global = await service.get_investigator_workload(inv_id, super_admin)
        assert wl_global.active_cases_count == 3

        # Dept Admin with None department raises error
        broken_admin = make_principal(RoleCode.DEPT_ADMIN.value, department_id=None)
        with pytest.raises(PermissionDeniedError) as exc_nodept:
            await service.get_investigator_workload(inv_id, broken_admin)
        assert exc_nodept.value.code == "PERMISSION_DENIED"

        # List assignments
        case_id = uuid4()
        c = make_case_entity(case_id=case_id, department_id=dept_id, title="C")
        mocks["case_repo"].get_by_id.return_value = c
        asgn = CaseAssignment(
            id=uuid4(),
            case_id=case_id,
            previous_investigator_id=None,
            new_investigator_id=inv_id,
            assigned_by_id=inv.user_id,
            assignment_reason="Reason",
            created_at=datetime.now(UTC),
        )
        mocks["case_repo"].list_assignments.return_value = [asgn]
        asgns = await service.list_assignments(case_id, inv)
        assert len(asgns) == 1
        assert asgns[0].new_investigator_id == inv_id

    async def test_create_case_edge_cases_and_collision_retry(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, mocks = mock_case_service
        dept_id = uuid4()
        inv_id = uuid4()
        inc_id = uuid4()

        # 1. No department specified and principal has no department
        no_dept_principal = make_principal(RoleCode.SUPER_ADMIN.value, department_id=None)
        with pytest.raises(BusinessRuleError) as exc_nodept:
            await service.create_case(
                CaseCreate(title="Valid Test Case", summary="Summary text"), no_dept_principal
            )
        assert exc_nodept.value.code == "DEPARTMENT_REQUIRED"

        # 2. Inactive department
        inactive_dept = Department(id=dept_id, name="Inactive Dept", code="INACT", is_active=False)
        mocks["department_repo"].get_by_id.return_value = inactive_dept
        admin = make_principal(RoleCode.DEPT_ADMIN.value, department_id=dept_id)
        with pytest.raises(BusinessRuleError) as exc_inact:
            await service.create_case(
                CaseCreate(title="Valid Test Case", summary="Summary text"), admin
            )
        assert exc_inact.value.code == "INACTIVE_DEPARTMENT"

        # 3. Collision retry and initial lead & incident creation
        active_dept = Department(id=dept_id, name="Active Dept", code="ACT", is_active=True)
        mocks["department_repo"].get_by_id.return_value = active_dept
        inv_user = User(
            id=inv_id,
            department_id=dept_id,
            is_active=True,
            email="inv@ewitness.edu",
            full_name="Inv",
        )
        mocks["user_repo"].get_by_id.return_value = inv_user
        mocks["case_repo"].count_active_cases_for_investigator.return_value = 0

        inc = Incident(
            id=inc_id,
            reference_number="INC-2026-1234",
            department_id=dept_id,
            title="Inc Title",
            reporter_id=uuid4(),
        )
        mocks["incident_repo"].get_by_id.return_value = inc

        # First call to get_by_reference_number returns an existing case (collision!), second returns None
        existing_collision = make_case_entity(case_id=uuid4(), department_id=dept_id)
        mocks["case_repo"].get_by_reference_number.side_effect = [existing_collision, None]

        created_entity = make_case_entity(
            case_id=uuid4(), department_id=dept_id, lead_investigator_id=inv_id
        )
        mocks["case_repo"].create.return_value = created_entity

        res = await service.create_case(
            CaseCreate(
                title="Collision Case",
                summary="Collision case summary",
                lead_investigator_id=inv_id,
                initial_incident_id=inc_id,
            ),
            admin,
        )
        assert res.id == created_entity.id
        assert mocks["case_repo"].record_assignment.called
        assert mocks["case_repo"].link_incident.called

    async def test_assign_case_reassign_and_permission_edge_cases(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, mocks = mock_case_service
        dept_id = uuid4()
        case_id = uuid4()
        old_lead_id = uuid4()
        new_lead_id = uuid4()

        existing = make_case_entity(
            case_id=case_id,
            department_id=dept_id,
            lead_investigator_id=old_lead_id,
            version_id=1,
        )
        mocks["case_repo"].get_by_id.return_value = existing

        # 1. No permission to assign
        student = make_principal(RoleCode.STUDENT.value, department_id=dept_id)
        with pytest.raises(PermissionDeniedError):
            await service.assign_case(
                case_id,
                CaseAssignRequest(new_investigator_id=new_lead_id, expected_version=1),
                student,
            )

        # 2. Cross department for dept admin
        other_dept_admin = make_principal(RoleCode.DEPT_ADMIN.value, department_id=uuid4())
        with pytest.raises(ResourceNotFoundError):
            await service.assign_case(
                case_id,
                CaseAssignRequest(new_investigator_id=new_lead_id, expected_version=1),
                other_dept_admin,
            )

        # 3. Concurrency conflict
        dept_admin = make_principal(RoleCode.DEPT_ADMIN.value, department_id=dept_id)
        with pytest.raises(BusinessRuleError) as exc_ver:
            await service.assign_case(
                case_id,
                CaseAssignRequest(new_investigator_id=new_lead_id, expected_version=99),
                dept_admin,
            )
        assert exc_ver.value.code == "CONCURRENCY_CONFLICT"

        # 4. Successful reassignment
        target_inv = User(
            id=new_lead_id,
            department_id=dept_id,
            is_active=True,
            email="new@ewitness.edu",
            full_name="New Lead",
        )
        mocks["user_repo"].get_by_id.return_value = target_inv
        mocks["case_repo"].count_active_cases_for_investigator.return_value = 2
        mocks["case_repo"].update.return_value = existing

        updated = await service.assign_case(
            case_id,
            CaseAssignRequest(
                new_investigator_id=new_lead_id,
                assignment_reason="Reassigning lead due to rotation",
                expected_version=1,
            ),
            dept_admin,
        )
        assert updated.lead_investigator_id == new_lead_id

    async def test_ai_segment_review_edge_cases(
        self,
        mock_case_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, mocks = mock_case_service
        dept_id = uuid4()
        case_id = uuid4()
        seg_id = uuid4()
        inv = make_principal(RoleCode.INVESTIGATOR.value, department_id=dept_id)

        # 1. Case not found
        mocks["case_repo"].get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await service.review_ai_segment(
                case_id,
                seg_id,
                CaseAISegmentReviewRequest(
                    review_status="confirmed",
                    review_rationale="Thorough inspection confirmed the detection.",
                ),
                inv,
            )

        # 2. Segment link not found
        existing_case = make_case_entity(case_id=case_id, department_id=dept_id)
        mocks["case_repo"].get_by_id.return_value = existing_case
        mocks["case_repo"].get_ai_segment_link.return_value = None
        with pytest.raises(ResourceNotFoundError) as exc_notlinked:
            await service.review_ai_segment(
                case_id,
                seg_id,
                CaseAISegmentReviewRequest(
                    review_status="confirmed",
                    review_rationale="Thorough inspection confirmed the detection.",
                ),
                inv,
            )
        assert exc_notlinked.value.code == "LINK_NOT_FOUND"

        # 3. Principal has no permission
        student = make_principal(RoleCode.STUDENT.value, department_id=dept_id)
        with pytest.raises(PermissionDeniedError):
            await service.review_ai_segment(
                case_id,
                seg_id,
                CaseAISegmentReviewRequest(
                    review_status="confirmed",
                    review_rationale="Thorough inspection confirmed the detection.",
                ),
                student,
            )

        # 4. Dismissed review path
        link = CaseAISegment(
            case_id=case_id,
            segment_id=seg_id,
            investigative_relevance="candidate_lead",
            created_at=datetime.now(UTC),
        )
        mocks["case_repo"].get_ai_segment_link.return_value = link
        seg = AICandidateSegment(
            id=seg_id,
            job_id=uuid4(),
            evidence_id=uuid4(),
            incident_id=uuid4(),
            department_id=dept_id,
            start_seconds=1.0,
            end_seconds=3.0,
            duration_seconds=2.0,
            raw_score=0.8,
            raw_label="violence",
            model_name="m",
            model_version="1",
            review_status="pending_review",
        )
        mocks["ai_segment_repo"].get_by_id.return_value = seg
        mocks["incident_repo"].get_by_id.return_value = Incident(
            id=seg.incident_id,
            department_id=dept_id,
            reporter_id=uuid4(),
            reference_number="INC-1",
            title="I",
        )

        rev_res = await service.review_ai_segment(
            case_id,
            seg_id,
            CaseAISegmentReviewRequest(
                review_status="rejected",
                review_rationale="False positive detection caused by lighting reflections.",
            ),
            inv,
        )
        assert rev_res.review_status == "rejected"
        assert rev_res.investigative_relevance == InvestigativeRelevance.DISMISSED


# =============================================================================
# CaseRepository Unit Tests
# =============================================================================


@pytest.mark.asyncio
class TestCaseRepositoryUnit:
    """Unit tests for CaseRepository methods and queries."""

    async def test_repository_list_paginated_invalid_sort(self) -> None:
        session = AsyncMock()
        repo = CaseRepository(session)
        with pytest.raises(BusinessRuleError) as exc1:
            await repo.list_paginated(sort_order="invalid_order")
        assert "Invalid sort order" in str(exc1.value.message)

        with pytest.raises(BusinessRuleError) as exc2:
            await repo.list_paginated(sort_by="unsupported_column")
        assert "Invalid sort field" in str(exc2.value.message)

    async def test_repository_list_paginated_and_count_queries(self) -> None:
        session = AsyncMock()
        repo = CaseRepository(session)
        c = make_case_entity(
            reference_number="CASE-2026-00000001", title="Test", status="open", priority="high"
        )
        mock_res = MagicMock()
        mock_res.scalars.return_value.all.return_value = [c]
        mock_res.scalar.return_value = 1
        session.execute.return_value = mock_res

        rows, total = await repo.list_paginated(
            limit=10,
            offset=0,
            department_id=uuid4(),
            lead_investigator_id=uuid4(),
            created_by_id=uuid4(),
            status="open",
            priority="high",
            is_legal_hold=False,
            search="keyword",
            sort_by="title",
            sort_order="asc",
        )
        assert len(rows) == 1
        assert total == 1

    async def test_repository_count_active_cases_for_investigator(self) -> None:
        session = AsyncMock()
        repo = CaseRepository(session)
        mock_res = MagicMock()
        mock_res.scalar.return_value = 4
        session.execute.return_value = mock_res

        cnt = await repo.count_active_cases_for_investigator(uuid4(), exclude_case_id=uuid4())
        assert cnt == 4

    async def test_repository_link_and_query_methods(self) -> None:
        session = AsyncMock()
        session.add = MagicMock()
        repo = CaseRepository(session)
        cid = uuid4()
        iid = uuid4()
        eid = uuid4()
        sid = uuid4()

        # Link incident
        inc_link = CaseIncident(case_id=cid, incident_id=iid)
        await repo.link_incident(inc_link)
        assert session.add.called

        # Get incident link
        mock_res = MagicMock()
        mock_res.scalars.return_value.first.return_value = inc_link
        session.execute.return_value = mock_res
        assert await repo.get_incident_link(cid, iid) == inc_link

        # Link evidence
        ev_link = CaseEvidence(case_id=cid, evidence_id=eid)
        await repo.link_evidence(ev_link)

        # Get evidence link
        mock_res.scalars.return_value.first.return_value = ev_link
        assert await repo.get_evidence_link(cid, eid) == ev_link

        # Link AI segment
        seg_link = CaseAISegment(case_id=cid, segment_id=sid)
        await repo.link_ai_segment(seg_link)

        # Get AI segment link
        mock_res.scalars.return_value.first.return_value = seg_link
        assert await repo.get_ai_segment_link(cid, sid) == seg_link

        # Record assignment
        asgn = CaseAssignment(case_id=cid, new_investigator_id=uuid4())
        await repo.record_assignment(asgn)

        # Unlink methods
        mock_res.rowcount = 1
        await repo.unlink_incident(cid, iid)
        await repo.unlink_evidence(cid, eid)
        await repo.unlink_ai_segment(cid, sid)
        assert session.execute.called

    async def test_repository_get_by_reference_number_and_queries(self) -> None:
        session = AsyncMock()
        repo = CaseRepository(session)
        cid = uuid4()
        did = uuid4()
        case_entity = make_case_entity(case_id=cid, department_id=did)
        mock_res = MagicMock()
        mock_res.scalars.return_value.first.return_value = case_entity
        mock_res.scalar.return_value = 5
        session.execute.return_value = mock_res

        # Get by reference number
        res1 = await repo.get_by_reference_number("CASE-2026-ABCDEF12")
        assert res1 == case_entity

        # Alternate sort branch
        mock_res.scalars.return_value.all.return_value = [case_entity]
        mock_res.scalar.return_value = 1
        rows, total = await repo.list_paginated(
            department_id=did,
            status="open",
            priority="high",
            is_legal_hold=True,
            lead_investigator_id=uuid4(),
            created_by_id=uuid4(),
            sort_by="created_at",
            sort_order="desc",
        )
        assert len(rows) == 1
        assert total == 1


# =============================================================================
# Case Schemas Unit Tests
# =============================================================================


class TestCaseSchemasUnit:
    """Unit tests for Case DTO schemas validation."""

    def test_case_create_schema_validation(self) -> None:
        # Valid
        c = CaseCreate(
            title="Valid Case Title",
            summary="Summary of the investigation case",
            priority=CasePriority.HIGH,
        )
        assert c.title == "Valid Case Title"

        # Title too short
        with pytest.raises(ValidationError):
            CaseCreate(title="No", summary="Valid summary")

        # Title empty
        with pytest.raises(ValidationError):
            CaseCreate(title="   ", summary="Valid summary")

        # Summary too short
        with pytest.raises(ValidationError):
            CaseCreate(title="Valid Case Title", summary="Short")

    def test_case_update_schema_validation(self) -> None:
        # Valid partial
        u = CaseUpdate(title="Updated Title", expected_version=2)
        assert u.title == "Updated Title"
        assert u.expected_version == 2

        # Invalid title too short
        with pytest.raises(ValidationError):
            CaseUpdate(title="Ab")

    def test_case_assign_request_schema(self) -> None:
        req = CaseAssignRequest(
            new_investigator_id=uuid4(), assignment_reason="Assigned to lead", expected_version=1
        )
        assert req.expected_version == 1

        with pytest.raises(ValidationError):
            CaseAssignRequest(new_investigator_id=uuid4(), assignment_reason="   ")

    def test_case_link_requests_schema(self) -> None:
        req_inc = CaseLinkIncidentRequest(incident_id=uuid4(), link_type=IncidentLinkType.RELATED)
        assert req_inc.link_type == IncidentLinkType.RELATED

        req_ev = CaseLinkEvidenceRequest(evidence_id=uuid4(), notes="Exhibit 1", is_exhibiting=True)
        assert req_ev.is_exhibiting is True

        req_seg = CaseLinkAISegmentRequest(
            segment_id=uuid4(), investigative_relevance=InvestigativeRelevance.CORROBORATING
        )
        assert req_seg.investigative_relevance == InvestigativeRelevance.CORROBORATING

    def test_case_ai_segment_review_request_schema(self) -> None:
        # Valid
        rev = CaseAISegmentReviewRequest(
            review_status="confirmed",
            review_rationale="Thorough frame inspection completed with positive verification.",
            corrected_label="physical_assault",
        )
        assert rev.review_status == "confirmed"

        # Rationale too short (< 10 chars)
        with pytest.raises(ValidationError):
            CaseAISegmentReviewRequest(review_status="confirmed", review_rationale="Too short")
