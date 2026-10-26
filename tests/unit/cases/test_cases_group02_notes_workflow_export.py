"""Comprehensive unit tests for Investigation Cases Phase 86-90 (Notes, Findings, Workflow, Exports).

Tests:
- Phase 86: Case notes, visibility tiers, evidence references, findings, and version history.
- Phase 87: Lifecycle transitions, prerequisites, supervisory approvals, and concurrency locks.
- Phase 88: Escalations, referrals, formal closure, legal hold preservation, and reopening.
- Phase 89: Case exports, evidence manifests, cryptographic digests, credential leakage guards, and statutory AI disclaimers.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from backend.app.config.settings import Settings
from backend.app.core.ai import SegmentReviewStatus
from backend.app.core.case import (
    AI_ADVISORY_DISCLAIMER,
    CaseApprovalDecision,
    CaseFindingType,
    CaseNoteVisibility,
    CaseStatus,
    EvidenceVerificationStatus,
    generate_case_reference_number,
)
from backend.app.core.exceptions import (
    BusinessRuleError,
    ConflictError,
    PermissionDeniedError,
    ResourceNotFoundError,
)
from backend.app.core.identity import RoleCode
from backend.app.models.case import (
    Case,
    CaseApproval,
    CaseEscalation,
    CaseExport,
    CaseFinding,
    CaseFindingHistory,
    CaseNote,
    CaseNoteHistory,
    CaseReferral,
)
from backend.app.models.department import Department
from backend.app.repositories.case import CaseRepository
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.case import (
    CaseApprovalRequest,
    CaseCloseRequest,
    CaseEscalationRequest,
    CaseExportRequest,
    CaseFindingCreate,
    CaseFindingUpdate,
    CaseNoteCreate,
    CaseNoteUpdate,
    CaseReferralCreate,
    CaseReferralUpdate,
    CaseReopenRequest,
    CaseTransitionRequest,
)
from backend.app.services.case import CaseService


def make_principal(
    role: RoleCode = RoleCode.INVESTIGATOR,
    user_id: UUID | None = None,
    department_id: UUID | None = None,
) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        user_id=user_id or uuid4(),
        email="investigator@institution.edu",
        full_name="Investigator Principal",
        role_code=role.value,
        account_status="active",
        is_active=True,
        department_id=department_id or uuid4(),
        session_id=uuid4(),
    )


def make_case_entity(
    *,
    case_id: UUID | None = None,
    department_id: UUID | None = None,
    title: str = "Investigation Case",
    summary: str = "Detailed investigation summary",
    status: str = "open",
    priority: str = "medium",
    reference_number: str | None = None,
    version_id: int = 1,
    is_legal_hold: bool = False,
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
        created_at=now,
        updated_at=now,
    )


@pytest.fixture
def mock_service(test_settings: Settings) -> tuple[CaseService, dict[str, AsyncMock]]:
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
        max_active_cases=10,
    )
    repos = {
        "case": case_repo,
        "incident": incident_repo,
        "evidence": evidence_repo,
        "ai_segment": ai_segment_repo,
        "department": department_repo,
        "user": user_repo,
        "audit": audit_repo,
    }
    return service, repos


# =============================================================================
# Phase 86: Case Notes & Findings Tests
# =============================================================================


class TestCaseNotesAndFindingsUnit:
    """Unit tests for Phase 86: Notes, visibility tiers, findings, and history."""

    @pytest.mark.asyncio
    async def test_create_case_note_internal_success(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        principal = make_principal(RoleCode.INVESTIGATOR)
        case_entity = make_case_entity(department_id=principal.department_id)
        repos["case"].get_by_id.return_value = case_entity
        repos["case"].create_note.side_effect = lambda note: note

        payload = CaseNoteCreate(
            visibility="internal",
            content="Interviewed witness regarding the lab incident.",
            evidence_reference_ids=[],
        )
        res = await service.create_case_note(case_entity.id, principal, payload)
        assert res.case_id == case_entity.id
        assert res.author_id == principal.user_id
        assert res.visibility == "internal"
        assert res.content == payload.content
        assert res.version_id == 1

    @pytest.mark.asyncio
    async def test_create_case_note_restricted_forbidden_for_standard_investigator(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        principal = make_principal(RoleCode.INVESTIGATOR)
        case_entity = make_case_entity(department_id=principal.department_id)
        repos["case"].get_by_id.return_value = case_entity

        payload = CaseNoteCreate(
            visibility="restricted",
            content="Privileged legal work product notes.",
        )
        with pytest.raises(PermissionDeniedError, match="restricted working notes"):
            await service.create_case_note(case_entity.id, principal, payload)

    @pytest.mark.asyncio
    async def test_create_case_note_restricted_allowed_for_dept_admin(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        admin = make_principal(RoleCode.DEPT_ADMIN)
        case_entity = make_case_entity(department_id=admin.department_id)
        repos["case"].get_by_id.return_value = case_entity
        repos["case"].create_note.side_effect = lambda note: note

        payload = CaseNoteCreate(
            visibility="restricted",
            content="Confidential disciplinary review notes.",
        )
        res = await service.create_case_note(case_entity.id, admin, payload)
        assert res.visibility == "restricted"

    @pytest.mark.asyncio
    async def test_create_case_note_invalid_evidence_reference_rejected(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        principal = make_principal(RoleCode.INVESTIGATOR)
        case_entity = make_case_entity(department_id=principal.department_id)
        repos["case"].get_by_id.return_value = case_entity
        repos["case"].list_case_evidence.return_value = []  # No linked evidence

        unlinked_evidence_id = uuid4()
        payload = CaseNoteCreate(
            visibility="internal",
            content="Examined video attachment 1.",
            evidence_reference_ids=[unlinked_evidence_id],
        )
        with pytest.raises(BusinessRuleError, match="not linked to this case"):
            await service.create_case_note(case_entity.id, principal, payload)

    @pytest.mark.asyncio
    async def test_update_case_note_success_and_concurrency(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        principal = make_principal(RoleCode.INVESTIGATOR)
        case_entity = make_case_entity(department_id=principal.department_id)
        note = CaseNote(
            id=uuid4(),
            case_id=case_entity.id,
            author_id=principal.user_id,
            visibility="internal",
            content="Original note content",
            version_id=1,
            is_archived=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        repos["case"].get_by_id.return_value = case_entity
        repos["case"].get_note_by_id.return_value = note
        repos["case"].create_note_history.side_effect = lambda h: h

        # 1. Successful update
        payload = CaseNoteUpdate(
            content="Corrected note content after re-interview.",
            edit_reason="Clarified interview timeline.",
            expected_version_id=1,
        )
        updated = await service.update_case_note(case_entity.id, note.id, principal, payload)
        assert updated.content == payload.content
        assert updated.version_id == 2

        # 2. Concurrency conflict with old expected_version_id
        stale_payload = CaseNoteUpdate(
            content="Stale update attempt",
            expected_version_id=1,  # Note is now at version 2
        )
        with pytest.raises(ConflictError, match="Note version conflict"):
            await service.update_case_note(case_entity.id, note.id, principal, stale_payload)

    @pytest.mark.asyncio
    async def test_update_case_note_foreign_author_forbidden(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        other_investigator = make_principal(RoleCode.INVESTIGATOR)
        note_author_id = uuid4()
        case_entity = make_case_entity(department_id=other_investigator.department_id)
        note = CaseNote(
            id=uuid4(),
            case_id=case_entity.id,
            author_id=note_author_id,  # Different author!
            visibility="internal",
            content="Original note",
            version_id=1,
            is_archived=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        repos["case"].get_by_id.return_value = case_entity
        repos["case"].get_note_by_id.return_value = note

        payload = CaseNoteUpdate(
            content="Unauthorized edit",
            expected_version_id=1,
        )
        with pytest.raises(
            PermissionDeniedError, match="cannot modify another investigator's note"
        ):
            await service.update_case_note(case_entity.id, note.id, other_investigator, payload)

    @pytest.mark.asyncio
    async def test_list_case_notes_visibility_filtering(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        principal = make_principal(RoleCode.INVESTIGATOR)
        case_entity = make_case_entity(department_id=principal.department_id)
        repos["case"].get_by_id.return_value = case_entity

        n_internal = CaseNote(
            id=uuid4(),
            case_id=case_entity.id,
            author_id=uuid4(),
            visibility="internal",
            content="Internal note visible to all dept investigators.",
            version_id=1,
            is_archived=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        n_restricted_other = CaseNote(
            id=uuid4(),
            case_id=case_entity.id,
            author_id=uuid4(),  # Authored by someone else
            visibility="restricted",
            content="Privileged note by another investigator.",
            version_id=1,
            is_archived=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        n_restricted_own = CaseNote(
            id=uuid4(),
            case_id=case_entity.id,
            author_id=principal.user_id,  # Authored by this investigator!
            visibility="restricted",
            content="My own restricted working note.",
            version_id=1,
            is_archived=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        repos["case"].list_notes_for_case.return_value = [
            n_internal,
            n_restricted_other,
            n_restricted_own,
        ]

        visible_notes = await service.list_case_notes(case_entity.id, principal)
        visible_ids = {vn.id for vn in visible_notes}
        assert n_internal.id in visible_ids
        assert n_restricted_own.id in visible_ids
        assert n_restricted_other.id not in visible_ids  # Redacted!

    @pytest.mark.asyncio
    async def test_create_case_finding_and_references(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        principal = make_principal(RoleCode.INVESTIGATOR)
        case_entity = make_case_entity(department_id=principal.department_id)
        repos["case"].get_by_id.return_value = case_entity

        # Set up linked entities
        ev_id = uuid4()
        seg_id = uuid4()
        inc_id = uuid4()
        ev_link = MagicMock(evidence_id=ev_id)
        seg_link = MagicMock(segment_id=seg_id)
        inc_link = MagicMock(incident_id=inc_id)
        repos["case"].list_case_evidence.return_value = [ev_link]
        repos["case"].list_case_ai_segments.return_value = [seg_link]
        repos["case"].list_case_incidents.return_value = [inc_link]
        repos["case"].create_finding.side_effect = lambda f: f

        payload = CaseFindingCreate(
            finding_type="inculpatory",
            title="Unauthorized Entry Detected",
            description="Security footage corroborates entry through west entrance at 22:15.",
            evidence_ids=[ev_id],
            ai_segment_ids=[seg_id],
            incident_ids=[inc_id],
            is_preliminary=False,
        )
        finding_res = await service.create_case_finding(case_entity.id, principal, payload)
        assert finding_res.title == payload.title
        assert finding_res.finding_type == "inculpatory"
        assert str(ev_id) in finding_res.evidence_ids
        assert str(seg_id) in finding_res.ai_segment_ids
        assert str(inc_id) in finding_res.incident_ids

    @pytest.mark.asyncio
    async def test_create_case_finding_invalid_reference_rejected(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        principal = make_principal(RoleCode.INVESTIGATOR)
        case_entity = make_case_entity(department_id=principal.department_id)
        repos["case"].get_by_id.return_value = case_entity
        repos["case"].list_case_evidence.return_value = []

        payload = CaseFindingCreate(
            finding_type="preliminary",
            title="Preliminary observation",
            description="Test finding description for validation.",
            evidence_ids=[uuid4()],
        )
        with pytest.raises(BusinessRuleError, match="not linked to this case"):
            await service.create_case_finding(case_entity.id, principal, payload)


# =============================================================================
# Phase 87: Lifecycle Transitions & Approvals Tests
# =============================================================================


class TestCaseLifecycleTransitionsAndApprovalsUnit:
    """Unit tests for Phase 87: Transition rules, prerequisites, approvals, and concurrency."""

    @pytest.mark.asyncio
    async def test_transition_to_under_investigation_requires_lead_and_incident(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        admin = make_principal(RoleCode.DEPT_ADMIN)
        case_no_lead = make_case_entity(
            department_id=admin.department_id,
            status="open",
            lead_investigator_id=None,  # No lead investigator!
        )
        repos["case"].get_by_id.return_value = case_no_lead

        payload = CaseTransitionRequest(
            target_status="under_investigation",
            reason="Starting field investigation.",
            expected_version_id=1,
        )
        with pytest.raises(BusinessRuleError, match="without an assigned lead investigator"):
            await service.transition_case_status(case_no_lead.id, admin, payload)

        # Now add lead investigator, but no incidents
        case_with_lead = make_case_entity(
            department_id=admin.department_id,
            status="open",
            lead_investigator_id=uuid4(),
        )
        repos["case"].get_by_id.return_value = case_with_lead
        repos["case"].list_case_incidents.return_value = []  # No incidents!

        with pytest.raises(BusinessRuleError, match="without at least one linked incident"):
            await service.transition_case_status(case_with_lead.id, admin, payload)

    @pytest.mark.asyncio
    async def test_transition_to_pending_review_blocked_by_unreviewed_ai_segment(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        admin = make_principal(RoleCode.DEPT_ADMIN)
        case_entity = make_case_entity(
            department_id=admin.department_id,
            status="under_investigation",
            lead_investigator_id=uuid4(),
        )
        repos["case"].get_by_id.return_value = case_entity
        repos["case"].list_notes_for_case.return_value = [MagicMock()]
        repos["case"].list_findings_for_case.return_value = []

        # Linked AI segment that is still pending review
        unreviewed_seg = MagicMock(review_status=SegmentReviewStatus.PENDING_REVIEW.value)
        link = MagicMock(segment=unreviewed_seg)
        repos["case"].list_case_ai_segments.return_value = [link]

        payload = CaseTransitionRequest(
            target_status="pending_review",
            reason="Completed investigation, submitting for review.",
            expected_version_id=1,
        )
        with pytest.raises(
            BusinessRuleError, match="while linked AI candidate segments remain unreviewed"
        ):
            await service.transition_case_status(case_entity.id, admin, payload)

    @pytest.mark.asyncio
    async def test_approve_case_transition_success(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        admin = make_principal(RoleCode.DEPT_ADMIN)
        case_entity = make_case_entity(
            department_id=admin.department_id,
            status="pending_review",
            version_id=3,
        )
        repos["case"].get_by_id.return_value = case_entity
        repos["case"].create_approval.side_effect = lambda a: a

        payload = CaseApprovalRequest(
            decision="approved",
            from_status="pending_review",
            to_status="resolved",
            rationale="Investigation thoroughly documented; findings supported by corroborated evidence.",
            expected_version_id=3,
        )
        approval_res = await service.approve_case_transition(case_entity.id, admin, payload)
        assert approval_res.decision == "approved"
        assert approval_res.to_status == "resolved"
        assert case_entity.status == "resolved"
        assert case_entity.version_id == 4
        assert case_entity.closed_at is not None

    @pytest.mark.asyncio
    async def test_approve_case_transition_changes_requested_resets_status(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        admin = make_principal(RoleCode.DEPT_ADMIN)
        case_entity = make_case_entity(
            department_id=admin.department_id,
            status="pending_review",
            version_id=3,
        )
        repos["case"].get_by_id.return_value = case_entity
        repos["case"].create_approval.side_effect = lambda a: a

        payload = CaseApprovalRequest(
            decision="changes_requested",
            from_status="pending_review",
            to_status="resolved",
            rationale="Further witness corroboration required for finding 2.",
            expected_version_id=3,
        )
        await service.approve_case_transition(case_entity.id, admin, payload)
        assert case_entity.status == "under_investigation"
        assert case_entity.closed_at is None


# =============================================================================
# Phase 88: Escalation, Referrals, Closure, and Reopening Tests
# =============================================================================


class TestCaseEscalationReferralCloseReopenUnit:
    """Unit tests for Phase 88: Escalation, referrals, closure, and reopening."""

    @pytest.mark.asyncio
    async def test_escalate_case_success_and_destination_validation(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        investigator = make_principal(RoleCode.INVESTIGATOR)
        case_entity = make_case_entity(department_id=investigator.department_id, version_id=2)
        repos["case"].get_by_id.return_value = case_entity

        target_dept_id = uuid4()
        repos["department"].get_by_id.return_value = Department(
            id=target_dept_id, code="LEGAL", name="Legal Counsel"
        )
        repos["case"].create_escalation.side_effect = lambda e: e

        payload = CaseEscalationRequest(
            escalated_to_department_id=target_dept_id,
            reason="Severe regulatory compliance exposure identified.",
            escalation_level="legal_counsel",
            expected_version_id=2,
        )
        esc_res = await service.escalate_case(case_entity.id, investigator, payload)
        assert esc_res.escalated_to_department_id == target_dept_id
        assert esc_res.escalation_level == "legal_counsel"
        assert case_entity.version_id == 3

    @pytest.mark.asyncio
    async def test_refer_case_and_update_status(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        investigator = make_principal(RoleCode.INVESTIGATOR)
        case_entity = make_case_entity(department_id=investigator.department_id)
        repos["case"].get_by_id.return_value = case_entity
        repos["case"].create_referral.side_effect = lambda r: r

        payload = CaseReferralCreate(
            target_external_agency="City Police Cybercrime Division",
            referral_purpose="External forensic examination of confiscated electronic hardware.",
        )
        referral = await service.refer_case(case_entity.id, investigator, payload)
        assert referral.target_external_agency == payload.target_external_agency
        assert referral.status == "pending"

        # Update referral outcome
        mock_ref_entity = CaseReferral(
            id=referral.id,
            case_id=case_entity.id,
            referred_by_id=investigator.user_id,
            target_external_agency="City Police Cybercrime Division",
            referral_purpose=payload.referral_purpose,
            status="pending",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        repos["case"].get_referral_by_id.return_value = mock_ref_entity

        update_payload = CaseReferralUpdate(
            status="accepted",
            resolution_notes="Case accepted by cybercrime unit for forensic intake.",
        )
        updated_ref = await service.update_referral_status(
            case_entity.id, referral.id, investigator, update_payload
        )
        assert updated_ref.status == "accepted"
        assert updated_ref.resolution_notes == update_payload.resolution_notes

    @pytest.mark.asyncio
    async def test_close_case_preserves_legal_hold(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        admin = make_principal(RoleCode.DEPT_ADMIN)
        case_entity = make_case_entity(
            department_id=admin.department_id,
            status="resolved",
            version_id=5,
            is_legal_hold=True,
        )
        repos["case"].get_by_id.return_value = case_entity

        payload = CaseCloseRequest(
            reason="Investigation concluded and institutional disciplinary action formalized.",
            expected_version_id=5,
        )
        closed_case = await service.close_case(case_entity.id, admin, payload)
        assert closed_case.status == CaseStatus.CLOSED
        assert closed_case.is_legal_hold is True  # Legal hold preserved!
        assert closed_case.version_id == 6

    @pytest.mark.asyncio
    async def test_reopen_case_from_closed_status(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        admin = make_principal(RoleCode.DEPT_ADMIN)
        case_entity = make_case_entity(
            department_id=admin.department_id,
            status="closed",
            version_id=6,
        )
        repos["case"].get_by_id.return_value = case_entity

        # 1. Reopening closed case succeeds
        reopen_payload = CaseReopenRequest(
            reason="New corroborating electronic evidence discovered requiring reopened investigation.",
            expected_version_id=6,
        )
        reopened = await service.reopen_case(case_entity.id, admin, reopen_payload)
        assert reopened.status == CaseStatus.UNDER_INVESTIGATION
        assert reopened.closed_at is None
        assert reopened.version_id == 7

        # 2. Reopening non-closed case fails
        active_case = make_case_entity(
            department_id=admin.department_id,
            status="under_investigation",
            version_id=7,
        )
        repos["case"].get_by_id.return_value = active_case
        with pytest.raises(
            BusinessRuleError, match="Only resolved or closed cases can be reopened"
        ):
            await service.reopen_case(active_case.id, admin, reopen_payload)


# =============================================================================
# Phase 89: Case Exports & Manifests Tests
# =============================================================================


class TestCaseExportAndManifestUnit:
    """Unit tests for Phase 89: Controlled export, evidence manifest, and credential leakage guards."""

    @pytest.mark.asyncio
    async def test_export_case_with_manifest_and_sha256(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        investigator = make_principal(RoleCode.INVESTIGATOR)
        case_entity = make_case_entity(department_id=investigator.department_id)
        repos["case"].get_by_id.return_value = case_entity

        # Valid 64-hex digest evidence attachment
        valid_digest = "a" * 64
        attachment_valid = MagicMock(
            original_filename="security_cam.mp4",
            sha256_hash=valid_digest,
            file_size=1048576,
        )
        ev_link = MagicMock(evidence_id=uuid4(), evidence=attachment_valid, notes="Primary footage")

        # Invalid/empty digest evidence
        attachment_invalid = MagicMock(
            original_filename="unverified.jpg",
            sha256_hash="invalid_short_digest",
            file_size=2048,
        )
        ev_link_invalid = MagicMock(
            evidence_id=uuid4(), evidence=attachment_invalid, notes="Unverified capture"
        )
        repos["case"].list_case_evidence.return_value = [ev_link, ev_link_invalid]
        repos["case"].list_notes_for_case.return_value = []
        repos["case"].list_findings_for_case.return_value = []
        repos["case"].list_case_ai_segments.return_value = []
        repos["case"].create_export.side_effect = lambda ex: ex

        payload = CaseExportRequest(
            export_scope="full_investigation",
            export_format="json",
            purpose="Preparation of formal hearing evidentiary dossier.",
            include_restricted_notes=False,
        )
        export_read = await service.export_case(case_entity.id, investigator, payload)
        assert export_read.case_id == case_entity.id
        assert export_read.evidence_count == 2
        assert len(export_read.manifest_sha256) == 64

        manifest = export_read.manifest_payload
        assert "evidence_manifest" in manifest
        items = manifest["evidence_manifest"]
        assert items[0]["verification_status"] == EvidenceVerificationStatus.VERIFIED.value
        assert items[1]["verification_status"] == EvidenceVerificationStatus.INTEGRITY_FAILED.value
        assert manifest["advisory_notice"] == AI_ADVISORY_DISCLAIMER

        # Strict credential leakage assertion
        manifest_str = json.dumps(manifest)
        assert "s3://" not in manifest_str
        assert "AWS_SECRET_ACCESS_KEY" not in manifest_str
        assert "minioadmin" not in manifest_str

    @pytest.mark.asyncio
    async def test_export_case_restricted_notes_requires_permission(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        investigator = make_principal(RoleCode.INVESTIGATOR)
        case_entity = make_case_entity(department_id=investigator.department_id)
        repos["case"].get_by_id.return_value = case_entity

        payload = CaseExportRequest(
            export_scope="full_investigation",
            purpose="Court evidentiary package preparation.",
            include_restricted_notes=True,  # Standard investigator not allowed!
        )
        with pytest.raises(PermissionDeniedError, match="Elevated permission required"):
            await service.export_case(case_entity.id, investigator, payload)

    @pytest.mark.asyncio
    async def test_get_case_export_tenant_isolation(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        investigator = make_principal(RoleCode.INVESTIGATOR)
        other_dept_id = uuid4()

        export_record = CaseExport(
            id=uuid4(),
            case_id=uuid4(),
            department_id=other_dept_id,  # Different department!
            exported_by_id=uuid4(),
            export_scope="summary",
            export_format="json",
            manifest_sha256="b" * 64,
            evidence_count=0,
            manifest_payload="{}",
            status="completed",
            purpose="Testing isolation",
            expires_at=datetime.now(UTC),
            created_at=datetime.now(UTC),
        )
        repos["case"].get_export_by_id.return_value = export_record

        with pytest.raises(ResourceNotFoundError, match="Case export not found"):
            await service.get_case_export(export_record.id, investigator)


# =============================================================================
# Schemas and Validators Tests
# =============================================================================


class TestCaseSchemasAndValidatorsUnit:
    """Unit tests for Pydantic v2 schemas and validators."""

    def test_case_note_create_validation(self) -> None:
        # Valid note
        valid = CaseNoteCreate(
            visibility="internal",
            content="Valid investigation observations.",
        )
        assert valid.visibility == "internal"

        # Invalid visibility
        with pytest.raises(ValidationError):
            CaseNoteCreate(
                visibility="invalid_visibility_mode",
                content="Valid content length.",
            )

        # Content too short (< 5 chars)
        with pytest.raises(ValidationError):
            CaseNoteCreate(
                visibility="internal",
                content="abc",
            )

    def test_case_finding_create_validation(self) -> None:
        # Valid finding
        valid = CaseFindingCreate(
            finding_type="exculpatory",
            title="Alibi Corroborated",
            description="Access logs verify subject was attending lecture elsewhere.",
        )
        assert valid.finding_type == "exculpatory"

        # Invalid finding type
        with pytest.raises(ValidationError):
            CaseFindingCreate(
                finding_type="not_a_finding_type",
                title="Invalid finding type test",
                description="Adequate description length provided.",
            )

    def test_case_transition_request_validation(self) -> None:
        valid = CaseTransitionRequest(
            target_status="under_investigation",
            reason="Investigation formally launched.",
            expected_version_id=1,
        )
        assert valid.target_status == "under_investigation"

        with pytest.raises(ValidationError):
            CaseTransitionRequest(
                target_status="invalid_status",
                reason="Adequate length reason provided.",
                expected_version_id=1,
            )

    def test_case_approval_request_validation(self) -> None:
        valid = CaseApprovalRequest(
            decision="approved",
            from_status="pending_review",
            to_status="resolved",
            rationale="Approved after complete supervisory inspection.",
            expected_version_id=2,
        )
        assert valid.decision == "approved"

        with pytest.raises(ValidationError):
            CaseApprovalRequest(
                decision="unsupported_decision",
                from_status="pending_review",
                to_status="resolved",
                rationale="Adequate rationale provided.",
                expected_version_id=2,
            )

    def test_case_export_request_validation(self) -> None:
        valid = CaseExportRequest(
            export_scope="full_investigation",
            export_format="json",
            purpose="Preparation of formal hearing evidentiary package.",
        )
        assert valid.export_scope == "full_investigation"
        assert valid.export_format == "json"

        with pytest.raises(ValidationError):
            CaseExportRequest(
                export_scope="unsupported_scope",
                export_format="json",
                purpose="Adequate purpose provided.",
            )


class TestCaseBranchCoverageExtensionsUnit:
    """Additional branch and error condition unit tests for Group 02."""

    @pytest.mark.asyncio
    async def test_update_case_note_not_found(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        investigator = make_principal(RoleCode.INVESTIGATOR)
        case_entity = make_case_entity(department_id=investigator.department_id)
        repos["case"].get_by_id.return_value = case_entity
        repos["case"].get_note_by_id.return_value = None

        with pytest.raises(ResourceNotFoundError, match="Case note not found"):
            await service.update_case_note(
                case_entity.id,
                uuid4(),
                investigator,
                CaseNoteUpdate(content="Updated note content", expected_version_id=1),
            )

    @pytest.mark.asyncio
    async def test_list_case_findings_and_history(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        investigator = make_principal(RoleCode.INVESTIGATOR)
        case_entity = make_case_entity(department_id=investigator.department_id)
        repos["case"].get_by_id.return_value = case_entity

        finding = CaseFinding(
            id=uuid4(),
            case_id=case_entity.id,
            author_id=investigator.user_id,
            finding_type=CaseFindingType.INCULPATORY.value,
            title="Unauthorized Entry Confirmed",
            description="Badge spoofing confirmed with sensor logs.",
            version_id=1,
            is_preliminary=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        repos["case"].list_findings_for_case.return_value = [finding]

        findings = await service.list_case_findings(case_entity.id, investigator)
        assert len(findings) == 1
        assert findings[0].id == finding.id

        # Finding history
        repos["case"].get_finding_by_id.return_value = finding
        repos["case"].list_finding_history.return_value = [
            CaseFindingHistory(
                id=uuid4(),
                finding_id=finding.id,
                version_id=1,
                editor_id=investigator.user_id,
                title="Preliminary Title",
                description="Preliminary Description",
                reason="Initial observation",
                created_at=datetime.now(UTC),
            )
        ]
        history = await service.get_case_finding_history(case_entity.id, finding.id, investigator)
        assert len(history) == 1
        assert history[0].version_id == 1

    @pytest.mark.asyncio
    async def test_update_case_finding_errors(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        investigator = make_principal(RoleCode.INVESTIGATOR)
        case_entity = make_case_entity(department_id=investigator.department_id)
        repos["case"].get_by_id.return_value = case_entity
        repos["case"].get_finding_by_id.return_value = None

        # Not found
        with pytest.raises(ResourceNotFoundError, match="Case finding not found"):
            await service.update_case_finding(
                case_entity.id,
                uuid4(),
                investigator,
                CaseFindingUpdate(description="Updated description text", expected_version_id=1),
            )

        # Concurrency conflict
        finding = CaseFinding(
            id=uuid4(),
            case_id=case_entity.id,
            author_id=investigator.user_id,
            finding_type=CaseFindingType.INCULPATORY.value,
            title="Entry",
            description="Original description text",
            version_id=3,
            is_preliminary=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        repos["case"].get_finding_by_id.return_value = finding

        with pytest.raises(ConflictError, match="Finding version conflict"):
            await service.update_case_finding(
                case_entity.id,
                finding.id,
                investigator,
                CaseFindingUpdate(description="Updated description text", expected_version_id=1),
            )

    @pytest.mark.asyncio
    async def test_transition_case_prerequisites_missing_notes(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        investigator = make_principal(RoleCode.INVESTIGATOR)
        case_entity = make_case_entity(
            department_id=investigator.department_id,
            status=CaseStatus.UNDER_INVESTIGATION.value,
            version_id=2,
        )
        repos["case"].get_by_id.return_value = case_entity
        repos["case"].list_notes_for_case.return_value = []
        repos["case"].list_findings_for_case.return_value = []

        with pytest.raises(BusinessRuleError, match="without investigation findings or notes"):
            await service.transition_case_status(
                case_entity.id,
                investigator,
                CaseTransitionRequest(
                    target_status="pending_review",
                    expected_version_id=2,
                    reason="Premature submission without notes or findings.",
                ),
            )

    @pytest.mark.asyncio
    async def test_transition_case_concurrency_conflict(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        investigator = make_principal(RoleCode.INVESTIGATOR)
        case_entity = make_case_entity(
            department_id=investigator.department_id,
            status=CaseStatus.OPEN.value,
            version_id=5,
        )
        repos["case"].get_by_id.return_value = case_entity

        with pytest.raises(ConflictError, match="Case version conflict"):
            await service.transition_case_status(
                case_entity.id,
                investigator,
                CaseTransitionRequest(
                    target_status="under_investigation",
                    expected_version_id=1,
                    reason="Stale expected version.",
                ),
            )

    @pytest.mark.asyncio
    async def test_escalation_concurrency_and_list(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        admin = make_principal(RoleCode.DEPT_ADMIN)
        case_entity = make_case_entity(
            department_id=admin.department_id,
            version_id=3,
        )
        repos["case"].get_by_id.return_value = case_entity
        target_dept = Department(id=uuid4(), code="LEGAL", name="General Counsel", is_active=True)
        repos["department"].get_by_id.return_value = target_dept

        # Concurrency conflict
        with pytest.raises(ConflictError, match="Case version conflict"):
            await service.escalate_case(
                case_entity.id,
                admin,
                CaseEscalationRequest(
                    escalated_to_department_id=target_dept.id,
                    reason="Escalating for legal consultation.",
                    expected_version_id=1,
                ),
            )

        # List escalations
        repos["case"].list_escalations_for_case.return_value = []
        escs = await service.list_case_escalations(case_entity.id, admin)
        assert escs == []

    @pytest.mark.asyncio
    async def test_referrals_target_dept_not_found_and_list(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        admin = make_principal(RoleCode.DEPT_ADMIN)
        case_entity = make_case_entity(department_id=admin.department_id)
        repos["case"].get_by_id.return_value = case_entity
        repos["department"].get_by_id.return_value = None

        with pytest.raises(ResourceNotFoundError, match="Target referral department not found"):
            await service.refer_case(
                case_entity.id,
                admin,
                CaseReferralCreate(
                    target_department_id=uuid4(),
                    referral_purpose="Transferring disciplinary review to conduct board.",
                ),
            )

        # List referrals
        repos["case"].list_referrals_for_case.return_value = []
        refs = await service.list_case_referrals(case_entity.id, admin)
        assert refs == []

    @pytest.mark.asyncio
    async def test_reopen_case_errors(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        admin = make_principal(RoleCode.DEPT_ADMIN)
        # Not in terminal status
        open_case = make_case_entity(
            department_id=admin.department_id,
            status=CaseStatus.UNDER_INVESTIGATION.value,
            version_id=2,
        )
        repos["case"].get_by_id.return_value = open_case

        with pytest.raises(
            BusinessRuleError, match="Only resolved or closed cases can be reopened"
        ):
            await service.reopen_case(
                open_case.id,
                admin,
                CaseReopenRequest(
                    reason="Attempting to reopen an already active investigation.",
                    expected_version_id=2,
                ),
            )

        # Concurrency conflict
        closed_case = make_case_entity(
            department_id=admin.department_id,
            status=CaseStatus.CLOSED.value,
            version_id=5,
        )
        repos["case"].get_by_id.return_value = closed_case

        with pytest.raises(ConflictError, match="Case version conflict"):
            await service.reopen_case(
                closed_case.id,
                admin,
                CaseReopenRequest(
                    reason="Legitimate new forensic analysis received from state forensics.",
                    expected_version_id=1,
                ),
            )

    @pytest.mark.asyncio
    async def test_case_note_history_errors(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        investigator = make_principal(RoleCode.INVESTIGATOR)
        case_id = uuid4()
        note_id = uuid4()

        # Case not found
        repos["case"].get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError, match="Case not found"):
            await service.get_case_note_history(case_id, note_id, investigator)

        # Case found, but note not found
        case_entity = make_case_entity(case_id=case_id, department_id=investigator.department_id)
        repos["case"].get_by_id.return_value = case_entity
        repos["case"].get_note_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError, match="Case note not found"):
            await service.get_case_note_history(case_id, note_id, investigator)

        # Note belongs to a different case
        foreign_note = CaseNote(
            id=note_id,
            case_id=uuid4(),
            author_id=investigator.user_id,
            visibility="internal",
            content="Foreign note",
            version_id=1,
            is_archived=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        repos["case"].get_note_by_id.return_value = foreign_note
        with pytest.raises(ResourceNotFoundError, match="Case note not found"):
            await service.get_case_note_history(case_id, note_id, investigator)

        # Restricted note history without permission
        restricted_note = CaseNote(
            id=note_id,
            case_id=case_id,
            author_id=uuid4(),
            visibility=CaseNoteVisibility.RESTRICTED.value,
            content="Restricted",
            version_id=1,
            is_archived=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        repos["case"].get_note_by_id.return_value = restricted_note
        with pytest.raises(PermissionDeniedError, match="Access to restricted note history denied"):
            await service.get_case_note_history(case_id, note_id, investigator)

    @pytest.mark.asyncio
    async def test_case_finding_invalid_ai_or_incident_refs(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        investigator = make_principal(RoleCode.INVESTIGATOR)
        case_entity = make_case_entity(department_id=investigator.department_id)
        repos["case"].get_by_id.return_value = case_entity

        # Invalid AI segment reference
        repos["case"].list_case_evidence.return_value = []
        repos["case"].list_case_ai_segments.return_value = []
        with pytest.raises(BusinessRuleError, match="is not linked to this case"):
            await service.create_case_finding(
                case_entity.id,
                investigator,
                CaseFindingCreate(
                    title="Finding with invalid AI reference",
                    description="Valid description for test finding.",
                    finding_type="preliminary",
                    ai_segment_ids=[uuid4()],
                ),
            )

        # Invalid Incident reference
        repos["case"].list_case_incidents.return_value = []
        with pytest.raises(BusinessRuleError, match="is not linked to this case"):
            await service.create_case_finding(
                case_entity.id,
                investigator,
                CaseFindingCreate(
                    title="Finding with invalid incident reference",
                    description="Valid description for test finding.",
                    finding_type="preliminary",
                    incident_ids=[uuid4()],
                ),
            )

    @pytest.mark.asyncio
    async def test_case_finding_history_not_found(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        investigator = make_principal(RoleCode.INVESTIGATOR)
        case_id = uuid4()
        finding_id = uuid4()

        repos["case"].get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError, match="Case not found"):
            await service.get_case_finding_history(case_id, finding_id, investigator)

        case_entity = make_case_entity(case_id=case_id, department_id=investigator.department_id)
        repos["case"].get_by_id.return_value = case_entity
        repos["case"].get_finding_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError, match="Case finding not found"):
            await service.get_case_finding_history(case_id, finding_id, investigator)

    @pytest.mark.asyncio
    async def test_case_finding_update_all_fields(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        investigator = make_principal(RoleCode.INVESTIGATOR)
        case_entity = make_case_entity(department_id=investigator.department_id)
        repos["case"].get_by_id.return_value = case_entity

        finding = CaseFinding(
            id=uuid4(),
            case_id=case_entity.id,
            author_id=investigator.user_id,
            finding_type=CaseFindingType.PRELIMINARY.value,
            title="Initial Title",
            description="Initial Description",
            evidence_ids_json=None,
            ai_segment_ids_json=None,
            incident_ids_json=None,
            version_id=1,
            is_preliminary=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        repos["case"].get_finding_by_id.return_value = finding
        repos["case"].create_finding_history.return_value = MagicMock()
        repos["case"].session.flush = AsyncMock()

        updated = await service.update_case_finding(
            case_entity.id,
            finding.id,
            investigator,
            CaseFindingUpdate(
                title="Updated Final Title",
                description="Updated full description of evidentiary finding.",
                finding_type=CaseFindingType.INCULPATORY.value,
                is_preliminary=False,
                evidence_ids=[uuid4()],
                ai_segment_ids=[uuid4()],
                incident_ids=[uuid4()],
                expected_version_id=1,
                reason="Refining finding with new digital forensics corroboration.",
            ),
        )
        assert updated.title == "Updated Final Title"
        assert updated.finding_type == CaseFindingType.INCULPATORY.value
        assert updated.is_preliminary is False
        assert updated.version_id == 2

    @pytest.mark.asyncio
    async def test_transition_case_status_additional_branches(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        investigator = make_principal(RoleCode.INVESTIGATOR)

        # Case not found
        repos["case"].get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError, match="Case not found"):
            await service.transition_case_status(
                uuid4(),
                investigator,
                CaseTransitionRequest(
                    target_status="open",
                    expected_version_id=1,
                    reason="Transition reason",
                ),
            )

        case_entity = make_case_entity(
            department_id=investigator.department_id,
            status=CaseStatus.PENDING_REVIEW.value,
            version_id=1,
        )
        repos["case"].get_by_id.return_value = case_entity

        # Direct transition to RESOLVED without CASE_TRANSITION_APPROVE permission
        with pytest.raises(
            PermissionDeniedError, match="Direct case resolution requires supervisor approval"
        ):
            await service.transition_case_status(
                case_entity.id,
                investigator,
                CaseTransitionRequest(
                    target_status="resolved",
                    expected_version_id=1,
                    reason="Investigator attempting direct resolution without supervisor approval.",
                ),
            )

        # Target CLOSED without CASE_CLOSE permission
        with pytest.raises(
            PermissionDeniedError, match="You do not have permission to close cases"
        ):
            await service.transition_case_status(
                case_entity.id,
                investigator,
                CaseTransitionRequest(
                    target_status="closed",
                    expected_version_id=1,
                    reason="Investigator attempting case closure without closure permission.",
                ),
            )

        # Direct transition to RESOLVED with DEPT_ADMIN permission succeeds and sets closed_at
        admin = make_principal(RoleCode.DEPT_ADMIN, department_id=investigator.department_id)
        repos["case"].session.flush = AsyncMock()
        resolved_case = await service.transition_case_status(
            case_entity.id,
            admin,
            CaseTransitionRequest(
                target_status="resolved",
                expected_version_id=1,
                reason="Formal resolution approved by department supervisor.",
            ),
        )
        assert resolved_case.status == "resolved"
        assert resolved_case.closed_at is not None

    @pytest.mark.asyncio
    async def test_approve_case_transition_additional_branches(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        investigator = make_principal(RoleCode.INVESTIGATOR)
        admin = make_principal(RoleCode.DEPT_ADMIN, department_id=investigator.department_id)

        # Permission denied for standard investigator
        with pytest.raises(
            PermissionDeniedError, match="You do not have permission to approve case transitions"
        ):
            await service.approve_case_transition(
                uuid4(),
                investigator,
                CaseApprovalRequest(
                    decision="approved",
                    from_status="pending_review",
                    to_status="resolved",
                    expected_version_id=1,
                    rationale="Unauthorized investigator approval attempt.",
                ),
            )

        # Case not found
        repos["case"].get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError, match="Case not found"):
            await service.approve_case_transition(
                uuid4(),
                admin,
                CaseApprovalRequest(
                    decision="approved",
                    from_status="pending_review",
                    to_status="resolved",
                    expected_version_id=1,
                    rationale="Approval for nonexistent case.",
                ),
            )

        # Status mismatch
        case_entity = make_case_entity(
            department_id=admin.department_id,
            status=CaseStatus.UNDER_INVESTIGATION.value,
            version_id=1,
        )
        repos["case"].get_by_id.return_value = case_entity
        with pytest.raises(BusinessRuleError, match="Case status mismatch"):
            await service.approve_case_transition(
                case_entity.id,
                admin,
                CaseApprovalRequest(
                    decision="approved",
                    from_status="pending_review",
                    to_status="resolved",
                    expected_version_id=1,
                    rationale="Status mismatch approval attempt.",
                ),
            )

        # Approved to RESOLVED sets closed_at
        case_entity.status = CaseStatus.PENDING_REVIEW.value
        repos["case"].create_approval.return_value = CaseApproval(
            id=uuid4(),
            case_id=case_entity.id,
            approver_id=admin.user_id,
            decision=CaseApprovalDecision.APPROVED.value,
            from_status="pending_review",
            to_status="resolved",
            rationale="Approved to resolved.",
            created_at=datetime.now(UTC),
        )
        repos["case"].session.flush = AsyncMock()
        approval_res = await service.approve_case_transition(
            case_entity.id,
            admin,
            CaseApprovalRequest(
                decision="approved",
                from_status="pending_review",
                to_status="resolved",
                expected_version_id=1,
                rationale="Approved to resolved.",
            ),
        )
        assert approval_res.decision == "approved"
        assert case_entity.status == "resolved"
        assert case_entity.closed_at is not None

        # List approvals not found
        repos["case"].get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError, match="Case not found"):
            await service.list_case_approvals(uuid4(), admin)

    @pytest.mark.asyncio
    async def test_escalate_and_refer_additional_branches(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        investigator = make_principal(RoleCode.INVESTIGATOR)
        student = make_principal(RoleCode.STUDENT, department_id=investigator.department_id)
        admin = make_principal(RoleCode.DEPT_ADMIN, department_id=investigator.department_id)

        # Escalate permission denied
        with pytest.raises(
            PermissionDeniedError, match="You do not have permission to escalate cases"
        ):
            await service.escalate_case(
                uuid4(),
                student,
                CaseEscalationRequest(
                    escalated_to_department_id=uuid4(),
                    reason="Unauthorized escalation attempt.",
                    expected_version_id=1,
                ),
            )

        # Escalate case not found
        repos["case"].get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError, match="Case not found"):
            await service.escalate_case(
                uuid4(),
                admin,
                CaseEscalationRequest(
                    escalated_to_department_id=uuid4(),
                    reason="Escalate nonexistent case.",
                    expected_version_id=1,
                ),
            )

        # List escalations case not found
        with pytest.raises(ResourceNotFoundError, match="Case not found"):
            await service.list_case_escalations(uuid4(), admin)

        # Refer permission denied
        with pytest.raises(
            PermissionDeniedError, match="You do not have permission to refer cases"
        ):
            await service.refer_case(
                uuid4(),
                student,
                CaseReferralCreate(
                    target_external_agency="State Police Department",
                    referral_purpose="Unauthorized referral attempt.",
                ),
            )

        # Refer case not found
        with pytest.raises(ResourceNotFoundError, match="Case not found"):
            await service.refer_case(
                uuid4(),
                admin,
                CaseReferralCreate(
                    target_external_agency="State Police Department",
                    referral_purpose="Referral for nonexistent case.",
                ),
            )

        # Target external agency referral success (without target_department_id)
        case_entity = make_case_entity(department_id=admin.department_id)
        repos["case"].get_by_id.return_value = case_entity
        repos["case"].create_referral.side_effect = lambda ref: ref
        ref_created = await service.refer_case(
            case_entity.id,
            admin,
            CaseReferralCreate(
                target_external_agency="Federal Bureau of Investigation",
                referral_purpose="Escalation to federal authorities for cross-state digital evidence.",
            ),
        )
        assert ref_created.target_external_agency == "Federal Bureau of Investigation"

        # Update referral status permission denied
        with pytest.raises(
            PermissionDeniedError, match="You do not have permission to manage case referrals"
        ):
            await service.update_referral_status(
                case_entity.id,
                ref_created.id,
                student,
                CaseReferralUpdate(
                    status="accepted",
                    resolution_notes="Accepted by external authority.",
                ),
            )

        # Update referral status referral not found
        repos["case"].get_referral_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError, match="Case referral not found"):
            await service.update_referral_status(
                case_entity.id,
                ref_created.id,
                admin,
                CaseReferralUpdate(status="rejected"),
            )

        # List referrals case not found
        repos["case"].get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError, match="Case not found"):
            await service.list_case_referrals(uuid4(), admin)

    @pytest.mark.asyncio
    async def test_close_reopen_and_export_additional_branches(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        investigator = make_principal(RoleCode.INVESTIGATOR)
        student = make_principal(RoleCode.STUDENT, department_id=investigator.department_id)
        admin = make_principal(RoleCode.DEPT_ADMIN, department_id=investigator.department_id)

        # Close case permission denied
        with pytest.raises(
            PermissionDeniedError, match="You do not have permission to close cases"
        ):
            await service.close_case(
                uuid4(),
                investigator,
                CaseCloseRequest(reason="Unauthorized closure attempt.", expected_version_id=1),
            )

        # Close case not found
        repos["case"].get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError, match="Case not found"):
            await service.close_case(
                uuid4(),
                admin,
                CaseCloseRequest(reason="Close nonexistent case.", expected_version_id=1),
            )

        # Close case draft state rejected
        draft_case = make_case_entity(department_id=admin.department_id, status="draft")
        repos["case"].get_by_id.return_value = draft_case
        with pytest.raises(
            BusinessRuleError, match="Draft cases cannot be closed without being opened"
        ):
            await service.close_case(
                draft_case.id,
                admin,
                CaseCloseRequest(reason="Attempting to close draft case.", expected_version_id=1),
            )

        # Reopen case permission denied
        with pytest.raises(
            PermissionDeniedError, match="You do not have permission to reopen cases"
        ):
            await service.reopen_case(
                uuid4(),
                investigator,
                CaseReopenRequest(reason="Unauthorized reopening.", expected_version_id=1),
            )

        # Reopen case not found
        repos["case"].get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError, match="Case not found"):
            await service.reopen_case(
                uuid4(),
                admin,
                CaseReopenRequest(reason="Reopen nonexistent case.", expected_version_id=1),
            )

        # Export case permission denied
        with pytest.raises(
            PermissionDeniedError, match="You do not have permission to export cases"
        ):
            await service.export_case(
                uuid4(),
                student,
                CaseExportRequest(
                    export_scope="full_investigation",
                    export_format="json",
                    purpose="Unauthorized export attempt.",
                ),
            )

        # Export case not found
        repos["case"].get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError, match="Case not found"):
            await service.export_case(
                uuid4(),
                admin,
                CaseExportRequest(
                    export_scope="full_investigation",
                    export_format="json",
                    purpose="Export nonexistent case.",
                ),
            )

        # Get case export not found
        repos["case"].get_export_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError, match="Case export not found"):
            await service.get_case_export(uuid4(), admin)

        # Get case export cross-department not found
        foreign_export = CaseExport(
            id=uuid4(),
            case_id=uuid4(),
            department_id=uuid4(),
            exported_by_id=uuid4(),
            export_scope="full_investigation",
            export_format="json",
            manifest_sha256="0" * 64,
            evidence_count=0,
            manifest_payload="{}",
            status="completed",
            purpose="Foreign export inspection",
            expires_at=datetime.now(UTC),
            created_at=datetime.now(UTC),
        )
        repos["case"].get_export_by_id.return_value = foreign_export
        with pytest.raises(ResourceNotFoundError, match="Case export not found"):
            await service.get_case_export(foreign_export.id, admin)

        # Get case export with invalid JSON payload falls back to empty dict
        same_dept_export = CaseExport(
            id=uuid4(),
            case_id=uuid4(),
            department_id=admin.department_id,
            exported_by_id=admin.user_id,
            export_scope="full_investigation",
            export_format="json",
            manifest_sha256="0" * 64,
            evidence_count=0,
            manifest_payload="NOT_VALID_JSON{",
            status="completed",
            purpose="Corrupted payload test",
            expires_at=datetime.now(UTC),
            created_at=datetime.now(UTC),
        )
        repos["case"].get_export_by_id.return_value = same_dept_export
        res = await service.get_case_export(same_dept_export.id, admin)
        assert res.manifest_payload == {}

    @pytest.mark.asyncio
    async def test_export_case_restricted_notes_redaction_and_inclusion(
        self,
        mock_service: tuple[CaseService, dict[str, AsyncMock]],
    ) -> None:
        service, repos = mock_service
        investigator = make_principal(RoleCode.INVESTIGATOR)
        admin = make_principal(RoleCode.DEPT_ADMIN, department_id=investigator.department_id)

        case_entity = make_case_entity(department_id=investigator.department_id)
        repos["case"].get_by_id.return_value = case_entity
        repos["case"].list_case_evidence.return_value = []
        repos["case"].list_findings_for_case.return_value = []
        repos["case"].list_case_ai_segments.return_value = []

        note_internal = CaseNote(
            id=uuid4(),
            case_id=case_entity.id,
            author_id=investigator.user_id,
            visibility=CaseNoteVisibility.INTERNAL.value,
            content="Internal working note",
            version_id=1,
            is_archived=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        note_restricted = CaseNote(
            id=uuid4(),
            case_id=case_entity.id,
            author_id=admin.user_id,
            visibility=CaseNoteVisibility.RESTRICTED.value,
            content="Sensitive whistleblower lead",
            version_id=1,
            is_archived=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        repos["case"].list_notes_for_case.return_value = [note_internal, note_restricted]
        repos["case"].create_export.side_effect = lambda exp: exp

        # Export by investigator with include_restricted_notes=False -> note_restricted must be excluded!
        exp1 = await service.export_case(
            case_entity.id,
            investigator,
            CaseExportRequest(
                export_scope="full_investigation",
                export_format="json",
                purpose="Standard export without restricted notes",
                include_restricted_notes=False,
            ),
        )
        notes_in_payload1 = exp1.manifest_payload.get("notes", [])
        assert len(notes_in_payload1) == 1
        assert notes_in_payload1[0]["content"] == "Internal working note"

        # Export by admin with include_restricted_notes=True -> both notes included!
        exp2 = await service.export_case(
            case_entity.id,
            admin,
            CaseExportRequest(
                export_scope="full_investigation",
                export_format="json",
                purpose="Administrative export with restricted notes",
                include_restricted_notes=True,
            ),
        )
        notes_in_payload2 = exp2.manifest_payload.get("notes", [])
        assert len(notes_in_payload2) == 2

    def test_case_models_repr_methods(self) -> None:
        note = CaseNote(
            id=uuid4(),
            case_id=uuid4(),
            author_id=uuid4(),
            visibility="internal",
            content="repr test note",
            version_id=1,
            is_archived=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        assert "CaseNote" in repr(note)

        history = CaseNoteHistory(
            id=uuid4(),
            note_id=note.id,
            version_id=1,
            author_id=uuid4(),
            editor_id=uuid4(),
            content="repr test history",
            edit_reason="Correction",
            created_at=datetime.now(UTC),
        )
        assert "CaseNoteHistory" in repr(history)

        finding = CaseFinding(
            id=uuid4(),
            case_id=uuid4(),
            author_id=uuid4(),
            finding_type="preliminary",
            title="repr test finding",
            description="desc",
            version_id=1,
            is_preliminary=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        assert "CaseFinding" in repr(finding)

        f_hist = CaseFindingHistory(
            id=uuid4(),
            finding_id=finding.id,
            version_id=1,
            editor_id=uuid4(),
            title="repr test finding history",
            description="desc",
            reason="Update",
            created_at=datetime.now(UTC),
        )
        assert "CaseFindingHistory" in repr(f_hist)

        approval = CaseApproval(
            id=uuid4(),
            case_id=uuid4(),
            approver_id=uuid4(),
            decision="approved",
            from_status="pending_review",
            to_status="resolved",
            rationale="Looks good",
            created_at=datetime.now(UTC),
        )
        assert "CaseApproval" in repr(approval)

        escalation = CaseEscalation(
            id=uuid4(),
            case_id=uuid4(),
            escalated_by_id=uuid4(),
            escalated_to_department_id=uuid4(),
            reason="High severity",
            escalation_level="department_head",
            case_version_id=1,
            created_at=datetime.now(UTC),
        )
        assert "CaseEscalation" in repr(escalation)

        referral = CaseReferral(
            id=uuid4(),
            case_id=uuid4(),
            referred_by_id=uuid4(),
            referral_purpose="Legal advice",
            status="pending",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        assert "CaseReferral" in repr(referral)

        export_rec = CaseExport(
            id=uuid4(),
            case_id=uuid4(),
            department_id=uuid4(),
            exported_by_id=uuid4(),
            export_scope="full_case",
            export_format="json",
            manifest_sha256="a" * 64,
            evidence_count=1,
            manifest_payload="{}",
            status="completed",
            purpose="Court disclosure",
            created_at=datetime.now(UTC),
        )
        assert "CaseExport" in repr(export_rec)

    @pytest.mark.asyncio
    async def test_case_repository_methods_with_mock_session(self) -> None:
        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_result.scalars.return_value.first.return_value = None
        session.execute.return_value = mock_result
        session.flush = AsyncMock()
        session.add = MagicMock()

        repo = CaseRepository(session)
        case_id = uuid4()
        note_id = uuid4()
        finding_id = uuid4()
        referral_id = uuid4()
        export_id = uuid4()

        note = CaseNote(
            id=note_id,
            case_id=case_id,
            author_id=uuid4(),
            visibility="internal",
            content="Repo note test",
            version_id=1,
            is_archived=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        assert await repo.create_note(note) == note
        assert await repo.get_note_by_id(note_id) is None
        assert await repo.list_notes_for_case(case_id) == []

        note_hist = CaseNoteHistory(
            id=uuid4(),
            note_id=note_id,
            version_id=1,
            author_id=uuid4(),
            editor_id=uuid4(),
            content="Repo note hist test",
            edit_reason="Correction",
            created_at=datetime.now(UTC),
        )
        assert await repo.create_note_history(note_hist) == note_hist
        assert await repo.list_note_history(note_id) == []

        finding = CaseFinding(
            id=finding_id,
            case_id=case_id,
            author_id=uuid4(),
            finding_type="preliminary",
            title="Repo finding test",
            description="desc",
            version_id=1,
            is_preliminary=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        assert await repo.create_finding(finding) == finding
        assert await repo.get_finding_by_id(finding_id) is None
        assert await repo.list_findings_for_case(case_id) == []

        finding_hist = CaseFindingHistory(
            id=uuid4(),
            finding_id=finding_id,
            version_id=1,
            editor_id=uuid4(),
            title="Repo finding hist test",
            description="desc",
            reason="Update",
            created_at=datetime.now(UTC),
        )
        assert await repo.create_finding_history(finding_hist) == finding_hist
        assert await repo.list_finding_history(finding_id) == []

        approval = CaseApproval(
            id=uuid4(),
            case_id=case_id,
            approver_id=uuid4(),
            decision="approved",
            from_status="pending_review",
            to_status="resolved",
            rationale="Approved",
            created_at=datetime.now(UTC),
        )
        assert await repo.create_approval(approval) == approval
        assert await repo.list_approvals_for_case(case_id) == []

        escalation = CaseEscalation(
            id=uuid4(),
            case_id=case_id,
            escalated_by_id=uuid4(),
            escalated_to_department_id=uuid4(),
            reason="High priority",
            escalation_level="department_head",
            case_version_id=1,
            created_at=datetime.now(UTC),
        )
        assert await repo.create_escalation(escalation) == escalation
        assert await repo.list_escalations_for_case(case_id) == []

        referral = CaseReferral(
            id=referral_id,
            case_id=case_id,
            referred_by_id=uuid4(),
            referral_purpose="Legal consultation",
            status="pending",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        assert await repo.create_referral(referral) == referral
        assert await repo.get_referral_by_id(referral_id) is None
        assert await repo.list_referrals_for_case(case_id) == []

        export_rec = CaseExport(
            id=export_id,
            case_id=case_id,
            department_id=uuid4(),
            exported_by_id=uuid4(),
            export_scope="full_case",
            export_format="json",
            manifest_sha256="c" * 64,
            evidence_count=0,
            manifest_payload="{}",
            status="completed",
            purpose="Legal discovery",
            created_at=datetime.now(UTC),
        )
        assert await repo.create_export(export_rec) == export_rec
        assert await repo.get_export_by_id(export_id) is None
        assert await repo.list_exports_for_case(case_id) == []
