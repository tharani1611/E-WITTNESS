"""Case repository for investigation cases, assignments, and relational linkages (Phases 81-85).

Enforces:
- Scoped case querying by department and lead investigator.
- Allowlisted sort columns and directions.
- Case incident, evidence, and AI candidate segment linkages.
- Append-only assignment record persistence.
- Investigator active case counting for capacity controls.
"""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.core.case import TERMINAL_CASE_STATUSES
from backend.app.core.exceptions import BusinessRuleError
from backend.app.models.case import (
    Case,
    CaseAISegment,
    CaseApproval,
    CaseAssignment,
    CaseEscalation,
    CaseEvidence,
    CaseExport,
    CaseFinding,
    CaseFindingHistory,
    CaseIncident,
    CaseNote,
    CaseNoteHistory,
    CaseReferral,
)

_ALLOWED_SORT_COLUMNS = {
    "created_at": Case.created_at,
    "updated_at": Case.updated_at,
    "reference_number": Case.reference_number,
    "title": Case.title,
    "status": Case.status,
    "priority": Case.priority,
}


class CaseRepository:
    """Async database repository for Case entities and related linkages."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(self, case_record: Case) -> Case:
        """Persist a new Case entity."""
        self.session.add(case_record)
        await self.session.flush()
        reloaded = await self.get_by_id(case_record.id)
        return reloaded if reloaded is not None else case_record

    async def get_by_id(self, case_id: UUID) -> Case | None:
        """Retrieve a Case by primary key with its relational collections loaded."""
        stmt = (
            select(Case)
            .where(Case.id == case_id)
            .options(
                selectinload(Case.incidents).selectinload(CaseIncident.incident),
                selectinload(Case.assignments),
                selectinload(Case.evidence).selectinload(CaseEvidence.evidence),
                selectinload(Case.ai_segments).selectinload(CaseAISegment.segment),
                selectinload(Case.notes),
                selectinload(Case.findings),
                selectinload(Case.approvals),
                selectinload(Case.escalations),
                selectinload(Case.referrals),
                selectinload(Case.exports),
                selectinload(Case.department),
                selectinload(Case.creator),
                selectinload(Case.lead_investigator),
            )
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def get_by_reference_number(self, reference_number: str) -> Case | None:
        """Retrieve a Case by unique reference number."""
        clean_ref = reference_number.strip().upper()
        stmt = (
            select(Case)
            .where(Case.reference_number == clean_ref)
            .options(
                selectinload(Case.incidents).selectinload(CaseIncident.incident),
                selectinload(Case.assignments),
                selectinload(Case.evidence).selectinload(CaseEvidence.evidence),
                selectinload(Case.ai_segments).selectinload(CaseAISegment.segment),
                selectinload(Case.department),
                selectinload(Case.creator),
                selectinload(Case.lead_investigator),
            )
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def update(self, case_record: Case) -> Case:
        """Flush changes to an existing Case."""
        self.session.add(case_record)
        await self.session.flush()
        reloaded = await self.get_by_id(case_record.id)
        return reloaded if reloaded is not None else case_record

    async def list_paginated(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        department_id: UUID | None = None,
        lead_investigator_id: UUID | None = None,
        created_by_id: UUID | None = None,
        status: str | None = None,
        priority: str | None = None,
        is_legal_hold: bool | None = None,
        search: str | None = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> tuple[Sequence[Case], int]:
        """List cases with filtering, search, pagination, and allowlisted sorting."""
        # 1. Validate sort parameters
        order_key = sort_order.strip().lower()
        if order_key not in {"asc", "desc"}:
            raise BusinessRuleError(
                f"Invalid sort order '{sort_order}'. Allowed: 'asc', 'desc'.",
                code="INVALID_SORT_ORDER",
                status_code=400,
            )

        col_key = sort_by.strip().lower()
        sort_col = _ALLOWED_SORT_COLUMNS.get(col_key)
        if sort_col is None:
            allowed_cols = ", ".join(repr(k) for k in _ALLOWED_SORT_COLUMNS)
            raise BusinessRuleError(
                f"Invalid sort field '{sort_by}'. Allowed: {allowed_cols}.",
                code="INVALID_SORT_FIELD",
                status_code=400,
            )

        # 2. Build filter predicates
        predicates = []
        if department_id is not None:
            predicates.append(Case.department_id == department_id)
        if lead_investigator_id is not None:
            predicates.append(Case.lead_investigator_id == lead_investigator_id)
        if created_by_id is not None:
            predicates.append(Case.created_by_id == created_by_id)
        if status is not None:
            predicates.append(Case.status == status.strip().lower())
        if priority is not None:
            predicates.append(Case.priority == priority.strip().lower())
        if is_legal_hold is not None:
            predicates.append(Case.is_legal_hold == is_legal_hold)

        if search:
            clean_search = f"%{search.strip()}%"
            predicates.append(
                or_(
                    Case.title.ilike(clean_search),
                    Case.summary.ilike(clean_search),
                    Case.reference_number.ilike(clean_search),
                )
            )

        # 3. Query total count
        count_stmt = select(func.count(Case.id))
        if predicates:
            count_stmt = count_stmt.where(*predicates)
        count_res = await self.session.execute(count_stmt)
        total_count = count_res.scalar() or 0

        # 4. Query paginated rows
        direction = sort_col.desc() if order_key == "desc" else sort_col.asc()
        data_stmt = (
            select(Case)
            .options(
                selectinload(Case.incidents).selectinload(CaseIncident.incident),
                selectinload(Case.assignments),
                selectinload(Case.evidence).selectinload(CaseEvidence.evidence),
                selectinload(Case.ai_segments).selectinload(CaseAISegment.segment),
                selectinload(Case.department),
                selectinload(Case.creator),
                selectinload(Case.lead_investigator),
            )
            .order_by(direction)
            .limit(limit)
            .offset(offset)
        )
        if predicates:
            data_stmt = data_stmt.where(*predicates)

        data_res = await self.session.execute(data_stmt)
        rows = data_res.scalars().all()
        return rows, total_count

    async def count_active_cases_for_investigator(
        self,
        investigator_id: UUID,
        *,
        exclude_case_id: UUID | None = None,
    ) -> int:
        """Count active (non-terminal) cases assigned to the specified investigator."""
        terminal_values = [s.value for s in TERMINAL_CASE_STATUSES]
        stmt = select(func.count(Case.id)).where(
            Case.lead_investigator_id == investigator_id,
            Case.status.not_in(terminal_values),
        )
        if exclude_case_id is not None:
            stmt = stmt.where(Case.id != exclude_case_id)
        result = await self.session.execute(stmt)
        return result.scalar() or 0

    # -------------------------------------------------------------------------
    # Case Incidents
    # -------------------------------------------------------------------------

    async def link_incident(self, case_incident: CaseIncident) -> CaseIncident:
        """Link an incident to a case."""
        self.session.add(case_incident)
        await self.session.flush()
        return case_incident

    async def get_incident_link(self, case_id: UUID, incident_id: UUID) -> CaseIncident | None:
        """Get a specific case-incident link."""
        stmt = select(CaseIncident).where(
            CaseIncident.case_id == case_id,
            CaseIncident.incident_id == incident_id,
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def unlink_incident(self, case_id: UUID, incident_id: UUID) -> bool:
        """Unlink an incident from a case."""
        stmt = delete(CaseIncident).where(
            CaseIncident.case_id == case_id,
            CaseIncident.incident_id == incident_id,
        )
        res = await self.session.execute(stmt)
        rowcount = getattr(res, "rowcount", 0)
        return int(rowcount or 0) > 0

    async def list_case_incidents(self, case_id: UUID) -> Sequence[CaseIncident]:
        """List all incidents linked to a case."""
        stmt = (
            select(CaseIncident)
            .where(CaseIncident.case_id == case_id)
            .options(selectinload(CaseIncident.incident))
            .order_by(CaseIncident.created_at.asc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    # -------------------------------------------------------------------------
    # Case Assignments
    # -------------------------------------------------------------------------

    async def record_assignment(self, assignment: CaseAssignment) -> CaseAssignment:
        """Record an append-only assignment/reassignment entry."""
        self.session.add(assignment)
        await self.session.flush()
        return assignment

    async def list_assignments(self, case_id: UUID) -> Sequence[CaseAssignment]:
        """List historical assignment events for a case."""
        stmt = (
            select(CaseAssignment)
            .where(CaseAssignment.case_id == case_id)
            .order_by(CaseAssignment.created_at.asc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    # -------------------------------------------------------------------------
    # Case Evidence
    # -------------------------------------------------------------------------

    async def link_evidence(self, case_evidence: CaseEvidence) -> CaseEvidence:
        """Link an evidence attachment to a case."""
        self.session.add(case_evidence)
        await self.session.flush()
        return case_evidence

    async def get_evidence_link(self, case_id: UUID, evidence_id: UUID) -> CaseEvidence | None:
        """Get a specific case-evidence link."""
        stmt = select(CaseEvidence).where(
            CaseEvidence.case_id == case_id,
            CaseEvidence.evidence_id == evidence_id,
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def unlink_evidence(self, case_id: UUID, evidence_id: UUID) -> bool:
        """Unlink an evidence attachment from a case."""
        stmt = delete(CaseEvidence).where(
            CaseEvidence.case_id == case_id,
            CaseEvidence.evidence_id == evidence_id,
        )
        res = await self.session.execute(stmt)
        rowcount = getattr(res, "rowcount", 0)
        return int(rowcount or 0) > 0

    async def list_case_evidence(self, case_id: UUID) -> Sequence[CaseEvidence]:
        """List all evidence linked to a case."""
        stmt = (
            select(CaseEvidence)
            .where(CaseEvidence.case_id == case_id)
            .options(selectinload(CaseEvidence.evidence))
            .order_by(CaseEvidence.created_at.asc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    # -------------------------------------------------------------------------
    # Case AI Segments
    # -------------------------------------------------------------------------

    async def link_ai_segment(self, case_ai_segment: CaseAISegment) -> CaseAISegment:
        """Link an AI candidate segment to a case."""
        self.session.add(case_ai_segment)
        await self.session.flush()
        return case_ai_segment

    async def get_ai_segment_link(self, case_id: UUID, segment_id: UUID) -> CaseAISegment | None:
        """Get a specific case-AI segment link."""
        stmt = select(CaseAISegment).where(
            CaseAISegment.case_id == case_id,
            CaseAISegment.segment_id == segment_id,
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def unlink_ai_segment(self, case_id: UUID, segment_id: UUID) -> bool:
        """Unlink an AI candidate segment from a case."""
        stmt = delete(CaseAISegment).where(
            CaseAISegment.case_id == case_id,
            CaseAISegment.segment_id == segment_id,
        )
        res = await self.session.execute(stmt)
        rowcount = getattr(res, "rowcount", 0)
        return int(rowcount or 0) > 0

    async def list_case_ai_segments(self, case_id: UUID) -> Sequence[CaseAISegment]:
        """List all AI segments linked to a case."""
        stmt = (
            select(CaseAISegment)
            .where(CaseAISegment.case_id == case_id)
            .options(selectinload(CaseAISegment.segment))
            .order_by(CaseAISegment.created_at.asc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    # -------------------------------------------------------------------------
    # Case Notes & History (Phase 86)
    # -------------------------------------------------------------------------

    async def create_note(self, note: CaseNote) -> CaseNote:
        """Persist a new CaseNote."""
        self.session.add(note)
        await self.session.flush()
        return note

    async def get_note_by_id(self, note_id: UUID) -> CaseNote | None:
        """Retrieve a CaseNote by ID."""
        stmt = (
            select(CaseNote)
            .where(CaseNote.id == note_id)
            .options(
                selectinload(CaseNote.author),
                selectinload(CaseNote.history).selectinload(CaseNoteHistory.editor),
            )
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def list_notes_for_case(self, case_id: UUID) -> Sequence[CaseNote]:
        """List all active notes for a case."""
        stmt = (
            select(CaseNote)
            .where(CaseNote.case_id == case_id, CaseNote.is_archived.is_(False))
            .options(
                selectinload(CaseNote.author),
                selectinload(CaseNote.history).selectinload(CaseNoteHistory.editor),
            )
            .order_by(CaseNote.created_at.asc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def create_note_history(self, history: CaseNoteHistory) -> CaseNoteHistory:
        """Persist a note history version entry."""
        self.session.add(history)
        await self.session.flush()
        return history

    async def list_note_history(self, note_id: UUID) -> Sequence[CaseNoteHistory]:
        """List version history for a note."""
        stmt = (
            select(CaseNoteHistory)
            .where(CaseNoteHistory.note_id == note_id)
            .options(selectinload(CaseNoteHistory.editor))
            .order_by(CaseNoteHistory.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    # -------------------------------------------------------------------------
    # Case Findings & History (Phase 86)
    # -------------------------------------------------------------------------

    async def create_finding(self, finding: CaseFinding) -> CaseFinding:
        """Persist a new CaseFinding."""
        self.session.add(finding)
        await self.session.flush()
        return finding

    async def get_finding_by_id(self, finding_id: UUID) -> CaseFinding | None:
        """Retrieve a CaseFinding by ID."""
        stmt = (
            select(CaseFinding)
            .where(CaseFinding.id == finding_id)
            .options(
                selectinload(CaseFinding.author),
                selectinload(CaseFinding.history).selectinload(CaseFindingHistory.editor),
            )
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def list_findings_for_case(self, case_id: UUID) -> Sequence[CaseFinding]:
        """List all findings for a case."""
        stmt = (
            select(CaseFinding)
            .where(CaseFinding.case_id == case_id)
            .options(
                selectinload(CaseFinding.author),
                selectinload(CaseFinding.history).selectinload(CaseFindingHistory.editor),
            )
            .order_by(CaseFinding.created_at.asc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def create_finding_history(self, history: CaseFindingHistory) -> CaseFindingHistory:
        """Persist a finding history version entry."""
        self.session.add(history)
        await self.session.flush()
        return history

    async def list_finding_history(self, finding_id: UUID) -> Sequence[CaseFindingHistory]:
        """List version history for a finding."""
        stmt = (
            select(CaseFindingHistory)
            .where(CaseFindingHistory.finding_id == finding_id)
            .options(selectinload(CaseFindingHistory.editor))
            .order_by(CaseFindingHistory.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    # -------------------------------------------------------------------------
    # Case Approvals (Phase 87)
    # -------------------------------------------------------------------------

    async def create_approval(self, approval: CaseApproval) -> CaseApproval:
        """Persist a CaseApproval decision."""
        self.session.add(approval)
        await self.session.flush()
        return approval

    async def list_approvals_for_case(self, case_id: UUID) -> Sequence[CaseApproval]:
        """List approval history for a case."""
        stmt = (
            select(CaseApproval)
            .where(CaseApproval.case_id == case_id)
            .options(selectinload(CaseApproval.approver))
            .order_by(CaseApproval.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    # -------------------------------------------------------------------------
    # Case Escalations (Phase 88)
    # -------------------------------------------------------------------------

    async def create_escalation(self, escalation: CaseEscalation) -> CaseEscalation:
        """Persist a CaseEscalation record."""
        self.session.add(escalation)
        await self.session.flush()
        return escalation

    async def list_escalations_for_case(self, case_id: UUID) -> Sequence[CaseEscalation]:
        """List escalations for a case."""
        stmt = (
            select(CaseEscalation)
            .where(CaseEscalation.case_id == case_id)
            .options(
                selectinload(CaseEscalation.escalated_by),
                selectinload(CaseEscalation.escalated_to_department),
            )
            .order_by(CaseEscalation.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    # -------------------------------------------------------------------------
    # Case Referrals (Phase 88)
    # -------------------------------------------------------------------------

    async def create_referral(self, referral: CaseReferral) -> CaseReferral:
        """Persist a CaseReferral."""
        self.session.add(referral)
        await self.session.flush()
        return referral

    async def get_referral_by_id(self, referral_id: UUID) -> CaseReferral | None:
        """Retrieve a CaseReferral by ID."""
        stmt = (
            select(CaseReferral)
            .where(CaseReferral.id == referral_id)
            .options(
                selectinload(CaseReferral.referred_by),
                selectinload(CaseReferral.target_department),
            )
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def list_referrals_for_case(self, case_id: UUID) -> Sequence[CaseReferral]:
        """List referrals for a case."""
        stmt = (
            select(CaseReferral)
            .where(CaseReferral.case_id == case_id)
            .options(
                selectinload(CaseReferral.referred_by),
                selectinload(CaseReferral.target_department),
            )
            .order_by(CaseReferral.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    # -------------------------------------------------------------------------
    # Case Exports (Phase 89)
    # -------------------------------------------------------------------------

    async def create_export(self, export_record: CaseExport) -> CaseExport:
        """Persist a CaseExport record."""
        self.session.add(export_record)
        await self.session.flush()
        return export_record

    async def get_export_by_id(self, export_id: UUID) -> CaseExport | None:
        """Retrieve a CaseExport by ID."""
        stmt = (
            select(CaseExport)
            .where(CaseExport.id == export_id)
            .options(
                selectinload(CaseExport.exported_by),
                selectinload(CaseExport.department),
            )
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def list_exports_for_case(self, case_id: UUID) -> Sequence[CaseExport]:
        """List exports generated for a case."""
        stmt = (
            select(CaseExport)
            .where(CaseExport.case_id == case_id)
            .options(
                selectinload(CaseExport.exported_by),
                selectinload(CaseExport.department),
            )
            .order_by(CaseExport.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
