"""Investigation case persistence models and relational linkages (Phases 81-85).

Enforces:
- Normalized, unique case reference numbers (`CASE-YYYY-XXXXXXXX`).
- Strict department ownership binding cases to departments and accountable creators/investigators.
- Relational linkages connecting cases to incidents, evidence attachments, and AI candidate segments
  without duplicating underlying entities.
- Append-only assignment history for auditing and accountability.
- Concurrency versioning (`version_id`) for optimistic locking.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.case import (
    CaseApprovalDecision,
    CaseEscalationLevel,
    CaseExportFormat,
    CaseExportScope,
    CaseFindingType,
    CaseNoteVisibility,
    CasePriority,
    CaseReferralStatus,
    CaseStatus,
    IncidentLinkType,
    InvestigativeRelevance,
)
from backend.app.models.base import (
    Base,
    TimestampMixin,
    UTCDateTime,
    UUIDPrimaryKeyMixin,
    utc_now,
)

if TYPE_CHECKING:
    from backend.app.models.ai import AICandidateSegment
    from backend.app.models.department import Department
    from backend.app.models.evidence import EvidenceAttachment
    from backend.app.models.incident import Incident
    from backend.app.models.user import User


_STATUS_VALUES = ", ".join(f"'{s.value}'" for s in CaseStatus)
_PRIORITY_VALUES = ", ".join(f"'{p.value}'" for p in CasePriority)
_LINK_TYPE_VALUES = ", ".join(f"'{t.value}'" for t in IncidentLinkType)
_RELEVANCE_VALUES = ", ".join(f"'{r.value}'" for r in InvestigativeRelevance)
_NOTE_VISIBILITY_VALUES = ", ".join(f"'{v.value}'" for v in CaseNoteVisibility)
_FINDING_TYPE_VALUES = ", ".join(f"'{f.value}'" for f in CaseFindingType)
_APPROVAL_DECISION_VALUES = ", ".join(f"'{a.value}'" for a in CaseApprovalDecision)
_ESCALATION_LEVEL_VALUES = ", ".join(f"'{e.value}'" for e in CaseEscalationLevel)
_REFERRAL_STATUS_VALUES = ", ".join(f"'{r.value}'" for r in CaseReferralStatus)
_EXPORT_SCOPE_VALUES = ", ".join(f"'{s.value}'" for s in CaseExportScope)
_EXPORT_FORMAT_VALUES = ", ".join(f"'{f.value}'" for f in CaseExportFormat)


class Case(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Investigation case record (`cases` table)."""

    __tablename__ = "cases"
    __table_args__ = (
        Index("ix_cases_reference_number", "reference_number", unique=True),
        Index("ix_cases_department_id_status", "department_id", "status"),
        Index("ix_cases_lead_investigator_id_status", "lead_investigator_id", "status"),
        Index("ix_cases_created_by_id", "created_by_id"),
        Index("ix_cases_created_at", "created_at"),
        CheckConstraint(
            "length(trim(title)) >= 5 AND length(title) <= 200",
            name="ck_cases_title_length",
        ),
        CheckConstraint(
            "length(trim(summary)) >= 10 AND length(summary) <= 10000",
            name="ck_cases_summary_length",
        ),
        CheckConstraint(
            f"status IN ({_STATUS_VALUES})",
            name="ck_cases_status_allowed_values",
        ),
        CheckConstraint(
            f"priority IN ({_PRIORITY_VALUES})",
            name="ck_cases_priority_allowed_values",
        ),
        CheckConstraint(
            "reference_number = upper(trim(reference_number)) AND length(reference_number) >= 13",
            name="ck_cases_reference_number_normalized",
        ),
        CheckConstraint(
            "version_id >= 1",
            name="ck_cases_version_id_positive",
        ),
    )

    reference_number: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )
    summary: Mapped[str] = mapped_column(
        String(10000),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=CaseStatus.OPEN.value,
        server_default=CaseStatus.OPEN.value,
    )
    priority: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=CasePriority.MEDIUM.value,
        server_default=CasePriority.MEDIUM.value,
    )
    department_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_by_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    lead_investigator_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        default=None,
    )
    version_id: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=1,
        server_default="1",
    )
    is_legal_hold: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )
    legal_hold_reason: Mapped[str | None] = mapped_column(
        String(1000),
        nullable=True,
        default=None,
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
        default=None,
    )

    # Relational associations
    department: Mapped[Department] = relationship(
        "Department",
        foreign_keys=[department_id],
        lazy="selectin",
    )
    creator: Mapped[User] = relationship(
        "User",
        foreign_keys=[created_by_id],
        lazy="selectin",
    )
    lead_investigator: Mapped[User | None] = relationship(
        "User",
        foreign_keys=[lead_investigator_id],
        lazy="selectin",
    )
    incidents: Mapped[list[CaseIncident]] = relationship(
        "CaseIncident",
        back_populates="case",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="CaseIncident.created_at",
    )
    evidence: Mapped[list[CaseEvidence]] = relationship(
        "CaseEvidence",
        back_populates="case",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="CaseEvidence.created_at",
    )
    ai_segments: Mapped[list[CaseAISegment]] = relationship(
        "CaseAISegment",
        back_populates="case",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="CaseAISegment.created_at",
    )
    assignments: Mapped[list[CaseAssignment]] = relationship(
        "CaseAssignment",
        back_populates="case",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="CaseAssignment.created_at",
    )
    notes: Mapped[list[CaseNote]] = relationship(
        "CaseNote",
        back_populates="case",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="CaseNote.created_at",
    )
    findings: Mapped[list[CaseFinding]] = relationship(
        "CaseFinding",
        back_populates="case",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="CaseFinding.created_at",
    )
    approvals: Mapped[list[CaseApproval]] = relationship(
        "CaseApproval",
        back_populates="case",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="CaseApproval.created_at",
    )
    escalations: Mapped[list[CaseEscalation]] = relationship(
        "CaseEscalation",
        back_populates="case",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="CaseEscalation.created_at",
    )
    referrals: Mapped[list[CaseReferral]] = relationship(
        "CaseReferral",
        back_populates="case",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="CaseReferral.created_at",
    )
    exports: Mapped[list[CaseExport]] = relationship(
        "CaseExport",
        back_populates="case",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="CaseExport.created_at",
    )

    def __repr__(self) -> str:
        return (
            f"<Case id={self.id} ref={self.reference_number!r} "
            f"status={self.status!r} priority={self.priority!r} dept_id={self.department_id}>"
        )


class CaseIncident(UUIDPrimaryKeyMixin, Base):
    """Relational association between an investigation case and an incident (`case_incidents` table)."""

    __tablename__ = "case_incidents"
    __table_args__ = (
        UniqueConstraint("case_id", "incident_id", name="uq_case_incidents_case_incident"),
        Index("ix_case_incidents_case_id", "case_id"),
        Index("ix_case_incidents_incident_id", "incident_id"),
        CheckConstraint(
            f"link_type IN ({_LINK_TYPE_VALUES})",
            name="ck_case_incidents_link_type",
        ),
    )

    case_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    incident_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
    )
    linked_by_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    link_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=IncidentLinkType.PRIMARY.value,
        server_default=IncidentLinkType.PRIMARY.value,
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )

    case: Mapped[Case] = relationship(
        "Case",
        back_populates="incidents",
        lazy="selectin",
    )
    incident: Mapped[Incident] = relationship(
        "Incident",
        foreign_keys=[incident_id],
        lazy="selectin",
    )
    linked_by: Mapped[User] = relationship(
        "User",
        foreign_keys=[linked_by_id],
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<CaseIncident case_id={self.case_id} incident_id={self.incident_id} type={self.link_type!r}>"


class CaseAssignment(UUIDPrimaryKeyMixin, Base):
    """Append-only assignment and reassignment audit record for cases (`case_assignments` table)."""

    __tablename__ = "case_assignments"
    __table_args__ = (
        Index("ix_case_assignments_case_created", "case_id", "created_at"),
        Index("ix_case_assignments_investigator", "new_investigator_id"),
    )

    case_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    previous_investigator_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        default=None,
    )
    new_investigator_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    assigned_by_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    assignment_reason: Mapped[str | None] = mapped_column(
        String(1000),
        nullable=True,
        default=None,
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )

    case: Mapped[Case] = relationship(
        "Case",
        back_populates="assignments",
        lazy="selectin",
    )
    previous_investigator: Mapped[User | None] = relationship(
        "User",
        foreign_keys=[previous_investigator_id],
        lazy="selectin",
    )
    new_investigator: Mapped[User] = relationship(
        "User",
        foreign_keys=[new_investigator_id],
        lazy="selectin",
    )
    assigned_by: Mapped[User] = relationship(
        "User",
        foreign_keys=[assigned_by_id],
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return (
            f"<CaseAssignment case_id={self.case_id} "
            f"from={self.previous_investigator_id} to={self.new_investigator_id}>"
        )


class CaseEvidence(UUIDPrimaryKeyMixin, Base):
    """Relational association binding evidence to an investigation case (`case_evidence` table)."""

    __tablename__ = "case_evidence"
    __table_args__ = (
        UniqueConstraint("case_id", "evidence_id", name="uq_case_evidence_case_evidence"),
        Index("ix_case_evidence_case_id", "case_id"),
        Index("ix_case_evidence_evidence_id", "evidence_id"),
    )

    case_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    evidence_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("evidence_attachments.id", ondelete="CASCADE"),
        nullable=False,
    )
    linked_by_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    notes: Mapped[str | None] = mapped_column(
        String(1000),
        nullable=True,
        default=None,
    )
    is_exhibiting: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )

    case: Mapped[Case] = relationship(
        "Case",
        back_populates="evidence",
        lazy="selectin",
    )
    evidence: Mapped[EvidenceAttachment] = relationship(
        "EvidenceAttachment",
        foreign_keys=[evidence_id],
        lazy="selectin",
    )
    linked_by: Mapped[User] = relationship(
        "User",
        foreign_keys=[linked_by_id],
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<CaseEvidence case_id={self.case_id} evidence_id={self.evidence_id}>"


class CaseAISegment(UUIDPrimaryKeyMixin, Base):
    """Relational association linking an AI candidate segment to a case (`case_ai_segments` table)."""

    __tablename__ = "case_ai_segments"
    __table_args__ = (
        UniqueConstraint("case_id", "segment_id", name="uq_case_ai_segments_case_segment"),
        Index("ix_case_ai_segments_case_id", "case_id"),
        Index("ix_case_ai_segments_segment_id", "segment_id"),
        CheckConstraint(
            f"investigative_relevance IN ({_RELEVANCE_VALUES})",
            name="ck_case_ai_segments_relevance",
        ),
    )

    case_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    segment_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("ai_candidate_segments.id", ondelete="CASCADE"),
        nullable=False,
    )
    linked_by_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    investigative_relevance: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default=InvestigativeRelevance.CANDIDATE_LEAD.value,
        server_default=InvestigativeRelevance.CANDIDATE_LEAD.value,
    )
    relevance_notes: Mapped[str | None] = mapped_column(
        String(1000),
        nullable=True,
        default=None,
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )

    case: Mapped[Case] = relationship(
        "Case",
        back_populates="ai_segments",
        lazy="selectin",
    )
    segment: Mapped[AICandidateSegment] = relationship(
        "AICandidateSegment",
        foreign_keys=[segment_id],
        lazy="selectin",
    )
    linked_by: Mapped[User] = relationship(
        "User",
        foreign_keys=[linked_by_id],
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return (
            f"<CaseAISegment case_id={self.case_id} segment_id={self.segment_id} "
            f"relevance={self.investigative_relevance!r}>"
        )


class CaseNote(UUIDPrimaryKeyMixin, Base):
    """Investigation case note with role/visibility restrictions (Phase 86)."""

    __tablename__ = "case_notes"
    __table_args__ = (
        Index("ix_case_notes_case_id", "case_id"),
        Index("ix_case_notes_author_id", "author_id"),
        Index("ix_case_notes_created_at", "created_at"),
        CheckConstraint(
            f"visibility IN ({_NOTE_VISIBILITY_VALUES})",
            name="ck_case_notes_visibility",
        ),
        CheckConstraint(
            "length(trim(content)) >= 5 AND length(content) <= 10000",
            name="ck_case_notes_content_length",
        ),
        CheckConstraint(
            "version_id >= 1",
            name="ck_case_notes_version_id_positive",
        ),
    )

    case_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    author_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    visibility: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=CaseNoteVisibility.INTERNAL.value,
        server_default=CaseNoteVisibility.INTERNAL.value,
    )
    content: Mapped[str] = mapped_column(
        String(10000),
        nullable=False,
    )
    version_id: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=1,
        server_default="1",
    )
    is_archived: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )
    evidence_reference_ids_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        default=None,
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    case: Mapped[Case] = relationship(
        "Case",
        back_populates="notes",
        lazy="selectin",
    )
    author: Mapped[User] = relationship(
        "User",
        foreign_keys=[author_id],
        lazy="selectin",
    )
    history: Mapped[list[CaseNoteHistory]] = relationship(
        "CaseNoteHistory",
        back_populates="note",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="CaseNoteHistory.created_at.desc()",
    )

    @property
    def evidence_reference_ids(self) -> list[str]:
        """Deserialize referenced evidence UUID strings."""
        if not self.evidence_reference_ids_json:
            return []
        try:
            val = json.loads(self.evidence_reference_ids_json)
            return list(val) if isinstance(val, list) else []
        except Exception:
            return []

    def __repr__(self) -> str:
        return f"<CaseNote id={self.id} case_id={self.case_id} author_id={self.author_id} vis={self.visibility!r}>"


class CaseNoteHistory(UUIDPrimaryKeyMixin, Base):
    """Historical version log for case note edits (Phase 86)."""

    __tablename__ = "case_note_history"
    __table_args__ = (
        Index("ix_case_note_history_note_version", "note_id", "version_id"),
        CheckConstraint(
            "length(trim(content)) >= 5 AND length(content) <= 10000",
            name="ck_case_note_history_content_length",
        ),
        CheckConstraint(
            "version_id >= 1",
            name="ck_case_note_history_version_id_positive",
        ),
    )

    note_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("case_notes.id", ondelete="CASCADE"),
        nullable=False,
    )
    version_id: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )
    author_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    editor_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    content: Mapped[str] = mapped_column(
        String(10000),
        nullable=False,
    )
    edit_reason: Mapped[str | None] = mapped_column(
        String(1000),
        nullable=True,
        default=None,
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )

    note: Mapped[CaseNote] = relationship(
        "CaseNote",
        back_populates="history",
        lazy="selectin",
    )
    editor: Mapped[User] = relationship(
        "User",
        foreign_keys=[editor_id],
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<CaseNoteHistory note_id={self.note_id} version={self.version_id}>"


class CaseFinding(UUIDPrimaryKeyMixin, Base):
    """Structured formal investigation finding with evidence and AI provenance links (Phase 86)."""

    __tablename__ = "case_findings"
    __table_args__ = (
        Index("ix_case_findings_case_id", "case_id"),
        Index("ix_case_findings_author_id", "author_id"),
        CheckConstraint(
            f"finding_type IN ({_FINDING_TYPE_VALUES})",
            name="ck_case_findings_type",
        ),
        CheckConstraint(
            "length(trim(title)) >= 5 AND length(title) <= 200",
            name="ck_case_findings_title_length",
        ),
        CheckConstraint(
            "length(trim(description)) >= 10 AND length(description) <= 10000",
            name="ck_case_findings_description_length",
        ),
        CheckConstraint(
            "version_id >= 1",
            name="ck_case_findings_version_id_positive",
        ),
    )

    case_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    author_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    finding_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=CaseFindingType.PRELIMINARY.value,
        server_default=CaseFindingType.PRELIMINARY.value,
    )
    title: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        String(10000),
        nullable=False,
    )
    evidence_ids_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        default=None,
    )
    ai_segment_ids_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        default=None,
    )
    incident_ids_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        default=None,
    )
    version_id: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=1,
        server_default="1",
    )
    is_preliminary: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    case: Mapped[Case] = relationship(
        "Case",
        back_populates="findings",
        lazy="selectin",
    )
    author: Mapped[User] = relationship(
        "User",
        foreign_keys=[author_id],
        lazy="selectin",
    )
    history: Mapped[list[CaseFindingHistory]] = relationship(
        "CaseFindingHistory",
        back_populates="finding",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="CaseFindingHistory.created_at.desc()",
    )

    @property
    def evidence_ids(self) -> list[str]:
        if not self.evidence_ids_json:
            return []
        try:
            val = json.loads(self.evidence_ids_json)
            return list(val) if isinstance(val, list) else []
        except Exception:
            return []

    @property
    def ai_segment_ids(self) -> list[str]:
        if not self.ai_segment_ids_json:
            return []
        try:
            val = json.loads(self.ai_segment_ids_json)
            return list(val) if isinstance(val, list) else []
        except Exception:
            return []

    @property
    def incident_ids(self) -> list[str]:
        if not self.incident_ids_json:
            return []
        try:
            val = json.loads(self.incident_ids_json)
            return list(val) if isinstance(val, list) else []
        except Exception:
            return []

    def __repr__(self) -> str:
        return f"<CaseFinding id={self.id} case_id={self.case_id} type={self.finding_type!r} title={self.title!r}>"


class CaseFindingHistory(UUIDPrimaryKeyMixin, Base):
    """Historical version log for investigation finding corrections (Phase 86)."""

    __tablename__ = "case_finding_history"
    __table_args__ = (
        Index("ix_case_finding_history_finding_version", "finding_id", "version_id"),
        CheckConstraint(
            "length(trim(title)) >= 5 AND length(title) <= 200",
            name="ck_case_finding_history_title_length",
        ),
        CheckConstraint(
            "length(trim(description)) >= 10 AND length(description) <= 10000",
            name="ck_case_finding_history_desc_length",
        ),
        CheckConstraint(
            "version_id >= 1",
            name="ck_case_finding_history_version_id_positive",
        ),
    )

    finding_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("case_findings.id", ondelete="CASCADE"),
        nullable=False,
    )
    version_id: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )
    editor_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        String(10000),
        nullable=False,
    )
    reason: Mapped[str | None] = mapped_column(
        String(1000),
        nullable=True,
        default=None,
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )

    finding: Mapped[CaseFinding] = relationship(
        "CaseFinding",
        back_populates="history",
        lazy="selectin",
    )
    editor: Mapped[User] = relationship(
        "User",
        foreign_keys=[editor_id],
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<CaseFindingHistory finding_id={self.finding_id} version={self.version_id}>"


class CaseApproval(UUIDPrimaryKeyMixin, Base):
    """Formal case transition approval decision record (Phase 87)."""

    __tablename__ = "case_approvals"
    __table_args__ = (
        Index("ix_case_approvals_case_id", "case_id"),
        Index("ix_case_approvals_approver_id", "approver_id"),
        CheckConstraint(
            f"decision IN ({_APPROVAL_DECISION_VALUES})",
            name="ck_case_approvals_decision",
        ),
        CheckConstraint(
            "length(trim(rationale)) >= 10 AND length(rationale) <= 2000",
            name="ck_case_approvals_rationale_length",
        ),
    )

    case_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    approver_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    decision: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    from_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    to_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    rationale: Mapped[str] = mapped_column(
        String(2000),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )

    case: Mapped[Case] = relationship(
        "Case",
        back_populates="approvals",
        lazy="selectin",
    )
    approver: Mapped[User] = relationship(
        "User",
        foreign_keys=[approver_id],
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<CaseApproval case_id={self.case_id} decision={self.decision!r} approver={self.approver_id}>"


class CaseEscalation(UUIDPrimaryKeyMixin, Base):
    """Case escalation to departmental or institutional leadership (Phase 88)."""

    __tablename__ = "case_escalations"
    __table_args__ = (
        Index("ix_case_escalations_case_id", "case_id"),
        Index("ix_case_escalations_escalated_to_dept", "escalated_to_department_id"),
        CheckConstraint(
            f"escalation_level IN ({_ESCALATION_LEVEL_VALUES})",
            name="ck_case_escalations_level",
        ),
        CheckConstraint(
            "length(trim(reason)) >= 10 AND length(reason) <= 1000",
            name="ck_case_escalations_reason_length",
        ),
    )

    case_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    escalated_by_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    escalated_to_department_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="RESTRICT"),
        nullable=False,
    )
    reason: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
    )
    escalation_level: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    case_version_id: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )

    case: Mapped[Case] = relationship(
        "Case",
        back_populates="escalations",
        lazy="selectin",
    )
    escalated_by: Mapped[User] = relationship(
        "User",
        foreign_keys=[escalated_by_id],
        lazy="selectin",
    )
    escalated_to_department: Mapped[Department] = relationship(
        "Department",
        foreign_keys=[escalated_to_department_id],
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<CaseEscalation case_id={self.case_id} to_dept={self.escalated_to_department_id} level={self.escalation_level!r}>"


class CaseReferral(UUIDPrimaryKeyMixin, Base):
    """Case referral to external agencies or internal partner departments (Phase 88)."""

    __tablename__ = "case_referrals"
    __table_args__ = (
        Index("ix_case_referrals_case_id", "case_id"),
        Index("ix_case_referrals_target_dept", "target_department_id"),
        CheckConstraint(
            f"status IN ({_REFERRAL_STATUS_VALUES})",
            name="ck_case_referrals_status",
        ),
        CheckConstraint(
            "length(trim(referral_purpose)) >= 10 AND length(referral_purpose) <= 1000",
            name="ck_case_referrals_purpose_length",
        ),
        CheckConstraint(
            "target_department_id IS NOT NULL OR target_external_agency IS NOT NULL",
            name="ck_case_referrals_target_present",
        ),
    )

    case_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    referred_by_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_department_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="SET NULL"),
        nullable=True,
        default=None,
    )
    target_external_agency: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True,
        default=None,
    )
    referral_purpose: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=CaseReferralStatus.PENDING.value,
        server_default=CaseReferralStatus.PENDING.value,
    )
    resolution_notes: Mapped[str | None] = mapped_column(
        String(2000),
        nullable=True,
        default=None,
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    case: Mapped[Case] = relationship(
        "Case",
        back_populates="referrals",
        lazy="selectin",
    )
    referred_by: Mapped[User] = relationship(
        "User",
        foreign_keys=[referred_by_id],
        lazy="selectin",
    )
    target_department: Mapped[Department | None] = relationship(
        "Department",
        foreign_keys=[target_department_id],
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<CaseReferral case_id={self.case_id} status={self.status!r}>"


class CaseExport(UUIDPrimaryKeyMixin, Base):
    """Cryptographically hashed, controlled disclosure case export package (Phase 89)."""

    __tablename__ = "case_exports"
    __table_args__ = (
        Index("ix_case_exports_case_id", "case_id"),
        Index("ix_case_exports_exported_by_id", "exported_by_id"),
        Index("ix_case_exports_department_id", "department_id"),
        CheckConstraint(
            f"export_scope IN ({_EXPORT_SCOPE_VALUES})",
            name="ck_case_exports_scope",
        ),
        CheckConstraint(
            f"export_format IN ({_EXPORT_FORMAT_VALUES})",
            name="ck_case_exports_format",
        ),
        CheckConstraint(
            "length(manifest_sha256) = 64",
            name="ck_case_exports_manifest_sha256_len",
        ),
    )

    case_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    department_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="RESTRICT"),
        nullable=False,
    )
    exported_by_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    export_scope: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    export_format: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    manifest_sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    evidence_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    manifest_payload: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="completed",
        server_default="completed",
    )
    purpose: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )

    case: Mapped[Case] = relationship(
        "Case",
        back_populates="exports",
        lazy="selectin",
    )
    department: Mapped[Department] = relationship(
        "Department",
        foreign_keys=[department_id],
        lazy="selectin",
    )
    exported_by: Mapped[User] = relationship(
        "User",
        foreign_keys=[exported_by_id],
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<CaseExport id={self.id} case_id={self.case_id} manifest_sha256={self.manifest_sha256!r}>"
