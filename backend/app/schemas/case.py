"""Pydantic v2 schemas for Investigation Cases and Linkages (Phases 81-85).

Enforces:
- Strict input validation bounds on case titles, summaries, and rationales.
- Optimistic locking version_id checks.
- Zero storage credential leakage in evidence inventory responses.
- Advisory disclaimers on all AI candidate segment responses.
- Typed enumerations for CaseStatus, CasePriority, IncidentLinkType, InvestigativeRelevance.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.app.core.case import (
    AI_ADVISORY_DISCLAIMER,
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
    parse_case_priority,
    parse_case_status,
)
from backend.app.core.exceptions import BusinessRuleError

# =============================================================================
# Case CRUD Schemas (Phase 81)
# =============================================================================


class CaseCreate(BaseModel):
    """Payload for initiating a new investigation case."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "title": "Investigation into Examination Misconduct Incident",
                "summary": "Formal inquiry into unauthorized material discovered in examination hall 3B.",
                "priority": "medium",
                "department_id": "a0000000-0000-0000-0000-000000000001",
            }
        },
    )

    title: str = Field(
        ...,
        min_length=5,
        max_length=200,
        description="Concise, formal title of the investigation case (5-200 chars).",
    )
    summary: str = Field(
        ...,
        min_length=10,
        max_length=10000,
        description="Comprehensive summary statement of the case objectives and background.",
    )
    priority: CasePriority = Field(
        default=CasePriority.MEDIUM,
        description="Case triage priority (low, medium, high, critical).",
    )
    department_id: UUID | None = Field(
        default=None,
        description="Owning department ID. Defaults to caller's assigned department if omitted.",
    )
    lead_investigator_id: UUID | None = Field(
        default=None,
        description="Optional investigator to assign as lead upon case initiation.",
    )
    initial_incident_id: UUID | None = Field(
        default=None,
        description="Optional initial incident ID to link immediately upon creation.",
    )

    @field_validator("priority", mode="before")
    @classmethod
    def validate_priority(cls, value: Any) -> CasePriority:
        if isinstance(value, CasePriority):
            return value
        if isinstance(value, str):
            try:
                return parse_case_priority(value)
            except BusinessRuleError as exc:
                raise ValueError(exc.message) from None
        raise ValueError(f"Invalid priority format: {value}")


class CaseUpdate(BaseModel):
    """Payload for updating case details or status with optimistic locking."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    title: str | None = Field(
        default=None,
        min_length=5,
        max_length=200,
        description="Updated case title (5-200 chars).",
    )
    summary: str | None = Field(
        default=None,
        min_length=10,
        max_length=10000,
        description="Updated case summary.",
    )
    priority: CasePriority | None = Field(
        default=None,
        description="Updated case priority.",
    )
    status: CaseStatus | None = Field(
        default=None,
        description="Target status for state machine transition.",
    )
    status_reason: str | None = Field(
        default=None,
        max_length=1000,
        description="Documented rationale for status change (required for terminal transitions).",
    )
    is_legal_hold: bool | None = Field(
        default=None,
        description="Toggle legal-hold evidence preservation flag.",
    )
    legal_hold_reason: str | None = Field(
        default=None,
        max_length=1000,
        description="Required justification when placing case under legal hold.",
    )
    expected_version: int = Field(
        ...,
        ge=1,
        description="Expected version_id for optimistic concurrency control.",
    )

    @field_validator("priority", mode="before")
    @classmethod
    def validate_priority(cls, value: Any) -> CasePriority | None:
        if value is None or isinstance(value, CasePriority):
            return value
        if isinstance(value, str):
            try:
                return parse_case_priority(value)
            except BusinessRuleError as exc:
                raise ValueError(exc.message) from None
        raise ValueError(f"Invalid priority format: {value}")

    @field_validator("status", mode="before")
    @classmethod
    def validate_status(cls, value: Any) -> CaseStatus | None:
        if value is None or isinstance(value, CaseStatus):
            return value
        if isinstance(value, str):
            try:
                return parse_case_status(value)
            except BusinessRuleError as exc:
                raise ValueError(exc.message) from None
        raise ValueError(f"Invalid status format: {value}")


class CaseRead(BaseModel):
    """Case representation for read operations."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    reference_number: str
    title: str
    summary: str
    status: CaseStatus
    priority: CasePriority
    department_id: UUID
    created_by_id: UUID
    lead_investigator_id: UUID | None = None
    version_id: int
    is_legal_hold: bool
    legal_hold_reason: str | None = None
    closed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    incidents_count: int = 0
    evidence_count: int = 0
    ai_segments_count: int = 0
    department_name: str | None = None
    lead_investigator_name: str | None = None


class PaginatedCasesRead(BaseModel):
    """Paginated collection of CaseRead items."""

    items: list[CaseRead]
    total: int
    limit: int
    offset: int


# =============================================================================
# Case Assignment & Capacity Schemas (Phase 82)
# =============================================================================


class CaseAssignRequest(BaseModel):
    """Payload for assigning or reassigning a case lead investigator."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    new_investigator_id: UUID = Field(
        ...,
        description="User ID of the investigator to be assigned as lead.",
    )
    assignment_reason: str | None = Field(
        default=None,
        max_length=1000,
        description="Audit documentation explaining the assignment or transfer of leadership.",
    )
    expected_version: int = Field(
        ...,
        ge=1,
        description="Expected version_id for optimistic concurrency control.",
    )


class CaseAssignmentRead(BaseModel):
    """Read schema for an append-only case assignment history entry."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    case_id: UUID
    previous_investigator_id: UUID | None = None
    new_investigator_id: UUID
    assigned_by_id: UUID
    assignment_reason: str | None = None
    created_at: datetime


class InvestigatorWorkloadRead(BaseModel):
    """Read schema for investigator active case workload and capacity."""

    investigator_id: UUID
    active_cases_count: int
    max_active_cases: int
    capacity_available: bool


# =============================================================================
# Case Incidents Schemas (Phase 81)
# =============================================================================


class CaseLinkIncidentRequest(BaseModel):
    """Payload for linking an incident to an investigation case."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    incident_id: UUID = Field(
        ...,
        description="ID of the incident to link.",
    )
    link_type: IncidentLinkType = Field(
        default=IncidentLinkType.PRIMARY,
        description="Relationship type: primary, related, or evidence_source.",
    )

    @field_validator("link_type", mode="before")
    @classmethod
    def validate_link_type(cls, value: Any) -> IncidentLinkType:
        if isinstance(value, IncidentLinkType):
            return value
        if isinstance(value, str):
            clean = value.strip().lower()
            for t in IncidentLinkType:
                if t.value == clean:
                    return t
        raise ValueError(f"Invalid incident link type: {value}")


class CaseIncidentRead(BaseModel):
    """Read schema for a linked case-incident association."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    case_id: UUID
    incident_id: UUID
    linked_by_id: UUID
    link_type: IncidentLinkType
    created_at: datetime
    incident_title: str | None = None
    incident_reference_number: str | None = None
    incident_status: str | None = None


# =============================================================================
# Case Evidence Schemas (Phase 83)
# =============================================================================


class CaseLinkEvidenceRequest(BaseModel):
    """Payload for attaching existing evidence to an investigation case."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    evidence_id: UUID = Field(
        ...,
        description="ID of the EvidenceAttachment to bind to the case.",
    )
    notes: str | None = Field(
        default=None,
        max_length=1000,
        description="Investigator notes describing the relevance of this evidence item.",
    )
    is_exhibiting: bool = Field(
        default=True,
        description="Whether this item is formally marked as an investigative exhibit.",
    )


class CaseEvidenceItemRead(BaseModel):
    """Enriched case evidence item with integrity verification metadata.

    NEVER exposes internal storage credentials, presigned upload URLs, or raw bucket keys.
    """

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    case_id: UUID
    evidence_id: UUID
    linked_by_id: UUID
    notes: str | None = None
    is_exhibiting: bool
    created_at: datetime

    # Enriched Evidence metadata
    file_name: str
    file_size_bytes: int
    content_type: str
    sha256_hash: str
    integrity_status: str = "verified"
    is_legal_hold: bool = False
    chain_of_custody_events_count: int = 0


# =============================================================================
# Case AI Candidate Segments & Human Review (Phases 84 & 85)
# =============================================================================


class CaseLinkAISegmentRequest(BaseModel):
    """Payload for linking an AI candidate segment into an investigation case."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    segment_id: UUID = Field(
        ...,
        description="ID of the AICandidateSegment to link.",
    )
    investigative_relevance: InvestigativeRelevance = Field(
        default=InvestigativeRelevance.CANDIDATE_LEAD,
        description="Initial investigative relevance tag.",
    )
    relevance_notes: str | None = Field(
        default=None,
        max_length=1000,
        description="Investigator context regarding why this segment is relevant.",
    )

    @field_validator("investigative_relevance", mode="before")
    @classmethod
    def validate_relevance(cls, value: Any) -> InvestigativeRelevance:
        if isinstance(value, InvestigativeRelevance):
            return value
        if isinstance(value, str):
            clean = value.strip().lower()
            for r in InvestigativeRelevance:
                if r.value == clean:
                    return r
        raise ValueError(f"Invalid investigative relevance: {value}")


class CaseAISegmentRead(BaseModel):
    """Enriched AI candidate segment linked to a case.

    Always contains the mandatory non-authoritative advisory disclaimer.
    """

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    case_id: UUID
    segment_id: UUID
    linked_by_id: UUID
    investigative_relevance: InvestigativeRelevance
    relevance_notes: str | None = None
    created_at: datetime

    # AI Segment provenance and model outputs
    job_id: UUID
    evidence_id: UUID
    incident_id: UUID
    start_seconds: float
    end_seconds: float
    score: float
    label: str
    review_status: str
    reviewed_by_id: UUID | None = None
    reviewed_at: datetime | None = None
    review_notes: str | None = None

    # Mandatory disclaimer
    advisory_disclaimer: str = AI_ADVISORY_DISCLAIMER


class CaseAISegmentReviewRequest(BaseModel):
    """Payload for authorized human review and classification of an AI candidate segment."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    review_status: str = Field(
        ...,
        description="Human review determination: confirmed, rejected, inconclusive, or escalated.",
    )
    review_rationale: str = Field(
        ...,
        min_length=10,
        max_length=1000,
        description="Detailed, documented human justification for the determination (10-1000 chars).",
    )
    corrected_label: str | None = Field(
        default=None,
        max_length=64,
        description="Optional human-corrected classification label.",
    )

    @field_validator("review_status")
    @classmethod
    def validate_review_status(cls, value: str) -> str:
        clean = value.strip().lower()
        allowed = {"confirmed", "rejected", "inconclusive", "escalated"}
        if clean not in allowed:
            raise ValueError(f"Invalid review status '{value}'. Allowed: {sorted(allowed)}.")
        return clean


# =============================================================================
# Case Notes & Findings Schemas (Phase 86)
# =============================================================================


class CaseNoteCreate(BaseModel):
    """Payload for creating a new investigation case note."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    visibility: str = Field(
        default=CaseNoteVisibility.INTERNAL.value,
        description="Visibility tier: internal, confidential, or restricted.",
    )
    content: str = Field(
        ...,
        min_length=5,
        max_length=10000,
        description="Note content or investigative observations (5-10000 chars).",
    )
    evidence_reference_ids: list[UUID] = Field(
        default_factory=list,
        description="Optional list of evidence IDs referenced in this note.",
    )

    @field_validator("visibility")
    @classmethod
    def validate_visibility(cls, value: str) -> str:
        clean = value.strip().lower()
        allowed = {v.value for v in CaseNoteVisibility}
        if clean not in allowed:
            raise ValueError(f"Invalid note visibility '{value}'. Allowed: {sorted(allowed)}.")
        return clean


class CaseNoteUpdate(BaseModel):
    """Payload for modifying an existing investigation note."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    content: str = Field(
        ...,
        min_length=5,
        max_length=10000,
        description="Updated note text content.",
    )
    edit_reason: str | None = Field(
        default=None,
        max_length=1000,
        description="Optional justification for editing the note.",
    )
    expected_version_id: int = Field(
        ...,
        ge=1,
        description="Optimistic locking version identifier.",
    )


class CaseNoteRead(BaseModel):
    """Read representation of an investigation case note."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    case_id: UUID
    author_id: UUID
    visibility: str
    content: str
    version_id: int
    is_archived: bool
    evidence_reference_ids: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class CaseNoteHistoryRead(BaseModel):
    """Audit version log for an edited case note."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    note_id: UUID
    version_id: int
    author_id: UUID
    editor_id: UUID
    content: str
    edit_reason: str | None = None
    created_at: datetime


class CaseFindingCreate(BaseModel):
    """Payload for recording a formal investigation finding."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    finding_type: str = Field(
        default=CaseFindingType.PRELIMINARY.value,
        description="Classification: inculpatory, exculpatory, procedural, inconclusive, preliminary.",
    )
    title: str = Field(
        ...,
        min_length=5,
        max_length=200,
        description="Concise summary title of the finding (5-200 chars).",
    )
    description: str = Field(
        ...,
        min_length=10,
        max_length=10000,
        description="Detailed investigative rationale and factual findings (10-10000 chars).",
    )
    evidence_ids: list[UUID] = Field(
        default_factory=list,
        description="Linked case evidence IDs supporting this finding.",
    )
    ai_segment_ids: list[UUID] = Field(
        default_factory=list,
        description="Linked AI candidate segment IDs relevant to this finding.",
    )
    incident_ids: list[UUID] = Field(
        default_factory=list,
        description="Linked incident IDs relevant to this finding.",
    )
    is_preliminary: bool = Field(
        default=True,
        description="Whether this finding is preliminary or formalized.",
    )

    @field_validator("finding_type")
    @classmethod
    def validate_finding_type(cls, value: str) -> str:
        clean = value.strip().lower()
        allowed = {f.value for f in CaseFindingType}
        if clean not in allowed:
            raise ValueError(f"Invalid finding type '{value}'. Allowed: {sorted(allowed)}.")
        return clean


class CaseFindingUpdate(BaseModel):
    """Payload for editing a formal investigation finding."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    title: str | None = Field(default=None, min_length=5, max_length=200)
    description: str | None = Field(default=None, min_length=10, max_length=10000)
    finding_type: str | None = Field(default=None)
    reason: str | None = Field(default=None, max_length=1000)
    is_preliminary: bool | None = None
    evidence_ids: list[UUID] | None = None
    ai_segment_ids: list[UUID] | None = None
    incident_ids: list[UUID] | None = None
    expected_version_id: int = Field(..., ge=1)

    @field_validator("finding_type")
    @classmethod
    def validate_finding_type(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip().lower()
        allowed = {f.value for f in CaseFindingType}
        if clean not in allowed:
            raise ValueError(f"Invalid finding type '{value}'. Allowed: {sorted(allowed)}.")
        return clean


class CaseFindingRead(BaseModel):
    """Read representation of an investigation finding."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    case_id: UUID
    author_id: UUID
    finding_type: str
    title: str
    description: str
    evidence_ids: list[str] = Field(default_factory=list)
    ai_segment_ids: list[str] = Field(default_factory=list)
    incident_ids: list[str] = Field(default_factory=list)
    version_id: int
    is_preliminary: bool
    created_at: datetime
    updated_at: datetime


class CaseFindingHistoryRead(BaseModel):
    """Audit version log for an edited case finding."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    finding_id: UUID
    version_id: int
    editor_id: UUID
    title: str
    description: str
    reason: str | None = None
    created_at: datetime


# =============================================================================
# Lifecycle Transitions & Approvals Schemas (Phase 87)
# =============================================================================


class CaseTransitionRequest(BaseModel):
    """Payload for requesting a case status transition."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target_status: str = Field(
        ...,
        description="Target case lifecycle status.",
    )
    reason: str = Field(
        ...,
        min_length=10,
        max_length=1000,
        description="Formal justification for the requested state transition (10-1000 chars).",
    )
    expected_version_id: int = Field(
        ...,
        ge=1,
        description="Current case version ID to enforce optimistic concurrency.",
    )

    @field_validator("target_status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        clean = value.strip().lower()
        allowed = {s.value for s in CaseStatus}
        if clean not in allowed:
            raise ValueError(f"Invalid target status '{value}'. Allowed: {sorted(allowed)}.")
        return clean


class CaseApprovalRequest(BaseModel):
    """Payload for an authorized supervisor approval decision on a case."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    decision: str = Field(
        ...,
        description="Approval decision: approved, rejected, or changes_requested.",
    )
    from_status: str = Field(..., description="Status transitioning from.")
    to_status: str = Field(..., description="Target status if approved.")
    rationale: str = Field(
        ...,
        min_length=10,
        max_length=2000,
        description="Detailed approval or rejection rationale (10-2000 chars).",
    )
    expected_version_id: int = Field(..., ge=1)

    @field_validator("decision")
    @classmethod
    def validate_decision(cls, value: str) -> str:
        clean = value.strip().lower()
        allowed = {d.value for d in CaseApprovalDecision}
        if clean not in allowed:
            raise ValueError(f"Invalid approval decision '{value}'. Allowed: {sorted(allowed)}.")
        return clean


class CaseApprovalRead(BaseModel):
    """Read representation of a formal case approval."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    case_id: UUID
    approver_id: UUID
    decision: str
    from_status: str
    to_status: str
    rationale: str
    created_at: datetime


# =============================================================================
# Escalation, Referrals, Closure, and Reopening Schemas (Phase 88)
# =============================================================================


class CaseEscalationRequest(BaseModel):
    """Payload for escalating an active investigation case."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    escalated_to_department_id: UUID = Field(
        ...,
        description="Target department ID receiving the escalation.",
    )
    reason: str = Field(
        ...,
        min_length=10,
        max_length=1000,
        description="Formal justification for case escalation.",
    )
    escalation_level: str = Field(
        default=CaseEscalationLevel.DEPARTMENT_HEAD.value,
        description="Escalation level tier.",
    )
    expected_version_id: int = Field(..., ge=1)

    @field_validator("escalation_level")
    @classmethod
    def validate_level(cls, value: str) -> str:
        clean = value.strip().lower()
        allowed = {lvl.value for lvl in CaseEscalationLevel}
        if clean not in allowed:
            raise ValueError(f"Invalid escalation level '{value}'. Allowed: {sorted(allowed)}.")
        return clean


class CaseEscalationRead(BaseModel):
    """Read representation of a case escalation record."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    case_id: UUID
    escalated_by_id: UUID
    escalated_to_department_id: UUID
    reason: str
    escalation_level: str
    case_version_id: int
    created_at: datetime


class CaseReferralCreate(BaseModel):
    """Payload for initiating a case referral."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target_department_id: UUID | None = Field(default=None)
    target_external_agency: str | None = Field(default=None, max_length=200)
    referral_purpose: str = Field(
        ...,
        min_length=10,
        max_length=1000,
        description="Specific purpose and scope for the referral.",
    )

    @field_validator("target_external_agency")
    @classmethod
    def validate_destination(cls, value: str | None, info: Any) -> str | None:
        target_dept = info.data.get("target_department_id") if hasattr(info, "data") else None
        if target_dept is None and (value is None or not value.strip()):
            raise ValueError(
                "Either target_department_id or target_external_agency must be provided."
            )
        return value


class CaseReferralUpdate(BaseModel):
    """Payload for updating referral outcome."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    status: str = Field(
        ..., description="Referral status: pending, accepted, rejected, transferred."
    )
    resolution_notes: str | None = Field(default=None, max_length=2000)

    @field_validator("status")
    @classmethod
    def validate_referral_status(cls, value: str) -> str:
        clean = value.strip().lower()
        allowed = {s.value for s in CaseReferralStatus}
        if clean not in allowed:
            raise ValueError(f"Invalid referral status '{value}'. Allowed: {sorted(allowed)}.")
        return clean


class CaseReferralRead(BaseModel):
    """Read representation of a case referral record."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    case_id: UUID
    referred_by_id: UUID
    target_department_id: UUID | None = None
    target_external_agency: str | None = None
    referral_purpose: str
    status: str
    resolution_notes: str | None = None
    created_at: datetime
    updated_at: datetime


class CaseCloseRequest(BaseModel):
    """Payload for formally closing an investigation case."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    reason: str = Field(
        ...,
        min_length=10,
        max_length=1000,
        description="Documented rationale and conclusion for closing the case.",
    )
    expected_version_id: int = Field(..., ge=1)


class CaseReopenRequest(BaseModel):
    """Payload for reopening a closed or resolved investigation case."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    reason: str = Field(
        ...,
        min_length=10,
        max_length=1000,
        description="Authorized factual justification for reopening the case.",
    )
    expected_version_id: int = Field(..., ge=1)


# =============================================================================
# Controlled Export & Evidence Manifest Schemas (Phase 89)
# =============================================================================


class EvidenceManifestItem(BaseModel):
    """Manifest item representing verified or recorded evidence in a case export."""

    evidence_id: UUID
    file_name: str
    sha256_digest: str
    file_size_bytes: int
    verification_status: str
    verified_at: datetime | None = None
    notes: str | None = None


class CaseExportRequest(BaseModel):
    """Payload for requesting a secure, controlled case export package."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    export_scope: str = Field(
        default=CaseExportScope.SUMMARY.value,
        description="Export scope: summary, full_investigation, evidence_manifest_only, court_package.",
    )
    export_format: str = Field(
        default=CaseExportFormat.JSON.value,
        description="Export format: json, zip, pdf_summary.",
    )
    purpose: str = Field(
        ...,
        min_length=10,
        max_length=1000,
        description="Documented lawful purpose for exporting this case data.",
    )
    include_restricted_notes: bool = Field(
        default=False,
        description="Whether to include restricted working notes (requires elevated permission).",
    )

    @field_validator("export_scope")
    @classmethod
    def validate_scope(cls, value: str) -> str:
        clean = value.strip().lower()
        allowed = {s.value for s in CaseExportScope}
        if clean not in allowed:
            raise ValueError(f"Invalid export scope '{value}'. Allowed: {sorted(allowed)}.")
        return clean

    @field_validator("export_format")
    @classmethod
    def validate_format(cls, value: str) -> str:
        clean = value.strip().lower()
        allowed = {f.value for f in CaseExportFormat}
        if clean not in allowed:
            raise ValueError(f"Invalid export format '{value}'. Allowed: {sorted(allowed)}.")
        return clean


class CaseExportRead(BaseModel):
    """Read representation of an exported case manifest and disclosure package."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    case_id: UUID
    department_id: UUID
    exported_by_id: UUID
    export_scope: str
    export_format: str
    manifest_sha256: str
    evidence_count: int
    manifest_payload: dict[str, Any]
    status: str
    purpose: str
    expires_at: datetime
    created_at: datetime
