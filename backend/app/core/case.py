"""Investigation case domain primitives, statuses, validation, and workload rules (Phases 81-85).

Enforces:
- Canonical investigation case lifecycle states (`CaseStatus`) and authorized state transitions.
- Investigation priority classification (`CasePriority`).
- Concurrency-safe, opaque case reference number generation (`CASE-YYYY-XXXXXXXX`).
- Configurable investigator active case workload limits.
- Clear non-authoritative advisory disclaimers for AI analysis candidates.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final

from backend.app.core.exceptions import BusinessRuleError

# Configurable maximum active case capacity per investigator
INVESTIGATOR_DEFAULT_MAX_ACTIVE_CASES: Final[int] = 10

# Mandatory statutory disclaimer for AI candidate segment findings
AI_ADVISORY_DISCLAIMER: Final[str] = (
    "Candidate video segments, scores, and classifications produced by AI analysis are "
    "probabilistic and advisory only. They do not establish that an incident occurred, "
    "constitute proof of guilt, identity, or wrongdoing, or justify autonomous disciplinary actions. "
    "All consequential investigative decisions require authorized human review and corroborating evidence."
)


class CaseStatus(StrEnum):
    """Explicit lifecycle states for formal investigation cases (Phase 81 & 87)."""

    DRAFT = "draft"
    OPEN = "open"
    UNDER_INVESTIGATION = "under_investigation"
    PENDING_REVIEW = "pending_review"
    SUSPENDED = "suspended"
    RESOLVED = "resolved"
    CLOSED = "closed"


class CasePriority(StrEnum):
    """Institutional triage and investigative priority classification."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentLinkType(StrEnum):
    """Relational nature of incident linkage to an investigation case."""

    PRIMARY = "primary"
    RELATED = "related"
    EVIDENCE_SOURCE = "evidence_source"


class InvestigativeRelevance(StrEnum):
    """Investigative relevance classification for linked AI candidate segments."""

    CANDIDATE_LEAD = "candidate_lead"
    CORROBORATING = "corroborating"
    EXCULPATORY = "exculpatory"
    DISMISSED = "dismissed"


class CaseNoteVisibility(StrEnum):
    """Visibility classification for case notes (Phase 86)."""

    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class CaseFindingType(StrEnum):
    """Structured classification for formal case findings (Phase 86)."""

    INCULPATORY = "inculpatory"
    EXCULPATORY = "exculpatory"
    PROCEDURAL = "procedural"
    INCONCLUSIVE = "inconclusive"
    PRELIMINARY = "preliminary"


class CaseApprovalDecision(StrEnum):
    """Formal case transition approval decision (Phase 87)."""

    APPROVED = "approved"
    REJECTED = "rejected"
    CHANGES_REQUESTED = "changes_requested"


class CaseEscalationLevel(StrEnum):
    """Institutional escalation destination tier (Phase 88)."""

    DEPARTMENT_HEAD = "department_head"
    INTERNAL_AFFAIRS = "internal_affairs"
    LEGAL_COUNSEL = "legal_counsel"
    SUPER_ADMIN = "super_admin"


class CaseReferralStatus(StrEnum):
    """Status lifecycle for case referrals to external or internal agencies (Phase 88)."""

    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    TRANSFERRED = "transferred"


class CaseExportScope(StrEnum):
    """Scope boundaries for controlled case disclosure and exports (Phase 89)."""

    SUMMARY = "summary"
    FULL_INVESTIGATION = "full_investigation"
    EVIDENCE_MANIFEST_ONLY = "evidence_manifest_only"
    COURT_PACKAGE = "court_package"


class CaseExportFormat(StrEnum):
    """Serialization formats supported for case exports (Phase 89)."""

    JSON = "json"
    ZIP = "zip"
    PDF_SUMMARY = "pdf_summary"


class EvidenceVerificationStatus(StrEnum):
    """Cryptographic and procedural verification status for evidence manifests (Phase 89)."""

    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    INTEGRITY_FAILED = "integrity_failed"


# Valid lifecycle status transitions for investigation cases
VALID_CASE_TRANSITIONS: Final[dict[CaseStatus, frozenset[CaseStatus]]] = {
    CaseStatus.DRAFT: frozenset({CaseStatus.OPEN, CaseStatus.CLOSED}),
    CaseStatus.OPEN: frozenset(
        {CaseStatus.UNDER_INVESTIGATION, CaseStatus.SUSPENDED, CaseStatus.CLOSED}
    ),
    CaseStatus.UNDER_INVESTIGATION: frozenset(
        {CaseStatus.PENDING_REVIEW, CaseStatus.SUSPENDED, CaseStatus.CLOSED}
    ),
    CaseStatus.PENDING_REVIEW: frozenset(
        {CaseStatus.UNDER_INVESTIGATION, CaseStatus.RESOLVED, CaseStatus.CLOSED}
    ),
    CaseStatus.SUSPENDED: frozenset({CaseStatus.UNDER_INVESTIGATION, CaseStatus.CLOSED}),
    CaseStatus.RESOLVED: frozenset({CaseStatus.CLOSED, CaseStatus.UNDER_INVESTIGATION}),
    CaseStatus.CLOSED: frozenset({CaseStatus.UNDER_INVESTIGATION}),
}


def parse_case_status(value: str) -> CaseStatus:
    """Parse and validate case status value."""
    normalized = value.strip().lower()
    try:
        return CaseStatus(normalized)
    except ValueError:
        valid_values = ", ".join(repr(s.value) for s in CaseStatus)
        raise BusinessRuleError(
            f"Invalid case status '{value}'. Allowed statuses: {valid_values}.",
            code="INVALID_CASE_STATUS",
        ) from None


TERMINAL_CASE_STATUSES: Final[frozenset[CaseStatus]] = frozenset(
    {CaseStatus.RESOLVED, CaseStatus.CLOSED}
)


def parse_case_priority(value: str) -> CasePriority:
    """Parse and validate case priority value."""
    normalized = value.strip().lower()
    try:
        return CasePriority(normalized)
    except ValueError:
        valid_values = ", ".join(repr(p.value) for p in CasePriority)
        raise BusinessRuleError(
            f"Invalid case priority '{value}'. Allowed priorities: {valid_values}.",
            code="INVALID_CASE_PRIORITY",
        ) from None


def validate_case_status_transition(
    current: CaseStatus | str,
    target: CaseStatus | str,
) -> None:
    """Validate whether transitioning from ``current`` to ``target`` is allowed."""
    curr = parse_case_status(current) if isinstance(current, str) else current
    tgt = parse_case_status(target) if isinstance(target, str) else target
    if curr == tgt:
        return

    allowed = VALID_CASE_TRANSITIONS.get(curr, frozenset())
    if tgt not in allowed:
        raise BusinessRuleError(
            f"Cannot transition case status from '{curr.value}' to '{tgt.value}'.",
            code="INVALID_CASE_TRANSITION",
        )


def generate_case_reference_number(when: datetime | None = None) -> str:
    """Generate a non-guessable, concurrency-safe, opaque case reference number.

    Format: `CASE-<YYYY>-<8-HEX>` e.g. `CASE-2026-A1B2C3D4`
    """
    timestamp = when or datetime.now(UTC)
    year = timestamp.strftime("%Y")
    entropy_hex = secrets.token_hex(4).upper()
    return f"CASE-{year}-{entropy_hex}"
