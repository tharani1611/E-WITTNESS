"""Evidence and upload session domain primitives and lifecycle states (Phases 43-44).

Enforces:
- Explicit evidence upload and ingestion lifecycle states.
- Session status tracking for short-lived upload authorizations.
- Validation functions for evidence domain boundaries.
"""

from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from backend.app.core.exceptions import BusinessRuleError


class UploadStatus(StrEnum):
    """Lifecycle state of an evidence file upload operation."""

    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class EvidenceStatus(StrEnum):
    """Legal and evidentiary custody status of an evidence attachment."""

    ATTACHED = "attached"
    QUARANTINED = "quarantined"
    SEALED = "sealed"


class UploadSessionStatus(StrEnum):
    """Lifecycle state of an authorized upload session."""

    ACTIVE = "active"
    COMPLETED = "completed"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class ScanStatus(StrEnum):
    """Malware and antivirus scanning lifecycle state of an evidence file."""

    PENDING = "pending"
    SCANNING = "scanning"
    CLEAN = "clean"
    INFECTED = "infected"
    FAILED = "failed"
    QUARANTINED = "quarantined"


# Default cumulative storage quota guardrails (SEC-011)
DEFAULT_MAX_INCIDENT_EVIDENCE_BYTES: int = 250 * 1024 * 1024  # 250 MB per incident
DEFAULT_MAX_USER_EVIDENCE_BYTES: int = 500 * 1024 * 1024  # 500 MB per user
DEFAULT_MAX_DEPARTMENT_EVIDENCE_BYTES: int = 5 * 1024 * 1024 * 1024  # 5 GB per department


def parse_upload_status(value: str) -> UploadStatus:
    """Parse and validate upload status."""
    normalized = value.strip().lower()
    try:
        return UploadStatus(normalized)
    except ValueError:
        valid_values = ", ".join(repr(s.value) for s in UploadStatus)
        raise BusinessRuleError(
            f"Invalid upload status '{value}'. Allowed: {valid_values}.",
            code="INVALID_UPLOAD_STATUS",
        ) from None


def parse_evidence_status(value: str) -> EvidenceStatus:
    """Parse and validate evidence status."""
    normalized = value.strip().lower()
    try:
        return EvidenceStatus(normalized)
    except ValueError:
        valid_values = ", ".join(repr(s.value) for s in EvidenceStatus)
        raise BusinessRuleError(
            f"Invalid evidence status '{value}'. Allowed: {valid_values}.",
            code="INVALID_EVIDENCE_STATUS",
        ) from None


def parse_upload_session_status(value: str) -> UploadSessionStatus:
    """Parse and validate upload session status."""
    normalized = value.strip().lower()
    try:
        return UploadSessionStatus(normalized)
    except ValueError:
        valid_values = ", ".join(repr(s.value) for s in UploadSessionStatus)
        raise BusinessRuleError(
            f"Invalid upload session status '{value}'. Allowed: {valid_values}.",
            code="INVALID_SESSION_STATUS",
        ) from None


def parse_scan_status(value: str) -> ScanStatus:
    """Parse and validate malware scan status."""
    normalized = value.strip().lower()
    try:
        return ScanStatus(normalized)
    except ValueError:
        valid_values = ", ".join(repr(s.value) for s in ScanStatus)
        raise BusinessRuleError(
            f"Invalid scan status '{value}'. Allowed: {valid_values}.",
            code="INVALID_SCAN_STATUS",
        ) from None


class CustodyActionType(StrEnum):
    """Immutable action types recorded in the evidence chain-of-custody ledger (EVI-004)."""

    INGESTED = "ingested"
    HASH_VERIFIED = "hash_verified"
    QUARANTINED = "quarantined"
    SEALED = "sealed"
    ACCESSED = "accessed"
    DOWNLOADED = "downloaded"
    SCAN_FAILED = "scan_failed"
    SCAN_RETRY = "scan_retry"
    COMPENSATING_CORRECTION = "compensating_correction"
    TAMPER_DETECTED = "tamper_detected"


class IntegrityVerificationStatus(StrEnum):
    """Outcomes of cryptographic evidence integrity verification checks (Phase 54)."""

    VERIFIED_MATCH = "verified_match"
    TAMPER_DETECTED = "tamper_detected"
    STORAGE_MISSING = "storage_missing"
    STORAGE_UNAVAILABLE = "storage_unavailable"
    UNVERIFIED = "unverified"


INTEGRITY_DISCLAIMER: str = (
    "Cryptographic hash match confirms bit-level integrity against the ingested byte stream; "
    "it does NOT prove the legal authenticity, truthfulness, or evidentiary accuracy of the content."
)


def compute_custody_event_hash(
    evidence_id: str | UUID,
    sequence_number: int,
    action_type: str,
    timestamp_iso: str,
    actor_id: str | UUID,
    evidence_sha256: str | None,
    previous_event_hash: str | None,
    details: str | None,
) -> str:
    """Compute deterministic SHA-256 digest for cryptographic custody event chaining (AUD-003)."""
    import hashlib

    canonical_repr = (
        f"{evidence_id}:{sequence_number}:{action_type}:{timestamp_iso}:{actor_id}:"
        f"{evidence_sha256 or 'NONE'}:{previous_event_hash or 'GENESIS'}:{details or ''}"
    )
    return hashlib.sha256(canonical_repr.encode("utf-8")).hexdigest()
