"""Domain models, status enums, licensing rules, and cryptographic helpers for Biometric Governance (Phases 71-75).

Enforces:
- Non-negotiable privacy-by-design and purpose limitation boundaries.
- Explicit prohibition on mass surveillance, emotion profiling, and autonomous guilt determination.
- Structured lawful basis, consent management, and withdrawal propagation.
- Opaque template hashing and metadata-only persistence.
- Documented readiness state machine and fail-closed NO-GO evaluations.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Sequence
from enum import StrEnum
from typing import Final

BIOMETRIC_ADVISORY_DISCLAIMER: Final[str] = (
    "Face detection identifies bounding box coordinates for authorized forensic review or "
    "privacy redaction. It does NOT establish identity, infer emotion or character, or make "
    "autonomous disciplinary or legal determinations."
)

BIOMETRIC_MATCHING_ADVISORY_DISCLAIMER: Final[str] = (
    "Candidate similarity score only; NOT proof of identity, innocence, or guilt. Automated "
    "matching decisions are strictly prohibited. Consequential determinations require "
    "qualified independent human verification under documented procedures."
)

DEFAULT_BIOMETRIC_RETENTION_DAYS: Final[int] = 90
MAX_BIOMETRIC_RETENTION_DAYS: Final[int] = 365


class BiometricPurpose(StrEnum):
    """Narrowly scoped, permissible operational biometric purposes (Phase 72)."""

    EXPLICIT_CONSENT_REFERENCE_ENROLLMENT = "explicit_consent_reference_enrollment"
    AUTHORIZED_INVESTIGATIVE_MANUAL_REVIEW = "authorized_investigative_manual_review"
    PRIVACY_REDACTION_BLURRING = "privacy_redaction_blurring"
    TESTING_SYNTHETIC_BENCHMARK = "testing_synthetic_benchmark"


class ProhibitedBiometricPurpose(StrEnum):
    """Explicitly unlawful and technically forbidden biometric operations (Phase 71 & 72)."""

    MASS_SURVEILLANCE_CROWD_SCANNING = "mass_surveillance_crowd_scanning"
    AUTONOMOUS_PUNITIVE_DECISION = "autonomous_punitive_decision"
    EMOTION_OR_SENTIMENT_INFERENCE = "emotion_or_sentiment_inference"
    DEMOGRAPHIC_PROFILING = "demographic_profiling"
    COVERT_UNAUTHORIZED_TRACKING = "covert_unauthorized_tracking"


PROHIBITED_BIOMETRIC_PURPOSES: Final[frozenset[str]] = frozenset(
    p.value for p in ProhibitedBiometricPurpose
)


class BiometricLawfulBasis(StrEnum):
    """Designated legal bases for biometric data processing (Phase 71 & 73)."""

    EXPLICIT_CONSENT = "explicit_consent"
    STATUTORY_LEGAL_OBLIGATION = "statutory_legal_obligation"
    SUBSTANTIAL_PUBLIC_INTEREST = "substantial_public_interest"
    RESEARCH_BENCHMARK_EXEMPT = "research_benchmark_exempt"


class ConsentStatus(StrEnum):
    """Consent lifecycle state of a biometric data subject (Phase 73)."""

    ACTIVE = "active"
    WITHDRAWN = "withdrawn"
    EXPIRED = "expired"
    REVOKED = "revoked"


class GovernanceStatus(StrEnum):
    """Administrative and legal review state of a biometric processing authorization."""

    PENDING_LEGAL_REVIEW = "pending_legal_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    REVOKED = "revoked"
    NO_GO = "no_go"


class BiometricReferenceStatus(StrEnum):
    """Lifecycle status of an enrolled biometric reference (Phase 74)."""

    PENDING_APPROVAL = "pending_approval"
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    PURGED = "purged"


class BiometricMatchVerdict(StrEnum):
    """Categorical matching verdict distinguishing match candidates, non-matches, and uncertainty (Phase 76 & 77)."""

    MATCH_CANDIDATE = "match_candidate"
    NON_MATCH_CANDIDATE = "non_match_candidate"
    INCONCLUSIVE_UNCERTAIN = "inconclusive_uncertain"
    INSUFFICIENT_QUALITY = "insufficient_quality"


class BiometricHumanVerdict(StrEnum):
    """Determination recorded by an authorized human reviewer (Phase 77)."""

    VERIFIED_MATCH = "verified_match"
    VERIFIED_NON_MATCH = "verified_non_match"
    REJECTED_OVERRIDE = "rejected_override"
    INCONCLUSIVE_DISMISSED = "inconclusive_dismissed"


class ImageQualityAssessment(StrEnum):
    """Input image quality assessment verdict (Phase 77)."""

    ACCEPTABLE = "acceptable"
    LOW_RESOLUTION = "low_resolution"
    POOR_CONTRAST = "poor_contrast"
    INVALID_DIMENSIONS = "invalid_dimensions"
    CORRUPTED_HEADER = "corrupted_header"


class BiometricReadinessState(StrEnum):
    """Overall operational deployment readiness verdict (Phase 71)."""

    GO = "GO"
    NO_GO = "NO_GO"


MANDATORY_READINESS_CHECKLIST_ITEMS: Final[tuple[str, ...]] = (
    "qualified_legal_opinion",
    "data_protection_impact_assessment",
    "published_privacy_policy",
    "executive_sign_off",
    "security_architecture_review",
    "tenant_admin_opt_in",
    "production_matching_lock",
    "subject_consent_or_warrant",
)


def compute_template_sha256(template_bytes: bytes) -> str:
    """Compute the canonical SHA-256 digest of biometric template bytes."""
    if not template_bytes:
        raise ValueError("Biometric template bytes cannot be empty.")
    return hashlib.sha256(template_bytes).hexdigest()


def validate_biometric_purpose(purpose: str) -> None:
    """Validate that `purpose` is an approved use case and not prohibited.

    Raises:
        ValueError: If `purpose` is unknown or explicitly prohibited.
    """
    cleaned = purpose.strip().lower()
    if cleaned in PROHIBITED_BIOMETRIC_PURPOSES:
        raise ValueError(
            f"Biometric operation with prohibited purpose '{cleaned}' is strictly forbidden by policy."
        )
    permitted_values = {p.value for p in BiometricPurpose}
    if cleaned not in permitted_values:
        raise ValueError(
            f"Invalid biometric purpose '{cleaned}'. Must be one of: {sorted(permitted_values)}."
        )


def evaluate_biometric_readiness_checklist(
    checklist: dict[str, bool],
) -> tuple[BiometricReadinessState, list[str]]:
    """Evaluate the 8 mandatory readiness prerequisites (Phase 71).

    Returns:
        tuple of (BiometricReadinessState, list of missing items).
        Fails closed to NO_GO if any prerequisite is False or missing.
    """
    missing: list[str] = []
    for item in MANDATORY_READINESS_CHECKLIST_ITEMS:
        if not checklist.get(item, False):
            missing.append(item)

    if missing:
        return BiometricReadinessState.NO_GO, missing
    return BiometricReadinessState.GO, []


def compute_cosine_similarity(vec1: Sequence[float], vec2: Sequence[float]) -> float:
    """Compute normalized cosine similarity between two feature vectors.

    Security & Correctness Guarantees:
    - Enforces non-empty, equal-length vectors.
    - Guards against division by zero (returns 0.0 for zero-magnitude vectors).
    - Clamps output strictly within [-1.0, 1.0].
    """
    if not vec1 or not vec2:
        raise ValueError("Feature vectors cannot be empty.")
    if len(vec1) != len(vec2):
        raise ValueError(
            f"Vector dimension mismatch: vector 1 has dimension {len(vec1)}, "
            f"vector 2 has dimension {len(vec2)}."
        )

    dot_product = sum(a * b for a, b in zip(vec1, vec2, strict=True))
    mag1 = math.sqrt(sum(a * a for a in vec1))
    mag2 = math.sqrt(sum(b * b for b in vec2))

    if mag1 == 0.0 or mag2 == 0.0:
        return 0.0

    raw_similarity = dot_product / (mag1 * mag2)
    return max(-1.0, min(1.0, raw_similarity))


def evaluate_matching_verdict(
    similarity: float,
    *,
    lower_bound: float = 0.60,
    upper_bound: float = 0.85,
) -> BiometricMatchVerdict:
    """Evaluate candidate match outcome with an explicit uncertainty band (Phase 76 & 77).

    Non-negotiable Invariant:
    A similarity score is never proof of identity. Between lower_bound and upper_bound,
    the model outcome is inconclusive and must not be forced into a binary classification.
    """
    if lower_bound >= upper_bound:
        raise ValueError("Uncertainty lower_bound must be strictly less than upper_bound.")

    if similarity >= upper_bound:
        return BiometricMatchVerdict.MATCH_CANDIDATE
    if similarity < lower_bound:
        return BiometricMatchVerdict.NON_MATCH_CANDIDATE
    return BiometricMatchVerdict.INCONCLUSIVE_UNCERTAIN
