"""Pydantic schemas for Biometric Governance, Reference Registry, and Face Detection (Phases 71-75).

Enforces:
- Strict validation of purpose, lawful basis, and versioned notices.
- Complete exclusion of raw biometric material or encrypted templates from ordinary read schemas.
- Mandatory advisory disclaimer inclusion in face detection responses.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.app.core.biometrics import (
    BIOMETRIC_ADVISORY_DISCLAIMER,
    BIOMETRIC_MATCHING_ADVISORY_DISCLAIMER,
    BiometricHumanVerdict,
    BiometricLawfulBasis,
    BiometricPurpose,
    GovernanceStatus,
    validate_biometric_purpose,
)


class BiometricGovernanceCreate(BaseModel):
    """Payload to register a new biometric governance, assessment, and consent record."""

    model_config = ConfigDict(extra="forbid")

    purpose: BiometricPurpose
    lawful_basis: BiometricLawfulBasis
    policy_version: str = Field(default="1.0.0", min_length=1, max_length=32)
    notice_version: str = Field(default="1.0.0", min_length=1, max_length=32)
    subject_user_id: UUID | None = None
    retention_days: int = Field(default=90, ge=1, le=365)
    consent_confirmed: bool = False
    legal_review_notes: str | None = Field(default=None, max_length=2000)

    @field_validator("purpose")
    @classmethod
    def check_purpose(cls, value: BiometricPurpose) -> BiometricPurpose:
        validate_biometric_purpose(value.value)
        return value


class BiometricGovernanceReviewRequest(BaseModel):
    """Payload to record legal and operational review decision for a governance record."""

    model_config = ConfigDict(extra="forbid")

    decision: str = Field(description="Verdict: 'approved', 'rejected', or 'no_go'")
    legal_review_notes: str = Field(min_length=5, max_length=2000)

    @field_validator("decision")
    @classmethod
    def check_decision(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean not in {
            GovernanceStatus.APPROVED.value,
            GovernanceStatus.REJECTED.value,
            GovernanceStatus.NO_GO.value,
        }:
            raise ValueError(f"Decision must be 'approved', 'rejected', or 'no_go'; got '{value}'.")
        return clean


class BiometricGovernanceRead(BaseModel):
    """Public read model for biometric governance records."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    department_id: UUID
    policy_version: str
    purpose: str
    lawful_basis: str
    notice_version: str
    subject_user_id: UUID | None
    status: str
    consent_status: str | None
    consented_at: datetime | None
    withdrawn_at: datetime | None
    approved_by_id: UUID | None
    approved_at: datetime | None
    legal_review_notes: str | None
    retention_days: int
    retention_expires_at: datetime | None
    created_at: datetime
    updated_at: datetime


class BiometricConsentWithdrawRequest(BaseModel):
    """Request to withdraw consent for biometric processing."""

    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=500)


class BiometricReferenceCreate(BaseModel):
    """Payload to enroll an approved biometric reference into the registry."""

    model_config = ConfigDict(extra="forbid")

    governance_record_id: UUID
    purpose: BiometricPurpose
    template_digest: str = Field(min_length=64, max_length=64, description="64-char SHA-256 digest")
    subject_user_id: UUID | None = None
    encrypted_template: str | None = Field(
        default=None, description="Encrypted template ciphertext if stored"
    )
    provenance_evidence_id: UUID | None = None
    enrollment_notes: str | None = Field(default=None, max_length=1000)

    @field_validator("purpose")
    @classmethod
    def check_purpose(cls, value: BiometricPurpose) -> BiometricPurpose:
        validate_biometric_purpose(value.value)
        return value

    @field_validator("template_digest")
    @classmethod
    def check_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if len(clean) != 64 or not all(c in "0123456789abcdef" for c in clean):
            raise ValueError(
                "template_digest must be a valid 64-character lowercase hex SHA-256 string."
            )
        return clean


class BiometricReferenceRead(BaseModel):
    """Public read model for biometric reference metadata.

    Security Guarantee: Never exposes raw template or encrypted template payloads.
    """

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    reference_id: str
    tenant_id: UUID
    department_id: UUID
    subject_user_id: UUID | None
    governance_record_id: UUID
    purpose: str
    status: str
    template_digest: str
    provenance_evidence_id: UUID | None
    enrollment_notes: str | None
    enrolled_by_id: UUID
    enrolled_at: datetime
    revoked_by_id: UUID | None
    revoked_at: datetime | None
    revocation_reason: str | None
    retention_expires_at: datetime
    created_at: datetime
    updated_at: datetime


class BiometricReferenceRevokeRequest(BaseModel):
    """Request to revoke an active biometric reference."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=3, max_length=500)


class DetectedFaceRead(BaseModel):
    """Individual face bounding box and localization confidence."""

    bounding_box: tuple[float, float, float, float]
    confidence: float
    landmarks: dict[str, tuple[float, float]] | None = None


class FaceDetectionRequest(BaseModel):
    """Payload to request face bounding box detection."""

    model_config = ConfigDict(extra="forbid")

    governance_record_id: UUID
    image_base64: str = Field(min_length=1, description="Base64-encoded image bytes")


class FaceDetectionResponse(BaseModel):
    """Structured response from face detection endpoint."""

    detected_faces: list[DetectedFaceRead]
    face_count: int
    image_width: int
    image_height: int
    model_name: str
    model_version: str
    inference_latency_ms: float
    disclaimer: str = BIOMETRIC_ADVISORY_DISCLAIMER
    metadata: dict[str, str] = Field(default_factory=dict)


class PaginatedBiometricGovernanceRead(BaseModel):
    """Paginated collection of biometric governance records."""

    items: list[BiometricGovernanceRead]
    total: int
    limit: int
    offset: int


class PaginatedBiometricReferenceRead(BaseModel):
    """Paginated collection of biometric references."""

    items: list[BiometricReferenceRead]
    total: int
    limit: int
    offset: int


class FaceMatchRequest(BaseModel):
    """Payload to request advisory biometric face matching between probe and reference."""

    model_config = ConfigDict(extra="forbid")

    governance_record_id: UUID
    probe_image_base64: str = Field(
        min_length=1, description="Base64-encoded probe face image bytes"
    )
    reference_id: UUID | None = Field(
        default=None, description="UUID of registered biometric reference"
    )
    reference_image_base64: str | None = Field(
        default=None, description="Optional base64-encoded reference face image bytes"
    )
    incident_id: UUID | None = Field(
        default=None, description="Optional linked incident identifier"
    )

    @model_validator(mode="after")
    def validate_reference_source(self) -> FaceMatchRequest:
        if self.reference_id is None and not self.reference_image_base64:
            raise ValueError("Either reference_id or reference_image_base64 must be provided.")
        return self


class FaceMatchResponse(BaseModel):
    """Structured response from face matching endpoint."""

    similarity_score: float
    verdict: str
    uncertainty_lower_bound: float
    uncertainty_upper_bound: float
    probe_image_hash: str
    verification_review_id: UUID | None = None
    model_name: str
    model_version: str
    latency_ms: float
    disclaimer: str = BIOMETRIC_MATCHING_ADVISORY_DISCLAIMER
    metadata: dict[str, Any] = Field(default_factory=dict)


class BiometricVerificationReviewCreate(BaseModel):
    """Payload for an authorized human reviewer recording a verification determination (Phase 77)."""

    model_config = ConfigDict(extra="forbid")

    human_verdict: BiometricHumanVerdict
    review_notes: str | None = Field(default=None, max_length=2000)
    override_reason: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def validate_override(self) -> BiometricVerificationReviewCreate:
        if self.human_verdict == BiometricHumanVerdict.REJECTED_OVERRIDE and not (
            self.override_reason and self.override_reason.strip()
        ):
            raise ValueError(
                "override_reason is strictly required when human_verdict is 'rejected_override'."
            )
        return self


class BiometricVerificationReviewRead(BaseModel):
    """Public read model for biometric verification review records."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    department_id: UUID
    incident_id: UUID | None
    reference_id: UUID | None
    probe_image_hash: str
    candidate_similarity: float
    uncertainty_lower_bound: float
    uncertainty_upper_bound: float
    automated_verdict: str
    human_verdict: str
    reviewer_id: UUID | None
    reviewed_at: datetime | None
    review_notes: str | None
    override_reason: str | None
    is_override: bool
    disclaimer: str = BIOMETRIC_MATCHING_ADVISORY_DISCLAIMER
    created_at: datetime
    updated_at: datetime


class PaginatedBiometricVerificationReviewRead(BaseModel):
    """Paginated collection of biometric verification reviews."""

    items: list[BiometricVerificationReviewRead]
    total: int
    limit: int
    offset: int


class BiometricEvaluationSummaryRead(BaseModel):
    """Public read model summarizing biometric accuracy, fairness, and PAD benchmarks (Phase 79)."""

    model_name: str
    model_version: str
    total_comparisons: int
    fta_rate: float
    eer: float
    eer_threshold: float
    operational_fmr_at_085: float
    operational_fnmr_at_085: float
    max_demographic_disparity_ratio: float
    disclaimer: str
    pad_summary: dict[str, Any] | None = None
    subgroups: list[dict[str, Any]] = Field(default_factory=list)
