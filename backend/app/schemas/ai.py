"""Pydantic schemas for AI datasets and asynchronous analysis jobs (Phases 61-65).

Enforces:
- Schema-level validation of dataset manifests and approved licenses.
- Separation of operational evidence from training datasets.
- Typed input/output contracts for job submission, progress tracking, and results.
- Mandatory advisory disclaimers on AI analysis outputs.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ai_services.violence_detection.requirements import AI_HUMAN_IN_THE_LOOP_DISCLAIMER
from backend.app.core.ai import (
    APPROVED_DATASET_LICENSES,
    CalibrationStatus,
    DatasetConsentStatus,
    DatasetType,
    SegmentReviewStatus,
    UncertaintyStatus,
    validate_model_provenance,
)


class DatasetManifestItem(BaseModel):
    """Single item entry in a dataset manifest."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(..., min_length=1, max_length=512, description="Relative file path")
    sha256_hash: str = Field(..., min_length=64, max_length=64, description="SHA-256 hex digest")
    label: str | None = Field(default=None, max_length=64, description="Annotation label")
    file_size_bytes: int | None = Field(default=None, ge=0, description="File size in bytes")

    @field_validator("sha256_hash")
    @classmethod
    def validate_sha256(cls, v: str) -> str:
        if len(v) != 64 or not all(c in "0123456789abcdefABCDEF" for c in v):
            raise ValueError("sha256_hash must be a 64-character hexadecimal string")
        return v.lower()


class DatasetRegisterRequest(BaseModel):
    """Payload to register an AI benchmark/training dataset (Phase 62)."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=128, description="Dataset name")
    version: str = Field(..., min_length=1, max_length=32, description="Semantic version string")
    dataset_type: DatasetType = Field(default=DatasetType.BENCHMARK, description="Dataset role")
    source_uri: str | None = Field(
        default=None, max_length=512, description="Source provenance URL or DOI"
    )
    license_id: str = Field(..., min_length=1, max_length=64, description="SPDX license identifier")
    consent_status: DatasetConsentStatus = Field(
        default=DatasetConsentStatus.CONSENTED,
        description="Consent or public domain review status",
    )
    provenance_details: dict[str, Any] = Field(
        default_factory=dict,
        description="Donor, institution, date, collection methodology details",
    )
    manifest_items: list[DatasetManifestItem] = Field(
        ...,
        min_length=1,
        description="List of manifest items belonging to this dataset",
    )

    @field_validator("license_id")
    @classmethod
    def validate_license(cls, v: str) -> str:
        clean = v.strip()
        if clean not in APPROVED_DATASET_LICENSES:
            raise ValueError(
                f"License '{clean}' is not in approved dataset licenses: {sorted(APPROVED_DATASET_LICENSES)}"
            )
        return clean


class DatasetReviewRequest(BaseModel):
    """Payload to approve, reject, or withdraw a registered dataset (Phase 62)."""

    model_config = ConfigDict(extra="forbid")

    decision: Literal["approved", "rejected", "withdrawn"]
    review_notes: str | None = Field(default=None, max_length=1024)


class AIDatasetRead(BaseModel):
    """Public read model for an AI dataset."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    version: str
    dataset_type: str
    source_uri: str | None = None
    license_id: str
    consent_status: str
    provenance_details: dict[str, Any] = Field(default_factory=dict)
    manifest_sha256: str
    manifest_item_count: int
    status: str
    reviewed_by_id: UUID | None = None
    reviewed_at: datetime | None = None
    review_notes: str | None = None
    created_by_id: UUID
    created_at: datetime
    updated_at: datetime


class AIJobSubmitRequest(BaseModel):
    """Payload to submit an asynchronous video analysis job (Phase 65)."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: UUID = Field(..., description="Evidence attachment UUID to analyze")
    model_name: str = Field(default="violence-classifier", max_length=64)
    model_version: str = Field(default="0.1.0", max_length=32)

    @model_validator(mode="after")
    def validate_provenance(self) -> AIJobSubmitRequest:
        try:
            validate_model_provenance(self.model_name, self.model_version)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        return self


class AIJobResultSummary(BaseModel):
    """Structured result summary produced by video analysis pipeline (Phase 64-65)."""

    model_config = ConfigDict(extra="forbid")

    is_violence_detected: bool = Field(..., description="Whether candidate violence was flagged")
    violence_score: float = Field(
        ..., ge=0.0, le=1.0, description="Raw uncalibrated violence probability score"
    )
    confidence_is_uncalibrated: bool = Field(
        default=True, description="Explicit disclaimer of uncalibrated confidence"
    )
    detected_segments: list[dict[str, Any]] = Field(
        default_factory=list, description="Preliminary segment timestamps"
    )
    video_metadata: dict[str, Any] = Field(
        default_factory=dict, description="Extracted video metadata"
    )
    frames_analyzed: int = Field(default=0, ge=0)
    processing_time_seconds: float = Field(default=0.0, ge=0.0)
    disclaimer: str = Field(default=AI_HUMAN_IN_THE_LOOP_DISCLAIMER)


class AIJobStatusRead(BaseModel):
    """Public read model for an AI analysis job (Phase 65)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    evidence_id: UUID
    incident_id: UUID
    department_id: UUID
    submitted_by_id: UUID
    status: str
    progress_percent: int
    current_step: str
    model_name: str
    model_version: str
    result_summary: dict[str, Any] | None = None
    error_message: str | None = None
    error_category: str | None = None
    retry_count: int
    max_retries: int
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class AICandidateSegmentRead(BaseModel):
    """Public read model for an AI candidate violence segment (Phase 66 & 69)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    job_id: UUID
    evidence_id: UUID
    incident_id: UUID
    department_id: UUID
    start_seconds: float
    end_seconds: float
    duration_seconds: float
    raw_score: float
    raw_label: str = "violence"
    model_name: str
    model_version: str
    preprocessing_version: str = "1.0.0"
    calibration_status: str = CalibrationStatus.UNCALIBRATED.value
    calibrated_score: float | None = None
    calibration_version: str | None = None
    uncertainty_status: str = UncertaintyStatus.UNCALIBRATED.value
    review_status: str = SegmentReviewStatus.PENDING_REVIEW.value
    reviewed_by_id: UUID | None = None
    reviewed_at: datetime | None = None
    review_notes: str | None = None
    false_positive_reason: str | None = None
    is_flagged_for_review: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None
    updated_at: datetime | None = None
    disclaimer: str = Field(default=AI_HUMAN_IN_THE_LOOP_DISCLAIMER)

    @model_validator(mode="before")
    @classmethod
    def _populate_segment_defaults(cls, data: Any) -> Any:
        if hasattr(data, "__dict__"):
            now = datetime.now(UTC)
            if getattr(data, "created_at", None) is None:
                data.created_at = now
            if getattr(data, "updated_at", None) is None:
                data.updated_at = now
            if getattr(data, "preprocessing_version", None) is None:
                data.preprocessing_version = "1.0.0"
            if getattr(data, "calibration_status", None) is None:
                data.calibration_status = CalibrationStatus.UNCALIBRATED.value
            if getattr(data, "uncertainty_status", None) is None:
                data.uncertainty_status = UncertaintyStatus.UNCALIBRATED.value
            if getattr(data, "is_flagged_for_review", None) is None:
                data.is_flagged_for_review = True
        return data


class SegmentReviewRequest(BaseModel):
    """Payload to review an AI candidate segment (Phase 69)."""

    model_config = ConfigDict(extra="forbid")

    decision: Literal["confirmed", "rejected", "inconclusive", "escalated"]
    review_notes: str = Field(
        ...,
        min_length=3,
        max_length=2000,
        description="Mandatory investigator rationale and factual findings",
    )
    false_positive_reason: str | None = Field(
        default=None,
        description="Required categorized justification when decision is 'rejected'",
    )

    @field_validator("false_positive_reason")
    @classmethod
    def validate_false_positive(cls, v: str | None, info: Any) -> str | None:
        decision = info.data.get("decision") if info.data else None
        if decision == "rejected" and not v:
            raise ValueError(
                "false_positive_reason is mandatory when rejecting a candidate segment"
            )
        return v


class PaginatedSegmentsRead(BaseModel):
    """Paginated list of AI candidate segments."""

    model_config = ConfigDict(extra="forbid")

    items: list[AICandidateSegmentRead]
    total: int
    limit: int
    offset: int


class AIRetentionPurgeRequest(BaseModel):
    """Payload to execute authorized retention purge of expired AI results (Phase 69.4)."""

    model_config = ConfigDict(extra="forbid")

    retention_days: int = Field(
        default=90,
        ge=1,
        le=3650,
        description="Candidate segments older than this many days will be purged",
    )
    department_id: UUID | None = Field(
        default=None,
        description="Target department filter for scoped purging",
    )


class AIRetentionPurgeResponse(BaseModel):
    """Summary of purged candidate segments under retention rules."""

    model_config = ConfigDict(extra="forbid")

    purged_count: int
    retention_days: int
    cutoff_date: datetime
    department_id: UUID | None = None
    disclaimer: str = Field(
        default="Original evidence objects and immutable security audit records are permanently preserved."
    )
