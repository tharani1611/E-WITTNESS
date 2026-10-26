"""AI Dataset governance and asynchronous analysis job persistence models (Phases 62 & 65).

Enforces:
- Cryptographic manifest verification and provenance tracking for datasets.
- Monotonic state transitions and progress reporting for AI analysis jobs.
- Relational integrity binding jobs to evidence attachments, incidents, and departments.
- Denial-by-default isolation of operational evidence from training datasets.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.ai import (
    AIJobStatus,
    CalibrationStatus,
    DatasetConsentStatus,
    DatasetStatus,
    DatasetType,
    SegmentReviewStatus,
    UncertaintyStatus,
)
from backend.app.models.base import (
    Base,
    TimestampMixin,
    UTCDateTime,
    UUIDPrimaryKeyMixin,
)

if TYPE_CHECKING:
    from backend.app.models.department import Department
    from backend.app.models.evidence import EvidenceAttachment
    from backend.app.models.incident import Incident
    from backend.app.models.user import User


_DATASET_STATUS_VALUES = ", ".join(f"'{s.value}'" for s in DatasetStatus)
_CONSENT_STATUS_VALUES = ", ".join(f"'{s.value}'" for s in DatasetConsentStatus)
_DATASET_TYPE_VALUES = ", ".join(f"'{s.value}'" for s in DatasetType)
_JOB_STATUS_VALUES = ", ".join(f"'{s.value}'" for s in AIJobStatus)
_SEGMENT_REVIEW_STATUS_VALUES = ", ".join(f"'{s.value}'" for s in SegmentReviewStatus)
_CALIBRATION_STATUS_VALUES = ", ".join(f"'{s.value}'" for s in CalibrationStatus)
_UNCERTAINTY_STATUS_VALUES = ", ".join(f"'{s.value}'" for s in UncertaintyStatus)


class AIDataset(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """AI Training/Benchmark Dataset governance record (`ai_datasets` table)."""

    __tablename__ = "ai_datasets"
    __table_args__ = (
        UniqueConstraint("name", "version", name="uq_ai_datasets_name_version"),
        CheckConstraint(
            "length(manifest_sha256) = 64",
            name="ck_ai_datasets_manifest_sha256_length",
        ),
        CheckConstraint(
            "manifest_item_count >= 0",
            name="ck_ai_datasets_item_count_non_negative",
        ),
        CheckConstraint(
            f"status IN ({_DATASET_STATUS_VALUES})",
            name="ck_ai_datasets_status",
        ),
        CheckConstraint(
            f"consent_status IN ({_CONSENT_STATUS_VALUES})",
            name="ck_ai_datasets_consent_status",
        ),
        CheckConstraint(
            f"dataset_type IN ({_DATASET_TYPE_VALUES})",
            name="ck_ai_datasets_dataset_type",
        ),
        Index("ix_ai_datasets_name", "name"),
        Index("ix_ai_datasets_status", "status"),
        Index("ix_ai_datasets_created_by_id", "created_by_id"),
        Index("ix_ai_datasets_reviewed_by_id", "reviewed_by_id"),
    )

    name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    dataset_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=DatasetType.BENCHMARK.value,
    )
    source_uri: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )
    license_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    consent_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=DatasetConsentStatus.CONSENTED.value,
    )
    provenance_details: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    manifest_sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    manifest_item_count: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    manifest_payload: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=DatasetStatus.PENDING_REVIEW.value,
    )
    reviewed_by_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
    )
    review_notes: Mapped[str | None] = mapped_column(
        String(1024),
        nullable=True,
    )
    created_by_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )

    creator: Mapped[User] = relationship(
        "User",
        foreign_keys=[created_by_id],
        lazy="selectin",
    )
    reviewer: Mapped[User | None] = relationship(
        "User",
        foreign_keys=[reviewed_by_id],
        lazy="selectin",
    )

    def get_provenance_dict(self) -> dict[str, Any]:
        """Deserialize provenance details JSON."""
        if not self.provenance_details:
            return {}
        try:
            val = json.loads(self.provenance_details)
            return cast(dict[str, Any], val) if isinstance(val, dict) else {}
        except Exception:
            return {}

    def get_manifest_dict(self) -> dict[str, Any]:
        """Deserialize manifest payload JSON."""
        if not self.manifest_payload:
            return {}
        try:
            val = json.loads(self.manifest_payload)
            return cast(dict[str, Any], val) if isinstance(val, dict) else {}
        except Exception:
            return {}


class AIAnalysisJob(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Asynchronous AI video analysis job entity (`ai_analysis_jobs` table)."""

    __tablename__ = "ai_analysis_jobs"
    __table_args__ = (
        CheckConstraint(
            "progress_percent >= 0 AND progress_percent <= 100",
            name="ck_ai_analysis_jobs_progress_range",
        ),
        CheckConstraint(
            "retry_count >= 0",
            name="ck_ai_analysis_jobs_retry_count_non_negative",
        ),
        CheckConstraint(
            f"status IN ({_JOB_STATUS_VALUES})",
            name="ck_ai_analysis_jobs_status",
        ),
        Index("ix_ai_analysis_jobs_evidence_id", "evidence_id"),
        Index("ix_ai_analysis_jobs_incident_id", "incident_id"),
        Index("ix_ai_analysis_jobs_department_id", "department_id"),
        Index("ix_ai_analysis_jobs_submitted_by_id", "submitted_by_id"),
        Index("ix_ai_analysis_jobs_status", "status"),
        Index("ix_ai_analysis_jobs_department_id_status", "department_id", "status"),
    )

    evidence_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("evidence_attachments.id", ondelete="CASCADE"),
        nullable=False,
    )
    incident_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
    )
    department_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="RESTRICT"),
        nullable=False,
    )
    submitted_by_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=AIJobStatus.QUEUED.value,
    )
    progress_percent: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    current_step: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="queued",
    )
    model_name: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="violence-classifier",
    )
    model_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="0.1.0",
    )
    result_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    error_message: Mapped[str | None] = mapped_column(
        String(1024),
        nullable=True,
    )
    error_category: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    retry_count: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    max_retries: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=3,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
    )

    evidence: Mapped[EvidenceAttachment] = relationship(
        "EvidenceAttachment",
        foreign_keys=[evidence_id],
        lazy="selectin",
    )
    incident: Mapped[Incident] = relationship(
        "Incident",
        foreign_keys=[incident_id],
        lazy="selectin",
    )
    department: Mapped[Department] = relationship(
        "Department",
        foreign_keys=[department_id],
        lazy="selectin",
    )
    submitter: Mapped[User] = relationship(
        "User",
        foreign_keys=[submitted_by_id],
        lazy="selectin",
    )
    candidate_segments: Mapped[list[AICandidateSegment]] = relationship(
        "AICandidateSegment",
        back_populates="job",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def get_result_dict(self) -> dict[str, Any] | None:
        """Deserialize result summary JSON."""
        if not self.result_summary:
            return None
        try:
            val = json.loads(self.result_summary)
            return cast(dict[str, Any], val) if isinstance(val, dict) else None
        except Exception:
            return None


class AICandidateSegment(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Timestamped candidate violence segment detected by AI analysis (`ai_candidate_segments`)."""

    __tablename__ = "ai_candidate_segments"
    __table_args__ = (
        CheckConstraint(
            "start_seconds >= 0.0",
            name="ck_ai_candidate_segments_start_seconds_non_negative",
        ),
        CheckConstraint(
            "end_seconds > start_seconds",
            name="ck_ai_candidate_segments_end_after_start",
        ),
        CheckConstraint(
            "duration_seconds > 0.0",
            name="ck_ai_candidate_segments_duration_positive",
        ),
        CheckConstraint(
            "raw_score >= 0.0 AND raw_score <= 1.0",
            name="ck_ai_candidate_segments_raw_score_bounds",
        ),
        CheckConstraint(
            "calibrated_score IS NULL OR (calibrated_score >= 0.0 AND calibrated_score <= 1.0)",
            name="ck_ai_candidate_segments_calibrated_score_bounds",
        ),
        CheckConstraint(
            f"review_status IN ({_SEGMENT_REVIEW_STATUS_VALUES})",
            name="ck_ai_candidate_segments_review_status",
        ),
        CheckConstraint(
            f"calibration_status IN ({_CALIBRATION_STATUS_VALUES})",
            name="ck_ai_candidate_segments_calibration_status",
        ),
        CheckConstraint(
            f"uncertainty_status IN ({_UNCERTAINTY_STATUS_VALUES})",
            name="ck_ai_candidate_segments_uncertainty_status",
        ),
        UniqueConstraint(
            "job_id",
            "start_seconds",
            "end_seconds",
            name="uq_ai_candidate_segments_job_window",
        ),
        Index("ix_ai_candidate_segments_job_id", "job_id"),
        Index("ix_ai_candidate_segments_evidence_id", "evidence_id"),
        Index("ix_ai_candidate_segments_incident_id", "incident_id"),
        Index("ix_ai_candidate_segments_department_id", "department_id"),
        Index(
            "ix_ai_candidate_segments_department_id_review_status", "department_id", "review_status"
        ),
        Index("ix_ai_candidate_segments_review_status", "review_status"),
        Index("ix_ai_candidate_segments_reviewed_by_id", "reviewed_by_id"),
        Index("ix_ai_candidate_segments_created_at", "created_at"),
    )

    job_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("ai_analysis_jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    evidence_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("evidence_attachments.id", ondelete="CASCADE"),
        nullable=False,
    )
    incident_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
    )
    department_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="RESTRICT"),
        nullable=False,
    )
    start_seconds: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    end_seconds: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    duration_seconds: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    raw_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    raw_label: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="violence",
    )
    model_name: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    model_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    preprocessing_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="1.0.0",
    )
    calibration_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=CalibrationStatus.UNCALIBRATED.value,
    )
    calibrated_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )
    calibration_version: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )
    uncertainty_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=UncertaintyStatus.UNCALIBRATED.value,
    )
    review_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=SegmentReviewStatus.PENDING_REVIEW.value,
    )
    reviewed_by_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
    )
    review_notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    false_positive_reason: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    is_flagged_for_review: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    metadata_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    job: Mapped[AIAnalysisJob] = relationship(
        "AIAnalysisJob",
        back_populates="candidate_segments",
        lazy="selectin",
    )
    evidence: Mapped[EvidenceAttachment] = relationship(
        "EvidenceAttachment",
        foreign_keys=[evidence_id],
        lazy="selectin",
    )
    incident: Mapped[Incident] = relationship(
        "Incident",
        foreign_keys=[incident_id],
        lazy="selectin",
    )
    department: Mapped[Department] = relationship(
        "Department",
        foreign_keys=[department_id],
        lazy="selectin",
    )
    reviewer: Mapped[User | None] = relationship(
        "User",
        foreign_keys=[reviewed_by_id],
        lazy="selectin",
    )

    def get_metadata_dict(self) -> dict[str, Any]:
        """Deserialize metadata JSON safely."""
        if not self.metadata_json:
            return {}
        try:
            val = json.loads(self.metadata_json)
            return cast(dict[str, Any], val) if isinstance(val, dict) else {}
        except Exception:
            return {}
