"""SQLAlchemy models for Biometric Governance and Reference Registry (Phases 73-74).

Enforces:
- Tenant and department scoping on all biometric records.
- Explicit lawful basis, purpose mapping, versioned notices, and consent tracking.
- Secure reference registry with SHA-256 template digests and encrypted template storage.
- Immutable foreign-key integrity linking references to governance authorizations and provenance evidence.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.biometrics import (
    BiometricHumanVerdict,
    BiometricLawfulBasis,
    BiometricMatchVerdict,
    BiometricPurpose,
    BiometricReferenceStatus,
    ConsentStatus,
    GovernanceStatus,
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

_GOVERNANCE_STATUS_VALUES = ", ".join(f"'{s.value}'" for s in GovernanceStatus)
_CONSENT_STATUS_VALUES = ", ".join(f"'{s.value}'" for s in ConsentStatus)
_PURPOSE_VALUES = ", ".join(f"'{p.value}'" for p in BiometricPurpose)
_LAWFUL_BASIS_VALUES = ", ".join(f"'{b.value}'" for b in BiometricLawfulBasis)
_REFERENCE_STATUS_VALUES = ", ".join(f"'{s.value}'" for s in BiometricReferenceStatus)
_MATCH_VERDICT_VALUES = ", ".join(f"'{v.value}'" for v in BiometricMatchVerdict)
_HUMAN_VERDICT_VALUES = ", ".join(f"'{v.value}'" for v in BiometricHumanVerdict)


class BiometricGovernanceRecord(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Biometric processing assessment, notice, and consent governance record (Phase 73)."""

    __tablename__ = "biometric_governance_records"
    __table_args__ = (
        CheckConstraint(
            f"status IN ({_GOVERNANCE_STATUS_VALUES})",
            name="ck_biometric_governance_status",
        ),
        CheckConstraint(
            f"consent_status IS NULL OR consent_status IN ({_CONSENT_STATUS_VALUES})",
            name="ck_biometric_governance_consent_status",
        ),
        CheckConstraint(
            f"purpose IN ({_PURPOSE_VALUES})",
            name="ck_biometric_governance_purpose",
        ),
        CheckConstraint(
            f"lawful_basis IN ({_LAWFUL_BASIS_VALUES})",
            name="ck_biometric_governance_lawful_basis",
        ),
        CheckConstraint(
            "retention_days > 0 AND retention_days <= 365",
            name="ck_biometric_governance_retention_days",
        ),
        Index("ix_biometric_governance_tenant_dept_status", "tenant_id", "department_id", "status"),
        Index("ix_biometric_governance_subject", "subject_user_id"),
    )

    tenant_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    department_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="CASCADE"),
        nullable=False,
    )
    policy_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="1.0.0",
    )
    purpose: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    lawful_basis: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    notice_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="1.0.0",
    )
    subject_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=GovernanceStatus.PENDING_LEGAL_REVIEW.value,
    )
    consent_status: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )
    consented_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime,
        nullable=True,
    )
    withdrawn_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime,
        nullable=True,
    )
    approved_by_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    approved_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime,
        nullable=True,
    )
    legal_review_notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    retention_days: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=90,
    )
    retention_expires_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime,
        nullable=True,
    )

    # Relationships
    department: Mapped[Department] = relationship()
    subject_user: Mapped[User | None] = relationship(foreign_keys=[subject_user_id])
    approved_by: Mapped[User | None] = relationship(foreign_keys=[approved_by_id])
    references: Mapped[list[BiometricReference]] = relationship(
        back_populates="governance_record",
        cascade="all, delete-orphan",
    )


class BiometricReference(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Restricted biometric reference registry record (Phase 74)."""

    __tablename__ = "biometric_references"
    __table_args__ = (
        UniqueConstraint("reference_id", name="uq_biometric_references_reference_id"),
        CheckConstraint(
            f"status IN ({_REFERENCE_STATUS_VALUES})",
            name="ck_biometric_references_status",
        ),
        CheckConstraint(
            "length(template_digest) = 64",
            name="ck_biometric_references_template_digest_length",
        ),
        CheckConstraint(
            f"purpose IN ({_PURPOSE_VALUES})",
            name="ck_biometric_references_purpose",
        ),
        Index("ix_biometric_references_tenant_dept_status", "tenant_id", "department_id", "status"),
        Index("ix_biometric_references_reference_id", "reference_id"),
        Index("ix_biometric_references_governance_id", "governance_record_id"),
        Index("ix_biometric_references_subject_id", "subject_user_id"),
    )

    reference_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    tenant_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    department_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="CASCADE"),
        nullable=False,
    )
    subject_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    governance_record_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("biometric_governance_records.id", ondelete="CASCADE"),
        nullable=False,
    )
    purpose: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=BiometricReferenceStatus.PENDING_APPROVAL.value,
    )
    template_digest: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    encrypted_template: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    provenance_evidence_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("evidence_attachments.id", ondelete="SET NULL"),
        nullable=True,
    )
    enrollment_notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    enrolled_by_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    enrolled_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        nullable=False,
    )
    revoked_by_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime,
        nullable=True,
    )
    revocation_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    retention_expires_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        nullable=False,
    )

    # Relationships
    governance_record: Mapped[BiometricGovernanceRecord] = relationship(
        back_populates="references",
    )
    enrolled_by: Mapped[User] = relationship(foreign_keys=[enrolled_by_id])
    revoked_by: Mapped[User | None] = relationship(foreign_keys=[revoked_by_id])
    provenance_evidence: Mapped[EvidenceAttachment | None] = relationship()


class BiometricVerificationReview(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Authorized human reviewer determination and audit trail for biometric match candidates (Phase 77)."""

    __tablename__ = "biometric_verification_reviews"
    __table_args__ = (
        CheckConstraint(
            f"automated_verdict IN ({_MATCH_VERDICT_VALUES})",
            name="ck_biometric_verification_automated_verdict",
        ),
        CheckConstraint(
            f"human_verdict IN ({_HUMAN_VERDICT_VALUES})",
            name="ck_biometric_verification_human_verdict",
        ),
        CheckConstraint(
            "length(probe_image_hash) = 64",
            name="ck_biometric_verification_probe_hash_length",
        ),
        CheckConstraint(
            "candidate_similarity >= -1.0 AND candidate_similarity <= 1.0",
            name="ck_biometric_verification_similarity_bounds",
        ),
        CheckConstraint(
            "uncertainty_lower_bound < uncertainty_upper_bound",
            name="ck_biometric_verification_uncertainty_bounds",
        ),
        Index("ix_biometric_verification_tenant_dept", "tenant_id", "department_id"),
        Index("ix_biometric_verification_reference_id", "reference_id"),
        Index("ix_biometric_verification_incident_id", "incident_id"),
        Index("ix_biometric_verification_reviewer_id", "reviewer_id"),
        Index("ix_biometric_verification_probe_hash", "probe_image_hash"),
    )

    tenant_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    department_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="CASCADE"),
        nullable=False,
    )
    incident_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
    )
    reference_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("biometric_references.id", ondelete="SET NULL"),
        nullable=True,
    )
    probe_image_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    candidate_similarity: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    uncertainty_lower_bound: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.60,
    )
    uncertainty_upper_bound: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.85,
    )
    automated_verdict: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    human_verdict: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=BiometricHumanVerdict.INCONCLUSIVE_DISMISSED.value,
    )
    reviewer_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime,
        nullable=True,
    )
    review_notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    override_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    is_override: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    # Relationships
    department: Mapped[Department] = relationship()
    incident: Mapped[Incident | None] = relationship()
    reference: Mapped[BiometricReference | None] = relationship()
    reviewer: Mapped[User | None] = relationship(foreign_keys=[reviewer_id])
