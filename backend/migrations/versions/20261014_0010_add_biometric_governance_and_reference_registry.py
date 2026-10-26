"""Add biometric governance records and reference registry tables (Phases 71-75).

Revision ID: 20261014_0010
Revises: 20261014_0009
Create Date: 2026-10-14 16:30:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from backend.app.models.base import UTCDateTime

revision: str = "20261014_0010"
down_revision: str | None = "20261014_0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_GOVERNANCE_STATUS_VALUES = "'pending_legal_review', 'approved', 'rejected', 'revoked', 'no_go'"
_CONSENT_STATUS_VALUES = "'active', 'withdrawn', 'expired', 'revoked'"
_PURPOSE_VALUES = (
    "'explicit_consent_reference_enrollment', 'authorized_investigative_manual_review', "
    "'privacy_redaction_blurring', 'testing_synthetic_benchmark'"
)
_LAWFUL_BASIS_VALUES = (
    "'explicit_consent', 'statutory_legal_obligation', 'substantial_public_interest', "
    "'research_benchmark_exempt'"
)
_REFERENCE_STATUS_VALUES = "'pending_approval', 'active', 'revoked', 'expired', 'purged'"


def upgrade() -> None:
    """Apply Phase 73-74 biometric schema additions."""
    # 1. Create biometric_governance_records table
    op.create_table(
        "biometric_governance_records",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column(
            "department_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("departments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("policy_version", sa.String(length=32), nullable=False, server_default="1.0.0"),
        sa.Column("purpose", sa.String(length=64), nullable=False),
        sa.Column("lawful_basis", sa.String(length=64), nullable=False),
        sa.Column("notice_version", sa.String(length=32), nullable=False, server_default="1.0.0"),
        sa.Column(
            "subject_user_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default="pending_legal_review",
        ),
        sa.Column("consent_status", sa.String(length=32), nullable=True),
        sa.Column("consented_at", UTCDateTime(), nullable=True),
        sa.Column("withdrawn_at", UTCDateTime(), nullable=True),
        sa.Column(
            "approved_by_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("approved_at", UTCDateTime(), nullable=True),
        sa.Column("legal_review_notes", sa.Text(), nullable=True),
        sa.Column("retention_days", sa.Integer(), nullable=False, server_default="90"),
        sa.Column("retention_expires_at", UTCDateTime(), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.CheckConstraint(
            f"status IN ({_GOVERNANCE_STATUS_VALUES})",
            name="ck_biometric_governance_status",
        ),
        sa.CheckConstraint(
            f"consent_status IS NULL OR consent_status IN ({_CONSENT_STATUS_VALUES})",
            name="ck_biometric_governance_consent_status",
        ),
        sa.CheckConstraint(
            f"purpose IN ({_PURPOSE_VALUES})",
            name="ck_biometric_governance_purpose",
        ),
        sa.CheckConstraint(
            f"lawful_basis IN ({_LAWFUL_BASIS_VALUES})",
            name="ck_biometric_governance_lawful_basis",
        ),
        sa.CheckConstraint(
            "retention_days > 0 AND retention_days <= 365",
            name="ck_biometric_governance_retention_days",
        ),
    )
    op.create_index(
        "ix_biometric_governance_tenant_dept_status",
        "biometric_governance_records",
        ["tenant_id", "department_id", "status"],
    )
    op.create_index(
        "ix_biometric_governance_subject",
        "biometric_governance_records",
        ["subject_user_id"],
    )

    # 2. Create biometric_references table
    op.create_table(
        "biometric_references",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("reference_id", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column(
            "department_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("departments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "subject_user_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "governance_record_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("biometric_governance_records.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("purpose", sa.String(length=64), nullable=False),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default="pending_approval",
        ),
        sa.Column("template_digest", sa.String(length=64), nullable=False),
        sa.Column("encrypted_template", sa.Text(), nullable=True),
        sa.Column(
            "provenance_evidence_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("evidence_attachments.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("enrollment_notes", sa.Text(), nullable=True),
        sa.Column(
            "enrolled_by_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("enrolled_at", UTCDateTime(), nullable=False),
        sa.Column(
            "revoked_by_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("revoked_at", UTCDateTime(), nullable=True),
        sa.Column("revocation_reason", sa.Text(), nullable=True),
        sa.Column("retention_expires_at", UTCDateTime(), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.UniqueConstraint("reference_id", name="uq_biometric_references_reference_id"),
        sa.CheckConstraint(
            f"status IN ({_REFERENCE_STATUS_VALUES})",
            name="ck_biometric_references_status",
        ),
        sa.CheckConstraint(
            "length(template_digest) = 64",
            name="ck_biometric_references_template_digest_length",
        ),
        sa.CheckConstraint(
            f"purpose IN ({_PURPOSE_VALUES})",
            name="ck_biometric_references_purpose",
        ),
    )
    op.create_index(
        "ix_biometric_references_tenant_dept_status",
        "biometric_references",
        ["tenant_id", "department_id", "status"],
    )
    op.create_index(
        "ix_biometric_references_reference_id",
        "biometric_references",
        ["reference_id"],
    )
    op.create_index(
        "ix_biometric_references_governance_id",
        "biometric_references",
        ["governance_record_id"],
    )
    op.create_index(
        "ix_biometric_references_subject_id",
        "biometric_references",
        ["subject_user_id"],
    )


def downgrade() -> None:
    """Revert Phase 73-74 biometric schema additions."""
    op.drop_table("biometric_references")
    op.drop_table("biometric_governance_records")
