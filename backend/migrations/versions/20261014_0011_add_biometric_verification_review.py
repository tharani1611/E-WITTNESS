"""Add biometric verification reviews table for human oversight (Phases 76-80).

Revision ID: 20261014_0011
Revises: 20261014_0010
Create Date: 2026-10-14 20:30:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from backend.app.models.base import UTCDateTime

revision: str = "20261014_0011"
down_revision: str | None = "20261014_0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_MATCH_VERDICT_VALUES = (
    "'match_candidate', 'non_match_candidate', 'inconclusive_uncertain', 'insufficient_quality'"
)
_HUMAN_VERDICT_VALUES = (
    "'verified_match', 'verified_non_match', 'rejected_override', 'inconclusive_dismissed'"
)


def upgrade() -> None:
    """Apply Phase 77 biometric verification review schema."""
    op.create_table(
        "biometric_verification_reviews",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column(
            "department_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("departments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "incident_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "reference_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("biometric_references.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("probe_image_hash", sa.String(length=64), nullable=False),
        sa.Column("candidate_similarity", sa.Float(), nullable=False),
        sa.Column("uncertainty_lower_bound", sa.Float(), nullable=False, server_default="0.60"),
        sa.Column("uncertainty_upper_bound", sa.Float(), nullable=False, server_default="0.85"),
        sa.Column("automated_verdict", sa.String(length=32), nullable=False),
        sa.Column(
            "human_verdict",
            sa.String(length=32),
            nullable=False,
            server_default="inconclusive_dismissed",
        ),
        sa.Column(
            "reviewer_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("reviewed_at", UTCDateTime(), nullable=True),
        sa.Column("review_notes", sa.Text(), nullable=True),
        sa.Column("override_reason", sa.Text(), nullable=True),
        sa.Column("is_override", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.CheckConstraint(
            f"automated_verdict IN ({_MATCH_VERDICT_VALUES})",
            name="ck_biometric_verification_automated_verdict",
        ),
        sa.CheckConstraint(
            f"human_verdict IN ({_HUMAN_VERDICT_VALUES})",
            name="ck_biometric_verification_human_verdict",
        ),
        sa.CheckConstraint(
            "length(probe_image_hash) = 64",
            name="ck_biometric_verification_probe_hash_length",
        ),
        sa.CheckConstraint(
            "candidate_similarity >= -1.0 AND candidate_similarity <= 1.0",
            name="ck_biometric_verification_similarity_bounds",
        ),
        sa.CheckConstraint(
            "uncertainty_lower_bound < uncertainty_upper_bound",
            name="ck_biometric_verification_uncertainty_bounds",
        ),
    )
    op.create_index(
        "ix_biometric_verification_tenant_dept",
        "biometric_verification_reviews",
        ["tenant_id", "department_id"],
    )
    op.create_index(
        "ix_biometric_verification_reference_id",
        "biometric_verification_reviews",
        ["reference_id"],
    )
    op.create_index(
        "ix_biometric_verification_incident_id",
        "biometric_verification_reviews",
        ["incident_id"],
    )
    op.create_index(
        "ix_biometric_verification_reviewer_id",
        "biometric_verification_reviews",
        ["reviewer_id"],
    )
    op.create_index(
        "ix_biometric_verification_probe_hash",
        "biometric_verification_reviews",
        ["probe_image_hash"],
    )


def downgrade() -> None:
    """Revert Phase 77 biometric verification review schema."""
    op.drop_table("biometric_verification_reviews")
