"""Add AI candidate segments table (Phases 66-70).

Revision ID: 20261014_0009
Revises: 20261014_0008
Create Date: 2026-10-14 14:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from backend.app.models.base import UTCDateTime

revision: str = "20261014_0009"
down_revision: str | None = "20261014_0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_REVIEW_STATUS_VALUES = (
    "'pending_review', 'under_review', 'confirmed', 'rejected', 'inconclusive', 'escalated'"
)
_CALIBRATION_STATUS_VALUES = "'uncalibrated', 'calibrated', 'unavailable', 'failed'"
_UNCERTAINTY_STATUS_VALUES = (
    "'high_confidence', 'low_confidence', 'borderline', 'uncalibrated', 'uncertain', 'abstained'"
)


def upgrade() -> None:
    """Apply Phase 66-70 schema additions."""
    op.create_table(
        "ai_candidate_segments",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "job_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("ai_analysis_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "evidence_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("evidence_attachments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "incident_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "department_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("departments.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("start_seconds", sa.Float(), nullable=False),
        sa.Column("end_seconds", sa.Float(), nullable=False),
        sa.Column("duration_seconds", sa.Float(), nullable=False),
        sa.Column("raw_score", sa.Float(), nullable=False),
        sa.Column("raw_label", sa.String(length=64), nullable=False, server_default="violence"),
        sa.Column("model_name", sa.String(length=64), nullable=False),
        sa.Column("model_version", sa.String(length=32), nullable=False),
        sa.Column(
            "preprocessing_version",
            sa.String(length=32),
            nullable=False,
            server_default="1.0.0",
        ),
        sa.Column(
            "calibration_status",
            sa.String(length=32),
            nullable=False,
            server_default="uncalibrated",
        ),
        sa.Column("calibrated_score", sa.Float(), nullable=True),
        sa.Column("calibration_version", sa.String(length=32), nullable=True),
        sa.Column(
            "uncertainty_status",
            sa.String(length=32),
            nullable=False,
            server_default="uncalibrated",
        ),
        sa.Column(
            "review_status",
            sa.String(length=32),
            nullable=False,
            server_default="pending_review",
        ),
        sa.Column(
            "reviewed_by_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("reviewed_at", UTCDateTime(), nullable=True),
        sa.Column("review_notes", sa.Text(), nullable=True),
        sa.Column("false_positive_reason", sa.String(length=64), nullable=True),
        sa.Column(
            "is_flagged_for_review",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.CheckConstraint(
            "start_seconds >= 0.0",
            name="ck_ai_candidate_segments_start_seconds_non_negative",
        ),
        sa.CheckConstraint(
            "end_seconds > start_seconds",
            name="ck_ai_candidate_segments_end_after_start",
        ),
        sa.CheckConstraint(
            "duration_seconds > 0.0",
            name="ck_ai_candidate_segments_duration_positive",
        ),
        sa.CheckConstraint(
            "raw_score >= 0.0 AND raw_score <= 1.0",
            name="ck_ai_candidate_segments_raw_score_bounds",
        ),
        sa.CheckConstraint(
            "calibrated_score IS NULL OR (calibrated_score >= 0.0 AND calibrated_score <= 1.0)",
            name="ck_ai_candidate_segments_calibrated_score_bounds",
        ),
        sa.CheckConstraint(
            f"review_status IN ({_REVIEW_STATUS_VALUES})",
            name="ck_ai_candidate_segments_review_status",
        ),
        sa.CheckConstraint(
            f"calibration_status IN ({_CALIBRATION_STATUS_VALUES})",
            name="ck_ai_candidate_segments_calibration_status",
        ),
        sa.CheckConstraint(
            f"uncertainty_status IN ({_UNCERTAINTY_STATUS_VALUES})",
            name="ck_ai_candidate_segments_uncertainty_status",
        ),
        sa.UniqueConstraint(
            "job_id",
            "start_seconds",
            "end_seconds",
            name="uq_ai_candidate_segments_job_window",
        ),
    )

    op.create_index(
        "ix_ai_candidate_segments_job_id",
        "ai_candidate_segments",
        ["job_id"],
    )
    op.create_index(
        "ix_ai_candidate_segments_evidence_id",
        "ai_candidate_segments",
        ["evidence_id"],
    )
    op.create_index(
        "ix_ai_candidate_segments_incident_id",
        "ai_candidate_segments",
        ["incident_id"],
    )
    op.create_index(
        "ix_ai_candidate_segments_department_id",
        "ai_candidate_segments",
        ["department_id"],
    )
    op.create_index(
        "ix_ai_candidate_segments_department_id_review_status",
        "ai_candidate_segments",
        ["department_id", "review_status"],
    )
    op.create_index(
        "ix_ai_candidate_segments_review_status",
        "ai_candidate_segments",
        ["review_status"],
    )
    op.create_index(
        "ix_ai_candidate_segments_reviewed_by_id",
        "ai_candidate_segments",
        ["reviewed_by_id"],
    )
    op.create_index(
        "ix_ai_candidate_segments_created_at",
        "ai_candidate_segments",
        ["created_at"],
    )


def downgrade() -> None:
    """Revert Phase 66-70 schema additions."""
    op.drop_index("ix_ai_candidate_segments_created_at", table_name="ai_candidate_segments")
    op.drop_index("ix_ai_candidate_segments_reviewed_by_id", table_name="ai_candidate_segments")
    op.drop_index("ix_ai_candidate_segments_review_status", table_name="ai_candidate_segments")
    op.drop_index(
        "ix_ai_candidate_segments_department_id_review_status", table_name="ai_candidate_segments"
    )
    op.drop_index("ix_ai_candidate_segments_department_id", table_name="ai_candidate_segments")
    op.drop_index("ix_ai_candidate_segments_incident_id", table_name="ai_candidate_segments")
    op.drop_index("ix_ai_candidate_segments_evidence_id", table_name="ai_candidate_segments")
    op.drop_index("ix_ai_candidate_segments_job_id", table_name="ai_candidate_segments")
    op.drop_table("ai_candidate_segments")
