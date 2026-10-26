"""Add AI datasets and analysis jobs tables (Phases 61-65).

Revision ID: 20261014_0008
Revises: 20261014_0007
Create Date: 2026-10-14 08:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from backend.app.models.base import UTCDateTime

revision: str = "20261014_0008"
down_revision: str | None = "20261014_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply Phase 61-65 schema additions."""
    # 1. Create ai_datasets table
    op.create_table(
        "ai_datasets",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column(
            "dataset_type",
            sa.String(length=32),
            nullable=False,
            server_default="benchmark",
        ),
        sa.Column("source_uri", sa.String(length=512), nullable=True),
        sa.Column("license_id", sa.String(length=64), nullable=False),
        sa.Column(
            "consent_status",
            sa.String(length=32),
            nullable=False,
            server_default="consented",
        ),
        sa.Column("provenance_details", sa.Text(), nullable=True),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "manifest_item_count",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("manifest_payload", sa.Text(), nullable=True),
        sa.Column(
            "status",
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
        sa.Column("review_notes", sa.String(length=1024), nullable=True),
        sa.Column(
            "created_by_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            UTCDateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            UTCDateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("name", "version", name="uq_ai_datasets_name_version"),
        sa.CheckConstraint(
            "length(manifest_sha256) = 64",
            name="ck_ai_datasets_manifest_sha256_length",
        ),
        sa.CheckConstraint(
            "manifest_item_count >= 0",
            name="ck_ai_datasets_item_count_non_negative",
        ),
        sa.CheckConstraint(
            "status IN ('pending_review', 'approved', 'rejected', 'withdrawn')",
            name="ck_ai_datasets_status",
        ),
        sa.CheckConstraint(
            "consent_status IN ('consented', 'public_domain_reviewed', 'synthetic_reviewed', 'unverified')",
            name="ck_ai_datasets_consent_status",
        ),
        sa.CheckConstraint(
            "dataset_type IN ('benchmark', 'training', 'validation', 'test')",
            name="ck_ai_datasets_dataset_type",
        ),
    )
    op.create_index("ix_ai_datasets_name", "ai_datasets", ["name"])
    op.create_index("ix_ai_datasets_status", "ai_datasets", ["status"])
    op.create_index("ix_ai_datasets_created_by_id", "ai_datasets", ["created_by_id"])
    op.create_index("ix_ai_datasets_reviewed_by_id", "ai_datasets", ["reviewed_by_id"])

    # 2. Create ai_analysis_jobs table
    op.create_table(
        "ai_analysis_jobs",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
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
        sa.Column(
            "submitted_by_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default="queued",
        ),
        sa.Column(
            "progress_percent",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "current_step",
            sa.String(length=64),
            nullable=False,
            server_default="queued",
        ),
        sa.Column(
            "model_name",
            sa.String(length=64),
            nullable=False,
            server_default="violence-classifier",
        ),
        sa.Column(
            "model_version",
            sa.String(length=32),
            nullable=False,
            server_default="0.1.0",
        ),
        sa.Column("result_summary", sa.Text(), nullable=True),
        sa.Column("error_message", sa.String(length=1024), nullable=True),
        sa.Column("error_category", sa.String(length=64), nullable=True),
        sa.Column(
            "retry_count",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "max_retries",
            sa.BigInteger(),
            nullable=False,
            server_default="3",
        ),
        sa.Column("started_at", UTCDateTime(), nullable=True),
        sa.Column("completed_at", UTCDateTime(), nullable=True),
        sa.Column(
            "created_at",
            UTCDateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            UTCDateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "progress_percent >= 0 AND progress_percent <= 100",
            name="ck_ai_analysis_jobs_progress_range",
        ),
        sa.CheckConstraint(
            "retry_count >= 0",
            name="ck_ai_analysis_jobs_retry_count_non_negative",
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')",
            name="ck_ai_analysis_jobs_status",
        ),
    )
    op.create_index("ix_ai_analysis_jobs_evidence_id", "ai_analysis_jobs", ["evidence_id"])
    op.create_index("ix_ai_analysis_jobs_incident_id", "ai_analysis_jobs", ["incident_id"])
    op.create_index("ix_ai_analysis_jobs_department_id", "ai_analysis_jobs", ["department_id"])
    op.create_index("ix_ai_analysis_jobs_submitted_by_id", "ai_analysis_jobs", ["submitted_by_id"])
    op.create_index("ix_ai_analysis_jobs_status", "ai_analysis_jobs", ["status"])
    op.create_index(
        "ix_ai_analysis_jobs_department_id_status",
        "ai_analysis_jobs",
        ["department_id", "status"],
    )


def downgrade() -> None:
    """Revert Phase 61-65 schema additions."""
    op.drop_index("ix_ai_analysis_jobs_department_id_status", table_name="ai_analysis_jobs")
    op.drop_index("ix_ai_analysis_jobs_status", table_name="ai_analysis_jobs")
    op.drop_index("ix_ai_analysis_jobs_submitted_by_id", table_name="ai_analysis_jobs")
    op.drop_index("ix_ai_analysis_jobs_department_id", table_name="ai_analysis_jobs")
    op.drop_index("ix_ai_analysis_jobs_incident_id", table_name="ai_analysis_jobs")
    op.drop_index("ix_ai_analysis_jobs_evidence_id", table_name="ai_analysis_jobs")
    op.drop_table("ai_analysis_jobs")

    op.drop_index("ix_ai_datasets_reviewed_by_id", table_name="ai_datasets")
    op.drop_index("ix_ai_datasets_created_by_id", table_name="ai_datasets")
    op.drop_index("ix_ai_datasets_status", table_name="ai_datasets")
    op.drop_index("ix_ai_datasets_name", table_name="ai_datasets")
    op.drop_table("ai_datasets")
