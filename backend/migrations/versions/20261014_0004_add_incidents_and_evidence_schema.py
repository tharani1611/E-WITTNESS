"""Add incidents, upload_sessions, and evidence_attachments tables (Phases 41-45).

Revision ID: 20261014_0004
Revises: 20261013_0003
Create Date: 2026-10-14 02:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from backend.app.models.base import UTCDateTime

revision: str = "20261014_0004"
down_revision: str | None = "20261013_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create `incidents`, `upload_sessions`, and `evidence_attachments` tables."""
    # 1. incidents table
    op.create_table(
        "incidents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("reference_number", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.String(length=10000), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column(
            "status",
            sa.String(length=32),
            server_default=sa.text("'submitted'"),
            nullable=False,
        ),
        sa.Column("location", sa.String(length=255), nullable=False),
        sa.Column("occurred_at", UTCDateTime(), nullable=False),
        sa.Column("reporter_id", sa.Uuid(), nullable=False),
        sa.Column("department_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            UTCDateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            UTCDateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incidents")),
        sa.ForeignKeyConstraint(
            ["reporter_id"],
            ["users.id"],
            name=op.f("fk_incidents_reporter_id_users"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["department_id"],
            ["departments.id"],
            name=op.f("fk_incidents_department_id_departments"),
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(trim(title)) >= 5 AND length(title) <= 200",
            name=op.f("ck_incidents_title_length"),
        ),
        sa.CheckConstraint(
            "length(trim(description)) >= 10 AND length(description) <= 10000",
            name=op.f("ck_incidents_description_length"),
        ),
        sa.CheckConstraint(
            "length(trim(location)) >= 2 AND length(location) <= 255",
            name=op.f("ck_incidents_location_length"),
        ),
        sa.CheckConstraint(
            "category IN ('academic_misconduct', 'harassment_discrimination', "
            "'property_damage_theft', 'safety_hazard', 'physical_assault', 'other')",
            name=op.f("ck_incidents_category_allowed_values"),
        ),
        sa.CheckConstraint(
            "status IN ('submitted', 'triaged', 'under_investigation', 'closed', 'dismissed')",
            name=op.f("ck_incidents_status_allowed_values"),
        ),
        sa.CheckConstraint(
            "reference_number = upper(trim(reference_number)) AND length(reference_number) >= 12",
            name=op.f("ck_incidents_reference_number_normalized"),
        ),
    )
    op.create_index(
        op.f("ix_incidents_reference_number"),
        "incidents",
        ["reference_number"],
        unique=True,
    )
    op.create_index(
        op.f("ix_incidents_department_id"),
        "incidents",
        ["department_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_incidents_reporter_id"),
        "incidents",
        ["reporter_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_incidents_status"),
        "incidents",
        ["status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_incidents_department_id_status"),
        "incidents",
        ["department_id", "status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_incidents_reporter_id_status"),
        "incidents",
        ["reporter_id", "status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_incidents_occurred_at"),
        "incidents",
        ["occurred_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_incidents_category"),
        "incidents",
        ["category"],
        unique=False,
    )

    # 2. upload_sessions table
    op.create_table(
        "upload_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("uploader_id", sa.Uuid(), nullable=False),
        sa.Column("department_id", sa.Uuid(), nullable=False),
        sa.Column("storage_key", sa.String(length=512), nullable=False),
        sa.Column("original_filename", sa.String(length=255), nullable=False),
        sa.Column("declared_mime_type", sa.String(length=128), nullable=False),
        sa.Column("expected_size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", UTCDateTime(), nullable=False),
        sa.Column(
            "session_status",
            sa.String(length=32),
            server_default=sa.text("'active'"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            UTCDateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            UTCDateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_upload_sessions")),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_upload_sessions_incident_id_incidents"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["uploader_id"],
            ["users.id"],
            name=op.f("fk_upload_sessions_uploader_id_users"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["department_id"],
            ["departments.id"],
            name=op.f("fk_upload_sessions_department_id_departments"),
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "expected_size_bytes > 0",
            name=op.f("ck_upload_sessions_size_positive"),
        ),
        sa.CheckConstraint(
            "session_status IN ('active', 'completed', 'expired', 'cancelled')",
            name=op.f("ck_upload_sessions_status"),
        ),
    )
    op.create_index(
        op.f("ix_upload_sessions_storage_key"),
        "upload_sessions",
        ["storage_key"],
        unique=True,
    )
    op.create_index(
        op.f("ix_upload_sessions_incident_id"),
        "upload_sessions",
        ["incident_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_upload_sessions_uploader_id"),
        "upload_sessions",
        ["uploader_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_upload_sessions_department_id"),
        "upload_sessions",
        ["department_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_upload_sessions_expires_at"),
        "upload_sessions",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_upload_sessions_session_status"),
        "upload_sessions",
        ["session_status"],
        unique=False,
    )

    # 3. evidence_attachments table
    op.create_table(
        "evidence_attachments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("uploader_id", sa.Uuid(), nullable=False),
        sa.Column("department_id", sa.Uuid(), nullable=False),
        sa.Column("upload_session_id", sa.Uuid(), nullable=True),
        sa.Column("original_filename", sa.String(length=255), nullable=False),
        sa.Column("storage_key", sa.String(length=512), nullable=False),
        sa.Column("declared_mime_type", sa.String(length=128), nullable=False),
        sa.Column("detected_mime_type", sa.String(length=128), nullable=True),
        sa.Column("file_size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256_hash", sa.String(length=64), nullable=True),
        sa.Column(
            "upload_status",
            sa.String(length=32),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        sa.Column(
            "evidence_status",
            sa.String(length=32),
            server_default=sa.text("'attached'"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            UTCDateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            UTCDateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evidence_attachments")),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_evidence_attachments_incident_id_incidents"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["uploader_id"],
            ["users.id"],
            name=op.f("fk_evidence_attachments_uploader_id_users"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["department_id"],
            ["departments.id"],
            name=op.f("fk_evidence_attachments_department_id_departments"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["upload_session_id"],
            ["upload_sessions.id"],
            name=op.f("fk_evidence_attachments_upload_session_id_upload_sessions"),
            ondelete="SET NULL",
        ),
        sa.CheckConstraint(
            "file_size_bytes > 0",
            name=op.f("ck_evidence_attachments_size_positive"),
        ),
        sa.CheckConstraint(
            "sha256_hash IS NULL OR length(sha256_hash) = 64",
            name=op.f("ck_evidence_attachments_sha256_length"),
        ),
        sa.CheckConstraint(
            "upload_status IN ('pending', 'completed', 'failed', 'cancelled')",
            name=op.f("ck_evidence_attachments_upload_status"),
        ),
        sa.CheckConstraint(
            "evidence_status IN ('attached', 'quarantined', 'sealed')",
            name=op.f("ck_evidence_attachments_evidence_status"),
        ),
    )
    op.create_index(
        op.f("ix_evidence_attachments_storage_key"),
        "evidence_attachments",
        ["storage_key"],
        unique=True,
    )
    op.create_index(
        op.f("ix_evidence_attachments_incident_id"),
        "evidence_attachments",
        ["incident_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_evidence_attachments_department_id"),
        "evidence_attachments",
        ["department_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_evidence_attachments_uploader_id"),
        "evidence_attachments",
        ["uploader_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_evidence_attachments_upload_session_id"),
        "evidence_attachments",
        ["upload_session_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_evidence_attachments_sha256_hash"),
        "evidence_attachments",
        ["sha256_hash"],
        unique=False,
    )
    op.create_index(
        op.f("ix_evidence_attachments_upload_status"),
        "evidence_attachments",
        ["upload_status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_evidence_attachments_evidence_status"),
        "evidence_attachments",
        ["evidence_status"],
        unique=False,
    )


def downgrade() -> None:
    """Drop `evidence_attachments`, `upload_sessions`, and `incidents` tables."""
    op.drop_table("evidence_attachments")
    op.drop_table("upload_sessions")
    op.drop_table("incidents")
