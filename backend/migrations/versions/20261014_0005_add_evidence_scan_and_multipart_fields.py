"""Add scan_status, scan_details, and multipart upload fields (Phases 46-48).

Revision ID: 20261014_0005
Revises: 20261014_0004
Create Date: 2026-10-14 03:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from backend.app.models.base import UTCDateTime

revision: str = "20261014_0005"
down_revision: str | None = "20261014_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add scan fields to evidence_attachments and multipart fields to upload_sessions."""
    # 1. Add scan columns to evidence_attachments
    op.add_column(
        "evidence_attachments",
        sa.Column(
            "scan_status",
            sa.String(length=32),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
    )
    op.add_column(
        "evidence_attachments",
        sa.Column(
            "scanned_at",
            UTCDateTime(),
            nullable=True,
        ),
    )
    op.add_column(
        "evidence_attachments",
        sa.Column(
            "scan_details",
            sa.String(length=512),
            nullable=True,
        ),
    )
    op.create_index(
        op.f("ix_evidence_attachments_scan_status"),
        "evidence_attachments",
        ["scan_status"],
        unique=False,
    )
    op.create_check_constraint(
        "ck_evidence_attachments_scan_status",
        "evidence_attachments",
        "scan_status IN ('pending', 'scanning', 'clean', 'infected', 'failed', 'quarantined')",
    )

    # 2. Add multipart columns to upload_sessions
    op.add_column(
        "upload_sessions",
        sa.Column(
            "upload_id",
            sa.String(length=256),
            nullable=True,
        ),
    )
    op.add_column(
        "upload_sessions",
        sa.Column(
            "total_parts",
            sa.Integer(),
            nullable=True,
        ),
    )
    op.add_column(
        "upload_sessions",
        sa.Column(
            "part_size_bytes",
            sa.BigInteger(),
            nullable=True,
        ),
    )
    op.create_index(
        op.f("ix_upload_sessions_upload_id"),
        "upload_sessions",
        ["upload_id"],
        unique=False,
    )


def downgrade() -> None:
    """Revert scan fields from evidence_attachments and multipart fields from upload_sessions."""
    # 1. Revert upload_sessions multipart columns
    op.drop_index(
        op.f("ix_upload_sessions_upload_id"),
        table_name="upload_sessions",
    )
    op.drop_column("upload_sessions", "part_size_bytes")
    op.drop_column("upload_sessions", "total_parts")
    op.drop_column("upload_sessions", "upload_id")

    # 2. Revert evidence_attachments scan columns
    op.drop_constraint(
        "ck_evidence_attachments_scan_status",
        "evidence_attachments",
        type_="check",
    )
    op.drop_index(
        op.f("ix_evidence_attachments_scan_status"),
        table_name="evidence_attachments",
    )
    op.drop_column("evidence_attachments", "scan_details")
    op.drop_column("evidence_attachments", "scanned_at")
    op.drop_column("evidence_attachments", "scan_status")
