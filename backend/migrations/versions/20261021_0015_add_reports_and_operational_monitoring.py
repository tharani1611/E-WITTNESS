"""Add report exports, worker heartbeats, and operational alerts schema (Phases 96-99).

Revision ID: 20261021_0015
Revises: 20261015_0014
Create Date: 2026-10-21 07:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from backend.app.models.base import UTCDateTime

revision: str = "20261021_0015"
down_revision: str | None = "20261015_0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_REPORT_TYPE_VALUES = "'incidents', 'cases', 'operational_summary', 'human_reviews'"
_REPORT_FORMAT_VALUES = "'csv', 'pdf'"
_EXPORT_STATUS_VALUES = "'pending', 'completed', 'failed', 'expired'"
_WORKER_STATUS_VALUES = "'active', 'stale', 'offline'"
_ALERT_SEVERITY_VALUES = "'info', 'warning', 'critical'"
_ALERT_TYPE_VALUES = "'queue_backlog', 'worker_stale', 'high_failure_rate', 'retry_exhaustion'"


def upgrade() -> None:
    """Apply Phase 96-99 report exports, worker heartbeats, and operational alerts tables."""
    # 1. Report exports table
    op.create_table(
        "report_exports",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("report_type", sa.String(length=64), nullable=False),
        sa.Column("export_format", sa.String(length=16), nullable=False),
        sa.Column(
            "department_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("departments.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column(
            "created_by_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("parameters_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default="completed",
        ),
        sa.Column("file_name", sa.String(length=255), nullable=False),
        sa.Column("file_size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("content_sha256", sa.String(length=64), nullable=True),
        sa.Column("storage_path", sa.String(length=512), nullable=True),
        sa.Column("download_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("expires_at", UTCDateTime(), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.CheckConstraint(
            f"report_type IN ({_REPORT_TYPE_VALUES})",
            name="ck_report_exports_type",
        ),
        sa.CheckConstraint(
            f"export_format IN ({_REPORT_FORMAT_VALUES})",
            name="ck_report_exports_format",
        ),
        sa.CheckConstraint(
            f"status IN ({_EXPORT_STATUS_VALUES})",
            name="ck_report_exports_status",
        ),
        sa.CheckConstraint(
            "download_count >= 0",
            name="ck_report_exports_download_count_non_negative",
        ),
    )
    op.create_index("ix_report_exports_created_by_id", "report_exports", ["created_by_id"])
    op.create_index("ix_report_exports_department_id", "report_exports", ["department_id"])
    op.create_index("ix_report_exports_status", "report_exports", ["status"])
    op.create_index("ix_report_exports_expires_at", "report_exports", ["expires_at"])
    op.create_index("ix_report_exports_created_at", "report_exports", ["created_at"])

    # 2. Worker heartbeats table
    op.create_table(
        "worker_heartbeats",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("worker_id", sa.String(length=64), nullable=False),
        sa.Column("hostname", sa.String(length=128), nullable=False),
        sa.Column("task_types", sa.String(length=256), nullable=False, server_default="all"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("last_heartbeat_at", UTCDateTime(), nullable=False),
        sa.Column("current_job_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("metrics_json", sa.Text(), nullable=True, server_default="{}"),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.UniqueConstraint("worker_id", name="uq_worker_heartbeats_worker_id"),
        sa.CheckConstraint(
            f"status IN ({_WORKER_STATUS_VALUES})",
            name="ck_worker_heartbeats_status",
        ),
    )
    op.create_index("ix_worker_heartbeats_status", "worker_heartbeats", ["status"])
    op.create_index(
        "ix_worker_heartbeats_last_heartbeat", "worker_heartbeats", ["last_heartbeat_at"]
    )

    # 3. Operational alerts table
    op.create_table(
        "operational_alerts",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("alert_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False, server_default="warning"),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("details_json", sa.Text(), nullable=True, server_default="{}"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("triggered_at", UTCDateTime(), nullable=False),
        sa.Column("resolved_at", UTCDateTime(), nullable=True),
        sa.Column(
            "notification_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("notifications.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.CheckConstraint(
            f"alert_type IN ({_ALERT_TYPE_VALUES})",
            name="ck_operational_alerts_type",
        ),
        sa.CheckConstraint(
            f"severity IN ({_ALERT_SEVERITY_VALUES})",
            name="ck_operational_alerts_severity",
        ),
    )
    op.create_index("ix_operational_alerts_type", "operational_alerts", ["alert_type"])
    op.create_index("ix_operational_alerts_severity", "operational_alerts", ["severity"])
    op.create_index("ix_operational_alerts_is_active", "operational_alerts", ["is_active"])
    op.create_index("ix_operational_alerts_triggered_at", "operational_alerts", ["triggered_at"])


def downgrade() -> None:
    """Drop Phase 96-99 report exports, worker heartbeats, and operational alerts tables."""
    op.drop_index("ix_operational_alerts_triggered_at", table_name="operational_alerts")
    op.drop_index("ix_operational_alerts_is_active", table_name="operational_alerts")
    op.drop_index("ix_operational_alerts_severity", table_name="operational_alerts")
    op.drop_index("ix_operational_alerts_type", table_name="operational_alerts")
    op.drop_table("operational_alerts")

    op.drop_index("ix_worker_heartbeats_last_heartbeat", table_name="worker_heartbeats")
    op.drop_index("ix_worker_heartbeats_status", table_name="worker_heartbeats")
    op.drop_table("worker_heartbeats")

    op.drop_index("ix_report_exports_created_at", table_name="report_exports")
    op.drop_index("ix_report_exports_expires_at", table_name="report_exports")
    op.drop_index("ix_report_exports_status", table_name="report_exports")
    op.drop_index("ix_report_exports_department_id", table_name="report_exports")
    op.drop_index("ix_report_exports_created_by_id", table_name="report_exports")
    op.drop_table("report_exports")
