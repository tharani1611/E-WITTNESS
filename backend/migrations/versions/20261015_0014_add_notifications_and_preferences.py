"""Add notifications, delivery attempts, and preferences schema (Phases 91-94).

Revision ID: 20261015_0014
Revises: 20261015_0013
Create Date: 2026-10-15 07:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from backend.app.models.base import UTCDateTime

revision: str = "20261015_0014"
down_revision: str | None = "20261015_0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_NOTIFICATION_CATEGORY_VALUES = (
    "'security_critical', 'assignment', 'status_update', 'system_notice'"
)
_NOTIFICATION_CHANNEL_VALUES = "'in_app', 'email'"
_NOTIFICATION_PRIORITY_VALUES = "'low', 'normal', 'high', 'urgent'"
_DELIVERY_STATUS_VALUES = (
    "'pending', 'delivered', 'failed', 'skipped', 'retrying', 'permanent_failure'"
)


def upgrade() -> None:
    """Apply Phase 91-94 notifications, delivery attempts, and preferences tables."""
    # 1. Notifications table
    op.create_table(
        "notifications",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "recipient_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "department_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("departments.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("category", sa.String(length=50), nullable=False),
        sa.Column(
            "channel",
            sa.String(length=20),
            nullable=False,
            server_default="in_app",
        ),
        sa.Column(
            "priority",
            sa.String(length=20),
            nullable=False,
            server_default="normal",
        ),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("data_json", sa.Text(), nullable=True),
        sa.Column(
            "is_read",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("read_at", UTCDateTime(), nullable=True),
        sa.Column(
            "delivery_status",
            sa.String(length=30),
            nullable=False,
            server_default="delivered",
        ),
        sa.Column("correlation_id", sa.String(length=128), nullable=True),
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
            f"category IN ({_NOTIFICATION_CATEGORY_VALUES})",
            name="ck_notifications_category",
        ),
        sa.CheckConstraint(
            f"channel IN ({_NOTIFICATION_CHANNEL_VALUES})",
            name="ck_notifications_channel",
        ),
        sa.CheckConstraint(
            f"priority IN ({_NOTIFICATION_PRIORITY_VALUES})",
            name="ck_notifications_priority",
        ),
        sa.CheckConstraint(
            f"delivery_status IN ({_DELIVERY_STATUS_VALUES})",
            name="ck_notifications_delivery_status",
        ),
    )
    op.create_index("ix_notifications_recipient_id", "notifications", ["recipient_id"])
    op.create_index("ix_notifications_department_id", "notifications", ["department_id"])
    op.create_index("ix_notifications_category", "notifications", ["category"])
    op.create_index("ix_notifications_is_read", "notifications", ["is_read"])
    op.create_index("ix_notifications_delivery_status", "notifications", ["delivery_status"])
    op.create_index("ix_notifications_correlation_id", "notifications", ["correlation_id"])
    op.create_index("ix_notifications_created_at", "notifications", ["created_at"])
    op.create_index(
        "ix_notifications_recipient_unread",
        "notifications",
        ["recipient_id", "is_read"],
    )

    # 2. Notification Delivery Attempts table (Phase 93)
    op.create_table(
        "notification_delivery_attempts",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "notification_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("notifications.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("deduplication_key", sa.String(length=128), nullable=False),
        sa.Column(
            "channel",
            sa.String(length=20),
            nullable=False,
            server_default="email",
        ),
        sa.Column(
            "attempt_number",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
        sa.Column(
            "status",
            sa.String(length=30),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("error_category", sa.String(length=50), nullable=True),
        sa.Column("error_message", sa.String(length=500), nullable=True),
        sa.Column(
            "attempted_at",
            UTCDateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("completed_at", UTCDateTime(), nullable=True),
        sa.Column("next_retry_at", UTCDateTime(), nullable=True),
        sa.CheckConstraint(
            "attempt_number >= 1",
            name="ck_notification_delivery_attempts_attempt_number",
        ),
        sa.UniqueConstraint(
            "deduplication_key",
            name="uq_notification_delivery_attempts_dedup",
        ),
    )
    op.create_index(
        "ix_notification_delivery_attempts_notification_id",
        "notification_delivery_attempts",
        ["notification_id"],
    )
    op.create_index(
        "ix_notification_delivery_attempts_deduplication_key",
        "notification_delivery_attempts",
        ["deduplication_key"],
        unique=True,
    )
    op.create_index(
        "ix_notification_delivery_attempts_status",
        "notification_delivery_attempts",
        ["status"],
    )
    op.create_index(
        "ix_notification_delivery_attempts_next_retry_at",
        "notification_delivery_attempts",
        ["next_retry_at"],
    )

    # 3. Notification Preferences table (Phase 94)
    op.create_table(
        "notification_preferences",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "user_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "email_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "in_app_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "assignments_email",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "assignments_in_app",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "status_updates_email",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "status_updates_in_app",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "system_notices_email",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "system_notices_in_app",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
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
        sa.UniqueConstraint("user_id", name="uq_notification_preferences_user_id"),
    )
    op.create_index(
        "ix_notification_preferences_user_id",
        "notification_preferences",
        ["user_id"],
        unique=True,
    )


def downgrade() -> None:
    """Revert Phase 91-94 notifications, delivery attempts, and preferences tables."""
    op.drop_table("notification_preferences")
    op.drop_table("notification_delivery_attempts")
    op.drop_table("notifications")
