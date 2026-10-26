"""Notification and preference persistence models (Phases 91-94).

Enforces:
- Normalized in-app notifications bound to recipient users and departments.
- Strict delivery status tracking and deduplication keys for idempotent delivery.
- User-configurable preferences with immutable security-critical communication protection.
- Check constraints and foreign key cascades.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.notification import (
    DeliveryStatus,
    NotificationCategory,
    NotificationChannel,
    NotificationPriority,
)
from backend.app.models.base import (
    Base,
    TimestampMixin,
    UTCDateTime,
    UUIDPrimaryKeyMixin,
    utc_now,
)

if TYPE_CHECKING:
    from backend.app.models.department import Department
    from backend.app.models.user import User


class Notification(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Persistent in-app notification record (Phase 92)."""

    __tablename__ = "notifications"

    recipient_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    department_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    category: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )
    channel: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=NotificationChannel.IN_APP.value,
    )
    priority: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=NotificationPriority.NORMAL.value,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    body: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    data_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    is_read: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
    )
    read_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
    )
    delivery_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default=DeliveryStatus.DELIVERED.value,
        index=True,
    )
    correlation_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        index=True,
    )

    # Relationships
    recipient: Mapped[User] = relationship("User", foreign_keys=[recipient_id])
    department: Mapped[Department | None] = relationship("Department", foreign_keys=[department_id])
    delivery_attempts: Mapped[list[NotificationDeliveryAttempt]] = relationship(
        "NotificationDeliveryAttempt",
        back_populates="notification",
        cascade="all, delete-orphan",
        order_by="NotificationDeliveryAttempt.attempt_number.asc()",
    )

    __table_args__ = (
        CheckConstraint(
            f"category IN ('{NotificationCategory.SECURITY_CRITICAL.value}', "
            f"'{NotificationCategory.ASSIGNMENT.value}', "
            f"'{NotificationCategory.STATUS_UPDATE.value}', "
            f"'{NotificationCategory.SYSTEM_NOTICE.value}')",
            name="ck_notifications_category",
        ),
        CheckConstraint(
            f"channel IN ('{NotificationChannel.IN_APP.value}', '{NotificationChannel.EMAIL.value}')",
            name="ck_notifications_channel",
        ),
        CheckConstraint(
            f"priority IN ('{NotificationPriority.LOW.value}', "
            f"'{NotificationPriority.NORMAL.value}', "
            f"'{NotificationPriority.HIGH.value}', "
            f"'{NotificationPriority.URGENT.value}')",
            name="ck_notifications_priority",
        ),
        CheckConstraint(
            f"delivery_status IN ('{DeliveryStatus.PENDING.value}', "
            f"'{DeliveryStatus.DELIVERED.value}', "
            f"'{DeliveryStatus.FAILED.value}', "
            f"'{DeliveryStatus.SKIPPED.value}', "
            f"'{DeliveryStatus.RETRYING.value}', "
            f"'{DeliveryStatus.PERMANENT_FAILURE.value}')",
            name="ck_notifications_delivery_status",
        ),
        Index("ix_notifications_recipient_unread", "recipient_id", "is_read"),
        Index("ix_notifications_created_at", "created_at"),
    )

    @property
    def data(self) -> dict[str, Any]:
        """Parsed data payload dictionary."""
        if not self.data_json:
            return {}
        try:
            loaded = json.loads(self.data_json)
            return cast(dict[str, Any], loaded if isinstance(loaded, dict) else {})
        except Exception:
            return {}

    def __repr__(self) -> str:
        return (
            f"<Notification id={self.id} recipient_id={self.recipient_id} "
            f"category='{self.category}' is_read={self.is_read}>"
        )


class NotificationDeliveryAttempt(Base, UUIDPrimaryKeyMixin):
    """Audit and retry attempt record for email/outbound notification delivery (Phase 93)."""

    __tablename__ = "notification_delivery_attempts"

    notification_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("notifications.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    deduplication_key: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        unique=True,
        index=True,
    )
    channel: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=NotificationChannel.EMAIL.value,
    )
    attempt_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
    )
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default=DeliveryStatus.PENDING.value,
        index=True,
    )
    error_category: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    error_message: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )
    attempted_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        default=utc_now,
        nullable=False,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
    )
    next_retry_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
        index=True,
    )

    # Relationships
    notification: Mapped[Notification] = relationship(
        "Notification",
        back_populates="delivery_attempts",
    )

    __table_args__ = (
        CheckConstraint(
            "attempt_number >= 1",
            name="ck_notification_delivery_attempts_attempt_number",
        ),
        UniqueConstraint("deduplication_key", name="uq_notification_delivery_attempts_dedup"),
    )

    def __repr__(self) -> str:
        return (
            f"<NotificationDeliveryAttempt id={self.id} notification_id={self.notification_id} "
            f"attempt={self.attempt_number} status='{self.status}'>"
        )


class NotificationPreference(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """User-level notification channel and category preference configuration (Phase 94)."""

    __tablename__ = "notification_preferences"

    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    email_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    in_app_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    assignments_email: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    assignments_in_app: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    status_updates_email: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    status_updates_in_app: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    system_notices_email: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    system_notices_in_app: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    # Relationships
    user: Mapped[User] = relationship("User", foreign_keys=[user_id])

    __table_args__ = (UniqueConstraint("user_id", name="uq_notification_preferences_user_id"),)

    def __repr__(self) -> str:
        return (
            f"<NotificationPreference id={self.id} user_id={self.user_id} "
            f"email_enabled={self.email_enabled} in_app_enabled={self.in_app_enabled}>"
        )
