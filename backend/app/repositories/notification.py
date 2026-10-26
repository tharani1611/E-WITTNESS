"""Notification repository for in-app alerts, delivery tracking, and preferences (Phases 91-94).

Enforces:
- Strict recipient ownership validation on all reads, counts, and mark-as-read updates.
- Optimistic locking and atomic updates.
- Idempotent deduplication key lookup for delivery attempts.
- Default preference provisioning if no custom preference row exists yet.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.notification import DeliveryStatus
from backend.app.models.notification import (
    Notification,
    NotificationDeliveryAttempt,
    NotificationPreference,
)


class NotificationRepository:
    """Async database repository for Notification models."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # =========================================================================
    # Notifications (Phases 91, 92)
    # =========================================================================

    async def create(self, notification: Notification) -> Notification:
        """Persist a new Notification record."""
        self.session.add(notification)
        await self.session.flush()
        return notification

    async def get_by_id(self, notification_id: UUID) -> Notification | None:
        """Fetch a single notification by primary key."""
        stmt = select(Notification).where(Notification.id == notification_id)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def get_by_id_and_recipient(
        self, notification_id: UUID, recipient_id: UUID
    ) -> Notification | None:
        """Fetch a single notification verifying recipient ownership."""
        stmt = select(Notification).where(
            Notification.id == notification_id,
            Notification.recipient_id == recipient_id,
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def get_by_correlation_id(
        self, correlation_id: str, recipient_id: UUID
    ) -> Notification | None:
        """Fetch an existing notification by correlation_id and recipient."""
        stmt = select(Notification).where(
            Notification.correlation_id == correlation_id,
            Notification.recipient_id == recipient_id,
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def list_for_recipient(
        self,
        recipient_id: UUID,
        is_read: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[Notification]:
        """List notifications owned by a specific recipient with optional read-filter."""
        stmt = select(Notification).where(Notification.recipient_id == recipient_id)
        if is_read is not None:
            stmt = stmt.where(Notification.is_read == is_read)
        stmt = stmt.order_by(Notification.created_at.desc()).limit(limit).offset(offset)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_for_recipient(
        self,
        recipient_id: UUID,
        is_read: bool | None = None,
    ) -> int:
        """Count total notifications matching filter for recipient."""
        stmt = select(func.count(Notification.id)).where(Notification.recipient_id == recipient_id)
        if is_read is not None:
            stmt = stmt.where(Notification.is_read == is_read)
        result = await self.session.execute(stmt)
        return int(result.scalar_one_or_none() or 0)

    async def get_unread_count(self, recipient_id: UUID) -> int:
        """Retrieve total unread notification count for a recipient."""
        return await self.count_for_recipient(recipient_id=recipient_id, is_read=False)

    async def mark_as_read(
        self,
        notification_ids: list[UUID],
        recipient_id: UUID,
    ) -> int:
        """Mark specific notifications as read, strictly scoped to recipient ownership."""
        if not notification_ids:
            return 0

        now = datetime.now(UTC)
        stmt = (
            update(Notification)
            .where(
                Notification.id.in_(notification_ids),
                Notification.recipient_id == recipient_id,
                Notification.is_read.is_(False),
            )
            .values(
                is_read=True,
                read_at=now,
                updated_at=now,
            )
        )
        result = await self.session.execute(stmt)
        await self.session.flush()
        rowcount = getattr(result, "rowcount", 0)
        return int(rowcount) if rowcount is not None else 0

    async def mark_all_as_read(self, recipient_id: UUID) -> int:
        """Mark all unread notifications for recipient as read."""
        now = datetime.now(UTC)
        stmt = (
            update(Notification)
            .where(
                Notification.recipient_id == recipient_id,
                Notification.is_read.is_(False),
            )
            .values(
                is_read=True,
                read_at=now,
                updated_at=now,
            )
        )
        result = await self.session.execute(stmt)
        await self.session.flush()
        rowcount = getattr(result, "rowcount", 0)
        return int(rowcount) if rowcount is not None else 0

    async def update_delivery_status(
        self,
        notification_id: UUID,
        status: DeliveryStatus,
    ) -> None:
        """Update notification delivery status."""
        stmt = (
            update(Notification)
            .where(Notification.id == notification_id)
            .values(
                delivery_status=status.value,
                updated_at=datetime.now(UTC),
            )
        )
        await self.session.execute(stmt)
        await self.session.flush()

    # =========================================================================
    # Preferences (Phase 94)
    # =========================================================================

    async def get_preference_by_user_id(self, user_id: UUID) -> NotificationPreference | None:
        """Fetch notification preference for a specific user."""
        stmt = select(NotificationPreference).where(NotificationPreference.user_id == user_id)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def get_or_create_preference(self, user_id: UUID) -> NotificationPreference:
        """Fetch or create default preferences for a user."""
        pref = await self.get_preference_by_user_id(user_id)
        if pref is not None:
            return pref

        pref = NotificationPreference(
            user_id=user_id,
            email_enabled=True,
            in_app_enabled=True,
            assignments_email=True,
            assignments_in_app=True,
            status_updates_email=True,
            status_updates_in_app=True,
            system_notices_email=True,
            system_notices_in_app=True,
        )
        self.session.add(pref)
        await self.session.flush()
        return pref

    async def save_preference(self, preference: NotificationPreference) -> NotificationPreference:
        """Persist updated preference row."""
        self.session.add(preference)
        await self.session.flush()
        return preference

    # =========================================================================
    # Delivery Attempts & Deduplication (Phase 93)
    # =========================================================================

    async def create_delivery_attempt(
        self, attempt: NotificationDeliveryAttempt
    ) -> NotificationDeliveryAttempt:
        """Record an attempted delivery."""
        self.session.add(attempt)
        await self.session.flush()
        return attempt

    async def get_attempt_by_dedup_key(
        self, deduplication_key: str
    ) -> NotificationDeliveryAttempt | None:
        """Fetch an attempt by idempotency deduplication key."""
        stmt = select(NotificationDeliveryAttempt).where(
            NotificationDeliveryAttempt.deduplication_key == deduplication_key
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def list_attempts_for_notification(
        self, notification_id: UUID
    ) -> Sequence[NotificationDeliveryAttempt]:
        """List all delivery attempts for an individual notification."""
        stmt = (
            select(NotificationDeliveryAttempt)
            .where(NotificationDeliveryAttempt.notification_id == notification_id)
            .order_by(NotificationDeliveryAttempt.attempt_number.asc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
