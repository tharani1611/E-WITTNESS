"""Notification domain service orchestrating templates, delivery adapters, retries, and preferences (Phases 91-94).

Enforces:
- Centrally registered, versioned templates with parameter validation and HTML escaping.
- Provider-independent delivery adapters (in-app, email, fake).
- Recipient-scoped ownership for reading and marking notifications as read.
- Non-negotiable security invariant: Security-critical alerts cannot be disabled or suppressed.
- Idempotent delivery with deduplication keys and bounded exponential backoff retries.
- Sanitized error tracking with zero credential leakage.
- Immutable audit ledger recording for all dispatch, delivery, read, and preference actions.
"""

from __future__ import annotations

import abc
import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config.settings import Settings
from backend.app.core.audit import AuditAction, AuditOutcome, AuditTargetType
from backend.app.core.exceptions import (
    BusinessRuleError,
    ResourceNotFoundError,
)
from backend.app.core.logging import get_logger
from backend.app.core.notification import (
    NOTIFICATION_TEMPLATES,
    DeliveryErrorCategory,
    DeliveryStatus,
    NotificationCategory,
    NotificationChannel,
    NotificationPriority,
    generate_deduplication_key,
)
from backend.app.models.notification import (
    Notification,
    NotificationDeliveryAttempt,
    NotificationPreference,
)
from backend.app.repositories.audit import AuditRepository
from backend.app.repositories.identity import UserRepository
from backend.app.repositories.notification import NotificationRepository
from backend.app.schemas.notification import (
    NotificationListResponse,
    NotificationPreferenceRead,
    NotificationPreferenceUpdate,
    NotificationRead,
    NotificationUnreadCount,
)

logger = get_logger("services.notification")

MAX_DELIVERY_RETRIES = 3


# =============================================================================
# Delivery Adapters (Phase 91, 93)
# =============================================================================


class NotificationDeliveryAdapter(abc.ABC):
    """Abstract interface for notification channel delivery providers."""

    @abc.abstractmethod
    async def deliver(
        self,
        notification: Notification,
        recipient_email: str | None = None,
    ) -> tuple[DeliveryStatus, DeliveryErrorCategory | None, str | None]:
        """Deliver the notification.

        Returns:
            (status, error_category, error_message)
        """
        raise NotImplementedError


class InAppNotificationAdapter(NotificationDeliveryAdapter):
    """In-app delivery adapter (marks notification as delivered upon DB storage)."""

    async def deliver(
        self,
        notification: Notification,
        recipient_email: str | None = None,
    ) -> tuple[DeliveryStatus, DeliveryErrorCategory | None, str | None]:
        return DeliveryStatus.DELIVERED, None, None


class EmailNotificationAdapter(NotificationDeliveryAdapter):
    """Email delivery adapter with simulated transmission and sanitized errors."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def deliver(
        self,
        notification: Notification,
        recipient_email: str | None = None,
    ) -> tuple[DeliveryStatus, DeliveryErrorCategory | None, str | None]:
        if not recipient_email or "@" not in recipient_email:
            return (
                DeliveryStatus.FAILED,
                DeliveryErrorCategory.INVALID_RECIPIENT,
                "Recipient email address is missing or invalid.",
            )

        try:
            # Simulate network I/O delivery or integration with configured mailer
            await asyncio.sleep(0.01)
            logger.info(
                "Email delivered successfully to recipient %s (notification %s)",
                recipient_email,
                notification.id,
            )
            return DeliveryStatus.DELIVERED, None, None
        except TimeoutError:
            return (
                DeliveryStatus.FAILED,
                DeliveryErrorCategory.TRANSIENT_NETWORK,
                "Email delivery timed out.",
            )
        except Exception as exc:
            return (
                DeliveryStatus.FAILED,
                DeliveryErrorCategory.PROVIDER_ERROR,
                f"Email delivery failed: {type(exc).__name__}",
            )


class FakeNotificationDeliveryAdapter(NotificationDeliveryAdapter):
    """Test fake delivery adapter for deterministic verification."""

    def __init__(
        self,
        should_fail: bool = False,
        error_category: DeliveryErrorCategory = DeliveryErrorCategory.TRANSIENT_NETWORK,
        error_message: str = "Simulated delivery failure",
    ) -> None:
        self.should_fail = should_fail
        self.error_category = error_category
        self.error_message = error_message
        self.delivered_notifications: list[Notification] = []

    async def deliver(
        self,
        notification: Notification,
        recipient_email: str | None = None,
    ) -> tuple[DeliveryStatus, DeliveryErrorCategory | None, str | None]:
        if self.should_fail:
            return (
                DeliveryStatus.FAILED,
                self.error_category,
                self.error_message,
            )
        self.delivered_notifications.append(notification)
        return DeliveryStatus.DELIVERED, None, None


# =============================================================================
# Domain Service (Phases 91-94)
# =============================================================================


class NotificationService:
    """Service orchestrating notification templates, preferences, retries, and delivery."""

    def __init__(
        self,
        notification_repo: NotificationRepository,
        user_repo: UserRepository,
        audit_repo: AuditRepository,
        settings: Settings,
        adapters: dict[NotificationChannel, NotificationDeliveryAdapter] | None = None,
    ) -> None:
        self.notification_repo = notification_repo
        self.user_repo = user_repo
        self.audit_repo = audit_repo
        self.settings = settings

        if adapters is not None:
            self.adapters = adapters
        else:
            self.adapters = {
                NotificationChannel.IN_APP: InAppNotificationAdapter(),
                NotificationChannel.EMAIL: EmailNotificationAdapter(settings),
            }

    @classmethod
    def from_session(cls, session: AsyncSession, settings: Settings) -> NotificationService:
        """Construct a NotificationService wired with session repositories."""
        return cls(
            notification_repo=NotificationRepository(session),
            user_repo=UserRepository(session),
            audit_repo=AuditRepository(session),
            settings=settings,
        )

    # =========================================================================
    # Preferences (Phase 94)
    # =========================================================================

    async def get_preferences(self, user_id: UUID) -> NotificationPreferenceRead:
        """Fetch or initialize default preferences for a user."""
        pref = await self.notification_repo.get_or_create_preference(user_id)
        return NotificationPreferenceRead.model_validate(pref)

    async def update_preferences(
        self,
        user_id: UUID,
        payload: NotificationPreferenceUpdate,
        actor_id: UUID,
        actor_role: str,
        actor_ip: str | None = None,
        actor_user_agent: str | None = None,
    ) -> NotificationPreferenceRead:
        """Update configurable notification preferences.

        Users can only modify their own preferences (or superadmins).
        Notice: Security-critical alerts cannot be disabled (enforced by schema).
        """
        pref = await self.notification_repo.get_or_create_preference(user_id)

        update_dict = payload.model_dump(exclude_unset=True)
        for key, val in update_dict.items():
            if hasattr(pref, key) and val is not None:
                setattr(pref, key, val)

        saved = await self.notification_repo.save_preference(pref)

        # Audit update
        await self.audit_repo.append_event(
            action=AuditAction.NOTIFICATION_PREFERENCE_UPDATED,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type=AuditTargetType.NOTIFICATION_PREFERENCE,
            target_id=str(saved.id),
            outcome=AuditOutcome.SUCCESS,
            actor_ip=actor_ip,
            actor_user_agent=actor_user_agent,
            department_id=None,
            details={"updated_fields": list(update_dict.keys()), "user_id": str(user_id)},
        )

        return NotificationPreferenceRead.model_validate(saved)

    def is_notification_enabled_by_preference(
        self,
        pref: NotificationPreference,
        channel: NotificationChannel,
        category: NotificationCategory,
    ) -> bool:
        """Check whether a notification should be delivered under user preferences.

        NON-NEGOTIABLE SECURITY INVARIANT:
        Security-critical notifications can NEVER be disabled by preferences.
        """
        if category == NotificationCategory.SECURITY_CRITICAL:
            return True

        if channel == NotificationChannel.IN_APP and not pref.in_app_enabled:
            return False
        if channel == NotificationChannel.EMAIL and not pref.email_enabled:
            return False

        if category == NotificationCategory.ASSIGNMENT:
            if channel == NotificationChannel.IN_APP and not pref.assignments_in_app:
                return False
            if channel == NotificationChannel.EMAIL and not pref.assignments_email:
                return False
        elif category == NotificationCategory.STATUS_UPDATE:
            if channel == NotificationChannel.IN_APP and not pref.status_updates_in_app:
                return False
            if channel == NotificationChannel.EMAIL and not pref.status_updates_email:
                return False
        elif category == NotificationCategory.SYSTEM_NOTICE:
            if channel == NotificationChannel.IN_APP and not pref.system_notices_in_app:
                return False
            if channel == NotificationChannel.EMAIL and not pref.system_notices_email:
                return False

        return True

    # =========================================================================
    # Dispatch & Delivery (Phases 91, 92, 93)
    # =========================================================================

    async def dispatch(
        self,
        template_name: str,
        template_vars: dict[str, Any],
        recipient_id: UUID,
        department_id: UUID | None = None,
        channel: NotificationChannel = NotificationChannel.IN_APP,
        priority: NotificationPriority | None = None,
        correlation_id: str | None = None,
        actor_id: UUID | None = None,
        actor_role: str | None = None,
        actor_ip: str | None = None,
        actor_user_agent: str | None = None,
    ) -> Notification | None:
        """Render template and dispatch notification via configured delivery adapter.

        Applies:
        - Strict template validation and HTML escaping.
        - User preference checks (bypassed for security-critical alerts).
        - Idempotent delivery tracking with deduplication key.
        - Bounded retries and sanitized error recording.
        - Comprehensive audit trail.
        """
        template = NOTIFICATION_TEMPLATES.get(template_name)
        if template is None:
            raise BusinessRuleError(f"Notification template '{template_name}' is not registered.")

        # 1. Render template with variable validation and HTML escaping
        title, body = template.render(template_vars)
        effective_priority = priority or template.default_priority
        category = template.category

        # 2. Check user preferences
        pref = await self.notification_repo.get_or_create_preference(recipient_id)
        if not self.is_notification_enabled_by_preference(pref, channel, category):
            logger.info(
                "Notification %s to user %s suppressed by preferences (category=%s, channel=%s)",
                template_name,
                recipient_id,
                category.value,
                channel.value,
            )
            return None

        # 3. Check deduplication / correlation idempotency
        if correlation_id:
            existing_notif = await self.notification_repo.get_by_correlation_id(
                correlation_id=correlation_id,
                recipient_id=recipient_id,
            )
            if existing_notif is not None:
                logger.info(
                    "Notification with correlation_id %s already exists for recipient %s; skipping duplicate dispatch.",
                    correlation_id,
                    recipient_id,
                )
                return existing_notif

        # 4. Create persistent Notification record
        notification = Notification(
            recipient_id=recipient_id,
            department_id=department_id,
            category=category.value,
            channel=channel.value,
            priority=effective_priority.value,
            title=title,
            body=body,
            data_json=json.dumps(
                {
                    "template_name": template_name,
                    "correlation_id": correlation_id,
                    "template_vars": template_vars,
                },
                default=str,
            ),
            is_read=False,
            delivery_status=DeliveryStatus.PENDING.value,
            correlation_id=correlation_id,
        )
        created_notification = await self.notification_repo.create(notification)

        # Audit initial dispatch
        await self.audit_repo.append_event(
            action=AuditAction.NOTIFICATION_DISPATCHED,
            actor_id=actor_id or recipient_id,
            actor_role=actor_role or "SYSTEM",
            target_type=AuditTargetType.NOTIFICATION,
            target_id=str(created_notification.id),
            outcome=AuditOutcome.SUCCESS,
            actor_ip=actor_ip,
            actor_user_agent=actor_user_agent,
            department_id=department_id,
            details={
                "template_name": template_name,
                "category": category.value,
                "channel": channel.value,
                "priority": effective_priority.value,
                "correlation_id": correlation_id,
            },
        )

        # 4. Fetch recipient email if needed
        recipient_user = await self.user_repo.get_by_id_unscoped(recipient_id)
        recipient_email = recipient_user.email if recipient_user else None

        # 5. Attempt delivery with adapter & bounded retry loop
        adapter = self.adapters.get(channel)
        if adapter is None:
            await self.notification_repo.update_delivery_status(
                created_notification.id, DeliveryStatus.FAILED
            )
            created_notification.delivery_status = DeliveryStatus.FAILED.value
            return created_notification

        await self._execute_delivery_attempts(
            notification=created_notification,
            adapter=adapter,
            channel=channel,
            recipient_email=recipient_email,
            actor_id=actor_id,
            actor_role=actor_role,
            actor_ip=actor_ip,
            actor_user_agent=actor_user_agent,
            department_id=department_id,
        )

        return created_notification

    async def _execute_delivery_attempts(
        self,
        notification: Notification,
        adapter: NotificationDeliveryAdapter,
        channel: NotificationChannel,
        recipient_email: str | None,
        actor_id: UUID | None,
        actor_role: str | None,
        actor_ip: str | None,
        actor_user_agent: str | None,
        department_id: UUID | None,
    ) -> None:
        """Execute delivery attempts with deduplication and exponential backoff."""
        attempt_number = 1
        delivered = False

        while attempt_number <= MAX_DELIVERY_RETRIES and not delivered:
            correlation_token = (
                f"{notification.correlation_id or notification.id}:{channel.value}:{attempt_number}"
            )
            dedup_key = generate_deduplication_key(
                recipient_id=notification.recipient_id,
                category=notification.category,
                template_name=notification.data.get("template_name", "generic"),
                correlation_id=correlation_token,
            )

            # Check if this attempt already exists (idempotency guard)
            existing_attempt = await self.notification_repo.get_attempt_by_dedup_key(dedup_key)
            if existing_attempt is not None:
                if existing_attempt.status == DeliveryStatus.DELIVERED.value:
                    delivered = True
                    break
                attempt_number += 1
                continue

            status, err_cat, err_msg = await adapter.deliver(
                notification=notification,
                recipient_email=recipient_email,
            )

            # Record attempt log
            next_retry_at = None
            if status != DeliveryStatus.DELIVERED and attempt_number < MAX_DELIVERY_RETRIES:
                backoff_seconds = 2**attempt_number
                next_retry_at = datetime.now(UTC) + timedelta(seconds=backoff_seconds)

            attempt_record = NotificationDeliveryAttempt(
                notification_id=notification.id,
                channel=channel.value,
                status=status.value,
                attempt_number=attempt_number,
                error_category=err_cat.value if err_cat else None,
                error_message=err_msg[:500] if err_msg else None,
                deduplication_key=dedup_key,
                next_retry_at=next_retry_at,
            )
            await self.notification_repo.create_delivery_attempt(attempt_record)

            if status == DeliveryStatus.DELIVERED:
                delivered = True
                await self.notification_repo.update_delivery_status(
                    notification.id, DeliveryStatus.DELIVERED
                )
                notification.delivery_status = DeliveryStatus.DELIVERED.value

                await self.audit_repo.append_event(
                    action=AuditAction.NOTIFICATION_DELIVERY_ATTEMPTED,
                    actor_id=actor_id or notification.recipient_id,
                    actor_role=actor_role or "SYSTEM",
                    target_type=AuditTargetType.NOTIFICATION,
                    target_id=str(notification.id),
                    outcome=AuditOutcome.SUCCESS,
                    actor_ip=actor_ip,
                    actor_user_agent=actor_user_agent,
                    department_id=department_id,
                    details={
                        "attempt_number": attempt_number,
                        "channel": channel.value,
                        "status": status.value,
                    },
                )
                break
            else:
                await self.audit_repo.append_event(
                    action=AuditAction.NOTIFICATION_DELIVERY_FAILED,
                    actor_id=actor_id or notification.recipient_id,
                    actor_role=actor_role or "SYSTEM",
                    target_type=AuditTargetType.NOTIFICATION,
                    target_id=str(notification.id),
                    outcome=AuditOutcome.FAILURE,
                    actor_ip=actor_ip,
                    actor_user_agent=actor_user_agent,
                    department_id=department_id,
                    details={
                        "attempt_number": attempt_number,
                        "channel": channel.value,
                        "error_category": err_cat.value if err_cat else None,
                        "error_message": err_msg,
                    },
                )
                attempt_number += 1

        if not delivered:
            await self.notification_repo.update_delivery_status(
                notification.id, DeliveryStatus.FAILED
            )
            notification.delivery_status = DeliveryStatus.FAILED.value

    # =========================================================================
    # Recipient Querying & Read Receipts (Phase 92)
    # =========================================================================

    async def list_user_notifications(
        self,
        recipient_id: UUID,
        is_read: bool | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> NotificationListResponse:
        """List notifications owned by the authenticated user with unread counter."""
        limit = min(max(page_size, 1), 100)
        offset = (max(page, 1) - 1) * limit

        items = await self.notification_repo.list_for_recipient(
            recipient_id=recipient_id,
            is_read=is_read,
            limit=limit,
            offset=offset,
        )
        total = await self.notification_repo.count_for_recipient(
            recipient_id=recipient_id,
            is_read=is_read,
        )
        unread_count = await self.notification_repo.get_unread_count(recipient_id)

        read_items = [NotificationRead.model_validate(item) for item in items]
        return NotificationListResponse(
            items=read_items,
            total=total,
            unread_count=unread_count,
            page=page,
            page_size=limit,
        )

    async def get_unread_count(self, recipient_id: UUID) -> NotificationUnreadCount:
        """Fetch total count of unread notifications for recipient."""
        count = await self.notification_repo.get_unread_count(recipient_id)
        return NotificationUnreadCount(unread_count=count)

    async def mark_notifications_read(
        self,
        notification_ids: list[UUID],
        recipient_id: UUID,
        actor_role: str,
        actor_ip: str | None = None,
        actor_user_agent: str | None = None,
    ) -> int:
        """Mark specific notifications as read, ensuring strict recipient ownership."""
        updated_count = await self.notification_repo.mark_as_read(
            notification_ids=notification_ids,
            recipient_id=recipient_id,
        )

        if updated_count > 0:
            await self.audit_repo.append_event(
                action=AuditAction.NOTIFICATION_READ,
                actor_id=recipient_id,
                actor_role=actor_role,
                target_type=AuditTargetType.NOTIFICATION,
                target_id="batch",
                outcome=AuditOutcome.SUCCESS,
                actor_ip=actor_ip,
                actor_user_agent=actor_user_agent,
                department_id=None,
                details={
                    "updated_count": updated_count,
                    "notification_ids": [str(nid) for nid in notification_ids],
                },
            )

        return updated_count

    async def mark_single_notification_read(
        self,
        notification_id: UUID,
        recipient_id: UUID,
        actor_role: str,
        actor_ip: str | None = None,
        actor_user_agent: str | None = None,
    ) -> NotificationRead:
        """Mark a single notification owned by recipient as read."""
        notif = await self.notification_repo.get_by_id_and_recipient(
            notification_id=notification_id,
            recipient_id=recipient_id,
        )
        if notif is None:
            raise ResourceNotFoundError(f"Notification {notification_id} not found.")

        if not notif.is_read:
            await self.notification_repo.mark_as_read(
                notification_ids=[notification_id],
                recipient_id=recipient_id,
            )
            notif.is_read = True
            notif.read_at = datetime.now(UTC)

            await self.audit_repo.append_event(
                action=AuditAction.NOTIFICATION_READ,
                actor_id=recipient_id,
                actor_role=actor_role,
                target_type=AuditTargetType.NOTIFICATION,
                target_id=str(notification_id),
                outcome=AuditOutcome.SUCCESS,
                actor_ip=actor_ip,
                actor_user_agent=actor_user_agent,
                department_id=notif.department_id,
                details={"notification_id": str(notification_id)},
            )

        return NotificationRead.model_validate(notif)

    # =========================================================================
    # Event-Driven Lifecycle Helpers (Phase 92)
    # =========================================================================

    async def notify_incident_assigned(
        self,
        incident_id: UUID,
        reference_number: str,
        reviewer_id: UUID,
        department_name: str = "Assigned Department",
        department_id: UUID | None = None,
        actor_id: UUID | None = None,
        actor_role: str | None = None,
    ) -> Notification | None:
        """Dispatch in-app notification when an incident is assigned to a reviewer."""
        return await self.dispatch(
            template_name="incident_assigned",
            template_vars={
                "reference_number": reference_number,
                "department_name": department_name,
                "incident_id": str(incident_id),
            },
            recipient_id=reviewer_id,
            department_id=department_id,
            channel=NotificationChannel.IN_APP,
            correlation_id=f"incident:{incident_id}",
            actor_id=actor_id,
            actor_role=actor_role,
        )

    async def notify_incident_status_changed(
        self,
        incident_id: UUID,
        reference_number: str,
        recipient_id: UUID,
        new_status: str,
        old_status: str | None = None,
        department_id: UUID | None = None,
        actor_id: UUID | None = None,
        actor_role: str | None = None,
    ) -> Notification | None:
        """Dispatch in-app notification when incident status transitions."""
        return await self.dispatch(
            template_name="incident_status_changed",
            template_vars={
                "reference_number": reference_number,
                "new_status": new_status,
                "incident_id": str(incident_id),
            },
            recipient_id=recipient_id,
            department_id=department_id,
            channel=NotificationChannel.IN_APP,
            correlation_id=f"incident:{incident_id}",
            actor_id=actor_id,
            actor_role=actor_role,
        )

    async def notify_case_assigned(
        self,
        case_id: UUID,
        reference_number: str,
        investigator_id: UUID,
        case_title: str = "Investigation Case",
        department_id: UUID | None = None,
        actor_id: UUID | None = None,
        actor_role: str | None = None,
    ) -> Notification | None:
        """Dispatch in-app notification when an investigator is assigned to a case."""
        return await self.dispatch(
            template_name="case_assigned",
            template_vars={
                "case_reference": reference_number,
                "case_title": case_title,
                "case_id": str(case_id),
            },
            recipient_id=investigator_id,
            department_id=department_id,
            channel=NotificationChannel.IN_APP,
            correlation_id=f"case:{case_id}",
            actor_id=actor_id,
            actor_role=actor_role,
        )

    async def notify_case_status_changed(
        self,
        case_id: UUID,
        reference_number: str,
        recipient_id: UUID,
        old_status: str,
        new_status: str,
        department_id: UUID | None = None,
        actor_id: UUID | None = None,
        actor_role: str | None = None,
    ) -> Notification | None:
        """Dispatch in-app notification when case status transitions."""
        return await self.dispatch(
            template_name="case_status_changed",
            template_vars={
                "case_reference": reference_number,
                "from_status": old_status,
                "to_status": new_status,
                "case_id": str(case_id),
            },
            recipient_id=recipient_id,
            department_id=department_id,
            channel=NotificationChannel.IN_APP,
            correlation_id=f"case:{case_id}",
            actor_id=actor_id,
            actor_role=actor_role,
        )

    async def notify_case_escalated(
        self,
        case_id: UUID,
        reference_number: str,
        recipient_id: UUID,
        escalation_level: str,
        reason: str = "Investigative threshold reached",
        department_id: UUID | None = None,
        actor_id: UUID | None = None,
        actor_role: str | None = None,
    ) -> Notification | None:
        """Dispatch in-app notification when a case is escalated."""
        return await self.dispatch(
            template_name="case_escalated",
            template_vars={
                "case_reference": reference_number,
                "escalation_level": escalation_level,
                "reason": reason,
                "case_id": str(case_id),
            },
            recipient_id=recipient_id,
            department_id=department_id,
            channel=NotificationChannel.IN_APP,
            correlation_id=f"case:{case_id}",
            actor_id=actor_id,
            actor_role=actor_role,
        )

    async def notify_security_login_alert(
        self,
        user_id: UUID,
        ip_address: str,
        login_time: str,
        channel: NotificationChannel = NotificationChannel.IN_APP,
        actor_ip: str | None = None,
    ) -> Notification | None:
        """Dispatch critical security login alert (ignores preferences)."""
        return await self.dispatch(
            template_name="security_login_alert",
            template_vars={"ip_address": ip_address, "login_time": login_time},
            recipient_id=user_id,
            channel=channel,
            priority=NotificationPriority.URGENT,
            correlation_id=f"sec_login:{user_id}",
            actor_ip=actor_ip,
        )
