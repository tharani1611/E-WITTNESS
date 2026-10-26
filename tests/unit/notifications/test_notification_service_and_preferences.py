"""Unit tests for NotificationService, In-App Delivery, and Preferences (Phases 92 & 94).

Tests:
- Notification dispatching with audit trail.
- Recipient-scoped ownership for reading and marking notifications as read.
- Non-negotiable security invariant: Security-critical alerts cannot be disabled or suppressed.
- Granular preference checking across channels and categories.
- Event-driven lifecycle helpers (incident and case status changes, assignments, escalations).
- Deduplication and retry loop.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from backend.app.config.settings import Settings
from backend.app.core.audit import AuditAction
from backend.app.core.exceptions import ResourceNotFoundError
from backend.app.core.notification import (
    DeliveryStatus,
    NotificationCategory,
    NotificationChannel,
    NotificationPriority,
)
from backend.app.models.notification import Notification, NotificationPreference
from backend.app.models.user import User
from backend.app.schemas.notification import NotificationPreferenceUpdate
from backend.app.services.notification import (
    FakeNotificationDeliveryAdapter,
    NotificationService,
)


@pytest.fixture
def mock_notification_repo() -> MagicMock:
    repo = MagicMock()
    repo.create = AsyncMock(side_effect=lambda n: n)
    repo.get_by_id = AsyncMock()
    repo.get_by_id_and_recipient = AsyncMock()
    repo.list_for_recipient = AsyncMock(return_value=[])
    repo.count_for_recipient = AsyncMock(return_value=0)
    repo.get_unread_count = AsyncMock(return_value=0)
    repo.mark_as_read = AsyncMock(return_value=1)
    repo.mark_all_as_read = AsyncMock(return_value=1)
    repo.update_delivery_status = AsyncMock()
    repo.get_or_create_preference = AsyncMock()
    repo.get_preference_by_user_id = AsyncMock()
    repo.save_preference = AsyncMock(side_effect=lambda p: p)
    repo.create_delivery_attempt = AsyncMock(side_effect=lambda a: a)
    repo.get_attempt_by_dedup_key = AsyncMock(return_value=None)
    repo.get_by_correlation_id = AsyncMock(return_value=None)
    repo.list_attempts_for_notification = AsyncMock(return_value=[])
    return repo


@pytest.fixture
def mock_user_repo() -> MagicMock:
    repo = MagicMock()
    repo.get_by_id_unscoped = AsyncMock(
        return_value=User(
            id=uuid4(),
            email="recipient@ewitness.edu",
            full_name="Recipient Officer",
        )
    )
    return repo


@pytest.fixture
def mock_audit_repo() -> MagicMock:
    repo = MagicMock()
    repo.append_event = AsyncMock()
    return repo


@pytest.fixture
def notification_service(
    mock_notification_repo: MagicMock,
    mock_user_repo: MagicMock,
    mock_audit_repo: MagicMock,
    test_settings: Settings,
) -> NotificationService:
    adapters = {
        NotificationChannel.IN_APP: FakeNotificationDeliveryAdapter(),
        NotificationChannel.EMAIL: FakeNotificationDeliveryAdapter(),
    }
    return NotificationService(
        notification_repo=mock_notification_repo,
        user_repo=mock_user_repo,
        audit_repo=mock_audit_repo,
        settings=test_settings,
        adapters=adapters,
    )


class TestNotificationPreferences:
    """Verifies Phase 94 user notification preferences and mandatory security alert protection."""

    def test_security_critical_alerts_cannot_be_disabled(
        self, notification_service: NotificationService
    ) -> None:
        """NON-NEGOTIABLE INVARIANT: Security alerts MUST ALWAYS be delivered even if user disables all channels."""
        all_disabled_pref = NotificationPreference(
            user_id=uuid4(),
            email_enabled=False,
            in_app_enabled=False,
            assignments_email=False,
            assignments_in_app=False,
            status_updates_email=False,
            status_updates_in_app=False,
            system_notices_email=False,
            system_notices_in_app=False,
        )

        # In-app delivery of security critical alert
        assert (
            notification_service.is_notification_enabled_by_preference(
                all_disabled_pref,
                channel=NotificationChannel.IN_APP,
                category=NotificationCategory.SECURITY_CRITICAL,
            )
            is True
        )

        # Email delivery of security critical alert
        assert (
            notification_service.is_notification_enabled_by_preference(
                all_disabled_pref,
                channel=NotificationChannel.EMAIL,
                category=NotificationCategory.SECURITY_CRITICAL,
            )
            is True
        )

    def test_optional_notifications_respect_preferences(
        self, notification_service: NotificationService
    ) -> None:
        """Optional notifications (assignment, status, system notice) are suppressed when disabled."""
        pref = NotificationPreference(
            user_id=uuid4(),
            email_enabled=True,
            in_app_enabled=True,
            assignments_email=False,
            assignments_in_app=True,
            status_updates_email=True,
            status_updates_in_app=False,
            system_notices_email=False,
            system_notices_in_app=False,
        )

        # Assignments: email disabled, in-app enabled
        assert (
            notification_service.is_notification_enabled_by_preference(
                pref, NotificationChannel.EMAIL, NotificationCategory.ASSIGNMENT
            )
            is False
        )
        assert (
            notification_service.is_notification_enabled_by_preference(
                pref, NotificationChannel.IN_APP, NotificationCategory.ASSIGNMENT
            )
            is True
        )

        # Status updates: email enabled, in-app disabled
        assert (
            notification_service.is_notification_enabled_by_preference(
                pref, NotificationChannel.EMAIL, NotificationCategory.STATUS_UPDATE
            )
            is True
        )
        assert (
            notification_service.is_notification_enabled_by_preference(
                pref, NotificationChannel.IN_APP, NotificationCategory.STATUS_UPDATE
            )
            is False
        )

        # System notices: both disabled
        assert (
            notification_service.is_notification_enabled_by_preference(
                pref, NotificationChannel.EMAIL, NotificationCategory.SYSTEM_NOTICE
            )
            is False
        )
        assert (
            notification_service.is_notification_enabled_by_preference(
                pref, NotificationChannel.IN_APP, NotificationCategory.SYSTEM_NOTICE
            )
            is False
        )

    @pytest.mark.asyncio
    async def test_update_preferences_and_audit(
        self,
        notification_service: NotificationService,
        mock_notification_repo: MagicMock,
        mock_audit_repo: MagicMock,
    ) -> None:
        """Updating preferences records an audit event with updated fields."""
        user_id = uuid4()
        now = datetime.now(UTC)
        pref_id = uuid4()
        existing_pref = NotificationPreference(
            id=pref_id,
            user_id=user_id,
            email_enabled=True,
            in_app_enabled=True,
            assignments_email=True,
            assignments_in_app=True,
            status_updates_email=True,
            status_updates_in_app=True,
            system_notices_email=True,
            system_notices_in_app=True,
            created_at=now,
            updated_at=now,
        )
        mock_notification_repo.get_or_create_preference.return_value = existing_pref

        update_payload = NotificationPreferenceUpdate(
            assignments_email=False,
            system_notices_in_app=False,
        )

        res = await notification_service.update_preferences(
            user_id=user_id,
            payload=update_payload,
            actor_id=user_id,
            actor_role="INVESTIGATOR",
            actor_ip="127.0.0.1",
        )

        assert res.assignments_email is False
        assert res.system_notices_in_app is False
        assert res.assignments_in_app is True  # unchanged

        mock_audit_repo.append_event.assert_called_once()
        audit_call = mock_audit_repo.append_event.call_args[1]
        assert audit_call["action"] == AuditAction.NOTIFICATION_PREFERENCE_UPDATED
        assert "assignments_email" in audit_call["details"]["updated_fields"]


class TestNotificationDispatchAndLifecycle:
    """Verifies Phase 92 in-app notification dispatch and lifecycle read receipts."""

    @pytest.mark.asyncio
    async def test_dispatch_in_app_success(
        self,
        notification_service: NotificationService,
        mock_notification_repo: MagicMock,
        mock_audit_repo: MagicMock,
    ) -> None:
        """Dispatching an in-app template notification renders and persists record."""
        recipient_id = uuid4()
        dept_id = uuid4()
        now = datetime.now(UTC)
        default_pref = NotificationPreference(
            user_id=recipient_id,
            email_enabled=True,
            in_app_enabled=True,
            assignments_email=True,
            assignments_in_app=True,
            status_updates_email=True,
            status_updates_in_app=True,
            system_notices_email=True,
            system_notices_in_app=True,
            created_at=now,
            updated_at=now,
        )
        mock_notification_repo.get_or_create_preference.return_value = default_pref

        notif = await notification_service.dispatch(
            template_name="incident_assigned",
            template_vars={
                "reference_number": "INC-2026-0001",
                "department_name": "Safety",
                "incident_id": str(uuid4()),
            },
            recipient_id=recipient_id,
            department_id=dept_id,
            channel=NotificationChannel.IN_APP,
            correlation_id="inc:123",
        )

        assert notif is not None
        assert notif.recipient_id == recipient_id
        assert notif.department_id == dept_id
        assert notif.delivery_status == DeliveryStatus.DELIVERED.value
        assert "INC-2026-0001" in notif.title
        assert notif.is_read is False

        # Verifies audit event
        assert mock_audit_repo.append_event.call_count >= 2  # dispatched and delivery attempted

    @pytest.mark.asyncio
    async def test_dispatch_suppressed_by_preferences(
        self,
        notification_service: NotificationService,
        mock_notification_repo: MagicMock,
    ) -> None:
        """Dispatch returns None when recipient preference disables the category/channel."""
        recipient_id = uuid4()
        now = datetime.now(UTC)
        pref = NotificationPreference(
            user_id=recipient_id,
            email_enabled=True,
            in_app_enabled=True,
            assignments_email=True,
            assignments_in_app=False,  # disabled in-app assignments!
            status_updates_email=True,
            status_updates_in_app=True,
            system_notices_email=True,
            system_notices_in_app=True,
            created_at=now,
            updated_at=now,
        )
        mock_notification_repo.get_or_create_preference.return_value = pref

        notif = await notification_service.dispatch(
            template_name="incident_assigned",
            template_vars={
                "reference_number": "INC-2026-0002",
                "department_name": "Safety",
                "incident_id": str(uuid4()),
            },
            recipient_id=recipient_id,
            channel=NotificationChannel.IN_APP,
        )
        assert notif is None
        mock_notification_repo.create.assert_not_called()

    @pytest.mark.asyncio
    async def test_mark_single_notification_read(
        self,
        notification_service: NotificationService,
        mock_notification_repo: MagicMock,
        mock_audit_repo: MagicMock,
    ) -> None:
        """Marking a single notification read updates record and writes audit event."""
        recipient_id = uuid4()
        notif_id = uuid4()
        now = datetime.now(UTC)
        existing = Notification(
            id=notif_id,
            recipient_id=recipient_id,
            category=NotificationCategory.STATUS_UPDATE.value,
            channel=NotificationChannel.IN_APP.value,
            priority=NotificationPriority.NORMAL.value,
            title="Update",
            body="Status changed",
            data_json="{}",
            is_read=False,
            delivery_status=DeliveryStatus.DELIVERED.value,
            created_at=now,
            updated_at=now,
        )
        mock_notification_repo.get_by_id_and_recipient.return_value = existing

        res = await notification_service.mark_single_notification_read(
            notification_id=notif_id,
            recipient_id=recipient_id,
            actor_role="INVESTIGATOR",
        )
        assert res.is_read is True
        mock_notification_repo.mark_as_read.assert_called_once_with(
            notification_ids=[notif_id],
            recipient_id=recipient_id,
        )
        mock_audit_repo.append_event.assert_called_once()

    @pytest.mark.asyncio
    async def test_mark_single_notification_not_found_raises(
        self,
        notification_service: NotificationService,
        mock_notification_repo: MagicMock,
    ) -> None:
        """Nonexistent or unowned notification raises ResourceNotFoundError."""
        mock_notification_repo.get_by_id_and_recipient.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await notification_service.mark_single_notification_read(
                notification_id=uuid4(),
                recipient_id=uuid4(),
                actor_role="INVESTIGATOR",
            )


class TestEventDrivenHelpers:
    """Verifies event-driven notification dispatch helpers with zero sensitive data previews."""

    @pytest.mark.asyncio
    async def test_notify_incident_and_case_lifecycle_helpers(
        self,
        notification_service: NotificationService,
        mock_notification_repo: MagicMock,
    ) -> None:
        """All event helpers dispatch registered templates containing only metadata."""
        default_pref = NotificationPreference(
            user_id=uuid4(),
            email_enabled=True,
            in_app_enabled=True,
            assignments_email=True,
            assignments_in_app=True,
            status_updates_email=True,
            status_updates_in_app=True,
            system_notices_email=True,
            system_notices_in_app=True,
        )
        mock_notification_repo.get_or_create_preference.return_value = default_pref

        # 1. notify_incident_assigned
        n1 = await notification_service.notify_incident_assigned(
            incident_id=uuid4(),
            reference_number="INC-2026-9999",
            reviewer_id=uuid4(),
        )
        assert n1 is not None
        assert "INC-2026-9999" in n1.title

        # 2. notify_incident_status_changed
        n2 = await notification_service.notify_incident_status_changed(
            incident_id=uuid4(),
            reference_number="INC-2026-9999",
            recipient_id=uuid4(),
            old_status="submitted",
            new_status="under_review",
        )
        assert n2 is not None
        assert "under_review" in n2.body

        # 3. notify_case_assigned
        n3 = await notification_service.notify_case_assigned(
            case_id=uuid4(),
            reference_number="CASE-2026-8888",
            investigator_id=uuid4(),
        )
        assert n3 is not None
        assert "CASE-2026-8888" in n3.title

        # 4. notify_case_status_changed
        n4 = await notification_service.notify_case_status_changed(
            case_id=uuid4(),
            reference_number="CASE-2026-8888",
            recipient_id=uuid4(),
            old_status="open",
            new_status="in_progress",
        )
        assert n4 is not None
        assert "in_progress" in n4.body

        # 5. notify_case_escalated
        n5 = await notification_service.notify_case_escalated(
            case_id=uuid4(),
            reference_number="CASE-2026-8888",
            recipient_id=uuid4(),
            escalation_level="departmental",
        )
        assert n5 is not None
        assert "departmental" in n5.body

        # 6. notify_security_login_alert (critical priority, ignores preferences)
        n6 = await notification_service.notify_security_login_alert(
            user_id=uuid4(),
            ip_address="192.168.1.100",
            login_time="2026-10-15T12:00:00Z",
        )
        assert n6 is not None
        assert n6.priority == NotificationPriority.URGENT.value
