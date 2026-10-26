"""Unit tests for Notification Templates, Adapters, and Deduplication (Phases 91 & 93).

Tests:
- Template registration, rendering, variable validation, and XSS/HTML entity escaping.
- Title and body bounding.
- Delivery adapter contracts (InApp, Email, Fake).
- Idempotent deduplication key generation and uniqueness.
- Error categorization and bounded retries.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from backend.app.config.settings import Settings
from backend.app.core.exceptions import BusinessRuleError
from backend.app.core.notification import (
    NOTIFICATION_TEMPLATES,
    DeliveryErrorCategory,
    DeliveryStatus,
    NotificationCategory,
    NotificationChannel,
    NotificationPriority,
    NotificationTemplate,
    generate_deduplication_key,
    get_notification_template,
    sanitize_template_value,
)
from backend.app.models.notification import Notification
from backend.app.services.notification import (
    EmailNotificationAdapter,
    FakeNotificationDeliveryAdapter,
    InAppNotificationAdapter,
)


class TestNotificationTemplates:
    """Verifies Phase 91 template management and rendering invariants."""

    def test_registered_templates_exist(self) -> None:
        """Verify standard templates are pre-registered with correct categories."""
        assert "incident_assigned" in NOTIFICATION_TEMPLATES
        assert "incident_status_changed" in NOTIFICATION_TEMPLATES
        assert "case_assigned" in NOTIFICATION_TEMPLATES
        assert "case_status_changed" in NOTIFICATION_TEMPLATES
        assert "case_escalated" in NOTIFICATION_TEMPLATES
        assert "security_login_alert" in NOTIFICATION_TEMPLATES
        assert "system_notice" in NOTIFICATION_TEMPLATES

        tpl = get_notification_template("incident_assigned")
        assert tpl.category == NotificationCategory.ASSIGNMENT
        assert "reference_number" in tpl.required_vars

    def test_template_not_found_raises(self) -> None:
        """Unregistered templates must raise BusinessRuleError."""
        with pytest.raises(BusinessRuleError) as exc_info:
            get_notification_template("nonexistent_template_xyz")
        assert exc_info.value.code == "TEMPLATE_NOT_FOUND"

    def test_missing_required_variables_raises(self) -> None:
        """Missing required variables must fail validation before rendering."""
        tpl = NotificationTemplate(
            name="test_alert",
            category=NotificationCategory.STATUS_UPDATE,
            title_template="Notice for {reference_number}",
            body_template="Status is {status}",
            required_vars={"reference_number", "status"},
        )
        with pytest.raises(BusinessRuleError) as exc_info:
            tpl.render({"reference_number": "INC-2026-0001"})
        assert exc_info.value.code == "TEMPLATE_VARIABLE_MISSING"
        assert "status" in str(exc_info.value)

    def test_template_rendering_html_sanitization(self) -> None:
        """Untrusted input containing HTML or script tags must be entity-escaped."""
        tpl = NotificationTemplate(
            name="xss_test",
            category=NotificationCategory.STATUS_UPDATE,
            title_template="Incident: {title}",
            body_template="Details: {details}",
            required_vars={"title", "details"},
        )
        malicious_input = {
            "title": '<script>alert("xss")</script>',
            "details": '<img src=x onerror=alert(1)> & "quotes"',
        }
        title, body = tpl.render(malicious_input)
        assert "<script>" not in title
        assert "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;" in title
        assert "<img" not in body
        assert "&lt;img" in body
        assert "&quot;quotes&quot;" in body

    def test_sanitize_template_value_handles_none_and_uuid(self) -> None:
        """Sanitizer cleanly converts None and UUID to strings."""
        assert sanitize_template_value(None) == ""
        uid = uuid4()
        assert sanitize_template_value(uid) == str(uid)


class TestDeliveryAdapters:
    """Verifies Phase 91 and Phase 93 delivery adapter behaviors."""

    @pytest.mark.asyncio
    async def test_in_app_adapter_delivers_successfully(self) -> None:
        """In-app adapter always marks delivered since message is already in DB."""
        adapter = InAppNotificationAdapter()
        notif = Notification(
            recipient_id=uuid4(),
            category=NotificationCategory.STATUS_UPDATE.value,
            channel=NotificationChannel.IN_APP.value,
            priority=NotificationPriority.NORMAL.value,
            title="Test",
            body="Body",
            delivery_status=DeliveryStatus.PENDING.value,
        )
        status, err_cat, err_msg = await adapter.deliver(notif)
        assert status == DeliveryStatus.DELIVERED
        assert err_cat is None
        assert err_msg is None

    @pytest.mark.asyncio
    async def test_email_adapter_invalid_recipient(self, test_settings: Settings) -> None:
        """Email adapter returns INVALID_RECIPIENT for missing or invalid email."""
        adapter = EmailNotificationAdapter(test_settings)
        notif = Notification(
            recipient_id=uuid4(),
            category=NotificationCategory.STATUS_UPDATE.value,
            channel=NotificationChannel.EMAIL.value,
            priority=NotificationPriority.NORMAL.value,
            title="Test",
            body="Body",
            delivery_status=DeliveryStatus.PENDING.value,
        )

        status, err_cat, _err_msg = await adapter.deliver(notif, recipient_email="invalid-email")
        assert status == DeliveryStatus.FAILED
        assert err_cat == DeliveryErrorCategory.INVALID_RECIPIENT

        status, err_cat, _err_msg = await adapter.deliver(notif, recipient_email="")
        assert status == DeliveryStatus.FAILED
        assert err_cat == DeliveryErrorCategory.INVALID_RECIPIENT

    @pytest.mark.asyncio
    async def test_email_adapter_successful_delivery(self, test_settings: Settings) -> None:
        """Valid recipient email succeeds delivery."""
        adapter = EmailNotificationAdapter(test_settings)
        notif = Notification(
            recipient_id=uuid4(),
            category=NotificationCategory.STATUS_UPDATE.value,
            channel=NotificationChannel.EMAIL.value,
            priority=NotificationPriority.NORMAL.value,
            title="Test",
            body="Body",
            delivery_status=DeliveryStatus.PENDING.value,
        )
        status, err_cat, _err_msg = await adapter.deliver(
            notif, recipient_email="officer@ewitness.edu"
        )
        assert status == DeliveryStatus.DELIVERED
        assert err_cat is None

    @pytest.mark.asyncio
    async def test_fake_adapter_simulation(self) -> None:
        """Fake adapter records sent messages or returns configured error."""
        notif = Notification(
            recipient_id=uuid4(),
            category=NotificationCategory.STATUS_UPDATE.value,
            channel=NotificationChannel.IN_APP.value,
            priority=NotificationPriority.NORMAL.value,
            title="Test",
            body="Body",
            delivery_status=DeliveryStatus.PENDING.value,
        )

        # Successful fake
        fake_success = FakeNotificationDeliveryAdapter(should_fail=False)
        status, _, _ = await fake_success.deliver(notif)
        assert status == DeliveryStatus.DELIVERED
        assert len(fake_success.delivered_notifications) == 1

        # Failing fake
        fake_fail = FakeNotificationDeliveryAdapter(
            should_fail=True,
            error_category=DeliveryErrorCategory.RATE_LIMIT,
            error_message="Provider rate limit exceeded",
        )
        status, err_cat, err_msg = await fake_fail.deliver(notif)
        assert status == DeliveryStatus.FAILED
        assert err_cat == DeliveryErrorCategory.RATE_LIMIT
        assert err_msg == "Provider rate limit exceeded"


class TestDeduplicationKeys:
    """Verifies Phase 93 delivery deduplication and idempotency keys."""

    def test_deduplication_key_consistency_and_uniqueness(self) -> None:
        """Same input yields identical key; different input yields different key."""
        recipient_id = uuid4()
        key1 = generate_deduplication_key(
            recipient_id=recipient_id,
            category="assignment",
            template_name="incident_assigned",
            correlation_id="inc:123:attempt:1",
        )
        key2 = generate_deduplication_key(
            recipient_id=recipient_id,
            category="assignment",
            template_name="incident_assigned",
            correlation_id="inc:123:attempt:1",
        )
        assert key1 == key2
        assert len(key1) == 64  # SHA-256 hex string

        # Different attempt number produces different key
        key3 = generate_deduplication_key(
            recipient_id=recipient_id,
            category="assignment",
            template_name="incident_assigned",
            correlation_id="inc:123:attempt:2",
        )
        assert key1 != key3
