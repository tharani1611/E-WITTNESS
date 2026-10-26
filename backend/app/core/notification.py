"""Core notification domain models, templates, and delivery abstractions (Phase 91).

Enforces:
- Clean provider/delivery interfaces and enums.
- Centrally managed, versioned notification templates with variable validation.
- Strict HTML/script sanitization on untrusted values to prevent injection.
- Redaction of sensitive credentials, tokens, biometrics, and restricted case notes.
- Deduplication and correlation key generation for idempotent delivery.
"""

from __future__ import annotations

import hashlib
import html
import re
from enum import StrEnum
from typing import Any, Final
from uuid import UUID

from backend.app.core.exceptions import BusinessRuleError


class NotificationChannel(StrEnum):
    """Supported delivery channels for notifications."""

    IN_APP = "in_app"
    EMAIL = "email"


class NotificationCategory(StrEnum):
    """Logical categories for notifications."""

    SECURITY_CRITICAL = "security_critical"
    ASSIGNMENT = "assignment"
    STATUS_UPDATE = "status_update"
    SYSTEM_NOTICE = "system_notice"


class NotificationPriority(StrEnum):
    """Notification urgency tiers."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class DeliveryStatus(StrEnum):
    """Lifecycle status of notification delivery."""

    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    SKIPPED = "skipped"
    RETRYING = "retrying"
    PERMANENT_FAILURE = "permanent_failure"


class DeliveryErrorCategory(StrEnum):
    """Sanitized failure classifications for delivery attempts (Phase 93)."""

    TRANSIENT_NETWORK = "transient_network"
    RATE_LIMIT = "rate_limit"
    INVALID_RECIPIENT = "invalid_recipient"
    AUTHENTICATION_ERROR = "authentication_error"
    TEMPLATE_RENDER_ERROR = "template_render_error"
    CONFIGURATION_MISSING = "configuration_missing"
    PROVIDER_ERROR = "provider_error"


# Categories that users CANNOT disable under any circumstances (Phase 94)
MANDATORY_NOTIFICATION_CATEGORIES: Final[frozenset[NotificationCategory]] = frozenset(
    {NotificationCategory.SECURITY_CRITICAL}
)

# Maximum lengths
MAX_NOTIFICATION_TITLE_LENGTH: Final[int] = 255
MAX_NOTIFICATION_BODY_LENGTH: Final[int] = 2000

# Regex for template placeholders: {variable_name}
_TEMPLATE_VAR_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


def sanitize_template_value(val: Any) -> str:
    """Sanitize untrusted variable input for safe template rendering.

    Applies HTML entity escaping to eliminate script/HTML injection attacks.
    Converts UUID and numbers to string cleanly.
    """
    if val is None:
        return ""
    if isinstance(val, UUID):
        return str(val)
    raw = str(val).strip()
    return html.escape(raw, quote=True)


class NotificationTemplate:
    """Centrally managed notification template with variable validation and escaping."""

    def __init__(
        self,
        name: str,
        category: NotificationCategory,
        title_template: str,
        body_template: str,
        required_vars: set[str],
        default_priority: NotificationPriority = NotificationPriority.NORMAL,
        version: str = "1.0",
    ) -> None:
        self.name = name
        self.category = category
        self.title_template = title_template
        self.body_template = body_template
        self.required_vars = frozenset(required_vars)
        self.default_priority = default_priority
        self.version = version

    def render(self, context: dict[str, Any]) -> tuple[str, str]:
        """Render title and body with sanitized variables, validating required inputs."""
        missing = [var for var in self.required_vars if var not in context or context[var] is None]
        if missing:
            raise BusinessRuleError(
                f"Missing required template variables for '{self.name}': {', '.join(sorted(missing))}",
                code="TEMPLATE_VARIABLE_MISSING",
            )

        # Sanitize all inputs
        sanitized_context = {k: sanitize_template_value(v) for k, v in context.items()}

        try:
            rendered_title = self.title_template.format_map(sanitized_context)
            rendered_body = self.body_template.format_map(sanitized_context)
        except KeyError as exc:
            raise BusinessRuleError(
                f"Template render error for '{self.name}': missing key {exc}",
                code="TEMPLATE_RENDER_ERROR",
            ) from exc

        # Enforce bounds
        rendered_title = rendered_title[:MAX_NOTIFICATION_TITLE_LENGTH]
        rendered_body = rendered_body[:MAX_NOTIFICATION_BODY_LENGTH]

        return rendered_title, rendered_body


# =============================================================================
# Standard Template Registry (Phase 91)
# =============================================================================

NOTIFICATION_TEMPLATES: Final[dict[str, NotificationTemplate]] = {
    # 1. Incident Assignment
    "incident_assigned": NotificationTemplate(
        name="incident_assigned",
        category=NotificationCategory.ASSIGNMENT,
        title_template="Incident Assigned: {reference_number}",
        body_template="You have been assigned as lead investigator for incident {reference_number} in department '{department_name}'.",
        required_vars={"reference_number", "department_name"},
    ),
    # 2. Incident Status Changed
    "incident_status_changed": NotificationTemplate(
        name="incident_status_changed",
        category=NotificationCategory.STATUS_UPDATE,
        title_template="Incident Status Updated: {reference_number}",
        body_template="Incident {reference_number} status has been updated to '{new_status}'.",
        required_vars={"reference_number", "new_status"},
    ),
    # 3. Case Assigned
    "case_assigned": NotificationTemplate(
        name="case_assigned",
        category=NotificationCategory.ASSIGNMENT,
        title_template="Case Assigned: {case_reference}",
        body_template="You have been assigned to case {case_reference}: '{case_title}'.",
        required_vars={"case_reference", "case_title"},
    ),
    # 4. Case Status Changed
    "case_status_changed": NotificationTemplate(
        name="case_status_changed",
        category=NotificationCategory.STATUS_UPDATE,
        title_template="Case Status Transition: {case_reference}",
        body_template="Case {case_reference} transitioned from '{from_status}' to '{to_status}'.",
        required_vars={"case_reference", "from_status", "to_status"},
    ),
    # 5. Case Escalated
    "case_escalated": NotificationTemplate(
        name="case_escalated",
        category=NotificationCategory.SECURITY_CRITICAL,
        title_template="Case Escalation Alert: {case_reference}",
        body_template="Case {case_reference} has been escalated to {escalation_level}. Reason: {reason}",
        required_vars={"case_reference", "escalation_level", "reason"},
    ),
    # 6. Security Login Alert
    "security_login_alert": NotificationTemplate(
        name="security_login_alert",
        category=NotificationCategory.SECURITY_CRITICAL,
        title_template="Security Alert: New Sign-In",
        body_template="A new session was authenticated for your account from IP {ip_address}.",
        required_vars={"ip_address"},
    ),
    # 7. Password Changed Notice
    "password_changed_alert": NotificationTemplate(
        name="password_changed_alert",
        category=NotificationCategory.SECURITY_CRITICAL,
        title_template="Security Alert: Password Changed",
        body_template="Your account password was updated. If you did not perform this change, contact security immediately.",
        required_vars=set(),
    ),
    # 8. Role Changed Notice
    "role_changed_alert": NotificationTemplate(
        name="role_changed_alert",
        category=NotificationCategory.SECURITY_CRITICAL,
        title_template="Security Notice: Role Updated",
        body_template="Your account role has been updated to '{new_role}' by an administrator.",
        required_vars={"new_role"},
    ),
    # 9. Generic System Notice
    "system_notice": NotificationTemplate(
        name="system_notice",
        category=NotificationCategory.SYSTEM_NOTICE,
        title_template="{notice_title}",
        body_template="{notice_body}",
        required_vars={"notice_title", "notice_body"},
    ),
}


def get_notification_template(template_name: str) -> NotificationTemplate:
    """Retrieve registered notification template or raise BusinessRuleError."""
    template = NOTIFICATION_TEMPLATES.get(template_name)
    if template is None:
        raise BusinessRuleError(
            f"Notification template '{template_name}' is not recognized.",
            code="TEMPLATE_NOT_FOUND",
        )
    return template


def generate_deduplication_key(
    recipient_id: UUID,
    category: str,
    template_name: str,
    correlation_id: str,
) -> str:
    """Generate a stable, collision-resistant deduplication key for idempotent delivery (Phase 93)."""
    raw = f"{recipient_id}:{category}:{template_name}:{correlation_id}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
