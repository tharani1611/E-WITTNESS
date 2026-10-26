"""Pydantic v2 schemas for Notifications and Notification Preferences (Phases 91-94).

Enforces:
- Strict validation for notification queries and preference updates.
- Invariant: Security-critical alerts cannot be disabled (no preference toggle exists).
- Zero storage credential leakage.
- Sanitized payload presentation.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.app.core.notification import (
    DeliveryErrorCategory,
    DeliveryStatus,
    NotificationCategory,
    NotificationChannel,
    NotificationPriority,
)


class NotificationRead(BaseModel):
    """Schema for returning an in-app notification to the recipient."""

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )

    id: UUID
    recipient_id: UUID
    department_id: UUID | None = None
    category: NotificationCategory
    channel: NotificationChannel
    priority: NotificationPriority
    title: str
    body: str
    data_json: dict[str, Any] = Field(default_factory=dict)
    is_read: bool
    read_at: datetime | None = None
    delivery_status: DeliveryStatus
    correlation_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("data_json", mode="before")
    @classmethod
    def _parse_data_json(cls, v: Any) -> dict[str, Any]:
        if isinstance(v, dict):
            return v
        if isinstance(v, str):
            try:
                loaded = json.loads(v)
                return loaded if isinstance(loaded, dict) else {}
            except Exception:
                return {}
        return {}


class NotificationListResponse(BaseModel):
    """Paginated list of notifications with unread count."""

    model_config = ConfigDict(extra="forbid")

    items: list[NotificationRead]
    total: int
    unread_count: int
    page: int = 1
    page_size: int = 20


class NotificationUnreadCount(BaseModel):
    """Unread notification counter schema."""

    model_config = ConfigDict(extra="forbid")

    unread_count: int = Field(ge=0, description="Total count of unread in-app notifications.")


class NotificationMarkReadRequest(BaseModel):
    """Payload for marking one or more notifications as read."""

    model_config = ConfigDict(extra="forbid")

    notification_ids: list[UUID] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="List of notification IDs owned by the current user to mark as read.",
    )


class NotificationPreferenceRead(BaseModel):
    """Schema for viewing user notification preferences."""

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )

    id: UUID
    user_id: UUID
    email_enabled: bool
    in_app_enabled: bool
    assignments_email: bool
    assignments_in_app: bool
    status_updates_email: bool
    status_updates_in_app: bool
    system_notices_email: bool
    system_notices_in_app: bool
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class NotificationPreferenceUpdate(BaseModel):
    """Payload for updating configurable notification preferences.

    Notice: Security-critical alerts cannot be disabled and are deliberately
    omitted from this schema.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    email_enabled: bool | None = Field(
        default=None,
        description="Enable or disable general email notifications.",
    )
    in_app_enabled: bool | None = Field(
        default=None,
        description="Enable or disable general in-app notifications.",
    )
    assignments_email: bool | None = Field(
        default=None,
        description="Receive assignment notifications via email.",
    )
    assignments_in_app: bool | None = Field(
        default=None,
        description="Receive assignment notifications in-app.",
    )
    status_updates_email: bool | None = Field(
        default=None,
        description="Receive incident/case status update notifications via email.",
    )
    status_updates_in_app: bool | None = Field(
        default=None,
        description="Receive incident/case status update notifications in-app.",
    )
    system_notices_email: bool | None = Field(
        default=None,
        description="Receive broadcast announcements via email.",
    )
    system_notices_in_app: bool | None = Field(
        default=None,
        description="Receive broadcast announcements in-app.",
    )


class NotificationDispatchCreate(BaseModel):
    """Schema for internal/system dispatching of notifications via templates."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    recipient_id: UUID = Field(..., description="Target user recipient ID.")
    department_id: UUID | None = Field(
        default=None,
        description="Department context for multi-tenant isolation.",
    )
    template_name: str = Field(
        ...,
        min_length=3,
        max_length=100,
        description="Registered notification template name.",
    )
    template_vars: dict[str, Any] = Field(
        default_factory=dict,
        description="Variables to substitute into the template.",
    )
    channel: NotificationChannel = Field(
        default=NotificationChannel.IN_APP,
        description="Target delivery channel.",
    )
    priority: NotificationPriority | None = Field(
        default=None,
        description="Optional priority override.",
    )
    correlation_id: str | None = Field(
        default=None,
        max_length=200,
        description="Trace/correlation identifier linking to incident, case, or task.",
    )


class NotificationDeliveryAttemptRead(BaseModel):
    """Audit schema for delivery attempts."""

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )

    id: UUID
    notification_id: UUID
    channel: NotificationChannel
    status: DeliveryStatus
    attempt_number: int
    error_category: DeliveryErrorCategory | None = None
    error_message: str | None = None
    deduplication_key: str
    attempted_at: datetime
