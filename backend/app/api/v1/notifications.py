"""Notification and User Preference API endpoints (Phases 91-94).

Provides RESTful operations for:
- Listing authenticated user notifications with pagination and read-filtering.
- Fetching live unread notification counts.
- Marking individual or batch notifications as read (strictly owned by caller).
- Viewing and managing user notification preferences.
- System/Admin template dispatching with delivery idempotency.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status

from backend.app.api.dependencies import (
    ClientIpDep,
    NotificationServiceDep,
    require_permission,
)
from backend.app.core.authorization import Permission
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.notification import (
    NotificationDispatchCreate,
    NotificationListResponse,
    NotificationMarkReadRequest,
    NotificationPreferenceRead,
    NotificationPreferenceUpdate,
    NotificationRead,
    NotificationUnreadCount,
)

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get(
    "",
    response_model=NotificationListResponse,
    status_code=status.HTTP_200_OK,
    summary="List authenticated user's notifications",
)
async def list_notifications(
    service: NotificationServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.NOTIFICATION_READ_OWN)),
    ],
    is_read: Annotated[bool | None, Query(description="Filter by read status.")] = None,
    page: Annotated[int, Query(ge=1, description="Page number (1-based).")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page.")] = 20,
) -> NotificationListResponse:
    """Retrieve paginated notifications owned by the authenticated caller."""
    return await service.list_user_notifications(
        recipient_id=principal.user_id,
        is_read=is_read,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/unread-count",
    response_model=NotificationUnreadCount,
    status_code=status.HTTP_200_OK,
    summary="Get unread notification count",
)
async def get_unread_count(
    service: NotificationServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.NOTIFICATION_READ_OWN)),
    ],
) -> NotificationUnreadCount:
    """Return count of unread in-app notifications for authenticated caller."""
    return await service.get_unread_count(recipient_id=principal.user_id)


@router.post(
    "/mark-read",
    status_code=status.HTTP_200_OK,
    summary="Mark batch of notifications as read",
)
async def mark_notifications_read(
    payload: NotificationMarkReadRequest,
    service: NotificationServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.NOTIFICATION_UPDATE_OWN)),
    ],
    client_ip: ClientIpDep,
    request: Request,
) -> dict[str, int]:
    """Mark a batch of notifications as read, strictly validating caller ownership."""
    marked = await service.mark_notifications_read(
        notification_ids=payload.notification_ids,
        recipient_id=principal.user_id,
        actor_role=principal.role_code,
        actor_ip=client_ip,
        actor_user_agent=request.headers.get("user-agent"),
    )
    return {"marked_read": marked}


@router.post(
    "/{notification_id}/read",
    response_model=NotificationRead,
    status_code=status.HTTP_200_OK,
    summary="Mark single notification as read",
)
async def mark_single_notification_read(
    notification_id: UUID,
    service: NotificationServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.NOTIFICATION_UPDATE_OWN)),
    ],
    client_ip: ClientIpDep,
    request: Request,
) -> NotificationRead:
    """Mark a single notification owned by caller as read."""
    return await service.mark_single_notification_read(
        notification_id=notification_id,
        recipient_id=principal.user_id,
        actor_role=principal.role_code,
        actor_ip=client_ip,
        actor_user_agent=request.headers.get("user-agent"),
    )


@router.get(
    "/preferences",
    response_model=NotificationPreferenceRead,
    status_code=status.HTTP_200_OK,
    summary="Get user notification preferences",
)
async def get_notification_preferences(
    service: NotificationServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.NOTIFICATION_PREFERENCE_MANAGE_OWN)),
    ],
) -> NotificationPreferenceRead:
    """Retrieve notification delivery preferences for the authenticated user."""
    return await service.get_preferences(user_id=principal.user_id)


@router.patch(
    "/preferences",
    response_model=NotificationPreferenceRead,
    status_code=status.HTTP_200_OK,
    summary="Update user notification preferences",
)
async def update_notification_preferences(
    payload: NotificationPreferenceUpdate,
    service: NotificationServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.NOTIFICATION_PREFERENCE_MANAGE_OWN)),
    ],
    client_ip: ClientIpDep,
    request: Request,
) -> NotificationPreferenceRead:
    """Update configurable notification delivery preferences.

    Security-critical alerts cannot be disabled (enforced by schema).
    """
    return await service.update_preferences(
        user_id=principal.user_id,
        payload=payload,
        actor_id=principal.user_id,
        actor_role=principal.role_code,
        actor_ip=client_ip,
        actor_user_agent=request.headers.get("user-agent"),
    )


@router.post(
    "/dispatch",
    response_model=NotificationRead | None,
    status_code=status.HTTP_201_CREATED,
    summary="Dispatch a notification template (system/admin)",
)
async def dispatch_notification(
    payload: NotificationDispatchCreate,
    service: NotificationServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_permission(Permission.NOTIFICATION_DISPATCH_SYSTEM)),
    ],
    client_ip: ClientIpDep,
    request: Request,
) -> NotificationRead | None:
    """Dispatch an in-app or email notification via a registered template.

    Requires NOTIFICATION_DISPATCH_SYSTEM permission.
    """
    notification = await service.dispatch(
        template_name=payload.template_name,
        template_vars=payload.template_vars,
        recipient_id=payload.recipient_id,
        department_id=payload.department_id,
        channel=payload.channel,
        priority=payload.priority,
        correlation_id=payload.correlation_id,
        actor_id=principal.user_id,
        actor_role=principal.role_code,
        actor_ip=client_ip,
        actor_user_agent=request.headers.get("user-agent"),
    )
    if notification is None:
        return None
    return NotificationRead.model_validate(notification)
