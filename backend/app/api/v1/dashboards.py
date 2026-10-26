"""Operational Dashboards API endpoints (Phase 95).

Provides RESTful read-only aggregation queries for:
- Incidents metrics by status, severity, and department.
- Investigation case metrics by status, priority, and escalations.
- System operational metrics for AI jobs and notification delivery queues.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status

from backend.app.api.dependencies import (
    ClientIpDep,
    DashboardServiceDep,
    require_any_permission,
)
from backend.app.core.authorization import Permission
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.dashboard import (
    CaseDashboardRead,
    DashboardDateFilter,
    IncidentDashboardRead,
    OperationsDashboardRead,
)

router = APIRouter(prefix="/dashboards", tags=["dashboards"])


@router.get(
    "/incidents",
    response_model=IncidentDashboardRead,
    status_code=status.HTTP_200_OK,
    summary="Get aggregated incident metrics",
)
async def get_incident_dashboard(
    service: DashboardServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.DASHBOARD_VIEW_DEPT,
                Permission.DASHBOARD_VIEW_GLOBAL,
            )
        ),
    ],
    client_ip: ClientIpDep,
    request: Request,
    start_date: Annotated[
        datetime | None,
        Query(description="Filter range start (UTC). Defaults to 30 days prior."),
    ] = None,
    end_date: Annotated[
        datetime | None,
        Query(description="Filter range end (UTC). Defaults to current timestamp."),
    ] = None,
    department_id: Annotated[
        UUID | None,
        Query(
            description="Target department filter (restricted to caller department for non-superadmins)."
        ),
    ] = None,
) -> IncidentDashboardRead:
    """Retrieve operational metrics for incidents within a bounded time window."""
    filter_params = DashboardDateFilter(
        start_date=start_date,
        end_date=end_date,
        department_id=department_id,
    )
    return await service.get_incident_dashboard(
        filter_params=filter_params,
        principal=principal,
        actor_ip=client_ip,
        actor_user_agent=request.headers.get("user-agent"),
    )


@router.get(
    "/cases",
    response_model=CaseDashboardRead,
    status_code=status.HTTP_200_OK,
    summary="Get aggregated case metrics",
)
async def get_case_dashboard(
    service: DashboardServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.DASHBOARD_VIEW_DEPT,
                Permission.DASHBOARD_VIEW_GLOBAL,
            )
        ),
    ],
    client_ip: ClientIpDep,
    request: Request,
    start_date: Annotated[
        datetime | None,
        Query(description="Filter range start (UTC). Defaults to 30 days prior."),
    ] = None,
    end_date: Annotated[
        datetime | None,
        Query(description="Filter range end (UTC). Defaults to current timestamp."),
    ] = None,
    department_id: Annotated[
        UUID | None,
        Query(
            description="Target department filter (restricted to caller department for non-superadmins)."
        ),
    ] = None,
) -> CaseDashboardRead:
    """Retrieve operational metrics for investigation cases within a bounded time window."""
    filter_params = DashboardDateFilter(
        start_date=start_date,
        end_date=end_date,
        department_id=department_id,
    )
    return await service.get_case_dashboard(
        filter_params=filter_params,
        principal=principal,
        actor_ip=client_ip,
        actor_user_agent=request.headers.get("user-agent"),
    )


@router.get(
    "/operations",
    response_model=OperationsDashboardRead,
    status_code=status.HTTP_200_OK,
    summary="Get aggregated operations and delivery metrics",
)
async def get_operations_dashboard(
    service: DashboardServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.DASHBOARD_VIEW_DEPT,
                Permission.DASHBOARD_VIEW_GLOBAL,
            )
        ),
    ],
    client_ip: ClientIpDep,
    request: Request,
    start_date: Annotated[
        datetime | None,
        Query(description="Filter range start (UTC). Defaults to 30 days prior."),
    ] = None,
    end_date: Annotated[
        datetime | None,
        Query(description="Filter range end (UTC). Defaults to current timestamp."),
    ] = None,
    department_id: Annotated[
        UUID | None,
        Query(
            description="Target department filter (restricted to caller department for non-superadmins)."
        ),
    ] = None,
) -> OperationsDashboardRead:
    """Retrieve system operations metrics for AI analysis and notification delivery."""
    filter_params = DashboardDateFilter(
        start_date=start_date,
        end_date=end_date,
        department_id=department_id,
    )
    return await service.get_operations_dashboard(
        filter_params=filter_params,
        principal=principal,
        actor_ip=client_ip,
        actor_user_agent=request.headers.get("user-agent"),
    )
