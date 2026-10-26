"""Authorized Analytics and Workload API endpoints (Phases 96 & 97).

Provides RESTful analytical queries and operational metrics for:
- Incident trends, categories, severities, and time-series histograms.
- Investigation case lifecycles, priorities, and escalation distributions.
- AI candidate human review outcomes and false-positive reasons.
- Reviewer workloads and active assignment distributions.
- Background worker throughput, processing durations, and retry counts.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status

from backend.app.api.dependencies import (
    AnalyticsServiceDep,
    ClientIpDep,
    WorkloadServiceDep,
    require_any_permission,
)
from backend.app.core.analytics import TimeBucket
from backend.app.core.authorization import Permission
from backend.app.schemas.analytics import (
    AnalyticsFilter,
    AnalyticsOverviewRead,
    CaseAnalyticsRead,
    IncidentAnalyticsRead,
    ReviewOutcomeAnalyticsRead,
)
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.workload import (
    ProcessingMetricsRead,
    ReviewerWorkloadSummaryRead,
)

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get(
    "/overview",
    response_model=AnalyticsOverviewRead,
    status_code=status.HTTP_200_OK,
    summary="Get cross-domain analytical summary overview",
)
async def get_analytics_overview(
    service: AnalyticsServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.ANALYTICS_VIEW_DEPT,
                Permission.ANALYTICS_VIEW_GLOBAL,
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
    bucket: Annotated[
        TimeBucket,
        Query(description="Aggregation bucket interval (day, week, month)."),
    ] = TimeBucket.DAY,
    department_id: Annotated[
        UUID | None,
        Query(description="Department ID filter. Subordinated to caller role scope."),
    ] = None,
) -> AnalyticsOverviewRead:
    """Fetch unified cross-domain analytical summary overview."""
    filter_params = AnalyticsFilter(
        start_date=start_date,
        end_date=end_date,
        bucket=bucket,
        department_id=department_id,
    )
    return await service.get_analytics_overview(
        principal=principal,
        filter_params=filter_params,
    )


@router.get(
    "/incidents",
    response_model=IncidentAnalyticsRead,
    status_code=status.HTTP_200_OK,
    summary="Get aggregated incident analytics and time-series histograms",
)
async def get_incident_analytics(
    service: AnalyticsServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.ANALYTICS_VIEW_DEPT,
                Permission.ANALYTICS_VIEW_GLOBAL,
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
    bucket: Annotated[
        TimeBucket,
        Query(description="Aggregation bucket interval (day, week, month)."),
    ] = TimeBucket.DAY,
    department_id: Annotated[
        UUID | None,
        Query(description="Department ID filter. Subordinated to caller role scope."),
    ] = None,
) -> IncidentAnalyticsRead:
    """Fetch incident analytics and time trends."""
    filter_params = AnalyticsFilter(
        start_date=start_date,
        end_date=end_date,
        bucket=bucket,
        department_id=department_id,
    )
    return await service.get_incident_analytics(
        principal=principal,
        filter_params=filter_params,
    )


@router.get(
    "/cases",
    response_model=CaseAnalyticsRead,
    status_code=status.HTTP_200_OK,
    summary="Get aggregated investigation case analytics",
)
async def get_case_analytics(
    service: AnalyticsServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.ANALYTICS_VIEW_DEPT,
                Permission.ANALYTICS_VIEW_GLOBAL,
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
    bucket: Annotated[
        TimeBucket,
        Query(description="Aggregation bucket interval (day, week, month)."),
    ] = TimeBucket.DAY,
    department_id: Annotated[
        UUID | None,
        Query(description="Department ID filter. Subordinated to caller role scope."),
    ] = None,
) -> CaseAnalyticsRead:
    """Fetch case analytics and investigation status trends."""
    filter_params = AnalyticsFilter(
        start_date=start_date,
        end_date=end_date,
        bucket=bucket,
        department_id=department_id,
    )
    return await service.get_case_analytics(
        principal=principal,
        filter_params=filter_params,
    )


@router.get(
    "/reviews",
    response_model=ReviewOutcomeAnalyticsRead,
    status_code=status.HTTP_200_OK,
    summary="Get human review outcome analytics and acceptance rates",
)
async def get_review_outcome_analytics(
    service: AnalyticsServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.ANALYTICS_VIEW_DEPT,
                Permission.ANALYTICS_VIEW_GLOBAL,
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
    bucket: Annotated[
        TimeBucket,
        Query(description="Aggregation bucket interval (day, week, month)."),
    ] = TimeBucket.DAY,
    department_id: Annotated[
        UUID | None,
        Query(description="Department ID filter. Subordinated to caller role scope."),
    ] = None,
) -> ReviewOutcomeAnalyticsRead:
    """Fetch AI candidate review outcomes and false-positive reasons."""
    filter_params = AnalyticsFilter(
        start_date=start_date,
        end_date=end_date,
        bucket=bucket,
        department_id=department_id,
    )
    return await service.get_review_outcome_analytics(
        principal=principal,
        filter_params=filter_params,
    )


@router.get(
    "/workload",
    response_model=ReviewerWorkloadSummaryRead,
    status_code=status.HTTP_200_OK,
    summary="Get authorized reviewer workload distribution",
)
async def get_reviewer_workload(
    service: WorkloadServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.CASE_WORKLOAD_READ_DEPT,
                Permission.CASE_WORKLOAD_READ_GLOBAL,
            )
        ),
    ],
    client_ip: ClientIpDep,
    request: Request,
    department_id: Annotated[
        UUID | None,
        Query(description="Department ID filter. Subordinated to caller role scope."),
    ] = None,
) -> ReviewerWorkloadSummaryRead:
    """Fetch reviewer workload distributions and pending reviews."""
    return await service.get_reviewer_workload(
        principal=principal,
        department_id=department_id,
    )


@router.get(
    "/processing-metrics",
    response_model=ProcessingMetricsRead,
    status_code=status.HTTP_200_OK,
    summary="Get background worker throughput and duration metrics",
)
async def get_processing_metrics(
    service: WorkloadServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.OPERATIONS_METRICS_READ_DEPT,
                Permission.OPERATIONS_METRICS_READ_GLOBAL,
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
        Query(description="Department ID filter. Subordinated to caller role scope."),
    ] = None,
) -> ProcessingMetricsRead:
    """Fetch background job metrics and notification queue performance."""
    filter_params = AnalyticsFilter(
        start_date=start_date,
        end_date=end_date,
        department_id=department_id,
    )
    return await service.get_processing_metrics(
        principal=principal,
        filter_params=filter_params,
    )
