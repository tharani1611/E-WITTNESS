"""Liveness, readiness, and deep operational health monitoring endpoints (Phases 06 & 99)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status

from backend.app.api.dependencies import (
    ClientIpDep,
    HealthServiceDep,
    OperationalMonitoringServiceDep,
    require_any_permission,
)
from backend.app.core.authorization import Permission
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.health import LivenessResponse, ReadinessResponse
from backend.app.schemas.monitoring import (
    OperationalAlertRead,
    SystemHealthDetailedRead,
    WorkerHeartbeatCreate,
    WorkerHeartbeatRead,
)

root_health_router = APIRouter(tags=["Health"])
v1_health_router = APIRouter(prefix="/health", tags=["Health"])


@root_health_router.get(
    "/health",
    response_model=LivenessResponse,
    status_code=status.HTTP_200_OK,
    summary="Application liveness probe",
)
async def get_root_liveness(health_service: HealthServiceDep) -> LivenessResponse:
    """Report application liveness without exposing secrets or internal credentials."""
    return health_service.get_liveness()


@v1_health_router.get(
    "/live",
    response_model=LivenessResponse,
    status_code=status.HTTP_200_OK,
    summary="Versioned application liveness probe",
)
async def get_v1_liveness(health_service: HealthServiceDep) -> LivenessResponse:
    """Report application liveness on the versioned API path."""
    return health_service.get_liveness()


@v1_health_router.get(
    "/ready",
    response_model=ReadinessResponse,
    status_code=status.HTTP_200_OK,
    summary="Versioned application readiness probe",
)
async def get_v1_readiness(
    response: Response,
    health_service: HealthServiceDep,
) -> ReadinessResponse:
    """Report application readiness and per-dependency verification status.

    Returns HTTP 200 when `ready` is True (`ok` or `unverified`), and HTTP 503
    when any registered infrastructure readiness probe fails (`degraded`).
    """
    result = await health_service.evaluate_readiness()
    if not result.ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return result


@v1_health_router.get(
    "/system",
    response_model=SystemHealthDetailedRead,
    status_code=status.HTTP_200_OK,
    summary="Detailed system health, background workers, and queue telemetry",
)
async def get_detailed_system_health(
    service: OperationalMonitoringServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.HEALTH_VIEW_DETAILED,
                Permission.DASHBOARD_VIEW_GLOBAL,
            )
        ),
    ],
    client_ip: ClientIpDep,
    request: Request,
) -> SystemHealthDetailedRead:
    """Assemble deep health diagnostics, worker heartbeats, and queue backlogs."""
    return await service.get_detailed_health(principal=principal)


@v1_health_router.post(
    "/workers/heartbeat",
    response_model=WorkerHeartbeatRead,
    status_code=status.HTTP_200_OK,
    summary="Register periodic background worker heartbeat",
)
async def post_worker_heartbeat(
    service: OperationalMonitoringServiceDep,
    payload: WorkerHeartbeatCreate,
) -> WorkerHeartbeatRead:
    """Register or refresh an active background worker heartbeat."""
    return await service.record_worker_heartbeat(payload=payload)


@v1_health_router.get(
    "/workers",
    response_model=list[WorkerHeartbeatRead],
    status_code=status.HTTP_200_OK,
    summary="List registered background workers and staleness states",
)
async def list_background_workers(
    service: OperationalMonitoringServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.HEALTH_VIEW_DETAILED,
                Permission.DASHBOARD_VIEW_GLOBAL,
            )
        ),
    ],
    client_ip: ClientIpDep,
    request: Request,
) -> list[WorkerHeartbeatRead]:
    """List all registered background worker instances and their health status."""
    detailed = await service.get_detailed_health(principal=principal)
    return detailed.workers


@v1_health_router.post(
    "/alerts/evaluate",
    response_model=list[OperationalAlertRead],
    status_code=status.HTTP_200_OK,
    summary="Evaluate operational alert conditions and dispatch system notices",
)
async def evaluate_operational_alerts(
    service: OperationalMonitoringServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.OPERATIONAL_ALERT_MANAGE,
                Permission.DASHBOARD_VIEW_GLOBAL,
            )
        ),
    ],
    client_ip: ClientIpDep,
    request: Request,
) -> list[OperationalAlertRead]:
    """Evaluate queue depths, worker heartbeats, and retry exhaustion conditions."""
    return await service.evaluate_operational_alerts(principal=principal)
