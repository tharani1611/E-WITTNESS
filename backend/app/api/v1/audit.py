"""Security audit and ledger verification API endpoints (Phases 58-59).

Provides:
- GET /audit/events: Scoped query interface over tamper-evident security audit events.
- GET /audit/verify: Cryptographic chain verification report with statutory disclaimer.
- GET /audit/exports: Scoped listing of historical evidence export packages.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from backend.app.api.dependencies import (
    AuditServiceDep,
    require_any_permission,
)
from backend.app.core.authorization import Permission
from backend.app.schemas.audit import (
    AuditSearchFilterParams,
    AuditVerificationReport,
    EvidenceExportResponse,
    SecurityAuditEventRead,
)
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.pagination import PaginatedResponse

router = APIRouter(prefix="/audit", tags=["Security Audit"])
v1_audit_router = router


@router.get(
    "/events",
    response_model=PaginatedResponse[SecurityAuditEventRead],
    summary="Search tamper-evident security audit events",
    description="Search audit records with department scoping and strict pagination bounds (max 100) (Phase 58-59).",
)
async def search_security_audit_events(
    audit_service: AuditServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.AUDIT_EVENT_READ_DEPT,
                Permission.AUDIT_EVENT_READ_GLOBAL,
            )
        ),
    ],
    actor_id: Annotated[UUID | None, Query(description="Filter by initiating actor ID")] = None,
    action: Annotated[str | None, Query(description="Filter by audit action")] = None,
    target_type: Annotated[str | None, Query(description="Filter by target classification")] = None,
    target_id: Annotated[str | None, Query(description="Filter by target identifier")] = None,
    department_id: Annotated[UUID | None, Query(description="Filter by department ID")] = None,
    outcome: Annotated[
        str | None, Query(description="Filter by outcome (success, failure, denied)")
    ] = None,
    start_time: Annotated[
        datetime | None, Query(description="Earliest created_at timestamp")
    ] = None,
    end_time: Annotated[datetime | None, Query(description="Latest created_at timestamp")] = None,
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 50,
) -> PaginatedResponse[SecurityAuditEventRead]:
    params = AuditSearchFilterParams(
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        department_id=department_id,
        outcome=outcome,
        start_time=start_time,
        end_time=end_time,
        page=page,
        page_size=page_size,
    )
    return await audit_service.search_audit_events(params, principal)


@router.get(
    "/verify",
    response_model=AuditVerificationReport,
    summary="Verify security audit chain integrity",
    description="Verify cryptographic hash chain integrity and sequence continuity across audit entries (Phase 58).",
)
async def verify_audit_chain(
    audit_service: AuditServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.AUDIT_EVENT_READ_DEPT,
                Permission.AUDIT_EVENT_READ_GLOBAL,
            )
        ),
    ],
    start_sequence: Annotated[
        int, Query(ge=1, description="Starting sequence number to verify from")
    ] = 1,
    limit: Annotated[
        int, Query(ge=1, le=5000, description="Maximum number of consecutive events to verify")
    ] = 1000,
) -> AuditVerificationReport:
    return await audit_service.verify_audit_chain(
        principal=principal,
        start_sequence=start_sequence,
        limit=limit,
    )


@router.get(
    "/exports",
    response_model=PaginatedResponse[EvidenceExportResponse],
    summary="List historical evidence exports",
    description="Retrieve authorized evidence export records scoped to caller's department or tenant (Phase 59).",
)
async def list_evidence_exports(
    audit_service: AuditServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.EVIDENCE_EXPORT_DEPT,
                Permission.EVIDENCE_EXPORT_GLOBAL,
            )
        ),
    ],
    incident_id: Annotated[UUID | None, Query(description="Filter exports by incident ID")] = None,
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 50,
) -> PaginatedResponse[EvidenceExportResponse]:
    return await audit_service.list_evidence_exports(
        principal=principal,
        incident_id=incident_id,
        page=page,
        page_size=page_size,
    )
