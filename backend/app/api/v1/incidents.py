"""Incident reporting, evidence attachment, and upload authorization endpoints (Phases 41-45).

Provides RESTful operations for:
- Submitting structured incident reports.
- Scoped listing and retrieval by ID or opaque reference number.
- Modifying incidents within lifecycle constraints.
- Administrative status transitions.
- Authorizing secure evidence upload sessions with pre-signed endpoints.
- Inspecting evidence metadata and upload session statuses.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status

from backend.app.api.dependencies import (
    AuditServiceDep,
    CurrentUserDep,
    EvidenceServiceDep,
    IncidentServiceDep,
    require_any_permission,
)
from backend.app.core.authorization import Permission
from backend.app.schemas.audit import EvidenceExportRequest, EvidenceExportResponse
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.evidence import (
    CompensatingEventCreateRequest,
    EvidenceAttachmentRead,
    EvidenceCustodyEventRead,
    EvidenceDownloadResponse,
    EvidenceIntegrityReportResponse,
    EvidenceProvenanceRead,
    MultipartUploadCompleteRequest,
    MultipartUploadInitRequest,
    MultipartUploadInitResponse,
    UploadSessionCreateRequest,
    UploadSessionResponse,
)
from backend.app.schemas.incident import (
    IncidentAssignmentRead,
    IncidentCreate,
    IncidentRead,
    IncidentRouteOverrideRequest,
    IncidentRoutingDecisionRead,
    IncidentStatusTransitionRequest,
    IncidentUpdate,
    ReviewerAssignRequest,
    ReviewerReassignRequest,
    ReviewQueueWorkloadSummary,
)
from backend.app.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    SortOrder,
)

router = APIRouter(prefix="/incidents", tags=["Incidents"])
v1_incidents_router = router


@router.post(
    "",
    response_model=IncidentRead,
    status_code=status.HTTP_201_CREATED,
    summary="Submit an incident report",
    description="Submits a structured incident report bound to the authenticated caller's identity.",
)
async def submit_incident(
    payload: IncidentCreate,
    incident_service: IncidentServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_any_permission(Permission.INCIDENT_CREATE)),
    ],
) -> IncidentRead:
    return await incident_service.create_incident(payload, principal)


@router.get(
    "",
    response_model=PaginatedResponse[IncidentRead],
    summary="List incidents",
    description="Retrieve a paginated collection of incidents scoped to the caller's authorized visibility.",
)
async def list_incidents(
    incident_service: IncidentServiceDep,
    principal: CurrentUserDep,
    page: Annotated[int, Query(ge=1, description="1-indexed page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
    status: Annotated[str | None, Query(description="Filter by incident status")] = None,
    category: Annotated[str | None, Query(description="Filter by incident category")] = None,
    severity: Annotated[str | None, Query(description="Filter by incident severity")] = None,
    search: Annotated[
        str | None, Query(description="Search term matching title/description/ref")
    ] = None,
    sort_by: Annotated[str, Query(description="Field to sort by")] = "created_at",
    sort_order: Annotated[SortOrder, Query(description="Sort direction")] = SortOrder.DESC,
) -> PaginatedResponse[IncidentRead]:
    pagination = PaginationParams(page=page, page_size=page_size)
    return await incident_service.list_incidents(
        principal,
        pagination,
        status=status,
        category=category,
        severity=severity,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order.value,
    )


@router.get(
    "/queue/workload",
    response_model=ReviewQueueWorkloadSummary,
    summary="Get review queue workload summary",
    description="Retrieve workload metrics (pending, assigned, unassigned, overdue, completed, total) for the caller's department (Phase 56).",
)
async def get_review_queue_workload(
    incident_service: IncidentServiceDep,
    principal: CurrentUserDep,
    reviewer_id: Annotated[
        UUID | None, Query(description="Filter counts by assigned reviewer")
    ] = None,
) -> ReviewQueueWorkloadSummary:
    return await incident_service.get_workload_summary(principal, reviewer_id=reviewer_id)


@router.get(
    "/queue",
    response_model=PaginatedResponse[IncidentRead],
    summary="List department review queue incidents",
    description="Retrieve paginated review queue incidents scoped to the caller's authorized tenant and department (Phase 56).",
)
async def get_review_queue(
    incident_service: IncidentServiceDep,
    principal: CurrentUserDep,
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
    reviewer_id: Annotated[UUID | None, Query(description="Filter by assigned reviewer")] = None,
    assignment_status: Annotated[
        str | None, Query(description="Filter by assignment status")
    ] = None,
    status: Annotated[str | None, Query(description="Filter by lifecycle status")] = None,
    category: Annotated[str | None, Query(description="Filter by category")] = None,
    severity: Annotated[str | None, Query(description="Filter by severity")] = None,
    search: Annotated[
        str | None, Query(description="Search term matching title/description/ref")
    ] = None,
    sort_by: Annotated[str, Query(description="Field to sort by")] = "created_at",
    sort_order: Annotated[SortOrder, Query(description="Sort direction")] = SortOrder.DESC,
) -> PaginatedResponse[IncidentRead]:
    pagination = PaginationParams(page=page, page_size=page_size)
    return await incident_service.get_review_queue(
        principal=principal,
        pagination=pagination,
        reviewer_id=reviewer_id,
        assignment_status=assignment_status,
        status=status,
        category=category,
        severity=severity,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order.value,
    )


@router.get(
    "/reference/{reference_number}",
    response_model=IncidentRead,
    summary="Get incident by reference number",
    description="Retrieve an incident record using its opaque reference number within authorized scope.",
)
async def get_incident_by_reference(
    reference_number: str,
    incident_service: IncidentServiceDep,
    principal: CurrentUserDep,
) -> IncidentRead:
    return await incident_service.get_incident_by_reference(reference_number, principal)


@router.get(
    "/{incident_id}",
    response_model=IncidentRead,
    summary="Get incident details",
    description="Retrieve an incident by ID within caller's authorized department or ownership scope.",
)
async def get_incident(
    incident_id: UUID,
    incident_service: IncidentServiceDep,
    principal: CurrentUserDep,
) -> IncidentRead:
    return await incident_service.get_incident(incident_id, principal)


@router.patch(
    "/{incident_id}",
    response_model=IncidentRead,
    summary="Update incident details",
    description="Modify permitted incident fields while in SUBMITTED status.",
)
async def update_incident(
    incident_id: UUID,
    payload: IncidentUpdate,
    incident_service: IncidentServiceDep,
    principal: CurrentUserDep,
) -> IncidentRead:
    return await incident_service.update_incident(incident_id, payload, principal)


@router.post(
    "/{incident_id}/status",
    response_model=IncidentRead,
    summary="Transition incident status",
    description="Administratively transition an incident's lifecycle status (Dept Admin / Super Admin only).",
)
async def transition_incident_status(
    incident_id: UUID,
    payload: IncidentStatusTransitionRequest,
    incident_service: IncidentServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.INCIDENT_UPDATE_DEPT,
                Permission.INCIDENT_UPDATE_GLOBAL,
            )
        ),
    ],
) -> IncidentRead:
    return await incident_service.transition_status(
        incident_id, payload.status, principal, reason=payload.reason
    )


@router.post(
    "/{incident_id}/assign",
    response_model=IncidentRead,
    summary="Assign reviewer to incident",
    description="Assign an eligible department reviewer to an incident with conflict-of-interest checks (Phase 57).",
)
async def assign_reviewer(
    incident_id: UUID,
    payload: ReviewerAssignRequest,
    incident_service: IncidentServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.INCIDENT_ASSIGN_DEPT,
                Permission.INCIDENT_ASSIGN_GLOBAL,
            )
        ),
    ],
) -> IncidentRead:
    return await incident_service.assign_reviewer(incident_id, payload, principal)


@router.post(
    "/{incident_id}/reassign",
    response_model=IncidentRead,
    summary="Reassign incident reviewer",
    description="Reassign an incident to a new reviewer with mandatory administrative justification (Phase 57).",
)
async def reassign_reviewer(
    incident_id: UUID,
    payload: ReviewerReassignRequest,
    incident_service: IncidentServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.INCIDENT_ASSIGN_DEPT,
                Permission.INCIDENT_ASSIGN_GLOBAL,
            )
        ),
    ],
) -> IncidentRead:
    return await incident_service.reassign_reviewer(incident_id, payload, principal)


@router.post(
    "/{incident_id}/acknowledge",
    response_model=IncidentRead,
    summary="Acknowledge incident assignment",
    description="Acknowledge case assignment by the assigned reviewer (Phase 57).",
)
async def acknowledge_assignment(
    incident_id: UUID,
    incident_service: IncidentServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.INCIDENT_ACKNOWLEDGE,
                Permission.INCIDENT_ASSIGN_GLOBAL,
            )
        ),
    ],
) -> IncidentRead:
    return await incident_service.acknowledge_assignment(incident_id, principal)


@router.get(
    "/{incident_id}/assignments",
    response_model=list[IncidentAssignmentRead],
    summary="Get incident reviewer assignment history",
    description="Retrieve chronological record of reviewer assignments and reassignments (Phase 57).",
)
async def get_incident_assignments(
    incident_id: UUID,
    incident_service: IncidentServiceDep,
    principal: CurrentUserDep,
) -> list[IncidentAssignmentRead]:
    return await incident_service.get_assignment_history(incident_id, principal)


@router.post(
    "/{incident_id}/export",
    response_model=EvidenceExportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Export incident evidence package",
    description="Generate an authorized evidence export package and cryptographic manifest (Phase 59).",
)
async def export_incident_evidence(
    incident_id: UUID,
    payload: EvidenceExportRequest,
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
) -> EvidenceExportResponse:
    return await audit_service.export_incident_evidence(incident_id, payload, principal)


@router.post(
    "/{incident_id}/attachments/upload-session",
    response_model=UploadSessionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create evidence upload session",
    description="Authorize and generate a short-lived pre-signed upload session for attaching evidence.",
)
async def create_upload_session(
    incident_id: UUID,
    payload: UploadSessionCreateRequest,
    evidence_service: EvidenceServiceDep,
    principal: CurrentUserDep,
    request: Request,
) -> UploadSessionResponse:
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    return await evidence_service.create_upload_session(
        incident_id, payload, principal, uploader_ip=ip, user_agent=ua
    )


@router.get(
    "/{incident_id}/attachments",
    response_model=list[EvidenceAttachmentRead],
    summary="List evidence attachments",
    description="Retrieve metadata for all evidence files attached to an incident within authorized scope.",
)
async def list_incident_attachments(
    incident_id: UUID,
    evidence_service: EvidenceServiceDep,
    principal: CurrentUserDep,
) -> list[EvidenceAttachmentRead]:
    return await evidence_service.list_attachments(incident_id, principal)


@router.get(
    "/{incident_id}/attachments/{attachment_id}",
    response_model=EvidenceAttachmentRead,
    summary="Get evidence attachment metadata",
    description="Retrieve metadata for a specific evidence attachment.",
)
async def get_incident_attachment(
    incident_id: UUID,
    attachment_id: UUID,
    evidence_service: EvidenceServiceDep,
    principal: CurrentUserDep,
) -> EvidenceAttachmentRead:
    return await evidence_service.get_attachment(attachment_id, principal)


@router.get(
    "/attachments/upload-sessions/{session_id}",
    response_model=UploadSessionResponse,
    summary="Get upload session status",
    description="Inspect the status and endpoint for an authorized evidence upload session.",
)
async def get_upload_session(
    session_id: UUID,
    evidence_service: EvidenceServiceDep,
    principal: CurrentUserDep,
) -> UploadSessionResponse:
    return await evidence_service.get_upload_session(session_id, principal)


@router.post(
    "/{incident_id}/attachments/upload-sessions/{session_id}/complete",
    response_model=EvidenceAttachmentRead,
    status_code=status.HTTP_200_OK,
    summary="Complete single-part evidence upload session",
    description="Verify uploaded object, enforce magic byte and checksum validation, trigger malware scanner, and attach evidence.",
)
@router.post(
    "/attachments/upload-sessions/{session_id}/complete",
    response_model=EvidenceAttachmentRead,
    status_code=status.HTTP_200_OK,
    summary="Complete evidence upload session",
    description="Verify uploaded object, enforce magic byte and checksum validation, trigger malware scanner, and attach evidence.",
)
async def complete_upload_session(
    session_id: UUID,
    evidence_service: EvidenceServiceDep,
    principal: CurrentUserDep,
    request: Request,
    incident_id: UUID | None = None,
) -> EvidenceAttachmentRead:
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    return await evidence_service.complete_upload_session(
        session_id, principal, incident_id=incident_id, uploader_ip=ip, user_agent=ua
    )


@router.post(
    "/{incident_id}/attachments/multipart/init",
    response_model=MultipartUploadInitResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Initiate multipart evidence upload session",
    description="Authorize and initiate a resumable multipart evidence upload session with pre-signed chunk URLs.",
)
async def initiate_multipart_upload(
    incident_id: UUID,
    payload: MultipartUploadInitRequest,
    evidence_service: EvidenceServiceDep,
    principal: CurrentUserDep,
    request: Request,
) -> MultipartUploadInitResponse:
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    return await evidence_service.initiate_multipart_upload(
        incident_id, payload, principal, uploader_ip=ip, user_agent=ua
    )


@router.post(
    "/{incident_id}/attachments/multipart/{session_id}/complete",
    response_model=EvidenceAttachmentRead,
    status_code=status.HTTP_200_OK,
    summary="Complete multipart evidence upload",
    description="Verify all uploaded chunks, assemble final object in storage, enforce malware scan, and attach evidence.",
)
@router.post(
    "/attachments/multipart/{session_id}/complete",
    response_model=EvidenceAttachmentRead,
    status_code=status.HTTP_200_OK,
    summary="Complete multipart evidence upload",
    description="Verify all uploaded chunks, assemble final object in storage, enforce malware scan, and attach evidence.",
)
async def complete_multipart_upload(
    session_id: UUID,
    payload: MultipartUploadCompleteRequest,
    evidence_service: EvidenceServiceDep,
    principal: CurrentUserDep,
    request: Request,
    incident_id: UUID | None = None,
) -> EvidenceAttachmentRead:
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    return await evidence_service.complete_multipart_upload(
        session_id, payload, principal, incident_id=incident_id, uploader_ip=ip, user_agent=ua
    )


@router.post(
    "/{incident_id}/attachments/multipart/{session_id}/abort",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Abort multipart evidence upload session",
    description="Cancel a multipart upload session and clean up all allocated chunk storage.",
)
@router.post(
    "/attachments/multipart/{session_id}/abort",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Abort multipart evidence upload session",
    description="Cancel a multipart upload session and clean up all allocated chunk storage.",
)
async def abort_multipart_upload(
    session_id: UUID,
    evidence_service: EvidenceServiceDep,
    principal: CurrentUserDep,
    incident_id: UUID | None = None,
) -> None:
    await evidence_service.abort_multipart_upload(session_id, principal, incident_id=incident_id)


@router.post(
    "/{incident_id}/attachments/{attachment_id}/scan-retry",
    response_model=EvidenceAttachmentRead,
    status_code=status.HTTP_200_OK,
    summary="Retry malware scan on attachment",
    description="Re-run malware scan on an attachment previously failed or quarantined.",
)
async def retry_attachment_scan(
    incident_id: UUID,
    attachment_id: UUID,
    evidence_service: EvidenceServiceDep,
    principal: CurrentUserDep,
) -> EvidenceAttachmentRead:
    return await evidence_service.retry_scan(attachment_id, principal, incident_id=incident_id)


@router.get(
    "/{incident_id}/attachments/{attachment_id}/download",
    response_model=EvidenceDownloadResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate authorized download URL",
    description="Verify custody and scan cleanliness, then generate a short-lived pre-signed download URL.",
)
async def get_attachment_download_url(
    incident_id: UUID,
    attachment_id: UUID,
    evidence_service: EvidenceServiceDep,
    principal: CurrentUserDep,
    expires_in_seconds: Annotated[int, Query(ge=60, le=3600)] = 300,
) -> EvidenceDownloadResponse:
    return await evidence_service.generate_download_url(
        attachment_id, principal, incident_id=incident_id, expires_in_seconds=expires_in_seconds
    )


@router.post(
    "/{incident_id}/route",
    response_model=IncidentRead,
    status_code=status.HTTP_200_OK,
    summary="Re-route incident department",
    description="Authorized administrative department re-routing with mandatory justification (Dept Admin / Super Admin only).",
)
async def override_incident_routing(
    incident_id: UUID,
    payload: IncidentRouteOverrideRequest,
    incident_service: IncidentServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.INCIDENT_UPDATE_DEPT,
                Permission.INCIDENT_UPDATE_GLOBAL,
            )
        ),
    ],
) -> IncidentRead:
    return await incident_service.override_incident_routing(
        incident_id, payload.target_department_id, payload.reason, principal
    )


@router.get(
    "/{incident_id}/routing-history",
    response_model=list[IncidentRoutingDecisionRead],
    summary="Get incident routing history",
    description="Retrieve traceable chronological department routing decisions for an incident.",
)
async def get_incident_routing_history(
    incident_id: UUID,
    incident_service: IncidentServiceDep,
    principal: CurrentUserDep,
) -> list[IncidentRoutingDecisionRead]:
    return await incident_service.get_incident_routing_history(incident_id, principal)


@router.post(
    "/{incident_id}/attachments/{attachment_id}/verify-integrity",
    response_model=EvidenceIntegrityReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify evidence integrity",
    description="Cryptographically verify live stored payload against trusted ingestion SHA-256 digest.",
)
@router.post(
    "/attachments/{attachment_id}/verify-integrity",
    response_model=EvidenceIntegrityReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify evidence integrity",
    description="Cryptographically verify live stored payload against trusted ingestion SHA-256 digest.",
)
async def verify_evidence_integrity(
    attachment_id: UUID,
    evidence_service: EvidenceServiceDep,
    principal: CurrentUserDep,
    incident_id: UUID | None = None,
) -> EvidenceIntegrityReportResponse:
    return await evidence_service.verify_evidence_integrity(
        attachment_id, principal, incident_id=incident_id
    )


@router.get(
    "/{incident_id}/attachments/{attachment_id}/custody",
    response_model=list[EvidenceCustodyEventRead],
    summary="Get chain of custody ledger",
    description="Retrieve immutable, cryptographically chained custody event ledger for this evidence.",
)
@router.get(
    "/attachments/{attachment_id}/custody",
    response_model=list[EvidenceCustodyEventRead],
    summary="Get chain of custody ledger",
    description="Retrieve immutable, cryptographically chained custody event ledger for this evidence.",
)
async def get_evidence_custody_ledger(
    attachment_id: UUID,
    evidence_service: EvidenceServiceDep,
    principal: CurrentUserDep,
    incident_id: UUID | None = None,
) -> list[EvidenceCustodyEventRead]:
    return await evidence_service.get_custody_ledger(
        attachment_id, principal, incident_id=incident_id
    )


@router.post(
    "/{incident_id}/attachments/{attachment_id}/custody/compensate",
    response_model=EvidenceCustodyEventRead,
    status_code=status.HTTP_201_CREATED,
    summary="Record compensating custody event",
    description="Append an authorized compensating correction linked to a prior custody event.",
)
@router.post(
    "/attachments/{attachment_id}/custody/compensate",
    response_model=EvidenceCustodyEventRead,
    status_code=status.HTTP_201_CREATED,
    summary="Record compensating custody event",
    description="Append an authorized compensating correction linked to a prior custody event.",
)
async def create_compensating_custody_event(
    attachment_id: UUID,
    payload: CompensatingEventCreateRequest,
    evidence_service: EvidenceServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.INCIDENT_UPDATE_DEPT,
                Permission.INCIDENT_UPDATE_GLOBAL,
            )
        ),
    ],
    incident_id: UUID | None = None,
) -> EvidenceCustodyEventRead:
    return await evidence_service.create_compensating_custody_event(
        attachment_id, payload, principal, incident_id=incident_id
    )


@router.get(
    "/{incident_id}/attachments/{attachment_id}/provenance",
    response_model=EvidenceProvenanceRead,
    summary="Get evidence provenance",
    description="Inspect structured provenance separating server-observed facts from user declarations.",
)
@router.get(
    "/attachments/{attachment_id}/provenance",
    response_model=EvidenceProvenanceRead,
    summary="Get evidence provenance",
    description="Inspect structured provenance separating server-observed facts from user declarations.",
)
async def get_evidence_provenance(
    attachment_id: UUID,
    evidence_service: EvidenceServiceDep,
    principal: CurrentUserDep,
    incident_id: UUID | None = None,
) -> EvidenceProvenanceRead:
    return await evidence_service.get_evidence_provenance(
        attachment_id, principal, incident_id=incident_id
    )
