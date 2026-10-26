"""Investigation case management, linkages, assignments, evidence, and AI review endpoints (Phases 81-85).

Provides RESTful operations for:
- Creating and retrieving investigation cases.
- Updating case metadata, lifecycle status transitions, and legal hold.
- Assigning/reassigning lead investigators with active case capacity controls.
- Querying investigator workload capacity.
- Linking/unlinking incidents, evidence inventory, and AI candidate segments.
- Performing authorized human review on AI candidate segments with reviewer conflict-of-interest checks.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status

from backend.app.api.dependencies import (
    CaseServiceDep,
    ClientIpDep,
    CurrentUserDep,
    require_any_permission,
)
from backend.app.core.authorization import Permission
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.case import (
    CaseAISegmentRead,
    CaseAISegmentReviewRequest,
    CaseApprovalRead,
    CaseApprovalRequest,
    CaseAssignmentRead,
    CaseAssignRequest,
    CaseCloseRequest,
    CaseCreate,
    CaseEscalationRead,
    CaseEscalationRequest,
    CaseEvidenceItemRead,
    CaseExportRead,
    CaseExportRequest,
    CaseFindingCreate,
    CaseFindingHistoryRead,
    CaseFindingRead,
    CaseFindingUpdate,
    CaseIncidentRead,
    CaseLinkAISegmentRequest,
    CaseLinkEvidenceRequest,
    CaseLinkIncidentRequest,
    CaseNoteCreate,
    CaseNoteHistoryRead,
    CaseNoteRead,
    CaseNoteUpdate,
    CaseRead,
    CaseReferralCreate,
    CaseReferralRead,
    CaseReferralUpdate,
    CaseReopenRequest,
    CaseTransitionRequest,
    CaseUpdate,
    InvestigatorWorkloadRead,
    PaginatedCasesRead,
)

router = APIRouter(prefix="/cases", tags=["Investigation Cases"])
v1_cases_router = router


# =============================================================================
# Phase 81: Case CRUD & Retrieval
# =============================================================================


@router.post(
    "",
    response_model=CaseRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create an investigation case",
    description="Initiate a new investigation case record bound to a department and creator.",
)
async def create_case(
    payload: CaseCreate,
    request: Request,
    case_service: CaseServiceDep,
    client_ip: ClientIpDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.CASE_CREATE_GLOBAL,
                Permission.CASE_CREATE_DEPT,
            )
        ),
    ],
) -> CaseRead:
    actor_user_agent = request.headers.get("user-agent")
    return await case_service.create_case(
        payload,
        principal,
        actor_ip=client_ip,
        actor_user_agent=actor_user_agent,
    )


@router.get(
    "",
    response_model=PaginatedCasesRead,
    summary="List investigation cases",
    description="Retrieve paginated cases scoped to caller's department or assignments.",
)
async def list_cases(
    case_service: CaseServiceDep,
    principal: CurrentUserDep,
    limit: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
    offset: Annotated[int, Query(ge=0, description="Items offset")] = 0,
    case_status: Annotated[
        str | None, Query(alias="status", description="Filter by status")
    ] = None,
    priority: Annotated[str | None, Query(description="Filter by priority")] = None,
    is_legal_hold: Annotated[bool | None, Query(description="Filter by legal hold")] = None,
    search: Annotated[str | None, Query(description="Search title, summary, or reference")] = None,
    sort_by: Annotated[str, Query(description="Field to sort by")] = "created_at",
    sort_order: Annotated[str, Query(description="Sort direction (asc/desc)")] = "desc",
) -> PaginatedCasesRead:
    return await case_service.list_cases(
        principal,
        limit=limit,
        offset=offset,
        status=case_status,
        priority=priority,
        is_legal_hold=is_legal_hold,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@router.get(
    "/{case_id}",
    response_model=CaseRead,
    summary="Get case by ID",
    description="Retrieve a case by UUID with relational linkages.",
)
async def get_case(
    case_id: UUID,
    case_service: CaseServiceDep,
    principal: CurrentUserDep,
) -> CaseRead:
    return await case_service.get_case(case_id, principal)


@router.get(
    "/ref/{reference_number}",
    response_model=CaseRead,
    summary="Get case by reference number",
    description="Retrieve a case by formatted reference number.",
)
@router.get(
    "/reference/{reference_number}",
    response_model=CaseRead,
    include_in_schema=False,
)
async def get_case_by_reference(
    reference_number: str,
    case_service: CaseServiceDep,
    principal: CurrentUserDep,
) -> CaseRead:
    return await case_service.get_case_by_reference(reference_number, principal)


@router.patch(
    "/{case_id}",
    response_model=CaseRead,
    summary="Update case or lifecycle status",
    description="Update case details, status transitions, or legal hold with optimistic locking.",
)
async def update_case(
    case_id: UUID,
    payload: CaseUpdate,
    request: Request,
    case_service: CaseServiceDep,
    client_ip: ClientIpDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.CASE_UPDATE_GLOBAL,
                Permission.CASE_UPDATE_DEPT,
            )
        ),
    ],
) -> CaseRead:
    actor_user_agent = request.headers.get("user-agent")
    return await case_service.update_case(
        case_id,
        payload,
        principal,
        actor_ip=client_ip,
        actor_user_agent=actor_user_agent,
    )


# =============================================================================
# Phase 82: Assignment & Workload Capacity
# =============================================================================


@router.post(
    "/{case_id}/assignments",
    response_model=CaseRead,
    summary="Assign lead investigator",
    description="Assign or transfer case lead investigator under active workload capacity limits.",
)
async def assign_case(
    case_id: UUID,
    payload: CaseAssignRequest,
    request: Request,
    case_service: CaseServiceDep,
    client_ip: ClientIpDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.CASE_ASSIGN_GLOBAL,
                Permission.CASE_ASSIGN_DEPT,
            )
        ),
    ],
) -> CaseRead:
    actor_user_agent = request.headers.get("user-agent")
    return await case_service.assign_case(
        case_id,
        payload,
        principal,
        actor_ip=client_ip,
        actor_user_agent=actor_user_agent,
    )


@router.get(
    "/{case_id}/assignments",
    response_model=list[CaseAssignmentRead],
    summary="List assignment history",
    description="Retrieve chronological append-only assignment events for a case.",
)
async def list_assignments(
    case_id: UUID,
    case_service: CaseServiceDep,
    principal: CurrentUserDep,
) -> list[CaseAssignmentRead]:
    return await case_service.list_assignments(case_id, principal)


@router.get(
    "/investigators/{investigator_id}/workload",
    response_model=InvestigatorWorkloadRead,
    summary="Inspect investigator workload",
    description="Retrieve active case count and remaining capacity for an investigator.",
)
async def get_investigator_workload(
    investigator_id: UUID,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.CASE_WORKLOAD_READ_GLOBAL,
                Permission.CASE_WORKLOAD_READ_DEPT,
            )
        ),
    ],
) -> InvestigatorWorkloadRead:
    return await case_service.get_investigator_workload(investigator_id, principal)


# =============================================================================
# Phase 81: Case Incident Linkages
# =============================================================================


@router.post(
    "/{case_id}/incidents",
    response_model=CaseIncidentRead,
    status_code=status.HTTP_201_CREATED,
    summary="Link incident to case",
    description="Establish a relational link between an incident and an investigation case.",
)
async def link_incident(
    case_id: UUID,
    payload: CaseLinkIncidentRequest,
    request: Request,
    case_service: CaseServiceDep,
    client_ip: ClientIpDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.CASE_UPDATE_GLOBAL,
                Permission.CASE_UPDATE_DEPT,
            )
        ),
    ],
) -> CaseIncidentRead:
    actor_user_agent = request.headers.get("user-agent")
    return await case_service.link_incident(
        case_id,
        payload,
        principal,
        actor_ip=client_ip,
        actor_user_agent=actor_user_agent,
    )


@router.get(
    "/{case_id}/incidents",
    response_model=list[CaseIncidentRead],
    summary="List linked incidents",
    description="List all incidents connected to the investigation case.",
)
async def list_case_incidents(
    case_id: UUID,
    case_service: CaseServiceDep,
    principal: CurrentUserDep,
) -> list[CaseIncidentRead]:
    return await case_service.list_case_incidents(case_id, principal)


@router.delete(
    "/{case_id}/incidents/{incident_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Unlink incident from case",
    description="Remove the link between an incident and a case.",
)
async def unlink_incident(
    case_id: UUID,
    incident_id: UUID,
    request: Request,
    case_service: CaseServiceDep,
    client_ip: ClientIpDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.CASE_UPDATE_GLOBAL,
                Permission.CASE_UPDATE_DEPT,
            )
        ),
    ],
) -> None:
    actor_user_agent = request.headers.get("user-agent")
    await case_service.unlink_incident(
        case_id,
        incident_id,
        principal,
        actor_ip=client_ip,
        actor_user_agent=actor_user_agent,
    )


# =============================================================================
# Phase 83: Case Evidence Inventory & Integrity
# =============================================================================


@router.post(
    "/{case_id}/evidence",
    response_model=CaseEvidenceItemRead,
    status_code=status.HTTP_201_CREATED,
    summary="Link evidence attachment to case",
    description="Link evidence to a case and enrich with integrity verification metadata.",
)
async def link_evidence(
    case_id: UUID,
    payload: CaseLinkEvidenceRequest,
    request: Request,
    case_service: CaseServiceDep,
    client_ip: ClientIpDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_any_permission(Permission.CASE_EVIDENCE_MANAGE)),
    ],
) -> CaseEvidenceItemRead:
    actor_user_agent = request.headers.get("user-agent")
    return await case_service.link_evidence(
        case_id,
        payload,
        principal,
        actor_ip=client_ip,
        actor_user_agent=actor_user_agent,
    )


@router.get(
    "/{case_id}/evidence",
    response_model=list[CaseEvidenceItemRead],
    summary="List case evidence inventory",
    description="List enriched evidence inventory without leaking storage credentials.",
)
async def list_case_evidence(
    case_id: UUID,
    case_service: CaseServiceDep,
    principal: CurrentUserDep,
) -> list[CaseEvidenceItemRead]:
    return await case_service.list_case_evidence(case_id, principal)


@router.delete(
    "/{case_id}/evidence/{evidence_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Unlink evidence from case",
    description="Remove evidence association from a case (prohibited under legal hold).",
)
async def unlink_evidence(
    case_id: UUID,
    evidence_id: UUID,
    request: Request,
    case_service: CaseServiceDep,
    client_ip: ClientIpDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_any_permission(Permission.CASE_EVIDENCE_MANAGE)),
    ],
) -> None:
    actor_user_agent = request.headers.get("user-agent")
    await case_service.unlink_evidence(
        case_id,
        evidence_id,
        principal,
        actor_ip=client_ip,
        actor_user_agent=actor_user_agent,
    )


# =============================================================================
# Phase 84: AI Candidate Segments Integration
# =============================================================================


@router.post(
    "/{case_id}/ai-segments",
    response_model=CaseAISegmentRead,
    status_code=status.HTTP_201_CREATED,
    summary="Link AI candidate segment to case",
    description="Associate an AI candidate segment to a case as an advisory lead.",
)
async def link_ai_segment(
    case_id: UUID,
    payload: CaseLinkAISegmentRequest,
    request: Request,
    case_service: CaseServiceDep,
    client_ip: ClientIpDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_any_permission(Permission.CASE_AI_SEGMENT_MANAGE)),
    ],
) -> CaseAISegmentRead:
    actor_user_agent = request.headers.get("user-agent")
    return await case_service.link_ai_segment(
        case_id,
        payload,
        principal,
        actor_ip=client_ip,
        actor_user_agent=actor_user_agent,
    )


@router.get(
    "/{case_id}/ai-segments",
    response_model=list[CaseAISegmentRead],
    summary="List linked AI candidate segments",
    description="List all AI segments with non-authoritative advisory disclaimers.",
)
async def list_case_ai_segments(
    case_id: UUID,
    case_service: CaseServiceDep,
    principal: CurrentUserDep,
) -> list[CaseAISegmentRead]:
    return await case_service.list_case_ai_segments(case_id, principal)


@router.delete(
    "/{case_id}/ai-segments/{segment_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Unlink AI candidate segment",
    description="Remove AI candidate segment linkage from a case.",
)
async def unlink_ai_segment(
    case_id: UUID,
    segment_id: UUID,
    request: Request,
    case_service: CaseServiceDep,
    client_ip: ClientIpDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_any_permission(Permission.CASE_AI_SEGMENT_MANAGE)),
    ],
) -> None:
    actor_user_agent = request.headers.get("user-agent")
    await case_service.unlink_ai_segment(
        case_id,
        segment_id,
        principal,
        actor_ip=client_ip,
        actor_user_agent=actor_user_agent,
    )


# =============================================================================
# Phase 85: Human Review & AI Classification Correction
# =============================================================================


@router.post(
    "/{case_id}/ai-segments/{segment_id}/review",
    response_model=CaseAISegmentRead,
    summary="Review AI candidate segment",
    description="Record authorized human review and correction on an AI candidate segment.",
)
async def review_ai_segment(
    case_id: UUID,
    segment_id: UUID,
    payload: CaseAISegmentReviewRequest,
    request: Request,
    case_service: CaseServiceDep,
    client_ip: ClientIpDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_any_permission(Permission.CASE_AI_SEGMENT_REVIEW)),
    ],
) -> CaseAISegmentRead:
    actor_user_agent = request.headers.get("user-agent")
    return await case_service.review_ai_segment(
        case_id,
        segment_id,
        payload,
        principal,
        actor_ip=client_ip,
        actor_user_agent=actor_user_agent,
    )


# =============================================================================
# Phase 86: Case Notes & Findings Endpoints
# =============================================================================


@router.post(
    "/{case_id}/notes",
    response_model=CaseNoteRead,
    status_code=status.HTTP_201_CREATED,
    summary="Add a case note",
    description="Author an investigation note with visibility restrictions and optional evidence references.",
)
async def create_case_note(
    case_id: UUID,
    payload: CaseNoteCreate,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_any_permission(Permission.CASE_NOTE_CREATE)),
    ],
) -> CaseNoteRead:
    return await case_service.create_case_note(case_id, principal, payload)


@router.get(
    "/{case_id}/notes",
    response_model=list[CaseNoteRead],
    summary="List case notes",
    description="Retrieve authorized investigation notes, redacting restricted notes if caller lacks permissions.",
)
async def list_case_notes(
    case_id: UUID,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_any_permission(Permission.CASE_NOTE_READ)),
    ],
) -> list[CaseNoteRead]:
    return await case_service.list_case_notes(case_id, principal)


@router.patch(
    "/{case_id}/notes/{note_id}",
    response_model=CaseNoteRead,
    summary="Update a case note",
    description="Update an existing case note with optimistic locking and historical version logging.",
)
async def update_case_note(
    case_id: UUID,
    note_id: UUID,
    payload: CaseNoteUpdate,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_any_permission(Permission.CASE_NOTE_CREATE)),
    ],
) -> CaseNoteRead:
    return await case_service.update_case_note(case_id, note_id, principal, payload)


@router.get(
    "/{case_id}/notes/{note_id}/history",
    response_model=list[CaseNoteHistoryRead],
    summary="Get note version history",
    description="View audit log of historical edits made to a case note.",
)
async def get_case_note_history(
    case_id: UUID,
    note_id: UUID,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_any_permission(Permission.CASE_NOTE_READ)),
    ],
) -> list[CaseNoteHistoryRead]:
    return await case_service.get_case_note_history(case_id, note_id, principal)


@router.post(
    "/{case_id}/findings",
    response_model=CaseFindingRead,
    status_code=status.HTTP_201_CREATED,
    summary="Record a formal finding",
    description="Create a structured investigation finding with evidence, AI segment, and incident linkages.",
)
async def create_case_finding(
    case_id: UUID,
    payload: CaseFindingCreate,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_any_permission(Permission.CASE_FINDING_MANAGE)),
    ],
) -> CaseFindingRead:
    return await case_service.create_case_finding(case_id, principal, payload)


@router.get(
    "/{case_id}/findings",
    response_model=list[CaseFindingRead],
    summary="List case findings",
    description="List all structured investigation findings recorded for a case.",
)
async def list_case_findings(
    case_id: UUID,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.CASE_READ_OWN, Permission.CASE_READ_DEPT, Permission.CASE_READ_GLOBAL
            )
        ),
    ],
) -> list[CaseFindingRead]:
    return await case_service.list_case_findings(case_id, principal)


@router.patch(
    "/{case_id}/findings/{finding_id}",
    response_model=CaseFindingRead,
    summary="Update an investigation finding",
    description="Edit an investigation finding with optimistic locking and version history preservation.",
)
async def update_case_finding(
    case_id: UUID,
    finding_id: UUID,
    payload: CaseFindingUpdate,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_any_permission(Permission.CASE_FINDING_MANAGE)),
    ],
) -> CaseFindingRead:
    return await case_service.update_case_finding(case_id, finding_id, principal, payload)


@router.get(
    "/{case_id}/findings/{finding_id}/history",
    response_model=list[CaseFindingHistoryRead],
    summary="Get finding version history",
    description="View audit log of historical modifications made to an investigation finding.",
)
async def get_case_finding_history(
    case_id: UUID,
    finding_id: UUID,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.CASE_READ_OWN, Permission.CASE_READ_DEPT, Permission.CASE_READ_GLOBAL
            )
        ),
    ],
) -> list[CaseFindingHistoryRead]:
    return await case_service.get_case_finding_history(case_id, finding_id, principal)


# =============================================================================
# Phase 87: Case Lifecycle Transitions & Approvals
# =============================================================================


@router.post(
    "/{case_id}/transitions",
    response_model=CaseRead,
    summary="Request a case status transition",
    description="Transition case status through the centralized lifecycle state machine with prerequisite validation.",
)
@router.post(
    "/{case_id}/transition",
    response_model=CaseRead,
    include_in_schema=False,
)
async def transition_case_status(
    case_id: UUID,
    payload: CaseTransitionRequest,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_any_permission(Permission.CASE_UPDATE_DEPT, Permission.CASE_UPDATE_GLOBAL)),
    ],
) -> CaseRead:
    return await case_service.transition_case_status(case_id, principal, payload)


@router.post(
    "/{case_id}/approvals",
    response_model=CaseApprovalRead,
    status_code=status.HTTP_201_CREATED,
    summary="Approve or reject a case transition",
    description="Record formal supervisory approval or rejection on a pending case transition.",
)
async def approve_case_transition(
    case_id: UUID,
    payload: CaseApprovalRequest,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_any_permission(Permission.CASE_TRANSITION_APPROVE)),
    ],
) -> CaseApprovalRead:
    return await case_service.approve_case_transition(case_id, principal, payload)


@router.get(
    "/{case_id}/approvals",
    response_model=list[CaseApprovalRead],
    summary="List case approval history",
    description="View formal supervisory approval decisions for a case.",
)
async def list_case_approvals(
    case_id: UUID,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.CASE_READ_OWN, Permission.CASE_READ_DEPT, Permission.CASE_READ_GLOBAL
            )
        ),
    ],
) -> list[CaseApprovalRead]:
    return await case_service.list_case_approvals(case_id, principal)


# =============================================================================
# Phase 88: Escalation, Referrals, Closure, and Reopening
# =============================================================================


@router.post(
    "/{case_id}/escalate",
    response_model=CaseEscalationRead,
    status_code=status.HTTP_201_CREATED,
    summary="Escalate an investigation case",
    description="Escalate a case to institutional leadership or oversight authority.",
)
@router.post(
    "/{case_id}/escalations",
    response_model=CaseEscalationRead,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
)
async def escalate_case(
    case_id: UUID,
    payload: CaseEscalationRequest,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_any_permission(Permission.CASE_ESCALATE)),
    ],
) -> CaseEscalationRead:
    return await case_service.escalate_case(case_id, principal, payload)


@router.get(
    "/{case_id}/escalations",
    response_model=list[CaseEscalationRead],
    summary="List case escalations",
    description="List all recorded escalations for a case.",
)
async def list_case_escalations(
    case_id: UUID,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.CASE_READ_OWN, Permission.CASE_READ_DEPT, Permission.CASE_READ_GLOBAL
            )
        ),
    ],
) -> list[CaseEscalationRead]:
    return await case_service.list_case_escalations(case_id, principal)


@router.post(
    "/{case_id}/referrals",
    response_model=CaseReferralRead,
    status_code=status.HTTP_201_CREATED,
    summary="Refer an investigation case",
    description="Refer a case to an internal partner department or external agency.",
)
async def refer_case(
    case_id: UUID,
    payload: CaseReferralCreate,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_any_permission(Permission.CASE_REFER)),
    ],
) -> CaseReferralRead:
    return await case_service.refer_case(case_id, principal, payload)


@router.patch(
    "/{case_id}/referrals/{referral_id}",
    response_model=CaseReferralRead,
    summary="Update referral outcome",
    description="Update referral resolution status and outcome notes.",
)
async def update_referral_status(
    case_id: UUID,
    referral_id: UUID,
    payload: CaseReferralUpdate,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_any_permission(Permission.CASE_REFER)),
    ],
) -> CaseReferralRead:
    return await case_service.update_referral_status(case_id, referral_id, principal, payload)


@router.get(
    "/{case_id}/referrals",
    response_model=list[CaseReferralRead],
    summary="List case referrals",
    description="List all referrals recorded for an investigation case.",
)
async def list_case_referrals(
    case_id: UUID,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.CASE_READ_OWN, Permission.CASE_READ_DEPT, Permission.CASE_READ_GLOBAL
            )
        ),
    ],
) -> list[CaseReferralRead]:
    return await case_service.list_case_referrals(case_id, principal)


@router.post(
    "/{case_id}/close",
    response_model=CaseRead,
    summary="Formally close a case",
    description="Formally close an investigation case with documented closure rationale.",
)
async def close_case(
    case_id: UUID,
    payload: CaseCloseRequest,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_any_permission(Permission.CASE_CLOSE)),
    ],
) -> CaseRead:
    return await case_service.close_case(case_id, principal, payload)


@router.post(
    "/{case_id}/reopen",
    response_model=CaseRead,
    summary="Reopen a closed or resolved case",
    description="Reopen a previously closed or resolved case back to under_investigation.",
)
async def reopen_case(
    case_id: UUID,
    payload: CaseReopenRequest,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_any_permission(Permission.CASE_REOPEN)),
    ],
) -> CaseRead:
    return await case_service.reopen_case(case_id, principal, payload)


# =============================================================================
# Phase 89: Case Exports & Manifests Endpoints
# =============================================================================


@router.post(
    "/{case_id}/export",
    response_model=CaseExportRead,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a case export package",
    description="Generate a cryptographically hashed, controlled disclosure export package with an evidence manifest.",
)
@router.post(
    "/{case_id}/exports",
    response_model=CaseExportRead,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
)
async def export_case(
    case_id: UUID,
    payload: CaseExportRequest,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_any_permission(Permission.CASE_EXPORT)),
    ],
) -> CaseExportRead:
    return await case_service.export_case(case_id, principal, payload)


@router.get(
    "/exports/{export_id}",
    response_model=CaseExportRead,
    summary="Retrieve an export disclosure package",
    description="Retrieve a previously generated case export manifest and disclosure package.",
)
@router.get(
    "/{case_id}/exports/{export_id}",
    response_model=CaseExportRead,
    include_in_schema=False,
)
async def get_case_export(
    export_id: UUID,
    case_service: CaseServiceDep,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.CASE_READ_OWN, Permission.CASE_READ_DEPT, Permission.CASE_READ_GLOBAL
            )
        ),
    ],
    case_id: UUID | None = None,
) -> CaseExportRead:
    return await case_service.get_case_export(export_id, principal)
