"""AI Violence Detection & Dataset Governance API routes (Phases 61-65).

Enforces:
- Strict role and permission checks on dataset registration and reviews.
- Tenant and department isolation on analysis job submission and status lookups.
- Standardized RESTful contracts and error representations.
- Zero direct database or model imports at the API boundary.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, Query, status

from backend.app.api.dependencies import (
    AIAnalysisJobServiceDep,
    AIDatasetServiceDep,
    AIRetentionServiceDep,
    AISegmentServiceDep,
    CurrentUserDep,
    require_permission,
)
from backend.app.core.authorization import Permission
from backend.app.core.logging import get_logger
from backend.app.schemas.ai import (
    AICandidateSegmentRead,
    AIDatasetRead,
    AIJobStatusRead,
    AIJobSubmitRequest,
    AIRetentionPurgeRequest,
    AIRetentionPurgeResponse,
    DatasetRegisterRequest,
    DatasetReviewRequest,
    SegmentReviewRequest,
)
from backend.app.schemas.pagination import PaginatedResponse, PaginationMetadata

logger = get_logger("api.ai")

router = APIRouter(prefix="/ai", tags=["AI Violence Detection"])


# ---------------------------------------------------------------------------
# Dataset Governance Endpoints (Phase 62)
# ---------------------------------------------------------------------------


@router.post(
    "/datasets",
    response_model=AIDatasetRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new AI benchmark or training dataset",
    dependencies=[Depends(require_permission(Permission.AI_DATASET_READ))],
)
async def register_dataset(
    payload: DatasetRegisterRequest,
    principal: CurrentUserDep,
    dataset_service: AIDatasetServiceDep,
) -> AIDatasetRead:
    """Register an AI dataset with verified licensing and provenance metadata."""
    return await dataset_service.register_dataset(payload, principal)


@router.get(
    "/datasets",
    response_model=PaginatedResponse[AIDatasetRead],
    summary="List registered AI datasets",
    dependencies=[Depends(require_permission(Permission.AI_DATASET_READ))],
)
async def list_datasets(
    principal: CurrentUserDep,
    dataset_service: AIDatasetServiceDep,
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> PaginatedResponse[AIDatasetRead]:
    """Retrieve datasets with optional status filtering."""
    items, total = await dataset_service.list_datasets(
        principal, status=status_filter, limit=limit, offset=offset
    )
    page = (offset // limit) + 1 if limit > 0 else 1

    return PaginatedResponse(
        items=list(items),
        pagination=PaginationMetadata.from_counts(
            page=page,
            page_size=limit,
            total_items=total,
        ),
    )


@router.get(
    "/datasets/{dataset_id}",
    response_model=AIDatasetRead,
    summary="Get AI dataset details",
    dependencies=[Depends(require_permission(Permission.AI_DATASET_READ))],
)
async def get_dataset(
    dataset_id: UUID,
    principal: CurrentUserDep,
    dataset_service: AIDatasetServiceDep,
) -> AIDatasetRead:
    """Retrieve metadata and manifest digest for a specific dataset."""
    return await dataset_service.get_dataset(dataset_id, principal)


@router.post(
    "/datasets/{dataset_id}/review",
    response_model=AIDatasetRead,
    summary="Review and approve/reject a dataset",
    dependencies=[Depends(require_permission(Permission.AI_DATASET_MANAGE))],
)
async def review_dataset(
    dataset_id: UUID,
    payload: DatasetReviewRequest,
    principal: CurrentUserDep,
    dataset_service: AIDatasetServiceDep,
) -> AIDatasetRead:
    """Perform authorized governance review (approval, rejection, withdrawal)."""
    return await dataset_service.review_dataset(dataset_id, payload, principal)


# ---------------------------------------------------------------------------
# Asynchronous Video Analysis Jobs Endpoints (Phase 65)
# ---------------------------------------------------------------------------


@router.post(
    "/jobs",
    response_model=AIJobStatusRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit an asynchronous video analysis job",
    dependencies=[Depends(require_permission(Permission.AI_JOB_SUBMIT))],
)
async def submit_analysis_job(
    payload: AIJobSubmitRequest,
    principal: CurrentUserDep,
    job_service: AIAnalysisJobServiceDep,
    background_tasks: BackgroundTasks,
) -> AIJobStatusRead:
    """Submit an evidence attachment for AI violence detection analysis."""
    job_read = await job_service.submit_analysis_job(payload, principal)

    # Dispatch pipeline execution in the background
    background_tasks.add_task(job_service.execute_job, job_read.id)

    return job_read


@router.get(
    "/jobs",
    response_model=PaginatedResponse[AIJobStatusRead],
    summary="List video analysis jobs",
    dependencies=[Depends(require_permission(Permission.AI_JOB_READ_OWN))],
)
async def list_jobs(
    principal: CurrentUserDep,
    job_service: AIAnalysisJobServiceDep,
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> PaginatedResponse[AIJobStatusRead]:
    """List jobs scoped to authorized department or global scope."""
    items, total = await job_service.list_jobs(
        principal, status=status_filter, limit=limit, offset=offset
    )
    page = (offset // limit) + 1 if limit > 0 else 1

    return PaginatedResponse(
        items=list(items),
        pagination=PaginationMetadata.from_counts(
            page=page,
            page_size=limit,
            total_items=total,
        ),
    )


@router.get(
    "/jobs/{job_id}",
    response_model=AIJobStatusRead,
    summary="Get video analysis job status and results",
    dependencies=[Depends(require_permission(Permission.AI_JOB_READ_OWN))],
)
async def get_job(
    job_id: UUID,
    principal: CurrentUserDep,
    job_service: AIAnalysisJobServiceDep,
) -> AIJobStatusRead:
    """Retrieve execution status, progress, and results for an analysis job."""
    return await job_service.get_job(job_id, principal)


@router.post(
    "/jobs/{job_id}/cancel",
    response_model=AIJobStatusRead,
    summary="Cancel an in-flight or queued analysis job",
    dependencies=[Depends(require_permission(Permission.AI_JOB_CANCEL_DEPT))],
)
async def cancel_job(
    job_id: UUID,
    principal: CurrentUserDep,
    job_service: AIAnalysisJobServiceDep,
) -> AIJobStatusRead:
    """Cancel an active or pending analysis job."""
    return await job_service.cancel_job(job_id, principal)


# ---------------------------------------------------------------------------
# Candidate Segment and Human Review Endpoints (Phases 66 & 69)
# ---------------------------------------------------------------------------


@router.get(
    "/jobs/{job_id}/segments",
    response_model=list[AICandidateSegmentRead],
    summary="List candidate violence segments for an analysis job",
    dependencies=[Depends(require_permission(Permission.AI_JOB_READ_OWN))],
)
async def list_job_segments(
    job_id: UUID,
    principal: CurrentUserDep,
    segment_service: AISegmentServiceDep,
) -> list[AICandidateSegmentRead]:
    """Retrieve all candidate segments produced by a specific analysis job."""
    return await segment_service.list_segments_for_job(job_id, principal)


@router.get(
    "/segments",
    response_model=PaginatedResponse[AICandidateSegmentRead],
    summary="List candidate violence segments across department review queue",
    dependencies=[Depends(require_permission(Permission.AI_SEGMENT_READ_DEPT))],
)
async def list_segments(
    principal: CurrentUserDep,
    segment_service: AISegmentServiceDep,
    status: str | None = Query(default=None),
    review_status: str | None = Query(default=None),
    is_flagged: bool | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> PaginatedResponse[AICandidateSegmentRead]:
    """Query candidate segments filtered by review status and flagging."""
    effective_status = review_status or status
    result = await segment_service.list_segments(
        principal,
        review_status=effective_status,
        is_flagged=is_flagged,
        limit=limit,
        offset=offset,
    )
    page = (offset // limit) + 1 if limit > 0 else 1

    return PaginatedResponse(
        items=result.items,
        pagination=PaginationMetadata.from_counts(
            page=page,
            page_size=limit,
            total_items=result.total,
        ),
    )


@router.get(
    "/segments/{segment_id}",
    response_model=AICandidateSegmentRead,
    summary="Get candidate segment details",
    dependencies=[Depends(require_permission(Permission.AI_SEGMENT_READ_DEPT))],
)
async def get_segment(
    segment_id: UUID,
    principal: CurrentUserDep,
    segment_service: AISegmentServiceDep,
) -> AICandidateSegmentRead:
    """Retrieve full metadata, scores, and provenance for a candidate segment."""
    return await segment_service.get_segment(segment_id, principal)


@router.post(
    "/segments/{segment_id}/review",
    response_model=AICandidateSegmentRead,
    summary="Submit authorized human review decision for a candidate segment",
    dependencies=[Depends(require_permission(Permission.AI_SEGMENT_REVIEW_DEPT))],
)
async def review_segment(
    segment_id: UUID,
    payload: SegmentReviewRequest,
    principal: CurrentUserDep,
    segment_service: AISegmentServiceDep,
) -> AICandidateSegmentRead:
    """Submit human reviewer decision (confirmed, rejected, inconclusive, escalated) with rationale."""
    return await segment_service.review_segment(segment_id, payload, principal)


# ---------------------------------------------------------------------------
# AI Result Retention Policy Endpoints (Phase 69.4)
# ---------------------------------------------------------------------------


@router.post(
    "/retention/purge",
    response_model=AIRetentionPurgeResponse,
    summary="Purge expired AI candidate segments respecting legal holds",
    dependencies=[Depends(require_permission(Permission.AI_RESULT_RETENTION_MANAGE))],
)
async def purge_expired_segments(
    payload: AIRetentionPurgeRequest,
    principal: CurrentUserDep,
    retention_service: AIRetentionServiceDep,
) -> AIRetentionPurgeResponse:
    """Execute retention purge of expired AI segments, strictly exempting active incidents."""
    return await retention_service.purge_expired_candidate_segments(
        retention_days=payload.retention_days,
        department_id=payload.department_id,
        principal=principal,
    )
