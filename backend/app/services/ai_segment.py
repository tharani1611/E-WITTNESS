"""Service for AI candidate segment management, human review workflow, and traceability (Phases 66 & 69).

Enforces:
- Department-scoped and tenant-isolated access controls on candidate segments.
- Strict human-in-the-loop review workflow: AI findings remain unverified candidates until reviewed.
- Mandatory conflict-of-interest check: Reviewers cannot review candidate segments for incidents they reported.
- Categorized false-positive tracking with mandatory factual rationale.
- Append-only security audit event logging for all review transitions.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config.settings import Settings
from backend.app.core.ai import (
    CalibrationStatus,
    SegmentReviewStatus,
    UncertaintyStatus,
)
from backend.app.core.audit import AuditAction, AuditOutcome, AuditTargetType
from backend.app.core.authorization import Permission, has_any_permission, has_permission
from backend.app.core.exceptions import (
    BusinessRuleError,
    ConflictError,
    PermissionDeniedError,
    ResourceNotFoundError,
)
from backend.app.models.ai import AICandidateSegment
from backend.app.models.base import utc_now
from backend.app.repositories.ai_segment import AICandidateSegmentRepository
from backend.app.repositories.audit import AuditRepository
from backend.app.repositories.incident import IncidentRepository
from backend.app.schemas.ai import (
    AICandidateSegmentRead,
    PaginatedSegmentsRead,
    SegmentReviewRequest,
)
from backend.app.schemas.auth import AuthenticatedPrincipal


class AICandidateSegmentService:
    """Business service governing AI candidate segments and human review transitions."""

    def __init__(
        self,
        *,
        segment_repo: AICandidateSegmentRepository,
        incident_repo: IncidentRepository,
        audit_repo: AuditRepository | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.segment_repo = segment_repo
        self.incident_repo = incident_repo
        self.audit_repo = audit_repo
        self.settings = settings

    @classmethod
    def from_session(
        cls,
        session: AsyncSession,
        settings: Settings,
        *,
        audit_repo: AuditRepository | None = None,
    ) -> AICandidateSegmentService:
        """Construct an AICandidateSegmentService bound to the active session."""
        return cls(
            segment_repo=AICandidateSegmentRepository(session),
            incident_repo=IncidentRepository(session),
            audit_repo=audit_repo or AuditRepository(session),
            settings=settings,
        )

    def _to_read_dto(self, segment: AICandidateSegment) -> AICandidateSegmentRead:
        """Convert AICandidateSegment ORM entity to public read schema."""
        meta = segment.get_metadata_dict()
        now = utc_now()
        return AICandidateSegmentRead(
            id=segment.id,
            job_id=segment.job_id,
            evidence_id=segment.evidence_id,
            incident_id=segment.incident_id,
            department_id=segment.department_id,
            start_seconds=segment.start_seconds,
            end_seconds=segment.end_seconds,
            duration_seconds=segment.duration_seconds,
            raw_score=segment.raw_score,
            raw_label=segment.raw_label or "violence",
            model_name=segment.model_name,
            model_version=segment.model_version,
            preprocessing_version=segment.preprocessing_version or "1.0.0",
            calibration_status=segment.calibration_status or CalibrationStatus.UNCALIBRATED.value,
            calibrated_score=segment.calibrated_score,
            calibration_version=segment.calibration_version,
            uncertainty_status=segment.uncertainty_status or UncertaintyStatus.UNCALIBRATED.value,
            review_status=segment.review_status or SegmentReviewStatus.PENDING_REVIEW.value,
            reviewed_by_id=segment.reviewed_by_id,
            reviewed_at=segment.reviewed_at,
            review_notes=segment.review_notes,
            false_positive_reason=segment.false_positive_reason,
            is_flagged_for_review=bool(segment.is_flagged_for_review)
            if segment.is_flagged_for_review is not None
            else True,
            metadata=meta,
            created_at=segment.created_at or now,
            updated_at=segment.updated_at or now,
        )

    async def get_segment(
        self,
        segment_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> AICandidateSegmentRead:
        """Fetch candidate segment with strict department scoping."""
        is_global = has_permission(principal.role, Permission.AI_SEGMENT_READ_GLOBAL)
        scoped_dept = None if is_global else principal.department_id

        segment = await self.segment_repo.get_by_id(segment_id, department_id=scoped_dept)
        if segment is None:
            raise ResourceNotFoundError("Candidate segment not found.", code="SEGMENT_NOT_FOUND")

        return self._to_read_dto(segment)

    async def list_segments_for_job(
        self,
        job_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> list[AICandidateSegmentRead]:
        """List candidate segments for a job with department scoping."""
        is_global = has_permission(principal.role, Permission.AI_SEGMENT_READ_GLOBAL)
        scoped_dept = None if is_global else principal.department_id

        segments = await self.segment_repo.list_for_job(job_id, department_id=scoped_dept)
        return [self._to_read_dto(s) for s in segments]

    async def list_segments(
        self,
        principal: AuthenticatedPrincipal,
        *,
        review_status: str | None = None,
        is_flagged: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> PaginatedSegmentsRead:
        """List candidate segments with pagination and department scoping."""
        is_global = has_permission(principal.role, Permission.AI_SEGMENT_READ_GLOBAL)
        scoped_dept = None if is_global else principal.department_id

        items, total = await self.segment_repo.list_segments(
            department_id=scoped_dept,
            review_status=review_status,
            is_flagged=is_flagged,
            limit=limit,
            offset=offset,
        )
        return PaginatedSegmentsRead(
            items=[self._to_read_dto(s) for s in items],
            total=total,
            limit=limit,
            offset=offset,
        )

    async def review_segment(
        self,
        segment_id: UUID,
        request: SegmentReviewRequest,
        principal: AuthenticatedPrincipal,
    ) -> AICandidateSegmentRead:
        """Submit authorized human review decision for an AI candidate segment (Phase 69)."""
        can_review = has_any_permission(
            principal.role,
            [Permission.AI_SEGMENT_REVIEW_DEPT, Permission.AI_SEGMENT_REVIEW_GLOBAL],
        )
        if not can_review:
            raise PermissionDeniedError(
                "Caller lacks permission to review AI candidate segments.",
                code="SEGMENT_REVIEW_DENIED",
            )

        is_global = has_permission(principal.role, Permission.AI_SEGMENT_REVIEW_GLOBAL)
        scoped_dept = None if is_global else principal.department_id

        segment = await self.segment_repo.get_by_id(segment_id, department_id=scoped_dept)
        if segment is None:
            raise ResourceNotFoundError("Candidate segment not found.", code="SEGMENT_NOT_FOUND")

        # Conflict of interest check: Reviewer cannot be the reporter of the parent incident
        if segment.incident and segment.incident.reporter_id == principal.user_id:
            raise ConflictError(
                "Reviewer conflict of interest: Users cannot review AI analysis results for incidents they reported.",
                code="REVIEWER_CONFLICT_OF_INTEREST",
            )

        if segment.review_status != SegmentReviewStatus.PENDING_REVIEW.value:
            raise BusinessRuleError(
                f"Candidate segment is already in '{segment.review_status}' review status and cannot be re-reviewed.",
                code="SEGMENT_ALREADY_REVIEWED",
            )

        # Apply review transition
        old_status = segment.review_status
        segment.review_status = request.decision
        segment.reviewed_by_id = principal.user_id
        segment.reviewed_at = utc_now()
        segment.review_notes = request.review_notes
        segment.false_positive_reason = request.false_positive_reason

        # If rejected, unflag from pending review
        if request.decision == "rejected":
            segment.is_flagged_for_review = False

        updated = await self.segment_repo.update(segment)

        if self.audit_repo:
            await self.audit_repo.append_event(
                action=AuditAction.AI_SEGMENT_REVIEWED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                department_id=segment.department_id,
                target_type=AuditTargetType.AI_SEGMENT.value,
                target_id=str(segment.id),
                outcome=AuditOutcome.SUCCESS.value,
                details={
                    "old_status": old_status,
                    "new_status": request.decision,
                    "false_positive_reason": request.false_positive_reason,
                    "job_id": str(segment.job_id),
                    "incident_id": str(segment.incident_id),
                },
            )

        return self._to_read_dto(updated)
