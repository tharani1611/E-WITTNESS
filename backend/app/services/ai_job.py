"""Domain service orchestrating asynchronous video analysis jobs (Phase 65).

Enforces:
- Tenant-isolated job management and authorization boundaries.
- Monotonic job lifecycle transitions (QUEUED -> RUNNING -> SUCCEEDED/FAILED/CANCELLED).
- Safe integration with storage provider, video parser, and classifier protocol.
- Audit ledger recording for all state transitions.
- Graceful failure states without synthetic score fabrication.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from ai_services.video.metadata import extract_video_metadata_from_bytes
from ai_services.video.preprocessing import generate_frame_sampling_plan
from ai_services.violence_detection.calibration import (
    IdentityCalibrator,
    VideoConfidenceCalibrator,
)
from ai_services.violence_detection.classifier import (
    PretrainedVideoClassifierProvider,
    VideoClassifierProtocol,
    VideoInputSpec,
)
from ai_services.violence_detection.requirements import DEFAULT_AI_CONSTRAINTS
from backend.app.config.settings import Settings
from backend.app.core.ai import (
    AIErrorCategory,
    AIJobStatus,
    AIJobStep,
    SegmentReviewStatus,
)
from backend.app.core.audit import AuditAction, AuditOutcome, AuditTargetType
from backend.app.core.authorization import Permission, has_permission
from backend.app.core.exceptions import (
    BusinessRuleError,
    ConflictError,
    ModelUnavailableError,
    PermissionDeniedError,
    ResourceNotFoundError,
    UnsupportedMediaTypeError,
    VideoProcessingError,
)
from backend.app.core.logging import get_logger
from backend.app.infrastructure.storage import (
    InMemoryStorageClient,
    ObjectStorageClient,
    S3StorageClient,
)
from backend.app.models.ai import AIAnalysisJob, AICandidateSegment
from backend.app.models.base import utc_now
from backend.app.repositories.ai_job import AIAnalysisJobRepository
from backend.app.repositories.ai_segment import AICandidateSegmentRepository
from backend.app.repositories.audit import AuditRepository
from backend.app.repositories.evidence import EvidenceRepository
from backend.app.repositories.incident import IncidentRepository
from backend.app.schemas.ai import (
    AIJobResultSummary,
    AIJobStatusRead,
    AIJobSubmitRequest,
)
from backend.app.schemas.auth import AuthenticatedPrincipal

logger = get_logger("services.ai_job")


class AIAnalysisJobService:
    """Service managing asynchronous AI analysis jobs for evidence attachments."""

    def __init__(
        self,
        job_repo: AIAnalysisJobRepository,
        evidence_repo: EvidenceRepository,
        incident_repo: IncidentRepository,
        storage_client: ObjectStorageClient,
        classifier: VideoClassifierProtocol | None = None,
        audit_repo: AuditRepository | None = None,
        segment_repo: AICandidateSegmentRepository | None = None,
        calibrator: VideoConfidenceCalibrator | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.job_repo = job_repo
        self.evidence_repo = evidence_repo
        self.incident_repo = incident_repo
        self.storage_client = storage_client
        self.classifier = classifier or PretrainedVideoClassifierProvider()
        self.audit_repo = audit_repo
        self.segment_repo = segment_repo
        self.calibrator = calibrator or IdentityCalibrator()
        self.settings = settings

    @classmethod
    def from_session(
        cls,
        session: AsyncSession,
        settings: Settings,
        *,
        storage_client: ObjectStorageClient | None = None,
        classifier: VideoClassifierProtocol | None = None,
        audit_repo: AuditRepository | None = None,
        segment_repo: AICandidateSegmentRepository | None = None,
        calibrator: VideoConfidenceCalibrator | None = None,
    ) -> AIAnalysisJobService:
        """Construct an AIAnalysisJobService bound to the provided session."""
        client = storage_client or (
            InMemoryStorageClient(settings.STORAGE_ENDPOINT_URL)
            if settings.ENVIRONMENT == "testing" and "test" in settings.STORAGE_ENDPOINT_URL
            else S3StorageClient(settings)
        )
        return cls(
            job_repo=AIAnalysisJobRepository(session),
            evidence_repo=EvidenceRepository(session),
            incident_repo=IncidentRepository(session),
            storage_client=client,
            classifier=classifier,
            audit_repo=audit_repo or AuditRepository(session),
            segment_repo=segment_repo or AICandidateSegmentRepository(session),
            calibrator=calibrator or IdentityCalibrator(),
            settings=settings,
        )

    async def submit_analysis_job(
        self,
        payload: AIJobSubmitRequest,
        principal: AuthenticatedPrincipal,
    ) -> AIJobStatusRead:
        """Submit a new asynchronous video analysis job."""
        if not has_permission(principal.role, Permission.AI_JOB_SUBMIT):
            raise PermissionDeniedError("Caller lacks permission to submit AI analysis jobs.")

        # 1. Fetch and validate evidence attachment
        evidence = await self.evidence_repo.get_attachment_by_id(payload.evidence_id)
        if evidence is None:
            raise ResourceNotFoundError("Evidence attachment not found.", code="EVIDENCE_NOT_FOUND")

        # Department scoping: ensure caller belongs to evidence department or has global access
        is_global = has_permission(principal.role, Permission.AI_JOB_READ_GLOBAL)
        if not is_global and evidence.department_id != principal.department_id:
            raise PermissionDeniedError(
                "Evidence belongs to a different department.",
                code="DEPARTMENT_ISOLATION_VIOLATION",
            )

        # Verify evidence upload status
        if evidence.upload_status != "completed":
            raise BusinessRuleError(
                f"Evidence upload is not finalized (status: {evidence.upload_status}).",
                code="EVIDENCE_NOT_FINALIZED",
            )

        # Content type check: must be video
        content_type = (evidence.detected_mime_type or evidence.declared_mime_type or "").lower()
        original_ext = (evidence.original_filename or "").split(".")[-1].lower()
        if not (
            content_type.startswith("video/")
            or original_ext in DEFAULT_AI_CONSTRAINTS.allowed_containers
        ):
            raise UnsupportedMediaTypeError(
                f"Evidence attachment '{evidence.original_filename}' is not a supported video file.",
                code="UNSUPPORTED_MEDIA_FOR_AI_ANALYSIS",
            )

        # Validate model provenance and prevent path traversal
        from backend.app.core.ai import validate_model_provenance

        try:
            validate_model_provenance(payload.model_name, payload.model_version)
        except ValueError as exc:
            raise BusinessRuleError(str(exc), code="INVALID_AI_MODEL_PROVENANCE") from exc

        # Guard against concurrent duplicate processing for same evidence attachment
        active_job = await self.job_repo.get_active_job_for_evidence(evidence.id)
        if active_job is not None:
            raise ConflictError(
                f"An active AI analysis job (id: {active_job.id}, status: {active_job.status}) is already in progress for this evidence attachment.",
                code="ACTIVE_JOB_EXISTS",
            )

        # Department-level concurrency quota (max 5 active jobs)
        active_dept_jobs = await self.job_repo.count_active_for_department(evidence.department_id)
        max_concurrent_jobs = 5
        if active_dept_jobs >= max_concurrent_jobs:
            raise BusinessRuleError(
                f"Department AI analysis job quota exceeded ({active_dept_jobs}/{max_concurrent_jobs} active). Please wait for active jobs to finish.",
                code="AI_JOB_QUOTA_EXCEEDED",
            )

        # 2. Instantiate and persist AIAnalysisJob
        job = AIAnalysisJob(
            evidence_id=evidence.id,
            incident_id=evidence.incident_id,
            department_id=evidence.department_id,
            submitted_by_id=principal.user_id,
            status=AIJobStatus.QUEUED.value,
            progress_percent=0,
            current_step=AIJobStep.QUEUED.value,
            model_name=payload.model_name,
            model_version=payload.model_version,
            retry_count=0,
            max_retries=3,
        )
        created = await self.job_repo.create(job)

        # 3. Security audit event
        if self.audit_repo:
            await self.audit_repo.append_event(
                action=AuditAction.AI_JOB_SUBMITTED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                department_id=evidence.department_id,
                target_type=AuditTargetType.AI_JOB.value,
                target_id=str(created.id),
                outcome=AuditOutcome.SUCCESS.value,
                details={
                    "evidence_id": str(evidence.id),
                    "incident_id": str(evidence.incident_id),
                    "model_name": created.model_name,
                    "model_version": created.model_version,
                },
            )

        logger.info(
            "AI analysis job queued",
            extra={
                "job_id": str(created.id),
                "evidence_id": str(evidence.id),
                "department_id": str(evidence.department_id),
            },
        )

        return self._to_read_dto(created)

    async def execute_job(self, job_id: UUID) -> AIJobStatusRead:
        """Run the end-to-end video analysis pipeline for a queued job."""
        job = await self.job_repo.get_by_id_unscoped(job_id)
        if job is None:
            raise ResourceNotFoundError("AI job not found.", code="JOB_NOT_FOUND")

        if job.status == AIJobStatus.CANCELLED.value:
            return self._to_read_dto(job)

        # 1. Transition to RUNNING
        job.status = AIJobStatus.RUNNING.value
        job.current_step = AIJobStep.VALIDATING_INPUT.value
        job.progress_percent = 10
        job.started_at = utc_now()
        job = await self.job_repo.update(job)

        if self.audit_repo:
            await self.audit_repo.append_event(
                action=AuditAction.AI_JOB_STARTED.value,
                actor_id=job.submitted_by_id,
                actor_role="system",
                department_id=job.department_id,
                target_type=AuditTargetType.AI_JOB.value,
                target_id=str(job.id),
                outcome=AuditOutcome.SUCCESS.value,
                details={"step": job.current_step},
            )

        try:
            # 2. Retrieve video bytes from storage
            evidence = await self.evidence_repo.get_attachment_by_id(job.evidence_id)
            if evidence is None:
                raise VideoProcessingError("Associated evidence attachment not found")

            video_bytes = await self.storage_client.get_object_bytes(evidence.storage_key)
            if len(video_bytes) == 0:
                raise VideoProcessingError("Evidence video payload is empty")

            # 3. Extract metadata
            job.current_step = AIJobStep.EXTRACTING_METADATA.value
            job.progress_percent = 35
            job = await self.job_repo.update(job)

            metadata = extract_video_metadata_from_bytes(video_bytes)

            if metadata.duration_seconds > DEFAULT_AI_CONSTRAINTS.max_video_duration_seconds:
                raise VideoProcessingError(
                    f"Video duration ({metadata.duration_seconds:.1f}s) exceeds max limit "
                    f"({DEFAULT_AI_CONSTRAINTS.max_video_duration_seconds:.1f}s)"
                )

            # 4. Generate sampling plan
            job.current_step = AIJobStep.PREPROCESSING_FRAMES.value
            job.progress_percent = 60
            job = await self.job_repo.update(job)

            sampling_plan = generate_frame_sampling_plan(metadata)

            # 5. Run model classification
            job.current_step = AIJobStep.RUNNING_INFERENCE.value
            job.progress_percent = 85
            job = await self.job_repo.update(job)

            video_spec = VideoInputSpec(
                video_id=str(evidence.id),
                duration_seconds=metadata.duration_seconds,
                fps=metadata.fps,
                width=metadata.width,
                height=metadata.height,
                codec=metadata.codec,
                frames_count=sampling_plan.target_sample_count,
                metadata={"container": metadata.container, "filesize": metadata.file_size_bytes},
            )

            result = self.classifier.classify(video_spec)

            # 6. Generate, calibrate, and persist candidate segments (Phases 66 & 67)
            if self.segment_repo:
                await self.segment_repo.delete_unreviewed_for_job(job.id)

                raw_segments = list(result.detected_segments)
                if not raw_segments and result.is_violence_detected:
                    raw_segments = [
                        {"start_seconds": 0.0, "end_seconds": metadata.duration_seconds}
                    ]

                for seg in raw_segments:
                    start_sec = max(0.0, float(seg.get("start_seconds", 0.0)))
                    end_sec = min(
                        metadata.duration_seconds,
                        float(seg.get("end_seconds", metadata.duration_seconds)),
                    )
                    if end_sec <= start_sec:
                        end_sec = min(metadata.duration_seconds, start_sec + 1.0)
                    dur = max(0.001, end_sec - start_sec)

                    cal_out = self.calibrator.calibrate(result.violence_score, threshold=0.50)
                    candidate_seg = AICandidateSegment(
                        job_id=job.id,
                        evidence_id=job.evidence_id,
                        incident_id=job.incident_id,
                        department_id=job.department_id,
                        start_seconds=round(start_sec, 2),
                        end_seconds=round(end_sec, 2),
                        duration_seconds=round(dur, 2),
                        raw_score=round(cal_out.raw_score, 4),
                        raw_label="violence" if result.is_violence_detected else "non_violence",
                        model_name=job.model_name,
                        model_version=job.model_version,
                        preprocessing_version="1.0.0",
                        calibration_status=cal_out.calibration_status.value,
                        calibrated_score=cal_out.calibrated_score,
                        calibration_version=cal_out.calibration_version,
                        uncertainty_status=cal_out.uncertainty_status.value,
                        review_status=SegmentReviewStatus.PENDING_REVIEW.value,
                        is_flagged_for_review=cal_out.is_flagged_for_review,
                        metadata_json=json.dumps(
                            {
                                "provenance": {
                                    "evidence_id": str(evidence.id),
                                    "evidence_sha256": evidence.sha256_hash,
                                    "fps": metadata.fps,
                                    "frames_analyzed": result.frames_analyzed,
                                }
                            }
                        ),
                    )
                    await self.segment_repo.create(candidate_seg)

            # 7. Finalize successful job
            summary = AIJobResultSummary(
                is_violence_detected=result.is_violence_detected,
                violence_score=result.violence_score,
                confidence_is_uncalibrated=True,
                detected_segments=result.detected_segments,
                video_metadata={
                    "duration_seconds": metadata.duration_seconds,
                    "width": metadata.width,
                    "height": metadata.height,
                    "fps": metadata.fps,
                    "codec": metadata.codec,
                },
                frames_analyzed=result.frames_analyzed,
                processing_time_seconds=round(
                    (utc_now() - (job.started_at or utc_now())).total_seconds(), 2
                ),
                disclaimer=result.disclaimer,
            )

            job.status = AIJobStatus.SUCCEEDED.value
            job.current_step = AIJobStep.FINALIZING_RESULTS.value
            job.progress_percent = 100
            job.result_summary = json.dumps(summary.model_dump())
            job.completed_at = utc_now()
            job = await self.job_repo.update(job)

            if self.audit_repo:
                await self.audit_repo.append_event(
                    action=AuditAction.AI_JOB_COMPLETED.value,
                    actor_id=job.submitted_by_id,
                    actor_role="system",
                    department_id=job.department_id,
                    target_type=AuditTargetType.AI_JOB.value,
                    target_id=str(job.id),
                    outcome=AuditOutcome.SUCCESS.value,
                    details={
                        "is_violence_detected": result.is_violence_detected,
                        "violence_score": result.violence_score,
                        "frames_analyzed": result.frames_analyzed,
                    },
                )

            logger.info("AI analysis job completed successfully", extra={"job_id": str(job.id)})
            return self._to_read_dto(job)

        except ModelUnavailableError as exc:
            return await self._handle_job_failure(
                job,
                category=AIErrorCategory.MODEL_UNAVAILABLE.value,
                message=exc.message,
            )
        except VideoProcessingError as exc:
            return await self._handle_job_failure(
                job,
                category=AIErrorCategory.UNSUPPORTED_FORMAT.value,
                message=exc.message,
            )
        except TimeoutError:
            return await self._handle_job_failure(
                job,
                category=AIErrorCategory.RESOURCE_EXHAUSTED.value,
                message="AI analysis job timed out during execution.",
            )
        except Exception:
            logger.exception(
                "Unexpected error during AI analysis job execution", extra={"job_id": str(job.id)}
            )
            return await self._handle_job_failure(
                job,
                category=AIErrorCategory.INTERNAL_ERROR.value,
                message="An unexpected internal error occurred during video analysis.",
            )

    async def _handle_job_failure(
        self,
        job: AIAnalysisJob,
        *,
        category: str,
        message: str,
    ) -> AIJobStatusRead:
        """Record job failure cleanly with typed category and security audit record."""
        job.status = AIJobStatus.FAILED.value
        job.current_step = AIJobStep.FAILED.value
        job.error_category = category
        job.error_message = message[:1024]
        job.completed_at = utc_now()
        updated = await self.job_repo.update(job)

        if self.audit_repo:
            await self.audit_repo.append_event(
                action=AuditAction.AI_JOB_FAILED.value,
                actor_id=job.submitted_by_id,
                actor_role="system",
                department_id=job.department_id,
                target_type=AuditTargetType.AI_JOB.value,
                target_id=str(job.id),
                outcome=AuditOutcome.FAILURE.value,
                details={
                    "error_category": category,
                    "error_message": message,
                },
            )

        logger.warning(
            "AI analysis job failed",
            extra={"job_id": str(job.id), "category": category, "error_details": message},
        )
        return self._to_read_dto(updated)

    async def get_job(
        self,
        job_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> AIJobStatusRead:
        """Retrieve job status enforcing department isolation."""
        is_global = has_permission(principal.role, Permission.AI_JOB_READ_GLOBAL)

        if is_global:
            job = await self.job_repo.get_by_id_unscoped(job_id)
        elif principal.department_id is not None:
            job = await self.job_repo.get_by_id(job_id, department_id=principal.department_id)
        else:
            raise PermissionDeniedError("Principal has no assigned department.")

        if job is None:
            raise ResourceNotFoundError("AI job not found.", code="JOB_NOT_FOUND")

        # Self-service access check: if user cannot read dept jobs, must be own submission
        if (
            not has_permission(principal.role, Permission.AI_JOB_READ_DEPT)
            and not is_global
            and job.submitted_by_id != principal.user_id
        ):
            raise PermissionDeniedError("Cannot access jobs submitted by other users.")

        return self._to_read_dto(job)

    async def cancel_job(
        self,
        job_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> AIJobStatusRead:
        """Cancel an in-flight or queued analysis job."""
        is_global = has_permission(principal.role, Permission.AI_JOB_CANCEL_GLOBAL)
        can_cancel_dept = has_permission(principal.role, Permission.AI_JOB_CANCEL_DEPT)

        if not is_global and not can_cancel_dept:
            raise PermissionDeniedError("Caller lacks permission to cancel jobs.")

        if is_global:
            job = await self.job_repo.get_by_id_unscoped(job_id)
        elif principal.department_id is not None:
            job = await self.job_repo.get_by_id(job_id, department_id=principal.department_id)
        else:
            raise PermissionDeniedError("Principal has no assigned department.")

        if job is None:
            raise ResourceNotFoundError("AI job not found.", code="JOB_NOT_FOUND")

        if job.status in (
            AIJobStatus.SUCCEEDED.value,
            AIJobStatus.FAILED.value,
            AIJobStatus.CANCELLED.value,
        ):
            raise ConflictError(
                f"Job is already in terminal state '{job.status}' and cannot be cancelled.",
                code="JOB_ALREADY_TERMINAL",
            )

        job.status = AIJobStatus.CANCELLED.value
        job.current_step = AIJobStep.CANCELLED.value
        job.completed_at = utc_now()
        updated = await self.job_repo.update(job)

        if self.audit_repo:
            await self.audit_repo.append_event(
                action=AuditAction.AI_JOB_CANCELLED.value,
                actor_id=principal.user_id,
                actor_role=principal.role_code,
                department_id=job.department_id,
                target_type=AuditTargetType.AI_JOB.value,
                target_id=str(job.id),
                outcome=AuditOutcome.SUCCESS.value,
                details={"reason": "Explicit cancellation request"},
            )

        logger.info("AI analysis job cancelled", extra={"job_id": str(job.id)})
        return self._to_read_dto(updated)

    async def list_jobs(
        self,
        principal: AuthenticatedPrincipal,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[Sequence[AIJobStatusRead], int]:
        """List jobs scoped to authorized department or global scope."""
        is_global = has_permission(principal.role, Permission.AI_JOB_READ_GLOBAL)

        if is_global:
            jobs = await self.job_repo.list_all_unscoped(limit=limit, offset=offset, status=status)
            total = len(jobs)
        elif principal.department_id is not None:
            jobs = await self.job_repo.list_for_department(
                department_id=principal.department_id,
                limit=limit,
                offset=offset,
                status=status,
            )
            total = await self.job_repo.count_for_department(
                department_id=principal.department_id, status=status
            )
        else:
            raise PermissionDeniedError("Principal has no assigned department.")

        return [self._to_read_dto(j) for j in jobs], total

    def _to_read_dto(self, job: AIAnalysisJob) -> AIJobStatusRead:
        now = utc_now()
        return AIJobStatusRead(
            id=job.id or uuid4(),
            evidence_id=job.evidence_id,
            incident_id=job.incident_id,
            department_id=job.department_id,
            submitted_by_id=job.submitted_by_id,
            status=job.status or AIJobStatus.QUEUED.value,
            progress_percent=job.progress_percent if job.progress_percent is not None else 0,
            current_step=job.current_step or AIJobStep.QUEUED.value,
            model_name=job.model_name or "violence_detector",
            model_version=job.model_version or "v1.0.0",
            result_summary=job.get_result_dict(),
            error_message=job.error_message,
            error_category=job.error_category,
            retry_count=job.retry_count if job.retry_count is not None else 0,
            max_retries=job.max_retries if job.max_retries is not None else 3,
            started_at=job.started_at,
            completed_at=job.completed_at,
            created_at=job.created_at or now,
            updated_at=job.updated_at or now,
        )
