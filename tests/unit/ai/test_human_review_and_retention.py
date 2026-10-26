"""Unit tests for Phase 69: Traceable AI results, human review workflow, false-positive tracking, and retention.

Enforces:
- Review workflow transitions (pending_review -> confirmed / rejected / inconclusive / escalated).
- Conflict-of-interest prevention: investigators cannot review candidate segments for incidents they reported.
- Categorized false-positive tracking with mandatory factual rationale.
- Retention lifecycle: candidate segments older than retention_days are purged while active investigations and legal holds are strictly protected.
- Preserves original evidence files and immutable audit ledgers untouched.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

from backend.app.core.ai import FalsePositiveReason, SegmentReviewStatus
from backend.app.core.authorization import RoleCode
from backend.app.core.exceptions import (
    BusinessRuleError,
    ConflictError,
    PermissionDeniedError,
)
from backend.app.models.ai import AICandidateSegment
from backend.app.models.incident import Incident
from backend.app.schemas.ai import SegmentReviewRequest
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.services.ai_retention import AIRetentionService
from backend.app.services.ai_segment import AICandidateSegmentService


def make_principal(
    *,
    user_id: str | None = None,
    role_code: str = "investigator",
    department_id: str | None = None,
) -> AuthenticatedPrincipal:
    uid = UUID(user_id) if user_id is not None else uuid4()
    dept = UUID(department_id) if department_id is not None else uuid4()
    return AuthenticatedPrincipal(
        user_id=uid,
        email="investigator@university.edu",
        full_name="Investigator User",
        account_status="active",
        is_active=True,
        role_code=role_code,
        department_id=dept,
        session_id=uuid4(),
    )


@pytest.mark.unit
class TestCandidateSegmentReviewService:
    """Verify human review authorization, state transitions, and conflict-of-interest checks."""

    @pytest.mark.asyncio
    async def test_successful_segment_confirmation(self) -> None:
        dept_id = uuid4()
        reporter_id = uuid4()
        reviewer = make_principal(department_id=str(dept_id), role_code=RoleCode.INVESTIGATOR.value)

        incident = MagicMock(spec=Incident)
        incident.reporter_id = reporter_id  # Different from reviewer

        segment = AICandidateSegment(
            id=uuid4(),
            job_id=uuid4(),
            evidence_id=uuid4(),
            incident_id=uuid4(),
            department_id=reviewer.department_id,
            start_seconds=0.0,
            end_seconds=3.0,
            duration_seconds=3.0,
            raw_score=0.88,
            raw_label="violence",
            model_name="timesformer",
            model_version="1.0",
            review_status=SegmentReviewStatus.PENDING_REVIEW.value,
        )
        segment.incident = incident

        segment_repo = AsyncMock()
        segment_repo.get_by_id.return_value = segment
        segment_repo.update.return_value = segment

        audit_repo = AsyncMock()
        service = AICandidateSegmentService(
            segment_repo=segment_repo,
            incident_repo=AsyncMock(),
            audit_repo=audit_repo,
        )

        request = SegmentReviewRequest(
            decision="confirmed",
            review_notes="Physical altercation verified on footage by investigator.",
        )

        result = await service.review_segment(segment.id, request, reviewer)
        assert result.review_status == "confirmed"
        assert result.reviewed_by_id == reviewer.user_id
        assert result.review_notes == "Physical altercation verified on footage by investigator."
        assert audit_repo.append_event.called

    @pytest.mark.asyncio
    async def test_successful_false_positive_rejection_unflags_candidate(self) -> None:
        reviewer = make_principal(role_code=RoleCode.INVESTIGATOR.value)
        incident = MagicMock(spec=Incident)
        incident.reporter_id = uuid4()

        segment = AICandidateSegment(
            id=uuid4(),
            job_id=uuid4(),
            evidence_id=uuid4(),
            incident_id=uuid4(),
            department_id=reviewer.department_id,
            start_seconds=1.0,
            end_seconds=4.0,
            duration_seconds=3.0,
            raw_score=0.72,
            raw_label="violence",
            model_name="timesformer",
            model_version="1.0",
            review_status=SegmentReviewStatus.PENDING_REVIEW.value,
            is_flagged_for_review=True,
        )
        segment.incident = incident

        segment_repo = AsyncMock()
        segment_repo.get_by_id.return_value = segment
        segment_repo.update.return_value = segment

        service = AICandidateSegmentService(
            segment_repo=segment_repo,
            incident_repo=AsyncMock(),
            audit_repo=AsyncMock(),
        )

        request = SegmentReviewRequest(
            decision="rejected",
            false_positive_reason=FalsePositiveReason.SPORTS_MOTION.value,
            review_notes="Students are engaging in recreational touch rugby.",
        )

        result = await service.review_segment(segment.id, request, reviewer)
        assert result.review_status == "rejected"
        assert result.is_flagged_for_review is False
        assert result.false_positive_reason == "sports_motion"

    @pytest.mark.asyncio
    async def test_reviewer_conflict_of_interest_rejection(self) -> None:
        reviewer = make_principal(role_code=RoleCode.INVESTIGATOR.value)
        incident = MagicMock(spec=Incident)
        # Reviewer IS the reporter of the incident
        incident.reporter_id = reviewer.user_id

        segment = AICandidateSegment(
            id=uuid4(),
            job_id=uuid4(),
            evidence_id=uuid4(),
            incident_id=uuid4(),
            department_id=reviewer.department_id,
            start_seconds=0.0,
            end_seconds=2.0,
            duration_seconds=2.0,
            raw_score=0.80,
            raw_label="violence",
            model_name="timesformer",
            model_version="1.0",
            review_status=SegmentReviewStatus.PENDING_REVIEW.value,
        )
        segment.incident = incident

        segment_repo = AsyncMock()
        segment_repo.get_by_id.return_value = segment

        service = AICandidateSegmentService(
            segment_repo=segment_repo,
            incident_repo=AsyncMock(),
            audit_repo=AsyncMock(),
        )

        request = SegmentReviewRequest(
            decision="confirmed",
            review_notes="Attempted self-investigation.",
        )

        with pytest.raises(
            ConflictError,
            match="Users cannot review AI analysis results for incidents they reported",
        ):
            await service.review_segment(segment.id, request, reviewer)

    @pytest.mark.asyncio
    async def test_unauthorized_student_cannot_review_candidate_segment(self) -> None:
        student = make_principal(role_code=RoleCode.STUDENT.value)
        service = AICandidateSegmentService(
            segment_repo=AsyncMock(),
            incident_repo=AsyncMock(),
            audit_repo=AsyncMock(),
        )

        request = SegmentReviewRequest(
            decision="confirmed",
            review_notes="Student review attempt.",
        )

        with pytest.raises(PermissionDeniedError, match="Caller lacks permission"):
            await service.review_segment(uuid4(), request, student)

    @pytest.mark.asyncio
    async def test_reviewing_already_reviewed_segment_raises_business_rule_error(self) -> None:
        reviewer = make_principal(role_code=RoleCode.INVESTIGATOR.value)
        incident = MagicMock(spec=Incident)
        incident.reporter_id = uuid4()

        segment = AICandidateSegment(
            id=uuid4(),
            job_id=uuid4(),
            evidence_id=uuid4(),
            incident_id=uuid4(),
            department_id=reviewer.department_id,
            start_seconds=0.0,
            end_seconds=2.0,
            duration_seconds=2.0,
            raw_score=0.80,
            raw_label="violence",
            model_name="timesformer",
            model_version="1.0",
            review_status=SegmentReviewStatus.CONFIRMED.value,  # Already confirmed
        )
        segment.incident = incident

        segment_repo = AsyncMock()
        segment_repo.get_by_id.return_value = segment

        service = AICandidateSegmentService(
            segment_repo=segment_repo,
            incident_repo=AsyncMock(),
            audit_repo=AsyncMock(),
        )

        request = SegmentReviewRequest(
            decision="confirmed",
            review_notes="Duplicate confirmation attempt.",
        )

        with pytest.raises(BusinessRuleError, match="already in 'confirmed' review status"):
            await service.review_segment(segment.id, request, reviewer)


@pytest.mark.unit
class TestAIRetentionService:
    """Verify retention purging behavior, legal-hold exemptions, and audit preservation."""

    @pytest.mark.asyncio
    async def test_retention_purge_respects_active_incident_exemptions(self) -> None:
        admin = make_principal(role_code=RoleCode.DEPT_ADMIN.value)

        session = AsyncMock()
        active_incident_id = uuid4()
        # Mock active incident query returning an incident under investigation
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [active_incident_id]
        session.execute.return_value = mock_result

        segment_repo = AsyncMock()
        segment_repo.purge_expired.return_value = 14  # 14 expired segments purged

        audit_repo = AsyncMock()
        service = AIRetentionService(
            session=session,
            segment_repo=segment_repo,
            audit_repo=audit_repo,
        )

        response = await service.purge_expired_candidate_segments(
            retention_days=90,
            principal=admin,
        )

        assert response.purged_count == 14
        assert response.retention_days == 90
        assert segment_repo.purge_expired.called

        # Verify active incident was exempted in repository call
        called_kwargs = segment_repo.purge_expired.call_args.kwargs
        assert active_incident_id in called_kwargs["exempt_incident_ids"]
        assert audit_repo.append_event.called

    @pytest.mark.asyncio
    async def test_unauthorized_user_cannot_purge_retention(self) -> None:
        investigator = make_principal(role_code=RoleCode.INVESTIGATOR.value)
        service = AIRetentionService(
            session=AsyncMock(),
            segment_repo=AsyncMock(),
            audit_repo=AsyncMock(),
        )

        with pytest.raises(
            PermissionDeniedError, match="lacks permission to manage AI result retention"
        ):
            await service.purge_expired_candidate_segments(
                retention_days=90,
                principal=investigator,
            )
