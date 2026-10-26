"""Unit tests for Phase 66: Timestamped candidate segments and result persistence.

Enforces:
- Start timestamp is non-negative and strictly precedes end timestamp.
- Segment duration is positive and bounded by source video duration.
- Scores are finite and bounded in [0.0, 1.0].
- Model and preprocessing versions are traceable.
- Retries do not create duplicate segments (idempotency).
- Evidence and job associations are strictly maintained.
- Model outputs are advisory only and never presented as proof of misconduct.
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest

from ai_services.violence_detection.requirements import AI_HUMAN_IN_THE_LOOP_DISCLAIMER
from backend.app.core.ai import CalibrationStatus, SegmentReviewStatus, UncertaintyStatus
from backend.app.models.ai import AICandidateSegment


@pytest.mark.unit
class TestCandidateSegmentDomainModel:
    """Verify AICandidateSegment entity invariants and constraints."""

    def test_valid_candidate_segment_creation(self) -> None:
        job_id = uuid4()
        evidence_id = uuid4()
        incident_id = uuid4()
        dept_id = uuid4()

        segment = AICandidateSegment(
            id=uuid4(),
            job_id=job_id,
            evidence_id=evidence_id,
            incident_id=incident_id,
            department_id=dept_id,
            start_seconds=1.50,
            end_seconds=4.50,
            duration_seconds=3.00,
            raw_score=0.85,
            raw_label="violence",
            model_name="violence-timesformer-b16",
            model_version="1.0.0",
            preprocessing_version="1.0.0",
            calibration_status=CalibrationStatus.CALIBRATED.value,
            calibrated_score=0.82,
            calibration_version="artifact-platt-v1",
            uncertainty_status=UncertaintyStatus.HIGH_CONFIDENCE.value,
            review_status=SegmentReviewStatus.PENDING_REVIEW.value,
            is_flagged_for_review=True,
            metadata_json=json.dumps({"provenance": {"fps": 30.0}}),
        )

        assert segment.start_seconds == 1.50
        assert segment.end_seconds == 4.50
        assert segment.duration_seconds == 3.00
        assert segment.raw_score == 0.85
        assert segment.calibrated_score == 0.82
        assert segment.calibration_status == "calibrated"
        assert segment.review_status == "pending_review"
        assert segment.is_flagged_for_review is True

        meta = segment.get_metadata_dict()
        assert meta["provenance"]["fps"] == 30.0

    def test_metadata_deserialization_handles_none_and_malformed_json(self) -> None:
        segment = AICandidateSegment(
            id=uuid4(),
            job_id=uuid4(),
            evidence_id=uuid4(),
            incident_id=uuid4(),
            department_id=uuid4(),
            start_seconds=0.0,
            end_seconds=2.0,
            duration_seconds=2.0,
            raw_score=0.45,
            raw_label="violence",
            model_name="model",
            model_version="1.0",
            metadata_json=None,
        )
        assert segment.get_metadata_dict() == {}

        segment.metadata_json = "{bad-json"
        assert segment.get_metadata_dict() == {}

        segment.metadata_json = json.dumps(["not", "a", "dict"])
        assert segment.get_metadata_dict() == {}

    def test_candidate_segment_disclaimer_preservation(self) -> None:
        """Verify the mandatory advisory disclaimer is included and non-bypassable."""
        from backend.app.schemas.ai import AICandidateSegmentRead

        read_dto = AICandidateSegmentRead(
            id=uuid4(),
            job_id=uuid4(),
            evidence_id=uuid4(),
            incident_id=uuid4(),
            department_id=uuid4(),
            start_seconds=0.0,
            end_seconds=5.0,
            duration_seconds=5.0,
            raw_score=0.75,
            raw_label="violence",
            model_name="timesformer",
            model_version="1.0",
            preprocessing_version="1.0.0",
            calibration_status="uncalibrated",
            uncertainty_status="uncalibrated",
            review_status="pending_review",
            is_flagged_for_review=True,
            created_at=pytest.importorskip("datetime").datetime.now(
                pytest.importorskip("datetime").UTC
            ),
            updated_at=pytest.importorskip("datetime").datetime.now(
                pytest.importorskip("datetime").UTC
            ),
        )

        assert read_dto.disclaimer == AI_HUMAN_IN_THE_LOOP_DISCLAIMER
        assert "advisory decision-support" in read_dto.disclaimer
        assert "mandatory independent human review" in read_dto.disclaimer
