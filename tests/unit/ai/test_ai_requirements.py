"""Unit tests for Phase 61: Violence-Detection Problem Definition and Requirements."""

from __future__ import annotations

import pytest

from ai_services.violence_detection.requirements import (
    AI_HUMAN_IN_THE_LOOP_DISCLAIMER,
    AI_MODEL_FALLBACK_DISCLAIMER,
    DEFAULT_AI_CONSTRAINTS,
    AIIntendedUse,
    AIOperationalConstraints,
    AIProhibitedUse,
    AIRequirementCode,
)


@pytest.mark.unit
class TestAIRequirementsAndGovernance:
    """Verify Phase 61 problem definition, intended use, prohibited use, and constraints."""

    def test_intended_uses_are_decision_support_and_triage(self) -> None:
        """Verify intended uses cover investigative decision support and triage only."""
        intended = {u.value for u in AIIntendedUse}
        assert "investigative_triage" in intended
        assert "decision_support" in intended
        assert "review_prioritization" in intended
        assert "candidate_flagging" in intended

    def test_prohibited_uses_include_autonomous_judgment_and_punitive_actions(self) -> None:
        """Verify strictly prohibited uses are defined according to justice ethics standards."""
        prohibited = {u.value for u in AIProhibitedUse}
        assert "automated_arrest" in prohibited
        assert "automated_disciplinary" in prohibited
        assert "sole_determination_of_guilt" in prohibited
        assert "demographic_profiling" in prohibited
        assert "biometric_surveillance" in prohibited
        assert "covert_mass_surveillance" in prohibited

    def test_canonical_requirement_codes_are_defined(self) -> None:
        """Verify requirement codes REQ-AI-001 through REQ-AI-044 exist."""
        req_codes = {r.value for r in AIRequirementCode}
        assert "REQ-AI-001" in req_codes
        assert "REQ-AI-003" in req_codes
        assert "REQ-AI-010" in req_codes
        assert "REQ-AI-020" in req_codes
        assert "REQ-AI-030" in req_codes
        assert "REQ-AI-040" in req_codes
        assert len(req_codes) >= 20

    def test_mandatory_disclaimers_state_human_in_the_loop_requirement(self) -> None:
        """Verify human-in-the-loop and fallback disclaimers are explicit and unambiguous."""
        assert "probabilistic, advisory decision-support" in AI_HUMAN_IN_THE_LOOP_DISCLAIMER
        assert "mandatory independent human review" in AI_HUMAN_IN_THE_LOOP_DISCLAIMER
        assert "No synthetic or fabricated confidence scores" in AI_MODEL_FALLBACK_DISCLAIMER

    def test_operational_constraints_defaults(self) -> None:
        """Verify resource and format bounds are within operational limits."""
        constraints = DEFAULT_AI_CONSTRAINTS
        assert constraints.max_video_duration_seconds == 600.0  # 10 minutes max
        assert constraints.max_file_size_bytes == 100 * 1024 * 1024  # 100 MB max
        assert "mp4" in constraints.allowed_containers
        assert "avc1" in constraints.allowed_codecs
        assert constraints.max_frames_to_sample == 64
        assert constraints.max_retries == 3

    def test_custom_operational_constraints_override(self) -> None:
        """Verify custom constraints can be instantiated."""
        custom = AIOperationalConstraints(
            max_video_duration_seconds=120.0,
            max_file_size_bytes=50 * 1024 * 1024,
            max_frames_to_sample=32,
        )
        assert custom.max_video_duration_seconds == 120.0
        assert custom.max_file_size_bytes == 50 * 1024 * 1024
        assert custom.max_frames_to_sample == 32
