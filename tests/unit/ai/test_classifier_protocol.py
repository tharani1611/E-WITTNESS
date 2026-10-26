"""Unit tests for Phase 64: Configurable Pretrained Video-Classification Model."""

from __future__ import annotations

import pytest

from ai_services.violence_detection.classifier import (
    MockVideoClassifier,
    PretrainedVideoClassifierProvider,
    VideoClassifierProtocol,
    VideoInputSpec,
)
from ai_services.violence_detection.requirements import (
    AI_HUMAN_IN_THE_LOOP_DISCLAIMER,
    AI_MODEL_FALLBACK_DISCLAIMER,
)
from backend.app.core.exceptions import ModelUnavailableError


@pytest.mark.unit
class TestVideoClassifierProtocolAndProvider:
    """Verify classifier interface, fallback handling, and uncalibrated output."""

    def test_protocol_runtime_checkability(self) -> None:
        """Verify protocol can be checked at runtime."""
        provider = PretrainedVideoClassifierProvider()
        mock = MockVideoClassifier()

        assert isinstance(provider, VideoClassifierProtocol)
        assert isinstance(mock, VideoClassifierProtocol)

    def test_provider_fails_safe_when_weights_or_runtime_missing(self) -> None:
        """Verify provider reports unavailable and raises ModelUnavailableError without inventing scores."""
        provider = PretrainedVideoClassifierProvider(
            weights_path="nonexistent_weights.pt",
        )

        assert provider.is_ready() is False
        info = provider.model_info()
        assert info["status"] == "unavailable"

        video_spec = VideoInputSpec(
            video_id="video-001",
            duration_seconds=10.0,
            fps=30.0,
            width=1280,
            height=720,
            codec="avc1",
            frames_count=10,
        )

        with pytest.raises(ModelUnavailableError, match="No synthetic or fabricated"):
            provider.classify(video_spec)

    def test_mock_classifier_returns_uncalibrated_result_and_disclaimer(self) -> None:
        """Verify test double produces structured uncalibrated result with mandatory disclaimers."""
        mock = MockVideoClassifier(
            is_violence_detected=True,
            violence_score=0.88,
            model_name="test-classifier-v1",
        )

        assert mock.is_ready() is True
        info = mock.model_info()
        assert info["status"] == "ready"

        video_spec = VideoInputSpec(
            video_id="video-002",
            duration_seconds=15.0,
            fps=30.0,
            width=1920,
            height=1080,
            codec="avc1",
            frames_count=15,
        )

        result = mock.classify(video_spec)

        assert result.model_name == "test-classifier-v1"
        assert result.is_violence_detected is True
        assert result.violence_score == 0.88
        assert result.confidence_is_uncalibrated is True
        assert result.class_probabilities["violence"] == 0.88
        assert round(result.class_probabilities["non_violence"], 2) == 0.12
        assert len(result.detected_segments) == 1
        assert result.frames_analyzed == 15
        assert result.disclaimer == AI_HUMAN_IN_THE_LOOP_DISCLAIMER

    def test_mock_classifier_fails_when_ready_override_false(self) -> None:
        mock = MockVideoClassifier(is_ready_override=False)
        assert mock.is_ready() is False

        video_spec = VideoInputSpec(
            video_id="v",
            duration_seconds=1.0,
            fps=1.0,
            width=10,
            height=10,
            codec="avc1",
            frames_count=1,
        )
        with pytest.raises(ModelUnavailableError, match=AI_MODEL_FALLBACK_DISCLAIMER):
            mock.classify(video_spec)
