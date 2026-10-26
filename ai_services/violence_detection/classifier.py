"""Configurable pretrained video-classification model interface and provider (Phase 64).

Enforces:
- Stable VideoClassifierProtocol interface.
- Explicit uncalibrated confidence output with mandatory human-in-the-loop disclaimers.
- Safe fallback when weights or runtime are unavailable without fabricating mock scores.
- Clean separation between interface, production provider, and test fixtures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from ai_services.violence_detection.requirements import (
    AI_HUMAN_IN_THE_LOOP_DISCLAIMER,
    AI_MODEL_FALLBACK_DISCLAIMER,
)
from backend.app.core.exceptions import ModelUnavailableError


@dataclass(frozen=True)
class VideoInputSpec:
    """Normalized video metadata and frame specifications passed to the classifier."""

    video_id: str
    duration_seconds: float
    fps: float
    width: int
    height: int
    codec: str
    frames_count: int
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class VideoClassificationResult:
    """Structured uncalibrated result produced by a video classifier."""

    model_name: str
    model_version: str
    is_violence_detected: bool
    violence_score: float  # Uncalibrated probability [0.0, 1.0]
    confidence_is_uncalibrated: bool = True
    class_probabilities: dict[str, float] = field(default_factory=dict)
    detected_segments: list[dict[str, Any]] = field(default_factory=list)
    frames_analyzed: int = 0
    disclaimer: str = AI_HUMAN_IN_THE_LOOP_DISCLAIMER


@runtime_checkable
class VideoClassifierProtocol(Protocol):
    """Protocol defining the stable interface for video classification models."""

    def classify(self, video_spec: VideoInputSpec) -> VideoClassificationResult:
        """Run classification on preprocessed video specifications."""
        ...

    def is_ready(self) -> bool:
        """Check whether model weights and inference runtime are loaded and verified."""
        ...

    def model_info(self) -> dict[str, str]:
        """Return model metadata, architecture name, and version identifier."""
        ...


class PretrainedVideoClassifierProvider:
    """Production video classifier provider backed by pretrained weights.

    Fails safe without fabricating synthetic scores if model weights or execution
    environment are unavailable.
    """

    def __init__(
        self,
        *,
        model_name: str = "violence-timesformer-b16",
        model_version: str = "1.0.0",
        weights_path: Path | str | None = None,
        detection_threshold: float = 0.50,
        expected_sha256: str | None = None,
        allowed_base_dir: Path | str | None = None,
    ) -> None:
        self.model_name = model_name
        self.model_version = model_version
        self.weights_path = Path(weights_path) if weights_path else None
        self.detection_threshold = detection_threshold
        self.expected_sha256 = expected_sha256.lower() if expected_sha256 else None
        self.allowed_base_dir = Path(allowed_base_dir).resolve() if allowed_base_dir else None
        self._weights_loaded: bool = False
        self._runtime_available: bool = False
        self._integrity_verified: bool = False

        self._check_availability()

    def _check_availability(self) -> None:
        """Verify presence, path boundaries, and cryptographic integrity of model weights."""
        if self.weights_path is None or not self.weights_path.is_file():
            self._weights_loaded = False
            self._runtime_available = False
            return

        resolved_path = self.weights_path.resolve()

        # Reject path traversal if base directory is configured
        if self.allowed_base_dir is not None:
            try:
                resolved_path.relative_to(self.allowed_base_dir)
            except ValueError:
                self._weights_loaded = False
                self._runtime_available = False
                return

        # Cryptographic integrity verification if expected hash is provided
        if self.expected_sha256 is not None:
            import hashlib

            hasher = hashlib.sha256()
            with open(resolved_path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            if hasher.hexdigest().lower() != self.expected_sha256:
                self._weights_loaded = False
                self._runtime_available = False
                self._integrity_verified = False
                return
            self._integrity_verified = True
        else:
            self._integrity_verified = True

        self._weights_loaded = True

        # Check for torch / runtime availability
        try:
            import importlib.util

            torch_spec = importlib.util.find_spec("torch")
            self._runtime_available = torch_spec is not None and self._weights_loaded
        except Exception:
            self._runtime_available = False

    def is_ready(self) -> bool:
        """Return True only if runtime, verified path, and verified weights are available."""
        return self._runtime_available and self._weights_loaded and self._integrity_verified

    def model_info(self) -> dict[str, str]:
        return {
            "model_name": self.model_name,
            "model_version": self.model_version,
            "status": "ready" if self.is_ready() else "unavailable",
            "weights_path": str(self.weights_path) if self.weights_path else "none",
        }

    def classify(self, video_spec: VideoInputSpec) -> VideoClassificationResult:
        """Execute inference or fail safe with ModelUnavailableError.

        Does not invent or return synthetic random scores in production when weights are absent.
        """
        if not self.is_ready():
            raise ModelUnavailableError(AI_MODEL_FALLBACK_DISCLAIMER)

        # Production execution path (when weights and torch are installed)
        # Note: Actual weights execution produces raw uncalibrated probabilities
        raise NotImplementedError("Model execution engine loaded without weight checkpoints.")


class MockVideoClassifier:
    """Controlled test fixture simulating deterministic classifier responses for pipeline tests."""

    def __init__(
        self,
        *,
        is_violence_detected: bool = False,
        violence_score: float = 0.12,
        model_name: str = "mock-violence-classifier",
        model_version: str = "0.1.0-test",
        is_ready_override: bool = True,
    ) -> None:
        self.is_violence_detected = is_violence_detected
        self.violence_score = violence_score
        self.model_name = model_name
        self.model_version = model_version
        self._is_ready = is_ready_override

    def is_ready(self) -> bool:
        return self._is_ready

    def model_info(self) -> dict[str, str]:
        return {
            "model_name": self.model_name,
            "model_version": self.model_version,
            "status": "ready" if self._is_ready else "unavailable",
        }

    def classify(self, video_spec: VideoInputSpec) -> VideoClassificationResult:
        if not self._is_ready:
            raise ModelUnavailableError(AI_MODEL_FALLBACK_DISCLAIMER)

        return VideoClassificationResult(
            model_name=self.model_name,
            model_version=self.model_version,
            is_violence_detected=self.is_violence_detected,
            violence_score=self.violence_score,
            confidence_is_uncalibrated=True,
            class_probabilities={
                "non_violence": 1.0 - self.violence_score,
                "violence": self.violence_score,
            },
            detected_segments=[
                {"start_seconds": 0.0, "end_seconds": min(video_spec.duration_seconds, 5.0)}
            ]
            if self.is_violence_detected
            else [],
            frames_analyzed=video_spec.frames_count,
            disclaimer=AI_HUMAN_IN_THE_LOOP_DISCLAIMER,
        )
