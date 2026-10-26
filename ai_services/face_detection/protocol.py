"""Standard interface and structured outputs for approved face detection (Phase 75).

Enforces:
- Strict segregation of face detection (bounding box localization) from identity recognition.
- Normalized coordinate bounding boxes [ymin, xmin, ymax, xmax] in [0.0, 1.0].
- Mandatory statutory advisory disclaimer on all detection results.
- Zero emotion, sentiment, criminality, or demographic inference.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from backend.app.core.biometrics import BIOMETRIC_ADVISORY_DISCLAIMER


@dataclass(frozen=True)
class FaceDetectionOptions:
    """Configurable runtime execution parameters for face detection."""

    confidence_threshold: float = 0.5
    max_faces: int = 50
    min_face_size_pixels: int = 20

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence_threshold <= 1.0):
            raise ValueError("confidence_threshold must be between 0.0 and 1.0.")
        if self.max_faces < 1:
            raise ValueError("max_faces must be at least 1.")
        if self.min_face_size_pixels < 4:
            raise ValueError("min_face_size_pixels must be at least 4.")


@dataclass(frozen=True)
class DetectedFace:
    """Localized bounding box coordinates and confidence for a single detected face."""

    bounding_box: tuple[float, float, float, float]  # (ymin, xmin, ymax, xmax) in [0.0, 1.0]
    confidence: float
    landmarks: dict[str, tuple[float, float]] | None = None

    def __post_init__(self) -> None:
        ymin, xmin, ymax, xmax = self.bounding_box
        if not (
            0.0 <= ymin <= 1.0 and 0.0 <= xmin <= 1.0 and 0.0 <= ymax <= 1.0 and 0.0 <= xmax <= 1.0
        ):
            raise ValueError("All bounding box coordinates must be normalized within [0.0, 1.0].")
        if ymin >= ymax:
            raise ValueError(
                f"Invalid vertical coordinates: ymin ({ymin}) must be strictly less than ymax ({ymax})."
            )
        if xmin >= xmax:
            raise ValueError(
                f"Invalid horizontal coordinates: xmin ({xmin}) must be strictly less than xmax ({xmax})."
            )
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Confidence score must be between 0.0 and 1.0.")


@dataclass(frozen=True)
class FaceDetectionResult:
    """Structured detection outcome produced by an approved face detector."""

    detected_faces: list[DetectedFace]
    face_count: int
    image_width: int
    image_height: int
    model_name: str
    model_version: str
    inference_latency_ms: float
    disclaimer: str = BIOMETRIC_ADVISORY_DISCLAIMER
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.face_count < 0:
            raise ValueError("face_count cannot be negative.")
        if self.image_width < 1 or self.image_height < 1:
            raise ValueError("image_width and image_height must be positive integers.")
        if self.inference_latency_ms < 0.0:
            raise ValueError("inference_latency_ms cannot be negative.")


@runtime_checkable
class FaceDetectorProtocol(Protocol):
    """Runtime protocol defining the face-detection engine contract."""

    def detect_faces(
        self,
        image_bytes: bytes,
        options: FaceDetectionOptions | None = None,
    ) -> FaceDetectionResult:
        """Detect human faces in raw image bytes without identifying individuals."""
        ...
