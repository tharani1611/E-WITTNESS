"""Face detection component abstractions, protocols, and providers (Phase 75)."""

from __future__ import annotations

from ai_services.face_detection.detector import (
    DisabledFaceDetectorProvider,
    LocalFaceDetectorProvider,
    MockFaceDetectorProvider,
    get_face_detector,
    inspect_image_dimensions_and_format,
)
from ai_services.face_detection.protocol import (
    DetectedFace,
    FaceDetectionOptions,
    FaceDetectionResult,
    FaceDetectorProtocol,
)

__all__ = [
    "DetectedFace",
    "DisabledFaceDetectorProvider",
    "FaceDetectionOptions",
    "FaceDetectionResult",
    "FaceDetectorProtocol",
    "LocalFaceDetectorProvider",
    "MockFaceDetectorProvider",
    "get_face_detector",
    "inspect_image_dimensions_and_format",
]
