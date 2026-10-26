"""Domain models, status enums, licensing rules, and cryptographic helpers for AI governance (Phases 61-65).

Enforces:
- Explicit typed lifecycle states for AI analysis jobs and governance datasets.
- Approved dataset licensing allowlist (SPDX identifiers).
- Deterministic canonical manifest SHA-256 calculation.
- Separation of operational evidence from training datasets.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any, Final


class DatasetStatus(StrEnum):
    """Lifecycle status of an AI governance dataset (Phase 62)."""

    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"


class DatasetConsentStatus(StrEnum):
    """Subject consent and provenance review classification (Phase 62)."""

    CONSENTED = "consented"
    PUBLIC_DOMAIN_REVIEWED = "public_domain_reviewed"
    SYNTHETIC_REVIEWED = "synthetic_reviewed"
    UNVERIFIED = "unverified"


class DatasetType(StrEnum):
    """Classification partition of AI datasets."""

    BENCHMARK = "benchmark"
    TRAINING = "training"
    VALIDATION = "validation"
    TEST = "test"


class AIJobStatus(StrEnum):
    """Monotonic status of an asynchronous video analysis job (Phase 65)."""

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AIJobStep(StrEnum):
    """Granular execution phase within an analysis job."""

    QUEUED = "queued"
    VALIDATING_INPUT = "validating_input"
    EXTRACTING_METADATA = "extracting_metadata"
    PREPROCESSING_FRAMES = "preprocessing_frames"
    RUNNING_INFERENCE = "running_inference"
    FINALIZING_RESULTS = "finalizing_results"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AIErrorCategory(StrEnum):
    """Standardized failure classification for AI processing jobs (Phase 65)."""

    VALIDATION_ERROR = "VALIDATION_ERROR"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class SegmentReviewStatus(StrEnum):
    """Lifecycle review status of an AI candidate segment (Phase 66 & 69)."""

    PENDING_REVIEW = "pending_review"
    UNDER_REVIEW = "under_review"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    ESCALATED = "escalated"


class FalsePositiveReason(StrEnum):
    """Categorized justification for rejecting an AI candidate detection (Phase 69)."""

    SPORTS_MOTION = "sports_motion"
    PLAY_FIGHTING = "play_fighting"
    CROWD_DENSITY = "crowd_density"
    OCCLUSION = "occlusion"
    CAMERA_SHAKE = "camera_shake"
    BENIGN_PHYSICAL_CONTACT = "benign_physical_contact"
    OTHER = "other"


class CalibrationStatus(StrEnum):
    """Confidence calibration state of an AI candidate detection (Phase 67)."""

    UNCALIBRATED = "uncalibrated"
    CALIBRATED = "calibrated"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"


class UncertaintyStatus(StrEnum):
    """Explicit epistemic uncertainty verdict for model outputs (Phase 67)."""

    HIGH_CONFIDENCE = "high_confidence"
    LOW_CONFIDENCE = "low_confidence"
    BORDERLINE = "borderline"
    UNCALIBRATED = "uncalibrated"
    UNCERTAIN = "uncertain"
    ABSTAINED = "abstained"


class CalibrationMethod(StrEnum):
    """Approved statistical confidence calibration algorithms (Phase 67)."""

    PLATT_SCALING = "platt_scaling"
    ISOTONIC_REGRESSION = "isotonic_regression"
    TEMPERATURE_SCALING = "temperature_scaling"
    IDENTITY_UNCALIBRATED = "identity_uncalibrated"


class EvaluationLevel(StrEnum):
    """Evaluation granularity partition for violence detection metrics (Phase 68)."""

    CLIP_LEVEL = "clip_level"
    WINDOW_LEVEL = "window_level"
    EVENT_LOCALIZATION = "event_localization"


# Approved SPDX license identifiers for AI training and benchmark datasets (Phase 62)
APPROVED_DATASET_LICENSES: Final[frozenset[str]] = frozenset(
    {
        "CC-BY-4.0",
        "CC-BY-SA-4.0",
        "CC0-1.0",
        "MIT",
        "Apache-2.0",
        "OpenRAIL-M",
        "ODC-BY-1.0",
        "CDLA-Permissive-2.0",
    }
)

# Approved AI inference models and verified semantic versions (Phase 106)
APPROVED_AI_MODELS: Final[dict[str, frozenset[str]]] = {
    "violence-classifier": frozenset({"0.1.0", "1.0.0"}),
    "violence-timesformer-b16": frozenset({"1.0.0"}),
    "mock-violence-classifier": frozenset({"0.1.0-test"}),
}


def validate_model_provenance(model_name: str, model_version: str) -> None:
    """Validate that requested model and version are approved, preventing path traversal and untrusted execution."""
    if not model_name or not model_version:
        raise ValueError("Model name and model version are required.")

    # Guard against path traversal and shell injection characters
    forbidden_chars = {"/", "\\", "..", "\x00", "~", ";", "|", "&", "$", "`"}
    if any(ch in model_name for ch in forbidden_chars) or any(
        ch in model_version for ch in forbidden_chars
    ):
        raise ValueError("Model name or version contains forbidden path traversal characters.")

    clean_name = model_name.strip()
    clean_version = model_version.strip()

    if clean_name not in APPROVED_AI_MODELS:
        raise ValueError(
            f"Model '{clean_name}' is not in approved AI model catalog: {sorted(APPROVED_AI_MODELS.keys())}"
        )

    allowed_versions = APPROVED_AI_MODELS[clean_name]
    if clean_version not in allowed_versions:
        raise ValueError(
            f"Version '{clean_version}' is not approved for model '{clean_name}'. Approved: {sorted(allowed_versions)}"
        )


def compute_manifest_sha256(manifest_items: list[dict[str, Any]]) -> str:
    """Calculate deterministic SHA-256 digest over normalized dataset manifest items.

    Items are sorted by 'path' to ensure reproducibility regardless of insertion order.
    """
    sorted_items = sorted(manifest_items, key=lambda x: str(x.get("path", "")))
    canonical_repr = json.dumps(
        sorted_items,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical_repr.encode("utf-8")).hexdigest()
