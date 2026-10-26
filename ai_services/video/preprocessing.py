"""Deterministic video preprocessing and frame sampling plan (Phase 63).

Enforces:
- Deterministic temporal frame sampling intervals.
- Strict operational constraints (duration, file size, codec allowlist).
- Safe temporary file isolation and cleanup.
- Reproducible normalization parameter specifications.
"""

from __future__ import annotations

import contextlib
import shutil
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from ai_services.video.metadata import VideoMetadata, extract_video_metadata_from_file
from ai_services.violence_detection.requirements import (
    DEFAULT_AI_CONSTRAINTS,
    AIOperationalConstraints,
)
from backend.app.core.exceptions import VideoProcessingError


@dataclass(frozen=True)
class FrameSamplingPlan:
    """Deterministic sampling specifications for downstream video classification."""

    sample_timestamps: tuple[float, ...]
    target_sample_count: int
    target_resolution: tuple[int, int] = (224, 224)
    normalize_mean: tuple[float, float, float] = (0.485, 0.456, 0.406)
    normalize_std: tuple[float, float, float] = (0.229, 0.224, 0.225)


@dataclass(frozen=True)
class PreprocessedVideoSpec:
    """Normalized video specification ready for inference dispatch."""

    video_id: str
    metadata: VideoMetadata
    sampling_plan: FrameSamplingPlan
    temp_working_dir: str | None = None


def generate_frame_sampling_plan(
    metadata: VideoMetadata,
    *,
    constraints: AIOperationalConstraints = DEFAULT_AI_CONSTRAINTS,
) -> FrameSamplingPlan:
    """Deterministically compute temporal frame sample timestamps.

    If video duration allows 1 fps within max_frames_to_sample, samples uniformly at 1-second intervals.
    If video duration exceeds max_frames_to_sample, samples uniformly across the entire duration.
    """
    duration = max(metadata.duration_seconds, 1.0)
    max_samples = constraints.max_frames_to_sample

    if duration <= float(max_samples):
        # 1 frame per second
        count = int(duration)
        if count < 1:
            count = 1
        timestamps = tuple(round(float(i), 3) for i in range(count))
    else:
        # Uniform sampling across duration
        step = duration / float(max_samples)
        timestamps = tuple(round(i * step, 3) for i in range(max_samples))

    return FrameSamplingPlan(
        sample_timestamps=timestamps,
        target_sample_count=len(timestamps),
        target_resolution=(224, 224),
    )


def validate_video_file_constraints(
    file_path: Path | str,
    *,
    constraints: AIOperationalConstraints = DEFAULT_AI_CONSTRAINTS,
) -> VideoMetadata:
    """Verify video file meets operational resource and security boundaries."""
    path = Path(file_path)
    if not path.is_file():
        raise VideoProcessingError(f"Video file does not exist: {path}")

    size = path.stat().st_size
    if size > constraints.max_file_size_bytes:
        raise VideoProcessingError(
            f"Video file size ({size} bytes) exceeds maximum limit "
            f"({constraints.max_file_size_bytes} bytes)"
        )

    metadata = extract_video_metadata_from_file(path)

    if metadata.duration_seconds > constraints.max_video_duration_seconds:
        raise VideoProcessingError(
            f"Video duration ({metadata.duration_seconds:.1f}s) exceeds maximum allowed "
            f"({constraints.max_video_duration_seconds:.1f}s)"
        )

    if metadata.codec not in constraints.allowed_codecs:
        raise VideoProcessingError(
            f"Video codec '{metadata.codec}' is not supported. "
            f"Allowed codecs: {constraints.allowed_codecs}"
        )

    return metadata


@contextlib.contextmanager
def isolated_video_temp_dir(prefix: str = "ewitness_video_") -> Iterator[Path]:
    """Provide a scoped temporary directory that is guaranteed to be cleaned up."""
    temp_dir = tempfile.mkdtemp(prefix=prefix)
    path = Path(temp_dir)
    try:
        yield path
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
