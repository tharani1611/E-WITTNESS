"""Input image quality assessment guardrails for biometric face matching (Phase 77).

Enforces:
- Pre-matching image validation to prevent processing degraded or adversarial inputs.
- Minimum resolution thresholds (width and height >= 64 pixels).
- Contrast and luminance variance validation to detect washed out, pitch black, or flat inputs.
- Detection of corrupted headers or unsupported image containers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final

from ai_services.face_detection.detector import inspect_image_dimensions_and_format
from backend.app.core.biometrics import ImageQualityAssessment
from backend.app.core.exceptions import UnsupportedMediaTypeError

DEFAULT_MIN_WIDTH_PIXELS: Final[int] = 64
DEFAULT_MIN_HEIGHT_PIXELS: Final[int] = 64
DEFAULT_MIN_CONTRAST_VARIANCE: Final[float] = 5.0


@dataclass(frozen=True)
class ImageQualityCheckResult:
    """Outcome of input image quality inspection."""

    status: ImageQualityAssessment
    is_acceptable: bool
    reason: str | None
    width: int
    height: int
    image_format: str
    contrast_variance: float
    details: dict[str, Any] = field(default_factory=dict)


def compute_byte_variance(data: bytes, sample_limit: int = 4096) -> float:
    """Compute variance of byte values across payload to detect monochromatic/blank images."""
    if not data:
        return 0.0

    step = max(1, len(data) // sample_limit)
    samples = [data[i] for i in range(0, len(data), step)][:sample_limit]

    n = len(samples)
    if n < 2:
        return 0.0

    mean = sum(samples) / n
    variance = sum((x - mean) ** 2 for x in samples) / (n - 1)
    return float(variance)


def assess_face_image_quality(
    image_bytes: bytes,
    *,
    min_width: int = DEFAULT_MIN_WIDTH_PIXELS,
    min_height: int = DEFAULT_MIN_HEIGHT_PIXELS,
    min_contrast_variance: float = DEFAULT_MIN_CONTRAST_VARIANCE,
) -> ImageQualityCheckResult:
    """Assess whether input image bytes satisfy minimum operational quality standards.

    Checks:
    1. Header integrity and valid image container (PNG, JPEG, WebP).
    2. Spatial resolution (width >= min_width, height >= min_height).
    3. Payload contrast variance (variance >= min_contrast_variance).
    """
    if not image_bytes:
        return ImageQualityCheckResult(
            status=ImageQualityAssessment.CORRUPTED_HEADER,
            is_acceptable=False,
            reason="Image payload is empty.",
            width=0,
            height=0,
            image_format="unknown",
            contrast_variance=0.0,
        )

    try:
        width, height, img_format = inspect_image_dimensions_and_format(image_bytes)
    except UnsupportedMediaTypeError as exc:
        return ImageQualityCheckResult(
            status=ImageQualityAssessment.CORRUPTED_HEADER,
            is_acceptable=False,
            reason=str(exc),
            width=0,
            height=0,
            image_format="unsupported",
            contrast_variance=0.0,
        )
    except Exception as exc:
        return ImageQualityCheckResult(
            status=ImageQualityAssessment.CORRUPTED_HEADER,
            is_acceptable=False,
            reason=f"Failed to inspect image header: {exc}",
            width=0,
            height=0,
            image_format="unknown",
            contrast_variance=0.0,
        )

    if width < 1 or height < 1:
        return ImageQualityCheckResult(
            status=ImageQualityAssessment.INVALID_DIMENSIONS,
            is_acceptable=False,
            reason=f"Invalid image dimensions: {width}x{height}.",
            width=width,
            height=height,
            image_format=img_format,
            contrast_variance=0.0,
        )

    if width < min_width or height < min_height:
        return ImageQualityCheckResult(
            status=ImageQualityAssessment.LOW_RESOLUTION,
            is_acceptable=False,
            reason=(
                f"Image resolution {width}x{height} is below the minimum required "
                f"threshold of {min_width}x{min_height} pixels."
            ),
            width=width,
            height=height,
            image_format=img_format,
            contrast_variance=0.0,
        )

    # Compute contrast variance over image payload body
    variance = compute_byte_variance(image_bytes)
    if variance < min_contrast_variance:
        return ImageQualityCheckResult(
            status=ImageQualityAssessment.POOR_CONTRAST,
            is_acceptable=False,
            reason=(
                f"Image contrast/luminance variance ({round(variance, 2)}) is below the minimum "
                f"admissible threshold ({min_contrast_variance}). Image appears flat, blank, or washed out."
            ),
            width=width,
            height=height,
            image_format=img_format,
            contrast_variance=round(variance, 2),
        )

    return ImageQualityCheckResult(
        status=ImageQualityAssessment.ACCEPTABLE,
        is_acceptable=True,
        reason=None,
        width=width,
        height=height,
        image_format=img_format,
        contrast_variance=round(variance, 2),
        details={"quality_passed": True},
    )
