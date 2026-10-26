"""Statistical confidence calibration and uncertainty handling for video AI (Phase 67).

Enforces:
- Explicit distinction between raw logits, uncalibrated probabilities, calibrated probabilities,
  decision thresholds, and uncertainty states.
- Reusable calibration interface supporting Platt scaling, Temperature scaling, and Isotonic regression.
- Strict data-leakage prevention (rejecting calibration fitting on evaluation/test splits).
- Model-version compatibility checks rejecting cross-architecture artifact reuse.
- Explicit epistemic uncertainty states for borderline, non-finite, and uncalibrated scores.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from ai_services.violence_detection.requirements import AI_HUMAN_IN_THE_LOOP_DISCLAIMER
from backend.app.core.ai import (
    CalibrationMethod,
    CalibrationStatus,
    UncertaintyStatus,
)
from backend.app.core.exceptions import CalibrationIncompatibilityError


@dataclass(frozen=True)
class CalibratedOutput:
    """Structured result containing both raw score and calibrated probability with uncertainty verdict."""

    raw_score: float
    calibrated_score: float
    calibration_status: CalibrationStatus
    uncertainty_status: UncertaintyStatus
    calibration_version: str | None
    is_flagged_for_review: bool
    disclaimer: str = AI_HUMAN_IN_THE_LOOP_DISCLAIMER


@dataclass(frozen=True)
class CalibrationArtifact:
    """Immutable metadata record for a fitted calibration artifact (Phase 67.3)."""

    artifact_id: str
    method: CalibrationMethod
    model_name: str
    model_version: str
    dataset_name: str
    manifest_sha256: str
    split_name: str
    parameters: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, float] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    is_approved: bool = True

    def validate_compatibility(self, model_name: str, model_version: str) -> None:
        """Validate that the calibration artifact matches the active inference model."""
        if self.model_name != model_name or self.model_version != model_version:
            raise CalibrationIncompatibilityError(
                f"Calibration artifact {self.artifact_id} was trained on "
                f"{self.model_name}:{self.model_version}, incompatible with active model "
                f"{model_name}:{model_version}."
            )
        split = self.split_name.lower().strip()
        if split in {"test", "eval", "evaluation", "final_test"}:
            raise CalibrationIncompatibilityError(
                f"Data leakage prevented: Calibration artifact {self.artifact_id} was fitted on "
                f"test/evaluation split '{self.split_name}'. Calibration must use a dedicated validation split."
            )


@runtime_checkable
class VideoConfidenceCalibrator(Protocol):
    """Protocol defining the interface for confidence calibration engines."""

    def calibrate(
        self,
        raw_score: float,
        *,
        threshold: float = 0.50,
        borderline_delta: float = 0.05,
    ) -> CalibratedOutput:
        """Transform raw model score into calibrated probability and evaluate uncertainty."""
        ...


def validate_score_is_finite(score: float) -> None:
    """Reject NaN, +Inf, -Inf scores."""
    if math.isnan(score) or math.isinf(score):
        raise ValueError(f"Score must be a finite float, got: {score}")


def evaluate_uncertainty(
    score: float,
    *,
    threshold: float = 0.50,
    borderline_delta: float = 0.05,
    is_calibrated: bool = True,
) -> tuple[UncertaintyStatus, bool]:
    """Evaluate uncertainty verdict and review flagging based on decision boundaries.

    Returns:
        tuple of (UncertaintyStatus, is_flagged_for_review)
    """
    if math.isnan(score) or math.isinf(score):
        return UncertaintyStatus.UNCERTAIN, True

    if not is_calibrated:
        return UncertaintyStatus.UNCALIBRATED, score >= threshold

    # Score within [threshold - delta, threshold + delta] is ambiguous
    if abs(score - threshold) <= borderline_delta:
        return UncertaintyStatus.BORDERLINE, True

    if score >= threshold:
        return UncertaintyStatus.HIGH_CONFIDENCE, True

    return UncertaintyStatus.LOW_CONFIDENCE, False


class PlattScalingCalibrator:
    """Logistic sigmoid calibrator using Platt scaling: P(y=1|s) = 1 / (1 + exp(-(A*s + B)))."""

    def __init__(self, artifact: CalibrationArtifact) -> None:
        if artifact.method != CalibrationMethod.PLATT_SCALING:
            raise CalibrationIncompatibilityError(
                f"PlattScalingCalibrator requires PLATT_SCALING method, got {artifact.method}"
            )
        self.artifact = artifact
        self.slope: float = float(artifact.parameters.get("slope", 1.0))
        self.intercept: float = float(artifact.parameters.get("intercept", 0.0))

    def calibrate(
        self,
        raw_score: float,
        *,
        threshold: float = 0.50,
        borderline_delta: float = 0.05,
    ) -> CalibratedOutput:
        validate_score_is_finite(raw_score)

        # Bounded logistic sigmoid
        z = self.slope * raw_score + self.intercept
        # Prevent math overflow for extreme logits
        if z > 35.0:
            calibrated = 1.0
        elif z < -35.0:
            calibrated = 0.0
        else:
            calibrated = 1.0 / (1.0 + math.exp(-z))

        calibrated = max(0.0, min(1.0, calibrated))

        uncertainty_status, is_flagged = evaluate_uncertainty(
            calibrated,
            threshold=threshold,
            borderline_delta=borderline_delta,
            is_calibrated=True,
        )

        return CalibratedOutput(
            raw_score=raw_score,
            calibrated_score=round(calibrated, 4),
            calibration_status=CalibrationStatus.CALIBRATED,
            uncertainty_status=uncertainty_status,
            calibration_version=self.artifact.artifact_id,
            is_flagged_for_review=is_flagged,
        )


class TemperatureScalingCalibrator:
    """Temperature scaling calibrator: scales logit by 1/T before sigmoid."""

    def __init__(self, artifact: CalibrationArtifact) -> None:
        if artifact.method != CalibrationMethod.TEMPERATURE_SCALING:
            raise CalibrationIncompatibilityError(
                f"TemperatureScalingCalibrator requires TEMPERATURE_SCALING method, got {artifact.method}"
            )
        self.artifact = artifact
        self.temperature: float = float(artifact.parameters.get("temperature", 1.0))
        if self.temperature <= 0.0:
            raise ValueError(f"Temperature parameter T must be positive, got {self.temperature}")

    def calibrate(
        self,
        raw_score: float,
        *,
        threshold: float = 0.50,
        borderline_delta: float = 0.05,
    ) -> CalibratedOutput:
        validate_score_is_finite(raw_score)

        # Convert raw probability in (0, 1) to logit, then scale by T
        clipped_p = max(1e-6, min(1.0 - 1e-6, raw_score))
        logit = math.log(clipped_p / (1.0 - clipped_p))
        scaled_logit = logit / self.temperature

        if scaled_logit > 35.0:
            calibrated = 1.0
        elif scaled_logit < -35.0:
            calibrated = 0.0
        else:
            calibrated = 1.0 / (1.0 + math.exp(-scaled_logit))

        calibrated = max(0.0, min(1.0, calibrated))

        uncertainty_status, is_flagged = evaluate_uncertainty(
            calibrated,
            threshold=threshold,
            borderline_delta=borderline_delta,
            is_calibrated=True,
        )

        return CalibratedOutput(
            raw_score=raw_score,
            calibrated_score=round(calibrated, 4),
            calibration_status=CalibrationStatus.CALIBRATED,
            uncertainty_status=uncertainty_status,
            calibration_version=self.artifact.artifact_id,
            is_flagged_for_review=is_flagged,
        )


class IsotonicRegressionCalibrator:
    """Non-parametric monotonic piecewise-linear calibrator."""

    def __init__(self, artifact: CalibrationArtifact) -> None:
        if artifact.method != CalibrationMethod.ISOTONIC_REGRESSION:
            raise CalibrationIncompatibilityError(
                f"IsotonicRegressionCalibrator requires ISOTONIC_REGRESSION method, got {artifact.method}"
            )
        self.artifact = artifact
        self.x_knots: list[float] = [
            float(x) for x in artifact.parameters.get("x_knots", [0.0, 1.0])
        ]
        self.y_knots: list[float] = [
            float(y) for y in artifact.parameters.get("y_knots", [0.0, 1.0])
        ]

        if len(self.x_knots) < 2 or len(self.x_knots) != len(self.y_knots):
            raise ValueError("Isotonic regression knots must have at least 2 coordinate pairs.")

    def calibrate(
        self,
        raw_score: float,
        *,
        threshold: float = 0.50,
        borderline_delta: float = 0.05,
    ) -> CalibratedOutput:
        validate_score_is_finite(raw_score)

        # Piecewise linear interpolation
        if raw_score <= self.x_knots[0]:
            calibrated = self.y_knots[0]
        elif raw_score >= self.x_knots[-1]:
            calibrated = self.y_knots[-1]
        else:
            calibrated = self.y_knots[-1]
            for i in range(len(self.x_knots) - 1):
                x0, x1 = self.x_knots[i], self.x_knots[i + 1]
                if x0 <= raw_score <= x1:
                    y0, y1 = self.y_knots[i], self.y_knots[i + 1]
                    calibrated = y0 if x1 == x0 else y0 + (raw_score - x0) * (y1 - y0) / (x1 - x0)
                    break

        calibrated = max(0.0, min(1.0, calibrated))

        uncertainty_status, is_flagged = evaluate_uncertainty(
            calibrated,
            threshold=threshold,
            borderline_delta=borderline_delta,
            is_calibrated=True,
        )

        return CalibratedOutput(
            raw_score=raw_score,
            calibrated_score=round(calibrated, 4),
            calibration_status=CalibrationStatus.CALIBRATED,
            uncertainty_status=uncertainty_status,
            calibration_version=self.artifact.artifact_id,
            is_flagged_for_review=is_flagged,
        )


class IdentityCalibrator:
    """Default fallback calibrator returning uncalibrated scores with advisory warnings."""

    def __init__(self, *, version: str = "uncalibrated-raw") -> None:
        self.version = version

    def calibrate(
        self,
        raw_score: float,
        *,
        threshold: float = 0.50,
        borderline_delta: float = 0.05,
    ) -> CalibratedOutput:
        validate_score_is_finite(raw_score)

        uncertainty_status, is_flagged = evaluate_uncertainty(
            raw_score,
            threshold=threshold,
            borderline_delta=borderline_delta,
            is_calibrated=False,
        )

        return CalibratedOutput(
            raw_score=raw_score,
            calibrated_score=raw_score,
            calibration_status=CalibrationStatus.UNCALIBRATED,
            uncertainty_status=uncertainty_status,
            calibration_version=None,
            is_flagged_for_review=is_flagged,
        )
