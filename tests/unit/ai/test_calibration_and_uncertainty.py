"""Unit tests for Phase 67: Confidence calibration and uncertainty handling.

Enforces:
- Exact transformation behavior for Platt scaling, Temperature scaling, and Isotonic regression.
- Epistemic uncertainty evaluation across decision boundaries and borderline bands.
- Strict data-leakage prevention (rejecting test and evaluation splits).
- Model-version compatibility verification.
- Rejection of non-finite scores (NaN, Inf).
"""

from __future__ import annotations

import pytest

from ai_services.violence_detection.calibration import (
    CalibrationArtifact,
    IdentityCalibrator,
    IsotonicRegressionCalibrator,
    PlattScalingCalibrator,
    TemperatureScalingCalibrator,
    evaluate_uncertainty,
    validate_score_is_finite,
)
from backend.app.core.ai import (
    CalibrationMethod,
    CalibrationStatus,
    UncertaintyStatus,
)
from backend.app.core.exceptions import CalibrationIncompatibilityError


@pytest.mark.unit
class TestConfidenceCalibrators:
    """Verify statistical calibration implementations and mathematical boundaries."""

    def test_platt_scaling_calibrator_transformation(self) -> None:
        artifact = CalibrationArtifact(
            artifact_id="platt-v1",
            method=CalibrationMethod.PLATT_SCALING,
            model_name="violence-timesformer-b16",
            model_version="1.0.0",
            dataset_name="rwf-2000-val",
            manifest_sha256="a" * 64,
            split_name="validation",
            parameters={"slope": 2.0, "intercept": -1.0},
        )
        calibrator = PlattScalingCalibrator(artifact)

        # At raw_score = 0.5: z = 2.0 * 0.5 - 1.0 = 0.0 -> P = 1 / (1 + 1) = 0.5
        out = calibrator.calibrate(0.5, threshold=0.50, borderline_delta=0.05)
        assert out.calibrated_score == 0.50
        assert out.calibration_status == CalibrationStatus.CALIBRATED
        assert out.uncertainty_status == UncertaintyStatus.BORDERLINE
        assert out.is_flagged_for_review is True

        # At raw_score = 1.0: z = 2.0 * 1.0 - 1.0 = 1.0 -> P = 1 / (1 + exp(-1)) = 0.7311
        out_high = calibrator.calibrate(1.0, threshold=0.50, borderline_delta=0.05)
        assert 0.72 < out_high.calibrated_score < 0.74
        assert out_high.uncertainty_status == UncertaintyStatus.HIGH_CONFIDENCE
        assert out_high.is_flagged_for_review is True

        # At raw_score = 0.0: z = 2.0 * 0.0 - 1.0 = -1.0 -> P = 1 / (1 + exp(1)) = 0.2689
        out_low = calibrator.calibrate(0.0, threshold=0.50, borderline_delta=0.05)
        assert 0.26 < out_low.calibrated_score < 0.28
        assert out_low.uncertainty_status == UncertaintyStatus.LOW_CONFIDENCE
        assert out_low.is_flagged_for_review is False

    def test_temperature_scaling_calibrator(self) -> None:
        artifact = CalibrationArtifact(
            artifact_id="temp-v1",
            method=CalibrationMethod.TEMPERATURE_SCALING,
            model_name="violence-timesformer-b16",
            model_version="1.0.0",
            dataset_name="ucf-crime-val",
            manifest_sha256="b" * 64,
            split_name="validation",
            parameters={"temperature": 1.5},
        )
        calibrator = TemperatureScalingCalibrator(artifact)

        # High raw score softened by temperature > 1.0
        out = calibrator.calibrate(0.90, threshold=0.50)
        assert out.calibrated_score < 0.90
        assert out.calibrated_score > 0.50
        assert out.calibration_status == CalibrationStatus.CALIBRATED

    def test_temperature_scaling_rejects_non_positive_temperature(self) -> None:
        artifact = CalibrationArtifact(
            artifact_id="temp-bad",
            method=CalibrationMethod.TEMPERATURE_SCALING,
            model_name="model",
            model_version="1.0",
            dataset_name="dataset",
            manifest_sha256="c" * 64,
            split_name="validation",
            parameters={"temperature": 0.0},
        )
        with pytest.raises(ValueError, match=r"(?i)temperature parameter T must be positive"):
            TemperatureScalingCalibrator(artifact)

    def test_isotonic_regression_calibrator_interpolation(self) -> None:
        artifact = CalibrationArtifact(
            artifact_id="isotonic-v1",
            method=CalibrationMethod.ISOTONIC_REGRESSION,
            model_name="model",
            model_version="1.0",
            dataset_name="dataset",
            manifest_sha256="d" * 64,
            split_name="validation",
            parameters={
                "x_knots": [0.0, 0.4, 0.6, 1.0],
                "y_knots": [0.0, 0.2, 0.8, 1.0],
            },
        )
        calibrator = IsotonicRegressionCalibrator(artifact)

        # At boundary x=0.0 -> y=0.0
        assert calibrator.calibrate(0.0).calibrated_score == 0.0
        # At boundary x=1.0 -> y=1.0
        assert calibrator.calibrate(1.0).calibrated_score == 1.0
        # Midpoint of [0.4, 0.6] -> raw=0.5 -> y=0.5
        assert calibrator.calibrate(0.5).calibrated_score == 0.5

    def test_isotonic_regression_rejects_invalid_knots(self) -> None:
        artifact = CalibrationArtifact(
            artifact_id="isotonic-bad",
            method=CalibrationMethod.ISOTONIC_REGRESSION,
            model_name="model",
            model_version="1.0",
            dataset_name="dataset",
            manifest_sha256="e" * 64,
            split_name="validation",
            parameters={"x_knots": [0.0], "y_knots": [0.0]},
        )
        with pytest.raises(ValueError, match="at least 2 coordinate pairs"):
            IsotonicRegressionCalibrator(artifact)

    def test_identity_calibrator_returns_uncalibrated_status(self) -> None:
        calibrator = IdentityCalibrator()
        out = calibrator.calibrate(0.68, threshold=0.50)
        assert out.calibrated_score == 0.68
        assert out.calibration_status == CalibrationStatus.UNCALIBRATED
        assert out.uncertainty_status == UncertaintyStatus.UNCALIBRATED
        assert out.calibration_version is None
        assert out.is_flagged_for_review is True


@pytest.mark.unit
class TestCalibrationSafetyAndUncertainty:
    """Verify safety invariants: data-leakage prevention, non-finite score checks, and version checks."""

    def test_rejects_test_split_for_calibration_fitting(self) -> None:
        for forbidden_split in ["test", "eval", "evaluation", "final_test"]:
            artifact = CalibrationArtifact(
                artifact_id="artifact-leak",
                method=CalibrationMethod.PLATT_SCALING,
                model_name="model",
                model_version="1.0",
                dataset_name="dataset",
                manifest_sha256="f" * 64,
                split_name=forbidden_split,
            )
            with pytest.raises(CalibrationIncompatibilityError, match="Data leakage prevented"):
                artifact.validate_compatibility("model", "1.0")

    def test_rejects_model_architecture_and_version_mismatches(self) -> None:
        artifact = CalibrationArtifact(
            artifact_id="artifact-mismatch",
            method=CalibrationMethod.PLATT_SCALING,
            model_name="timesformer-b16",
            model_version="1.0.0",
            dataset_name="dataset",
            manifest_sha256="a" * 64,
            split_name="validation",
        )
        # Mismatched model name
        with pytest.raises(CalibrationIncompatibilityError, match="incompatible with active model"):
            artifact.validate_compatibility("mobilenet-v2", "1.0.0")

        # Mismatched model version
        with pytest.raises(CalibrationIncompatibilityError, match="incompatible with active model"):
            artifact.validate_compatibility("timesformer-b16", "2.0.0")

    def test_rejects_non_finite_scores(self) -> None:
        with pytest.raises(ValueError, match="Score must be a finite float"):
            validate_score_is_finite(float("nan"))
        with pytest.raises(ValueError, match="Score must be a finite float"):
            validate_score_is_finite(float("inf"))
        with pytest.raises(ValueError, match="Score must be a finite float"):
            validate_score_is_finite(float("-inf"))

    def test_uncertainty_verdicts_for_borderline_and_uncertain(self) -> None:
        # Borderline band: within [0.45, 0.55] for threshold=0.50 and delta=0.05
        status, flagged = evaluate_uncertainty(
            0.48, threshold=0.50, borderline_delta=0.05, is_calibrated=True
        )
        assert status == UncertaintyStatus.BORDERLINE
        assert flagged is True

        # Non-finite score returns UNCERTAIN and flags for human review
        status_nan, flagged_nan = evaluate_uncertainty(
            float("nan"), threshold=0.50, is_calibrated=True
        )
        assert status_nan == UncertaintyStatus.UNCERTAIN
        assert flagged_nan is True

        # Uncalibrated score returns UNCALIBRATED
        status_uncal, flagged_uncal = evaluate_uncertainty(
            0.60, threshold=0.50, is_calibrated=False
        )
        assert status_uncal == UncertaintyStatus.UNCALIBRATED
        assert flagged_uncal is True
