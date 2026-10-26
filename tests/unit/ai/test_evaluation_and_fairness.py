"""Unit tests for Phase 68: Evaluation metrics, calibration error, fairness disaggregation, and reporting.

Enforces:
- Exact mathematical formulas for binary classification metrics with zero-denominator safety.
- Expected Calibration Error (ECE) and Brier Score computation.
- Multi-threshold sweep analysis for operational trade-off visualization.
- Strict refusal to evaluate against prohibited demographic attributes.
- Sample size reliability thresholds (N >= 30) for disaggregated evaluations.
- Reproducibility hashing over canonical evaluation results.
"""

from __future__ import annotations

import pytest

from ai_services.violence_detection.evaluation import (
    calculate_classification_metrics,
    calculate_expected_calibration_error,
    evaluate_fairness_subgroups,
    evaluate_threshold_sweep,
    generate_reproducibility_hash,
)
from backend.app.core.exceptions import BusinessRuleError


@pytest.mark.unit
class TestEvaluationMetricsComputation:
    """Verify exact formula calculations and division-by-zero boundary protections."""

    def test_known_confusion_matrix_metrics(self) -> None:
        # y_true: [1, 1, 0, 0], y_pred: [1, 0, 0, 1]
        # TP = 1, FP = 1, TN = 1, FN = 1
        y_true = [1, 1, 0, 0]
        y_pred = [1, 0, 0, 1]
        y_prob = [0.85, 0.40, 0.20, 0.90]

        metrics = calculate_classification_metrics(y_true, y_pred, y_prob)

        assert metrics.tp == 1
        assert metrics.fp == 1
        assert metrics.tn == 1
        assert metrics.fn == 1
        assert metrics.total == 4
        assert metrics.precision == 0.50
        assert metrics.recall == 0.50
        assert metrics.specificity == 0.50
        assert metrics.false_positive_rate == 0.50
        assert metrics.false_negative_rate == 0.50
        assert metrics.f1_score == 0.50
        assert metrics.is_statistically_reliable is False  # N = 4 < 30

        # Brier score: ((0.85-1)^2 + (0.4-1)^2 + (0.2-0)^2 + (0.9-0)^2) / 4
        # = (0.0225 + 0.36 + 0.04 + 0.81) / 4 = 1.2325 / 4 = 0.3081
        assert metrics.brier_score is not None
        assert 0.30 < metrics.brier_score < 0.32

    def test_zero_denominator_boundary_safety(self) -> None:
        # No predicted positives: TP=0, FP=0 -> Precision is None, not division by zero
        y_true = [0, 0, 0]
        y_pred = [0, 0, 0]
        metrics = calculate_classification_metrics(y_true, y_pred)

        assert metrics.tp == 0
        assert metrics.fp == 0
        assert metrics.tn == 3
        assert metrics.fn == 0
        assert metrics.precision is None
        assert metrics.recall is None
        assert metrics.specificity == 1.0
        assert metrics.f1_score is None

    def test_empty_sample_list_handling(self) -> None:
        metrics = calculate_classification_metrics([], [])
        assert metrics.total == 0
        assert metrics.precision is None
        assert metrics.is_statistically_reliable is False

    def test_mismatched_vector_lengths_raise_value_error(self) -> None:
        with pytest.raises(ValueError, match="identical length"):
            calculate_classification_metrics([1, 0], [1])


@pytest.mark.unit
class TestExpectedCalibrationError:
    """Verify binned Expected Calibration Error (ECE) calculations."""

    def test_perfect_calibration_produces_zero_ece(self) -> None:
        # All confidence probabilities exactly equal accuracy in their bins
        y_true = [1, 1, 0, 0]
        y_prob = [1.0, 1.0, 0.0, 0.0]
        ece = calculate_expected_calibration_error(y_true, y_prob, n_bins=2)
        assert ece == 0.0

    def test_uncalibrated_overconfident_ece(self) -> None:
        # Overconfident predictions on false labels
        y_true = [0, 0, 0, 0]
        y_prob = [0.99, 0.95, 0.92, 0.90]
        ece = calculate_expected_calibration_error(y_true, y_prob, n_bins=5)
        assert ece > 0.80


@pytest.mark.unit
class TestThresholdSweepAndWorkloadTradeoff:
    """Verify multi-threshold evaluation exposing precision-recall trade-offs."""

    def test_threshold_sweep_monotonic_behavior(self) -> None:
        y_true = [1, 1, 1, 0, 0, 0]
        y_scores = [0.90, 0.70, 0.55, 0.45, 0.30, 0.10]
        thresholds = [0.20, 0.50, 0.80]

        sweep = evaluate_threshold_sweep(y_true, y_scores, thresholds)
        assert len(sweep) == 3

        # At low threshold (0.20): high recall, potential false positives
        t_low = sweep["threshold_0.20"]
        assert t_low.recall == 1.0

        # At high threshold (0.80): high precision, lower recall
        t_high = sweep["threshold_0.80"]
        assert t_high.precision == 1.0
        assert t_high.recall is not None and t_high.recall < 1.0


@pytest.mark.unit
class TestFairnessDisaggregationAndGovernance:
    """Verify governed subgroup metrics, sample reliability thresholds, and demographic bans."""

    def test_environmental_subgroup_disaggregation(self) -> None:
        y_true = [1] * 20 + [0] * 20
        y_pred = [1] * 18 + [0] * 2 + [0] * 19 + [1] * 1
        lighting = ["low_light"] * 20 + ["normal_light"] * 20

        disaggregated = evaluate_fairness_subgroups(
            y_true,
            y_pred,
            {"lighting_condition": lighting},
        )

        assert "lighting_condition" in disaggregated
        assert "low_light" in disaggregated["lighting_condition"]
        assert "normal_light" in disaggregated["lighting_condition"]

        low_metrics = disaggregated["lighting_condition"]["low_light"]
        assert low_metrics.total == 20
        assert low_metrics.is_statistically_reliable is False  # N=20 < 30

    def test_large_sample_size_marks_reliable(self) -> None:
        y_true = [1] * 35 + [0] * 35
        y_pred = [1] * 35 + [0] * 35
        lighting = ["normal"] * 70

        disaggregated = evaluate_fairness_subgroups(
            y_true,
            y_pred,
            {"lighting": lighting},
        )
        assert disaggregated["lighting"]["normal"].is_statistically_reliable is True

    def test_strictly_rejects_sensitive_demographic_attributes(self) -> None:
        y_true = [1, 0]
        y_pred = [1, 0]

        for forbidden in ["race", "gender", "ethnicity", "religion", "sexual_orientation"]:
            with pytest.raises(BusinessRuleError, match="strictly forbids"):
                evaluate_fairness_subgroups(
                    y_true,
                    y_pred,
                    {forbidden: ["group_a", "group_b"]},
                )

    def test_reproducibility_hash_consistency(self) -> None:
        report_data = {
            "dataset": "benchmark-v1",
            "model": "classifier-v1",
            "f1": 0.88,
        }
        h1 = generate_reproducibility_hash(report_data)
        h2 = generate_reproducibility_hash(report_data)
        assert h1 == h2
        assert len(h1) == 64
