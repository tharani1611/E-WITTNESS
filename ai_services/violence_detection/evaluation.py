"""Evaluation metrics, calibration error, fairness disaggregation, and operational reporting (Phase 68).

Enforces:
- Exact formulas for TP, FP, TN, FN, Precision, Recall, Specificity, FPR, FNR, F1, and Brier Score.
- Expected Calibration Error (ECE) calculation over binned confidence probabilities.
- Explicit evaluation level distinction (clip-level vs window-level vs event temporal localization).
- Multi-threshold sweep analysis for operational reviewer workload vs missed-event trade-offs.
- Governed environmental subgroup disaggregation with sample size reliability thresholds (N >= 30).
- Strict refusal to infer sensitive demographic attributes from video pixels.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

from ai_services.violence_detection.requirements import AI_HUMAN_IN_THE_LOOP_DISCLAIMER
from backend.app.core.ai import EvaluationLevel
from backend.app.core.exceptions import BusinessRuleError

# Strictly prohibited demographic/personal attributes that must never be inferred from video pixels
FORBIDDEN_DEMOGRAPHIC_KEYS: Final[frozenset[str]] = frozenset(
    {
        "race",
        "ethnicity",
        "gender",
        "sex",
        "religion",
        "creed",
        "sexual_orientation",
        "nationality",
        "disability",
        "age",
    }
)

MINIMUM_STATISTICAL_SAMPLE_SIZE: Final[int] = 30


@dataclass(frozen=True)
class ConfusionMatrix:
    """Standard binary classification confusion matrix components."""

    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    total_samples: int


@dataclass(frozen=True)
class MetricSummary:
    """Comprehensive metric evaluation summary with zero-division safety."""

    tp: int
    fp: int
    tn: int
    fn: int
    total: int
    precision: float | None
    recall: float | None
    specificity: float | None
    false_positive_rate: float | None
    false_negative_rate: float | None
    f1_score: float | None
    brier_score: float | None = None
    expected_calibration_error: float | None = None
    is_statistically_reliable: bool = True


@dataclass(frozen=True)
class EvaluationReport:
    """Structured, reproducible evaluation report (Phase 68.6)."""

    report_id: str
    dataset_name: str
    dataset_version: str
    manifest_sha256: str
    model_name: str
    model_version: str
    evaluation_level: EvaluationLevel
    threshold_used: float
    primary_metrics: MetricSummary
    threshold_sweep: dict[str, MetricSummary] = field(default_factory=dict)
    subgroup_metrics: dict[str, dict[str, MetricSummary]] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    reproducibility_hash: str = ""
    disclaimer: str = AI_HUMAN_IN_THE_LOOP_DISCLAIMER


def calculate_classification_metrics(
    y_true: list[int],
    y_pred: list[int],
    y_prob: list[float] | None = None,
) -> MetricSummary:
    """Calculate binary classification metrics with explicit zero-denominator handling.

    y_true: binary ground truth labels (0 or 1)
    y_pred: binary predictions (0 or 1)
    y_prob: optional predicted probabilities [0.0, 1.0] for Brier and ECE computation
    """
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must have identical length.")
    if y_prob is not None and len(y_prob) != len(y_true):
        raise ValueError("y_prob must have identical length to y_true.")

    n = len(y_true)
    if n == 0:
        return MetricSummary(
            tp=0,
            fp=0,
            tn=0,
            fn=0,
            total=0,
            precision=None,
            recall=None,
            specificity=None,
            false_positive_rate=None,
            false_negative_rate=None,
            f1_score=None,
            brier_score=None,
            expected_calibration_error=None,
            is_statistically_reliable=False,
        )

    tp = sum(1 for yt, yp in zip(y_true, y_pred, strict=False) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred, strict=False) if yt == 0 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred, strict=False) if yt == 0 and yp == 0)
    fn = sum(1 for yt, yp in zip(y_true, y_pred, strict=False) if yt == 1 and yp == 0)

    # Precision = TP / (TP + FP)
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else None

    # Recall (Sensitivity, TPR) = TP / (TP + FN)
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else None

    # Specificity (TNR) = TN / (TN + FP)
    specificity = (tn / (tn + fp)) if (tn + fp) > 0 else None

    # False Positive Rate = FP / (FP + TN)
    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else None

    # False Negative Rate = FN / (FN + TP)
    fnr = (fn / (fn + tp)) if (fn + tp) > 0 else None

    # F1 Score = 2 * P * R / (P + R)
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = 2 * (precision * recall) / (precision + recall)
    else:
        f1 = None

    # Brier Score = (1/N) * sum((p_i - y_i)^2)
    brier = None
    ece = None
    if y_prob is not None and n > 0:
        brier = sum((p - y) ** 2 for p, y in zip(y_prob, y_true, strict=False)) / n
        ece = calculate_expected_calibration_error(y_true, y_prob)

    is_reliable = n >= MINIMUM_STATISTICAL_SAMPLE_SIZE

    return MetricSummary(
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        total=n,
        precision=round(precision, 4) if precision is not None else None,
        recall=round(recall, 4) if recall is not None else None,
        specificity=round(specificity, 4) if specificity is not None else None,
        false_positive_rate=round(fpr, 4) if fpr is not None else None,
        false_negative_rate=round(fnr, 4) if fnr is not None else None,
        f1_score=round(f1, 4) if f1 is not None else None,
        brier_score=round(brier, 4) if brier is not None else None,
        expected_calibration_error=round(ece, 4) if ece is not None else None,
        is_statistically_reliable=is_reliable,
    )


def calculate_expected_calibration_error(
    y_true: list[int],
    y_prob: list[float],
    n_bins: int = 10,
) -> float:
    """Calculate Expected Calibration Error (ECE) with equal-width confidence bins."""
    n = len(y_true)
    if n == 0 or n_bins <= 0:
        return 0.0

    bin_boundaries = [i / n_bins for i in range(n_bins + 1)]
    ece = 0.0

    for i in range(n_bins):
        low, high = bin_boundaries[i], bin_boundaries[i + 1]
        # Include upper boundary in last bin
        if i == n_bins - 1:
            indices = [idx for idx, p in enumerate(y_prob) if low <= p <= high]
        else:
            indices = [idx for idx, p in enumerate(y_prob) if low <= p < high]

        bin_size = len(indices)
        if bin_size > 0:
            bin_acc = sum(y_true[idx] for idx in indices) / bin_size
            bin_conf = sum(y_prob[idx] for idx in indices) / bin_size
            ece += (bin_size / n) * abs(bin_acc - bin_conf)

    return ece


def evaluate_threshold_sweep(
    y_true: list[int],
    y_scores: list[float],
    thresholds: list[float] | None = None,
) -> dict[str, MetricSummary]:
    """Evaluate performance across an array of decision thresholds to expose precision/recall trade-offs."""
    if thresholds is None:
        thresholds = [0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80]

    sweep_results: dict[str, MetricSummary] = {}
    for t in sorted(thresholds):
        y_pred = [1 if s >= t else 0 for s in y_scores]
        key = f"threshold_{t:.2f}"
        sweep_results[key] = calculate_classification_metrics(y_true, y_pred, y_scores)

    return sweep_results


def evaluate_fairness_subgroups(
    y_true: list[int],
    y_pred: list[int],
    subgroup_annotations: dict[str, list[str]],
    y_prob: list[float] | None = None,
) -> dict[str, dict[str, MetricSummary]]:
    """Compute disaggregated metrics across authorized environmental subgroups (Phase 68.5).

    Rejects attempts to evaluate against unverified or prohibited personal demographic categories.
    """
    for group_key in subgroup_annotations:
        normalized_key = group_key.lower().strip()
        if normalized_key in FORBIDDEN_DEMOGRAPHIC_KEYS:
            raise BusinessRuleError(
                f"Prohibited demographic attribute '{group_key}': E-WITNESS strictly forbids "
                f"inferring or disaggregating by sensitive personal demographics from video pixels."
            )

    disaggregated: dict[str, dict[str, MetricSummary]] = {}
    n = len(y_true)

    for group_name, labels in subgroup_annotations.items():
        if len(labels) != n:
            raise ValueError(
                f"Subgroup '{group_name}' label length ({len(labels)}) does not match sample count ({n})"
            )

        unique_labels = sorted(set(labels))
        group_results: dict[str, MetricSummary] = {}

        for val in unique_labels:
            indices = [i for i, lbl in enumerate(labels) if lbl == val]
            sub_y_true = [y_true[i] for i in indices]
            sub_y_pred = [y_pred[i] for i in indices]
            sub_y_prob = [y_prob[i] for i in indices] if y_prob is not None else None

            group_results[val] = calculate_classification_metrics(
                sub_y_true, sub_y_pred, sub_y_prob
            )

        disaggregated[group_name] = group_results

    return disaggregated


def generate_reproducibility_hash(report_dict: dict[str, Any]) -> str:
    """Generate SHA-256 fingerprint over canonical evaluation metrics."""
    serialized = json.dumps(report_dict, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
