"""Biometric accuracy, fairness, and presentation-attack evaluation engine (Phase 79).

Enforces:
- Standard biometric performance metrics: FMR, FNMR, FTA, and DET sweep.
- ISO/IEC 30107-3 compliant Presentation Attack Detection (PAD) simulation (APCER, BPCER).
- Demographic subgroup disparity analysis with mandatory synthetic data limitation warnings.
- Explicit non-go production matching advisory disclaimers on all evaluation reports.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Final

SYNTHETIC_BENCHMARK_DISCLAIMER: Final[str] = (
    "SYNTHETIC BENCHMARK EVALUATION ONLY: This evaluation was executed using synthetic and "
    "mock benchmark datasets. It does NOT establish real-world operational accuracy, "
    "demographic parity across human subpopulations, or clinical/legal reliability. "
    "Production matching in E-WITNESS remains strictly prohibited under policy (NO-GO)."
)


@dataclass(frozen=True)
class DetectionErrorTradeoffPoint:
    """Single operating point on a Detection Error Tradeoff (DET) / ROC curve."""

    threshold: float
    fmr: float  # False Match Rate (False Positive Rate)
    fnmr: float  # False Non-Match Rate (False Negative Rate)
    tp: int
    fp: int
    tn: int
    fn: int


@dataclass(frozen=True)
class PresentationAttackMetrics:
    """Presentation Attack Detection (PAD) performance metrics (ISO/IEC 30107-3)."""

    apcer: float  # Attack Presentation Classification Error Rate (attacks classified as bona fide)
    bpcer: float  # Bona Fide Presentation Classification Error Rate (bona fide rejected as attacks)
    total_attack_presentations: int
    total_bona_fide_presentations: int
    attacks_misclassified: int
    bona_fide_misclassified: int


@dataclass(frozen=True)
class DemographicDisparityMetrics:
    """Subgroup-specific error rates and disparity ratios."""

    subgroup_name: str
    sample_count: int
    subgroup_fmr: float
    subgroup_fnmr: float
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BiometricEvaluationReportData:
    """Comprehensive biometric evaluation report encompassing accuracy, fairness, and PAD."""

    model_name: str
    model_version: str
    total_comparisons: int
    fta_rate: float  # Failure to Acquire rate
    eer: float  # Equal Error Rate
    eer_threshold: float
    operational_fmr_at_085: float
    operational_fnmr_at_085: float
    det_curve: list[DetectionErrorTradeoffPoint]
    pad_metrics: PresentationAttackMetrics | None
    demographic_disparities: list[DemographicDisparityMetrics]
    max_demographic_disparity_ratio: float
    disclaimer: str = SYNTHETIC_BENCHMARK_DISCLAIMER

    def to_dict(self) -> dict[str, Any]:
        """Serialize report to a dictionary."""
        return asdict(self)


def calculate_confusion_at_threshold(
    pairs: list[tuple[bool, float]],
    threshold: float,
) -> tuple[int, int, int, int]:
    """Calculate TP, FP, TN, FN given pairs of (is_same_identity, similarity_score)."""
    tp = fp = tn = fn = 0
    for is_same, score in pairs:
        is_predicted_match = score >= threshold
        if is_same and is_predicted_match:
            tp += 1
        elif not is_same and is_predicted_match:
            fp += 1
        elif not is_same and not is_predicted_match:
            tn += 1
        else:
            fn += 1
    return tp, fp, tn, fn


def evaluate_biometric_matching_benchmark(
    comparison_pairs: list[tuple[bool, float]],
    *,
    model_name: str = "mock-face-matcher",
    model_version: str = "1.0.0-test",
    threshold_step: float = 0.05,
    failed_acquisitions: int = 0,
    total_acquisition_attempts: int | None = None,
    presentation_attack_data: tuple[int, int, int, int] | None = None,
    subgroup_comparisons: dict[str, list[tuple[bool, float]]] | None = None,
) -> BiometricEvaluationReportData:
    """Evaluate matching benchmark performance and generate a full audit report.

    Args:
        comparison_pairs: List of tuples (is_same_identity, similarity_score).
        model_name: Identifier of model evaluated.
        model_version: Version of model evaluated.
        threshold_step: Step size for threshold sweep between 0.0 and 1.0.
        failed_acquisitions: Number of samples rejected by quality checks.
        total_acquisition_attempts: Total input attempts (defaults to failed + comparisons).
        presentation_attack_data: Optional tuple of (total_attacks, attacks_misclassified,
            total_bona_fide, bona_fide_misclassified).
        subgroup_comparisons: Optional mapping of subgroup name to comparison pairs.
    """
    if not comparison_pairs:
        raise ValueError("comparison_pairs cannot be empty.")

    total_comps = len(comparison_pairs)
    total_attempts = total_acquisition_attempts or (total_comps + failed_acquisitions)
    fta_rate = failed_acquisitions / total_attempts if total_attempts > 0 else 0.0

    # Sweep thresholds to generate DET / ROC curve
    det_points: list[DetectionErrorTradeoffPoint] = []
    current_th = 0.0
    min_eer_diff = float("inf")
    eer = 0.0
    eer_th = 0.5

    while current_th <= 1.0001:
        th = round(current_th, 4)
        tp, fp, tn, fn = calculate_confusion_at_threshold(comparison_pairs, th)

        fmr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnmr = fn / (tp + fn) if (tp + fn) > 0 else 0.0

        det_points.append(
            DetectionErrorTradeoffPoint(
                threshold=th,
                fmr=round(fmr, 4),
                fnmr=round(fnmr, 4),
                tp=tp,
                fp=fp,
                tn=tn,
                fn=fn,
            )
        )

        diff = abs(fmr - fnmr)
        if diff < min_eer_diff:
            min_eer_diff = diff
            eer = round((fmr + fnmr) / 2.0, 4)
            eer_th = th

        current_th += threshold_step

    # Operational point at 0.85 threshold (upper bound of uncertainty band)
    tp_85, fp_85, tn_85, fn_85 = calculate_confusion_at_threshold(comparison_pairs, 0.85)
    fmr_85 = fp_85 / (fp_85 + tn_85) if (fp_85 + tn_85) > 0 else 0.0
    fnmr_85 = fn_85 / (tp_85 + fn_85) if (tp_85 + fn_85) > 0 else 0.0

    # Presentation Attack Detection (PAD) simulation
    pad_metrics: PresentationAttackMetrics | None = None
    if presentation_attack_data is not None:
        n_att, mis_att, n_bf, mis_bf = presentation_attack_data
        apcer = mis_att / n_att if n_att > 0 else 0.0
        bpcer = mis_bf / n_bf if n_bf > 0 else 0.0
        pad_metrics = PresentationAttackMetrics(
            apcer=round(apcer, 4),
            bpcer=round(bpcer, 4),
            total_attack_presentations=n_att,
            total_bona_fide_presentations=n_bf,
            attacks_misclassified=mis_att,
            bona_fide_misclassified=mis_bf,
        )

    # Subgroup disparity analysis
    subgroup_results: list[DemographicDisparityMetrics] = []
    fmr_values: list[float] = []

    if subgroup_comparisons:
        for grp_name, grp_pairs in subgroup_comparisons.items():
            if not grp_pairs:
                continue
            tp_g, fp_g, tn_g, fn_g = calculate_confusion_at_threshold(grp_pairs, 0.85)
            grp_fmr = fp_g / (fp_g + tn_g) if (fp_g + tn_g) > 0 else 0.0
            grp_fnmr = fn_g / (tp_g + fn_g) if (tp_g + fn_g) > 0 else 0.0

            subgroup_results.append(
                DemographicDisparityMetrics(
                    subgroup_name=grp_name,
                    sample_count=len(grp_pairs),
                    subgroup_fmr=round(grp_fmr, 4),
                    subgroup_fnmr=round(grp_fnmr, 4),
                )
            )
            fmr_values.append(grp_fmr)

    max_ratio = 1.0
    if len(fmr_values) >= 2:
        max_fmr = max(fmr_values)
        min_fmr = min(fmr_values)
        if min_fmr > 0.0:
            max_ratio = round(max_fmr / min_fmr, 2)
        elif max_fmr > 0.0:
            max_ratio = float("inf")

    return BiometricEvaluationReportData(
        model_name=model_name,
        model_version=model_version,
        total_comparisons=total_comps,
        fta_rate=round(fta_rate, 4),
        eer=eer,
        eer_threshold=eer_th,
        operational_fmr_at_085=round(fmr_85, 4),
        operational_fnmr_at_085=round(fnmr_85, 4),
        det_curve=det_points,
        pad_metrics=pad_metrics,
        demographic_disparities=subgroup_results,
        max_demographic_disparity_ratio=max_ratio,
    )
