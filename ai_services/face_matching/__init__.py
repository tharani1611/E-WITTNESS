"""Biometric face feature extraction, matching, quality assessment, and evaluation engine (Phases 76-79).

Enforces:
- Disabled-by-default posture with fail-closed security.
- Explicit non-binary uncertainty bands and mandatory statutory disclaimers.
- Pre-matching image quality verification.
- Reproducible FMR, FNMR, FTA, DET/ROC, and PAD metric calculations.
"""

from __future__ import annotations

from ai_services.face_matching.evaluation import (
    BiometricEvaluationReportData,
    DemographicDisparityMetrics,
    DetectionErrorTradeoffPoint,
    PresentationAttackMetrics,
    evaluate_biometric_matching_benchmark,
)
from ai_services.face_matching.protocol import (
    DisabledFaceMatcherProvider,
    FaceFeatureVector,
    FaceMatcherProtocol,
    LocalFaceMatcherProvider,
    MatchCandidateResult,
    MockFaceMatcherProvider,
    get_face_matcher,
)
from ai_services.face_matching.quality import (
    ImageQualityCheckResult,
    assess_face_image_quality,
)

__all__ = [
    "BiometricEvaluationReportData",
    "DemographicDisparityMetrics",
    "DetectionErrorTradeoffPoint",
    "DisabledFaceMatcherProvider",
    "FaceFeatureVector",
    "FaceMatcherProtocol",
    "ImageQualityCheckResult",
    "LocalFaceMatcherProvider",
    "MatchCandidateResult",
    "MockFaceMatcherProvider",
    "PresentationAttackMetrics",
    "assess_face_image_quality",
    "evaluate_biometric_matching_benchmark",
    "get_face_matcher",
]
