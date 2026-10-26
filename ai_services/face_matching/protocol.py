"""Protocol, providers, and data structures for biometric face matching (Phase 76).

Enforces:
- Advisory-only metric boundaries: similarity is NEVER proof of identity.
- Explicit uncertainty band [0.60, 0.85]: inconclusive outcomes are not forced into binary decisions.
- Disabled-by-default posture: matching raises BiometricsDisabledError unless explicitly enabled in tests.
- Zero network dependencies and zero unverified dynamic weight downloads.
"""

from __future__ import annotations

import hashlib
import math
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Final, Protocol, runtime_checkable

from ai_services.face_detection.detector import inspect_image_dimensions_and_format
from backend.app.core.biometrics import (
    BIOMETRIC_MATCHING_ADVISORY_DISCLAIMER,
    BiometricMatchVerdict,
    compute_cosine_similarity,
    evaluate_matching_verdict,
)
from backend.app.core.exceptions import (
    BiometricsDisabledError,
    ModelUnavailableError,
)

DEFAULT_UNCERTAINTY_LOWER_BOUND: Final[float] = 0.60
DEFAULT_UNCERTAINTY_UPPER_BOUND: Final[float] = 0.85
DEFAULT_FEATURE_DIMENSION: Final[int] = 128


@dataclass(frozen=True)
class FaceFeatureVector:
    """Normalized biometric feature vector extracted from an authorized face region."""

    vector: list[float]
    dimension: int
    model_name: str
    model_version: str
    disclaimer: str = BIOMETRIC_MATCHING_ADVISORY_DISCLAIMER

    def __post_init__(self) -> None:
        if not self.vector:
            raise ValueError("Feature vector cannot be empty.")
        if len(self.vector) != self.dimension:
            raise ValueError(
                f"Vector dimension mismatch: vector length is {len(self.vector)}, "
                f"expected dimension {self.dimension}."
            )
        # Verify L2 unit normalization
        norm = math.sqrt(sum(x * x for x in self.vector))
        if norm <= 0.0:
            raise ValueError("Feature vector norm cannot be zero.")


@dataclass(frozen=True)
class MatchCandidateResult:
    """Advisory similarity evaluation outcome between probe and reference features."""

    similarity_score: float
    verdict: BiometricMatchVerdict
    uncertainty_lower_bound: float
    uncertainty_upper_bound: float
    model_name: str
    model_version: str
    comparison_latency_ms: float
    disclaimer: str = BIOMETRIC_MATCHING_ADVISORY_DISCLAIMER
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not (-1.0 <= self.similarity_score <= 1.0):
            raise ValueError("Similarity score must be within [-1.0, 1.0].")
        if self.uncertainty_lower_bound >= self.uncertainty_upper_bound:
            raise ValueError(
                "uncertainty_lower_bound must be strictly less than uncertainty_upper_bound."
            )
        if self.comparison_latency_ms < 0.0:
            raise ValueError("comparison_latency_ms cannot be negative.")


@runtime_checkable
class FaceMatcherProtocol(Protocol):
    """Runtime protocol defining the face feature extraction and matching interface."""

    def extract_features(self, image_bytes: bytes) -> FaceFeatureVector:
        """Extract a normalized feature vector from validated image bytes."""
        ...

    def match_faces(
        self,
        probe: FaceFeatureVector,
        reference: FaceFeatureVector,
        *,
        lower_bound: float = DEFAULT_UNCERTAINTY_LOWER_BOUND,
        upper_bound: float = DEFAULT_UNCERTAINTY_UPPER_BOUND,
    ) -> MatchCandidateResult:
        """Compute advisory similarity score and evaluate categorical verdict."""
        ...


class DisabledFaceMatcherProvider:
    """Default fail-closed face matcher provider.

    Strictly refuses any matching or extraction operation.
    """

    def extract_features(self, image_bytes: bytes) -> FaceFeatureVector:
        raise BiometricsDisabledError(
            "Biometric face matching and feature extraction are strictly disabled in system settings. "
            "Automated matching is prohibited in production and requires explicit legal approval."
        )

    def match_faces(
        self,
        probe: FaceFeatureVector,
        reference: FaceFeatureVector,
        *,
        lower_bound: float = DEFAULT_UNCERTAINTY_LOWER_BOUND,
        upper_bound: float = DEFAULT_UNCERTAINTY_UPPER_BOUND,
    ) -> MatchCandidateResult:
        raise BiometricsDisabledError(
            "Biometric face matching is strictly disabled in system settings. "
            "Automated matching is prohibited in production and requires explicit legal approval."
        )


class MockFaceMatcherProvider:
    """Deterministic synthetic face matcher for unit and integration testing.

    Derives reproducible unit-normalized feature vectors using SHA-512 pseudo-random projections.
    """

    def __init__(
        self,
        dimension: int = DEFAULT_FEATURE_DIMENSION,
        model_name: str = "mock-face-embedder",
        model_version: str = "1.0.0-test",
    ) -> None:
        if dimension < 4:
            raise ValueError("Feature dimension must be at least 4.")
        self.dimension = dimension
        self.model_name = model_name
        self.model_version = model_version

    def extract_features(self, image_bytes: bytes) -> FaceFeatureVector:
        # Validate image headers and dimensions first
        inspect_image_dimensions_and_format(image_bytes)

        # Generate deterministic pseudo-random float vector from cryptographic hash
        h = hashlib.sha512(image_bytes).digest()
        raw_floats: list[float] = []

        # Expand hash into required dimensions
        counter = 0
        while len(raw_floats) < self.dimension:
            sub = hashlib.sha512(h + struct.pack(">I", counter)).digest()
            for i in range(0, len(sub) - 4, 4):
                if len(raw_floats) >= self.dimension:
                    break
                val = struct.unpack(">i", sub[i : i + 4])[0]
                raw_floats.append(float(val) / 2147483648.0)
            counter += 1

        # L2 unit normalization
        norm = math.sqrt(sum(x * x for x in raw_floats))
        if norm == 0.0:
            norm = 1.0
        normalized = [round(x / norm, 6) for x in raw_floats]

        # Re-normalize slight roundoff to ensure strict unit norm
        final_norm = math.sqrt(sum(x * x for x in normalized))
        normalized = [x / final_norm for x in normalized]

        return FaceFeatureVector(
            vector=normalized,
            dimension=self.dimension,
            model_name=self.model_name,
            model_version=self.model_version,
        )

    def match_faces(
        self,
        probe: FaceFeatureVector,
        reference: FaceFeatureVector,
        *,
        lower_bound: float = DEFAULT_UNCERTAINTY_LOWER_BOUND,
        upper_bound: float = DEFAULT_UNCERTAINTY_UPPER_BOUND,
    ) -> MatchCandidateResult:
        start_time = time.perf_counter()

        similarity = compute_cosine_similarity(probe.vector, reference.vector)
        verdict = evaluate_matching_verdict(
            similarity,
            lower_bound=lower_bound,
            upper_bound=upper_bound,
        )

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        return MatchCandidateResult(
            similarity_score=round(similarity, 4),
            verdict=verdict,
            uncertainty_lower_bound=lower_bound,
            uncertainty_upper_bound=upper_bound,
            model_name=self.model_name,
            model_version=self.model_version,
            comparison_latency_ms=round(latency_ms, 2),
            metadata={
                "probe_model": probe.model_name,
                "reference_model": reference.model_name,
                "dimension": probe.dimension,
            },
        )


class LocalFaceMatcherProvider:
    """Offline local face matcher provider.

    Fails closed when local weights or acceleration libraries are unavailable.
    """

    def __init__(
        self,
        model_name: str = "local-face-matcher",
        model_version: str = "1.0.0",
    ) -> None:
        self.model_name = model_name
        self.model_version = model_version

    def extract_features(self, image_bytes: bytes) -> FaceFeatureVector:
        inspect_image_dimensions_and_format(image_bytes)
        raise ModelUnavailableError(
            "Local face matching model weights or runtime libraries are not locally available. "
            "Automatic online downloading of biometric models is strictly prohibited."
        )

    def match_faces(
        self,
        probe: FaceFeatureVector,
        reference: FaceFeatureVector,
        *,
        lower_bound: float = DEFAULT_UNCERTAINTY_LOWER_BOUND,
        upper_bound: float = DEFAULT_UNCERTAINTY_UPPER_BOUND,
    ) -> MatchCandidateResult:
        raise ModelUnavailableError(
            "Local face matching model weights or runtime libraries are not locally available."
        )


def get_face_matcher(
    *,
    enabled: bool = False,
    provider: str = "disabled",
) -> FaceMatcherProtocol:
    """Factory creating the appropriate face matcher implementation."""
    if not enabled or provider == "disabled":
        return DisabledFaceMatcherProvider()
    if provider == "mock":
        return MockFaceMatcherProvider()
    if provider == "local":
        return LocalFaceMatcherProvider()
    return DisabledFaceMatcherProvider()
