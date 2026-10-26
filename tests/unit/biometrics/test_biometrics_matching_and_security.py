"""Comprehensive unit tests for Biometric Matching, Quality, Security, and Evaluation (Phases 76-80).

Verifies:
- Cosine similarity computation, clamping, zero-norm guardrails, and uncertainty band thresholds.
- Protocol implementations: DisabledFaceMatcherProvider, MockFaceMatcherProvider, LocalFaceMatcherProvider.
- Input quality assessment: resolution, contrast variance, header parsing, and fail-closed rejections.
- AES-256-GCM template encryption, envelope formatting, key rotation, and fail-closed key revocation.
- Biometric evaluation engine: FMR, FNMR, FTA, DET sweep, EER, PAD (APCER/BPCER), and demographic disparity.
- Pydantic schemas, validation invariants, and mandatory override reason enforcement.
"""

from __future__ import annotations

import struct
from uuid import uuid4

import pytest

from ai_services.face_matching.evaluation import (
    SYNTHETIC_BENCHMARK_DISCLAIMER,
    calculate_confusion_at_threshold,
    evaluate_biometric_matching_benchmark,
)
from ai_services.face_matching.protocol import (
    DisabledFaceMatcherProvider,
    FaceFeatureVector,
    LocalFaceMatcherProvider,
    MockFaceMatcherProvider,
    get_face_matcher,
)
from ai_services.face_matching.quality import (
    assess_face_image_quality,
)
from backend.app.core.biometric_crypto import (
    ENVELOPE_VERSION,
    BiometricKeyManager,
)
from backend.app.core.biometrics import (
    BIOMETRIC_MATCHING_ADVISORY_DISCLAIMER,
    BiometricHumanVerdict,
    BiometricMatchVerdict,
    ImageQualityAssessment,
    compute_cosine_similarity,
    evaluate_matching_verdict,
)
from backend.app.core.exceptions import (
    BiometricKeyError,
    BiometricKeyRevokedError,
    BiometricsDisabledError,
    ModelUnavailableError,
)
from backend.app.models.biometrics import BiometricVerificationReview
from backend.app.schemas.biometrics import (
    BiometricVerificationReviewCreate,
    FaceMatchRequest,
)


# Helper to generate minimal valid 64x64 PNG bytes
def make_valid_png_bytes(width: int = 64, height: int = 64, fill_byte: int = 120) -> bytes:
    signature = b"\x89PNG\r\n\x1a\n"
    # IHDR chunk: 4 bytes length, 4 bytes "IHDR", 13 bytes data, 4 bytes CRC
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr_chunk = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + b"\x00\x00\x00\x00"
    # Synthetic varied payload to have high contrast variance
    varied_body = bytes([(fill_byte + (i % 80)) % 256 for i in range(256)])
    idat_chunk = struct.pack(">I", len(varied_body)) + b"IDAT" + varied_body + b"\x00\x00\x00\x00"
    iend_chunk = struct.pack(">I", 0) + b"IEND" + b"\x00\x00\x00\x00"
    return signature + ihdr_chunk + idat_chunk + iend_chunk


# =========================================================================
# 1. Mathematical Helpers & Decision Boundaries (Phase 76 & 77)
# =========================================================================


def test_cosine_similarity_identical_vectors() -> None:
    v1 = [1.0, 0.0, 0.0]
    assert compute_cosine_similarity(v1, v1) == pytest.approx(1.0)


def test_cosine_similarity_orthogonal_vectors() -> None:
    v1 = [1.0, 0.0, 0.0]
    v2 = [0.0, 1.0, 0.0]
    assert compute_cosine_similarity(v1, v2) == pytest.approx(0.0)


def test_cosine_similarity_opposite_vectors() -> None:
    v1 = [1.0, 0.0]
    v2 = [-1.0, 0.0]
    assert compute_cosine_similarity(v1, v2) == pytest.approx(-1.0)


def test_cosine_similarity_zero_norm_guard() -> None:
    v1 = [0.0, 0.0]
    v2 = [1.0, 1.0]
    assert compute_cosine_similarity(v1, v2) == 0.0


def test_cosine_similarity_mismatched_dimension() -> None:
    with pytest.raises(ValueError, match="Vector dimension mismatch"):
        compute_cosine_similarity([1.0], [1.0, 2.0])


def test_cosine_similarity_empty_vectors() -> None:
    with pytest.raises(ValueError, match="Feature vectors cannot be empty"):
        compute_cosine_similarity([], [])


def test_evaluate_matching_verdict_three_zones() -> None:
    # Match candidate zone (>= 0.85)
    assert evaluate_matching_verdict(0.95) == BiometricMatchVerdict.MATCH_CANDIDATE
    assert evaluate_matching_verdict(0.85) == BiometricMatchVerdict.MATCH_CANDIDATE

    # Uncertainty zone (0.60 <= score < 0.85)
    assert evaluate_matching_verdict(0.8499) == BiometricMatchVerdict.INCONCLUSIVE_UNCERTAIN
    assert evaluate_matching_verdict(0.72) == BiometricMatchVerdict.INCONCLUSIVE_UNCERTAIN
    assert evaluate_matching_verdict(0.60) == BiometricMatchVerdict.INCONCLUSIVE_UNCERTAIN

    # Non-match candidate zone (< 0.60)
    assert evaluate_matching_verdict(0.5999) == BiometricMatchVerdict.NON_MATCH_CANDIDATE
    assert evaluate_matching_verdict(0.10) == BiometricMatchVerdict.NON_MATCH_CANDIDATE
    assert evaluate_matching_verdict(-0.5) == BiometricMatchVerdict.NON_MATCH_CANDIDATE


def test_evaluate_matching_verdict_invalid_bounds() -> None:
    with pytest.raises(ValueError, match="lower_bound must be strictly less than upper_bound"):
        evaluate_matching_verdict(0.8, lower_bound=0.9, upper_bound=0.7)


# =========================================================================
# 2. Face Matcher Protocol & Providers (Phase 76)
# =========================================================================


def test_disabled_matcher_fails_closed() -> None:
    disabled = DisabledFaceMatcherProvider()
    valid_png = make_valid_png_bytes()

    with pytest.raises(BiometricsDisabledError, match="strictly disabled"):
        disabled.extract_features(valid_png)

    dummy_feat = FaceFeatureVector(
        vector=[1.0, 0.0],
        dimension=2,
        model_name="test",
        model_version="1.0",
    )
    with pytest.raises(BiometricsDisabledError, match="strictly disabled"):
        disabled.match_faces(dummy_feat, dummy_feat)


def test_local_matcher_fails_closed_without_weights() -> None:
    local_matcher = LocalFaceMatcherProvider()
    valid_png = make_valid_png_bytes()

    with pytest.raises(
        ModelUnavailableError, match="weights or runtime libraries are not locally available"
    ):
        local_matcher.extract_features(valid_png)


def test_mock_matcher_deterministic_extraction_and_matching() -> None:
    matcher = MockFaceMatcherProvider(dimension=128)
    png_a = make_valid_png_bytes(64, 64, fill_byte=10)
    png_b = make_valid_png_bytes(64, 64, fill_byte=200)

    vec_a1 = matcher.extract_features(png_a)
    vec_a2 = matcher.extract_features(png_a)
    vec_b = matcher.extract_features(png_b)

    # Determinism: same image produces identical feature vector
    assert vec_a1.vector == vec_a2.vector
    assert vec_a1.dimension == 128
    assert vec_a1.disclaimer == BIOMETRIC_MATCHING_ADVISORY_DISCLAIMER

    # Match identical features -> similarity 1.0 -> MATCH_CANDIDATE
    res_same = matcher.match_faces(vec_a1, vec_a2)
    assert res_same.similarity_score == pytest.approx(1.0, abs=1e-4)
    assert res_same.verdict == BiometricMatchVerdict.MATCH_CANDIDATE
    assert res_same.disclaimer == BIOMETRIC_MATCHING_ADVISORY_DISCLAIMER

    # Match distinct features -> advisory comparison
    res_diff = matcher.match_faces(vec_a1, vec_b)
    assert -1.0 <= res_diff.similarity_score <= 1.0
    assert res_diff.verdict in {
        BiometricMatchVerdict.MATCH_CANDIDATE,
        BiometricMatchVerdict.NON_MATCH_CANDIDATE,
        BiometricMatchVerdict.INCONCLUSIVE_UNCERTAIN,
    }


def test_get_face_matcher_factory() -> None:
    assert isinstance(get_face_matcher(enabled=False, provider="mock"), DisabledFaceMatcherProvider)
    assert isinstance(
        get_face_matcher(enabled=True, provider="disabled"), DisabledFaceMatcherProvider
    )
    assert isinstance(get_face_matcher(enabled=True, provider="mock"), MockFaceMatcherProvider)
    assert isinstance(get_face_matcher(enabled=True, provider="local"), LocalFaceMatcherProvider)


# =========================================================================
# 3. Input Image Quality Assessment (Phase 77)
# =========================================================================


def test_quality_empty_payload() -> None:
    res = assess_face_image_quality(b"")
    assert not res.is_acceptable
    assert res.status == ImageQualityAssessment.CORRUPTED_HEADER


def test_quality_corrupted_header() -> None:
    res = assess_face_image_quality(b"NOT_AN_IMAGE_HEADER_AT_ALL_12345678")
    assert not res.is_acceptable
    assert res.status == ImageQualityAssessment.CORRUPTED_HEADER


def test_quality_low_resolution() -> None:
    # 32x32 image is below minimum 64x64
    small_png = make_valid_png_bytes(32, 32)
    res = assess_face_image_quality(small_png, min_width=64, min_height=64)
    assert not res.is_acceptable
    assert res.status == ImageQualityAssessment.LOW_RESOLUTION
    assert "below the minimum required" in (res.reason or "")


def test_quality_poor_contrast_monochromatic() -> None:
    # Solid uniform image bytes
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 64, 64, 8, 2, 0, 0, 0)
    ihdr_chunk = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + b"\x00\x00\x00\x00"
    uniform_bytes = b"\x00" * 256  # zero contrast variance
    idat_chunk = (
        struct.pack(">I", len(uniform_bytes)) + b"IDAT" + uniform_bytes + b"\x00\x00\x00\x00"
    )
    iend_chunk = struct.pack(">I", 0) + b"IEND" + b"\x00\x00\x00\x00"
    blank_png = signature + ihdr_chunk + idat_chunk + iend_chunk

    res = assess_face_image_quality(blank_png, min_contrast_variance=500.0)
    assert not res.is_acceptable
    assert res.status == ImageQualityAssessment.POOR_CONTRAST


def test_quality_acceptable_png() -> None:
    valid_png = make_valid_png_bytes(128, 128)
    res = assess_face_image_quality(valid_png)
    assert res.is_acceptable
    assert res.status == ImageQualityAssessment.ACCEPTABLE
    assert res.width == 128
    assert res.height == 128
    assert res.image_format == "png"


# =========================================================================
# 4. Cryptographic Key Management & Template Security (Phase 78)
# =========================================================================


def test_key_manager_encryption_decryption_lifecycle() -> None:
    manager = BiometricKeyManager(default_key_id="k-init")
    raw_template = b'{"features": [0.12, 0.45, 0.88], "model": "face-v1"}'

    envelope = manager.encrypt(raw_template)
    assert envelope.startswith(f"{ENVELOPE_VERSION}:k-init:")

    decrypted = manager.decrypt(envelope)
    assert decrypted == raw_template


def test_key_manager_rotation() -> None:
    manager = BiometricKeyManager(default_key_id="k1")
    raw_template = b"secret-template-data-k1"

    envelope_k1 = manager.encrypt(raw_template)
    assert envelope_k1.startswith("v1:k1:")

    # Rotate active key to k2
    manager.rotate_key("k2")
    assert manager.active_key_id == "k2"

    # Historic envelope can still be decrypted with rotated k1
    assert manager.decrypt(envelope_k1) == raw_template

    # New encryptions use k2
    envelope_k2 = manager.encrypt(b"secret-template-data-k2")
    assert envelope_k2.startswith("v1:k2:")

    # Re-encryption migrates k1 ciphertext to active k2
    reencrypted = manager.reencrypt(envelope_k1)
    assert reencrypted.startswith("v1:k2:")
    assert manager.decrypt(reencrypted) == raw_template


def test_key_manager_revocation_fails_closed() -> None:
    manager = BiometricKeyManager(default_key_id="k-rev")
    envelope = manager.encrypt(b"confidential-template-bytes")

    # Revoke key
    manager.revoke_key("k-rev")
    assert manager.active_key_id is None

    # Decryption must fail closed
    with pytest.raises(BiometricKeyRevokedError, match="has been revoked"):
        manager.decrypt(envelope)

    # New encryption attempts fail closed because no active key is available
    with pytest.raises(BiometricKeyError, match="No active biometric encryption key available"):
        manager.encrypt(b"new-template-attempt")


def test_key_manager_tampered_envelope_fails_closed() -> None:
    manager = BiometricKeyManager(default_key_id="k1")
    envelope = manager.encrypt(b"sample-template")

    parts = envelope.split(":")
    # Tamper with the base64 ciphertext
    tampered_b64 = parts[2][:-4] + "AAAA"
    tampered_envelope = f"{parts[0]}:{parts[1]}:{tampered_b64}"

    with pytest.raises(BiometricKeyError, match="authentication failed"):
        manager.decrypt(tampered_envelope)


def test_key_manager_unknown_key_fails_closed() -> None:
    manager = BiometricKeyManager(default_key_id="k1")
    fake_envelope = "v1:k-unknown:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBka"
    with pytest.raises(BiometricKeyError, match="not found in keyring"):
        manager.decrypt(fake_envelope)


def test_key_manager_redaction_in_repr() -> None:
    manager = BiometricKeyManager(default_key_id="k-audit")
    repr_str = repr(manager)
    assert "k-audit" in repr_str
    # Raw key bytes should never be printed in representation
    assert "key_bytes" not in repr_str


# =========================================================================
# 5. Biometric Accuracy, Fairness & PAD Evaluation (Phase 79)
# =========================================================================


def test_confusion_at_threshold() -> None:
    # 2 true pairs (0.9, 0.8), 2 false pairs (0.7, 0.3)
    pairs = [(True, 0.9), (True, 0.8), (False, 0.7), (False, 0.3)]
    tp, fp, tn, fn = calculate_confusion_at_threshold(pairs, threshold=0.75)
    # At threshold 0.75:
    # (True, 0.9) -> TP
    # (True, 0.8) -> TP
    # (False, 0.7) -> TN
    # (False, 0.3) -> TN
    assert tp == 2
    assert fp == 0
    assert tn == 2
    assert fn == 0


def test_biometric_evaluation_benchmark_full_report() -> None:
    comparison_pairs = [
        (True, 0.95),
        (True, 0.90),
        (True, 0.86),
        (True, 0.70),
        (False, 0.20),
        (False, 0.30),
        (False, 0.62),
        (False, 0.88),
    ]
    subgroups = {
        "demographic_cohort_1": [(True, 0.92), (False, 0.25)],
        "demographic_cohort_2": [(True, 0.88), (False, 0.35)],
    }
    pad_data = (100, 2, 100, 3)

    report = evaluate_biometric_matching_benchmark(
        comparison_pairs=comparison_pairs,
        failed_acquisitions=1,
        total_acquisition_attempts=9,
        presentation_attack_data=pad_data,
        subgroup_comparisons=subgroups,
    )

    assert report.total_comparisons == 8
    assert report.fta_rate == pytest.approx(1 / 9, abs=1e-3)
    assert 0.0 <= report.eer <= 1.0
    assert len(report.det_curve) > 0
    assert report.pad_metrics is not None
    assert report.pad_metrics.apcer == 0.02
    assert report.pad_metrics.bpcer == 0.03
    assert len(report.demographic_disparities) == 2
    assert report.disclaimer == SYNTHETIC_BENCHMARK_DISCLAIMER


# =========================================================================
# 6. Pydantic Schemas & Override Validation (Phase 76 & 77)
# =========================================================================


def test_face_match_request_requires_reference_source() -> None:
    gov_id = uuid4()
    # Fails if neither reference_id nor reference_image_base64 is provided
    with pytest.raises(
        ValueError, match="Either reference_id or reference_image_base64 must be provided"
    ):
        FaceMatchRequest(
            governance_record_id=gov_id,
            probe_image_base64="valid_probe_b64",
        )

    # Succeeds with reference_id
    req1 = FaceMatchRequest(
        governance_record_id=gov_id,
        probe_image_base64="valid_probe_b64",
        reference_id=uuid4(),
    )
    assert req1.reference_id is not None

    # Succeeds with reference_image_base64
    req2 = FaceMatchRequest(
        governance_record_id=gov_id,
        probe_image_base64="valid_probe_b64",
        reference_image_base64="valid_ref_b64",
    )
    assert req2.reference_image_base64 == "valid_ref_b64"


def test_verification_review_create_override_reason_enforcement() -> None:
    # Fails when human_verdict is rejected_override without an override_reason
    with pytest.raises(ValueError, match="override_reason is strictly required"):
        BiometricVerificationReviewCreate(
            human_verdict=BiometricHumanVerdict.REJECTED_OVERRIDE,
            review_notes="Just rejecting",
            override_reason="",
        )

    # Succeeds when override_reason is provided
    review_create = BiometricVerificationReviewCreate(
        human_verdict=BiometricHumanVerdict.REJECTED_OVERRIDE,
        review_notes="Investigator inspected CCTV high-res photo",
        override_reason="Ear lobe geometry and jawline definitively exclude candidate.",
    )
    assert review_create.human_verdict == BiometricHumanVerdict.REJECTED_OVERRIDE
    assert review_create.override_reason is not None


def test_biometric_verification_review_model_properties() -> None:
    review = BiometricVerificationReview(
        id=uuid4(),
        tenant_id=uuid4(),
        department_id=uuid4(),
        probe_image_hash="a" * 64,
        candidate_similarity=0.88,
        uncertainty_lower_bound=0.60,
        uncertainty_upper_bound=0.85,
        automated_verdict=BiometricMatchVerdict.MATCH_CANDIDATE.value,
        human_verdict=BiometricHumanVerdict.INCONCLUSIVE_DISMISSED.value,
        is_override=False,
    )
    assert review.candidate_similarity == 0.88
    assert review.automated_verdict == "match_candidate"
    assert not review.is_override
