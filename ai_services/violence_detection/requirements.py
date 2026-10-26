"""Violence detection AI requirements, intended use, prohibited use, and governance definitions (Phase 61).

Enforces:
- Explicit intended use definitions (decision support, investigative triage).
- Strict prohibitions (no automated disciplinary action, no autonomous guilt determination,
  no biometric/demographic profiling, no covert mass surveillance).
- Operational constraints (video duration limits, supported formats, deterministic execution).
- Mandatory human-in-the-loop disclaimers adhering to criminal justice and institutional ethics standards.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final


class AIIntendedUse(StrEnum):
    """Permitted and intended use cases for violence-detection AI models in E-WITNESS."""

    INVESTIGATIVE_TRIAGE = "investigative_triage"
    DECISION_SUPPORT = "decision_support"
    REVIEW_PRIORITIZATION = "review_prioritization"
    CANDIDATE_FLAGGING = "candidate_flagging"


class AIProhibitedUse(StrEnum):
    """Strictly prohibited use cases for violence-detection AI models in E-WITNESS."""

    AUTOMATED_ARREST = "automated_arrest"
    AUTOMATED_DISCIPLINARY = "automated_disciplinary"
    SOLE_DETERMINATION_OF_GUILT = "sole_determination_of_guilt"
    DEMOGRAPHIC_PROFILING = "demographic_profiling"
    BIOMETRIC_SURVEILLANCE = "biometric_surveillance"
    COVERT_MASS_SURVEILLANCE = "covert_mass_surveillance"
    RETROACTIVE_UNCONSENTED_HARVESTING = "retroactive_unconsented_harvesting"


class AIRequirementCode(StrEnum):
    """Canonical requirement identifiers (REQ-AI-001 through REQ-AI-044)."""

    # Problem Definition & Governance (Phase 61)
    REQ_AI_001 = "REQ-AI-001"  # Decision-support only; never autonomous judgment
    REQ_AI_002 = "REQ-AI-002"  # Strict prohibition of punitive/disciplinary automation
    REQ_AI_003 = "REQ-AI-003"  # Mandatory human-in-the-loop review
    REQ_AI_004 = "REQ-AI-004"  # Explicit advisory disclaimer on all outputs
    REQ_AI_005 = "REQ-AI-005"  # Demographic and identity neutrality

    # Dataset Ingestion & Licensing (Phase 62)
    REQ_AI_010 = "REQ-AI-010"  # Explicit dataset registration with SPDX license
    REQ_AI_011 = "REQ-AI-011"  # Cryptographic manifest SHA-256 verification
    REQ_AI_012 = "REQ-AI-012"  # Verifiable consent status and institutional review
    REQ_AI_013 = "REQ-AI-013"  # Strict isolation of operational evidence from training sets
    REQ_AI_014 = "REQ-AI-014"  # Immutable dataset audit logging

    # Video Preprocessing & Extraction (Phase 63)
    REQ_AI_020 = "REQ-AI-020"  # Safe bounded MP4 parsing without shell execution
    REQ_AI_021 = "REQ-AI-021"  # Frame dimension, duration, and codec extraction
    REQ_AI_022 = "REQ-AI-022"  # Deterministic temporal frame sampling
    REQ_AI_023 = "REQ-AI-023"  # Strict temporary file isolation and cleanup
    REQ_AI_024 = "REQ-AI-024"  # Resource bounds (duration <= 600s, size <= 100MB)

    # Model Integration (Phase 64)
    REQ_AI_030 = "REQ-AI-030"  # Stable VideoClassifierProtocol abstraction
    REQ_AI_031 = "REQ-AI-031"  # Explicit uncalibrated confidence output
    REQ_AI_032 = "REQ-AI-032"  # Graceful fallback when weights/runtime unavailable
    REQ_AI_033 = "REQ-AI-033"  # Prohibition of fabricated or random mock scores in production
    REQ_AI_034 = "REQ-AI-034"  # Model version and weights provenance tracking

    # Asynchronous Analysis Jobs (Phase 65)
    REQ_AI_040 = "REQ-AI-040"  # Monotonic job status lifecycle (QUEUED -> RUNNING -> FINAL)
    REQ_AI_041 = "REQ-AI-041"  # Progress tracking with bounded percentages
    REQ_AI_042 = "REQ-AI-042"  # Bounded retries and typed failure categories
    REQ_AI_043 = "REQ-AI-043"  # Department and tenant isolation on job access
    REQ_AI_044 = "REQ-AI-044"  # Security audit ledger integration for all job lifecycle events


AI_HUMAN_IN_THE_LOOP_DISCLAIMER: Final[str] = (
    "NOTICE: AI-assisted violence detection outputs are probabilistic, advisory decision-support "
    "signals only. They do not constitute factual determinations of guilt, unlawful conduct, or "
    "disciplinary infractions. Every candidate detection requires mandatory independent human "
    "review by an authorized investigator or administrator prior to taking any investigative, "
    "disciplinary, or administrative action."
)

AI_MODEL_FALLBACK_DISCLAIMER: Final[str] = (
    "AI runtime or pretrained model weights are not loaded. Analysis cannot be performed "
    "without verified model weights. No synthetic or fabricated confidence scores are generated."
)


@dataclass(frozen=True)
class AIOperationalConstraints:
    """Operational resource limits and safety boundaries for video analysis."""

    max_video_duration_seconds: float = 600.0  # 10 minutes max
    max_file_size_bytes: int = 100 * 1024 * 1024  # 100 MB max
    allowed_containers: tuple[str, ...] = ("mp4", "m4v")
    allowed_codecs: tuple[str, ...] = ("avc1", "h264", "mp4v")
    max_frames_to_sample: int = 64
    default_sample_fps: float = 1.0
    job_timeout_seconds: int = 300
    max_retries: int = 3


DEFAULT_AI_CONSTRAINTS: Final[AIOperationalConstraints] = AIOperationalConstraints()
