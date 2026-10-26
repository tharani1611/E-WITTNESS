"""Liveness and readiness health check response schemas (Phase 06)."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class DependencyCheckStatus(StrEnum):
    """Status of an individual downstream infrastructure readiness check."""

    NOT_CHECKED = "not_checked"
    READY = "ready"
    UNAVAILABLE = "unavailable"


class LivenessResponse(BaseModel):
    """Safe application liveness response confirming process responsiveness."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: Literal["ok"] = "ok"
    service: str = Field(..., description="Configured application name.")
    version: str = Field(..., description="Semantic application version.")
    environment: str = Field(..., description="Active runtime environment name.")


class ReadinessResponse(BaseModel):
    """Application readiness response separating liveness from downstream checks.

    Never claims database, Redis, or object-storage readiness unless an actual
    verification probe has been registered and executed for that dependency.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: Literal["ok", "unverified", "degraded"] = Field(
        ...,
        description=(
            "'ok' when all registered dependency probes pass; "
            "'unverified' when infrastructure probes are not yet wired; "
            "'degraded' when one or more registered dependency probes fail."
        ),
    )
    ready: bool = Field(
        ...,
        description="True if the process can accept traffic and no registered probe failed.",
    )
    checks: dict[str, DependencyCheckStatus] = Field(
        ...,
        description="Per-dependency verification state (never fabricates readiness).",
    )
    message: str = Field(
        ...,
        description="Human-readable explanation of current readiness state.",
    )
