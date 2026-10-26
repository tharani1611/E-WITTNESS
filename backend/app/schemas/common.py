"""Common Pydantic v2 API response and error envelope schemas (Phases 06-07)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ErrorDetail(BaseModel):
    """Granular field or constraint failure item inside a structured error response."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    field: str | None = Field(
        default=None,
        description="Dot-delimited field location if applicable (e.g., 'body.title').",
    )
    message: str = Field(
        ...,
        description="Sanitized, human-readable validation or constraint failure message.",
    )
    error_type: str = Field(
        default="validation_error",
        description="Machine-readable error classification token.",
    )


class ErrorBody(BaseModel):
    """Inner payload of the standardized E-WITNESS API error envelope (NFR-007)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: str = Field(
        ...,
        description="Stable, uppercase machine-readable error code (e.g., 'REQUEST_VALIDATION_ERROR').",
    )
    message: str = Field(
        ...,
        description="Safe, human-readable error summary free of secrets or stack traces.",
    )
    request_id: str | None = Field(
        default=None,
        description="Active request correlation ID for log and audit traceability.",
    )
    details: list[ErrorDetail] | None = Field(
        default=None,
        description="Optional list of sanitized field-level validation issues.",
    )


class ErrorResponse(BaseModel):
    """Top-level JSON error response envelope returned on all 4xx and 5xx responses."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    error: ErrorBody
