"""Domain and application exception hierarchy (Phases 06-07).

Business services and domain components raise `AppError` subclasses rather than
HTTP framework exceptions (`fastapi.HTTPException`). The API boundary translates
these exceptions into standardized, sanitized `ErrorResponse` payloads.
"""

from __future__ import annotations

from typing import Any


class AppError(Exception):
    """Base exception for known domain and application errors."""

    default_code: str = "APPLICATION_ERROR"
    default_status_code: int = 400

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        status_code: int | None = None,
        details: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code or self.default_code
        self.status_code = status_code if status_code is not None else self.default_status_code
        self.details = details


class ResourceNotFoundError(AppError):
    """Raised when a requested domain resource does not exist within authorized scope."""

    default_code = "RESOURCE_NOT_FOUND"
    default_status_code = 404


class ConflictError(AppError):
    """Raised when an operation conflicts with existing resource state or constraints."""

    default_code = "RESOURCE_CONFLICT"
    default_status_code = 409


class BusinessRuleError(AppError):
    """Raised when a domain invariant or workflow state transition rule is violated."""

    default_code = "BUSINESS_RULE_VIOLATION"
    default_status_code = 422


class AuthenticationError(AppError):
    """Raised when credentials or authentication tokens are missing, expired, or invalid."""

    default_code = "AUTHENTICATION_REQUIRED"
    default_status_code = 401


class PermissionDeniedError(AppError):
    """Raised when an authenticated principal lacks role, department, or case permission."""

    default_code = "PERMISSION_DENIED"
    default_status_code = 403


class PayloadTooLargeError(AppError):
    """Raised when a request payload or stream exceeds configured byte limits."""

    default_code = "PAYLOAD_TOO_LARGE"
    default_status_code = 413


class ServiceUnavailableError(AppError):
    """Raised when a required downstream dependency or readiness check is unavailable."""

    default_code = "DEPENDENCY_UNAVAILABLE"
    default_status_code = 503


class RateLimitExceededError(AppError):
    """Raised when request frequency exceeds configured rate limits."""

    default_code = "RATE_LIMIT_EXCEEDED"
    default_status_code = 429

    def __init__(
        self,
        message: str = "Too many requests. Please wait before trying again.",
        *,
        code: str | None = None,
        retry_after: int | None = None,
        details: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(
            message,
            code=code or self.default_code,
            status_code=self.default_status_code,
            details=details,
        )
        self.retry_after = retry_after


class UnsupportedMediaTypeError(AppError):
    """Raised when an uploaded payload or media type is unsupported or mismatched (HTTP 415)."""

    default_code = "UNSUPPORTED_MEDIA_TYPE"
    default_status_code = 415


class SecurityError(AppError):
    """Raised when a security invariant or audit integrity check fails (Phases 58-60)."""

    default_code = "SECURITY_VIOLATION"
    default_status_code = 500


class ModelUnavailableError(AppError):
    """Raised when an AI model or runtime weights are unavailable (Phase 64)."""

    default_code = "MODEL_UNAVAILABLE"
    default_status_code = 503


class VideoProcessingError(AppError):
    """Raised when video parsing, decoding, or preprocessing fails safely (Phase 63)."""

    default_code = "VIDEO_PROCESSING_ERROR"
    default_status_code = 422


class CalibrationIncompatibilityError(AppError):
    """Raised when a calibration artifact is incompatible with model version or data splits (Phase 67)."""

    default_code = "CALIBRATION_INCOMPATIBLE"
    default_status_code = 422


class BiometricsDisabledError(AppError):
    """Raised when biometric capabilities are requested but disabled in configuration or policy (Phase 71 & 75)."""

    default_code = "BIOMETRICS_DISABLED"
    default_status_code = 403


class BiometricGovernanceError(AppError):
    """Raised when an operation violates biometric governance, consent, or purpose policies (Phase 72 & 73)."""

    default_code = "BIOMETRIC_GOVERNANCE_VIOLATION"
    default_status_code = 422


class BiometricKeyError(AppError):
    """Raised when cryptographic key retrieval, validation, or derivation fails (Phase 78)."""

    default_code = "BIOMETRIC_KEY_ERROR"
    default_status_code = 500


class BiometricKeyRevokedError(BiometricKeyError):
    """Raised when an attempt is made to decrypt or use a revoked biometric encryption key (Phase 78)."""

    default_code = "BIOMETRIC_KEY_REVOKED"
    default_status_code = 403


class BiometricQualityError(AppError):
    """Raised when an input biometric image fails minimum resolution, contrast, or quality thresholds (Phase 77)."""

    default_code = "BIOMETRIC_QUALITY_INSUFFICIENT"
    default_status_code = 422
