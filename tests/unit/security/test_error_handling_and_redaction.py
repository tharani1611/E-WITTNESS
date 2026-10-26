"""Unit tests for Phase 26 exception handling, sensitive field redaction, and error envelopes."""

from __future__ import annotations

import pytest
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request

from backend.app.api.errors import (
    _SENSITIVE_FIELD_NAMES,
    handle_app_error,
    handle_http_exception,
    handle_request_validation_error,
    handle_unexpected_exception,
)
from backend.app.core.exceptions import (
    AppError,
    AuthenticationError,
    BusinessRuleError,
    ConflictError,
    PayloadTooLargeError,
    PermissionDeniedError,
    RateLimitExceededError,
    ResourceNotFoundError,
    UnsupportedMediaTypeError,
)


def _build_dummy_request(
    path: str = "/api/v1/test",
    headers: dict[str, str] | None = None,
) -> Request:
    """Build a minimal dummy ASGI request for testing error handlers directly."""
    raw_headers = [
        (k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in (headers or {}).items()
    ]
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "raw_path": path.encode("latin-1"),
        "headers": raw_headers,
        "query_string": b"",
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8000),
        "scheme": "http",
    }
    req = Request(scope)
    lowered = {k.lower(): v for k, v in (headers or {}).items()}
    req.state.request_id = lowered.get("x-request-id", "test-corr-id-001")
    return req


@pytest.mark.unit
class TestSensitiveFieldRedactionInValidationErrors:
    """Verify sensitive fields are never reflected in validation failure details."""

    def test_sensitive_field_names_set_covers_critical_credentials(self) -> None:
        expected_keys = {
            "password",
            "new_password",
            "confirm_password",
            "current_password",
            "token",
            "secret",
            "authorization",
            "credit_card",
            "pin",
            "ssn",
        }
        assert expected_keys.issubset(_SENSITIVE_FIELD_NAMES)

    async def test_validation_error_handler_masks_sensitive_input_value(self) -> None:
        raw_errors = [
            {
                "type": "string_too_short",
                "loc": ("body", "password"),
                "msg": "String should have at least 12 characters",
                "input": "SuperSecretPassword123!",
                "ctx": {"min_length": 12},
            }
        ]
        req = _build_dummy_request()
        exc = RequestValidationError(errors=raw_errors)
        resp = await handle_request_validation_error(req, exc)

        assert resp.status_code == 422
        body = bytes(resp.body).decode("utf-8")
        assert "password" in body
        assert "SuperSecretPassword123!" not in body

    async def test_validation_error_handler_handles_json_invalid(self) -> None:
        raw_errors = [
            {
                "type": "json_invalid",
                "loc": ("body",),
                "msg": "JSON decode error: Expecting value",
                "input": "{invalid_json",
            }
        ]
        req = _build_dummy_request()
        exc = RequestValidationError(errors=raw_errors)
        resp = await handle_request_validation_error(req, exc)

        assert resp.status_code == 422
        body = bytes(resp.body).decode("utf-8")
        assert "Malformed JSON payload in request body" in body


@pytest.mark.unit
class TestErrorEnvelopesAndPropagation:
    """Verify all domain errors produce standard envelopes with expected HTTP status and headers."""

    @pytest.mark.parametrize(
        ("exc_class", "status_code", "default_code"),
        [
            (ResourceNotFoundError, 404, "RESOURCE_NOT_FOUND"),
            (ConflictError, 409, "RESOURCE_CONFLICT"),
            (BusinessRuleError, 422, "BUSINESS_RULE_VIOLATION"),
            (AuthenticationError, 401, "AUTHENTICATION_REQUIRED"),
            (PermissionDeniedError, 403, "PERMISSION_DENIED"),
            (PayloadTooLargeError, 413, "PAYLOAD_TOO_LARGE"),
            (RateLimitExceededError, 429, "RATE_LIMIT_EXCEEDED"),
            (UnsupportedMediaTypeError, 415, "UNSUPPORTED_MEDIA_TYPE"),
        ],
    )
    async def test_domain_exceptions_produce_valid_envelope(
        self,
        exc_class: type[AppError],
        status_code: int,
        default_code: str,
    ) -> None:
        req = _build_dummy_request(headers={"X-Request-ID": "corr-req-001"})
        exc = exc_class("Test error occurred.")
        resp = await handle_app_error(req, exc)

        assert resp.status_code == status_code
        data = bytes(resp.body).decode("utf-8")
        assert default_code in data
        assert "corr-req-001" in data

    async def test_rate_limit_exceeded_propagates_retry_after_header(self) -> None:
        req = _build_dummy_request()
        exc = RateLimitExceededError(
            "Rate limit exceeded.",
            retry_after=45,
        )
        resp = await handle_app_error(req, exc)
        assert resp.status_code == 429
        assert resp.headers.get("retry-after") == "45"

    async def test_handle_http_exception_preserves_custom_headers(self) -> None:
        req = _build_dummy_request()
        exc = StarletteHTTPException(
            status_code=401,
            detail="Unauthorized access",
            headers={"WWW-Authenticate": "Bearer"},
        )
        resp = await handle_http_exception(req, exc)
        assert resp.status_code == 401
        assert resp.headers.get("www-authenticate") == "Bearer"

    async def test_handle_unexpected_exception_hides_stack_trace_and_paths(self) -> None:
        req = _build_dummy_request()
        exc = RuntimeError(
            "Database connection string postgresql://admin:SecretPass99@db:5432/prod died"
        )
        resp = await handle_unexpected_exception(req, exc)

        assert resp.status_code == 500
        body = bytes(resp.body).decode("utf-8")
        assert "SecretPass99" not in body
        assert "postgresql://" not in body
        assert "RuntimeError" not in body
        assert "An unexpected internal server error occurred." in body
