"""Centralized FastAPI exception handlers and error sanitization (Phase 06).

Translates request validation failures, known domain exceptions (`AppError`),
HTTP exceptions, and unexpected server errors into a consistent `ErrorResponse`
JSON envelope without leaking tracebacks, SQL statements, connection strings,
tokens, or filesystem paths.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.app.core.context import (
    CORRELATION_ID_HEADER,
    get_request_id,
    is_valid_correlation_id,
    reset_request_id,
    set_request_id,
)
from backend.app.core.exceptions import AppError
from backend.app.core.logging import get_logger, sanitize_log_text
from backend.app.schemas.common import ErrorBody, ErrorDetail, ErrorResponse

logger = get_logger("api.errors")


_SENSITIVE_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "password",
        "confirm_password",
        "current_password",
        "new_password",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "api_key",
        "credit_card",
        "cvv",
        "pin",
        "ssn",
        "private_key",
    }
)


def _resolve_request_id(request: Request) -> str | None:
    state_id = getattr(request.state, "request_id", None)
    if isinstance(state_id, str) and state_id:
        return state_id
    return get_request_id()


def _response_headers(
    request_id: str | None,
    extra_headers: Mapping[str, str] | None = None,
) -> dict[str, str]:
    headers: dict[str, str] = {}
    if request_id:
        headers[CORRELATION_ID_HEADER] = request_id
    if extra_headers:
        headers.update(extra_headers)
    return headers


async def handle_request_validation_error(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Return a sanitized 422 response for request validation failures."""
    request_id = _resolve_request_id(request)
    details: list[ErrorDetail] = []
    for err in exc.errors():
        loc_parts = [str(part) for part in err.get("loc", ()) if str(part)]
        field_path = ".".join(loc_parts) if loc_parts else None
        err_type = sanitize_log_text(str(err.get("type", "validation_error")), redact=False)

        # Sanitize message: never echo sensitive submitted values
        is_sensitive = any(part.lower() in _SENSITIVE_FIELD_NAMES for part in loc_parts)
        if err.get("type") == "json_invalid":
            safe_msg = "Malformed JSON payload in request body."
        elif is_sensitive:
            # Preserve validation rule constraint while stripping any submitted values
            raw_msg = str(err.get("msg", "Invalid parameter."))
            safe_msg = sanitize_log_text(raw_msg, redact=True)
            # Extra safety: remove any quoted strings that might echo the user's password/token
            if "'" in safe_msg or '"' in safe_msg:
                safe_msg = "Invalid value provided for sensitive field."
        else:
            raw_msg = str(err.get("msg", "Invalid request parameter."))
            safe_msg = sanitize_log_text(raw_msg, redact=True)

        details.append(
            ErrorDetail(
                field=field_path,
                message=safe_msg,
                error_type=err_type,
            )
        )

    logger.warning(
        "Request validation failed",
        extra={
            "error_code": "REQUEST_VALIDATION_ERROR",
            "http_path": request.url.path,
            "error_count": len(details),
        },
    )

    payload = ErrorResponse(
        error=ErrorBody(
            code="REQUEST_VALIDATION_ERROR",
            message="Request payload or parameters failed validation.",
            request_id=request_id,
            details=details,
        )
    )
    return JSONResponse(
        status_code=422,
        content=payload.model_dump(mode="json"),
        headers=_response_headers(request_id),
    )


async def handle_app_error(
    request: Request,
    exc: AppError,
) -> JSONResponse:
    """Return a sanitized response for known domain/application errors (`AppError`)."""
    request_id = _resolve_request_id(request)
    safe_message = sanitize_log_text(exc.message, redact=True)

    details: list[ErrorDetail] | None = None
    if exc.details:
        details = [
            ErrorDetail(
                field=sanitize_log_text(str(item["field"]), redact=False)
                if item.get("field") is not None
                else None,
                message=sanitize_log_text(str(item.get("message", "")), redact=True),
                error_type=sanitize_log_text(
                    str(item.get("error_type", "domain_error")), redact=False
                ),
            )
            for item in exc.details
        ]

    extra_headers: dict[str, str] = {}
    retry_after = getattr(exc, "retry_after", None)
    if retry_after is not None:
        extra_headers["Retry-After"] = str(retry_after)

    log_extra = {
        "error_code": exc.code,
        "status_code": exc.status_code,
        "http_path": request.url.path,
    }
    if exc.status_code >= 500:
        logger.error("Application error returned 5xx status", extra=log_extra)
    else:
        logger.warning("Application domain error", extra=log_extra)

    payload = ErrorResponse(
        error=ErrorBody(
            code=exc.code,
            message=safe_message,
            request_id=request_id,
            details=details,
        )
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=payload.model_dump(mode="json"),
        headers=_response_headers(request_id, extra_headers=extra_headers),
    )


async def handle_http_exception(
    request: Request,
    exc: StarletteHTTPException,
) -> JSONResponse:
    """Return a sanitized `ErrorResponse` for framework HTTP exceptions (e.g., 404/405)."""
    request_id = _resolve_request_id(request)
    status_code = int(exc.status_code)
    extra_headers: dict[str, str] = dict(exc.headers) if exc.headers else {}

    if status_code >= 500:
        safe_message = "An unexpected internal server error occurred."
        code = "INTERNAL_SERVER_ERROR"
        logger.error(
            "HTTPException with 5xx status intercepted",
            extra={"error_code": code, "status_code": status_code, "http_path": request.url.path},
        )
    else:
        raw_detail = str(exc.detail) if exc.detail else "HTTP request error."
        safe_message = sanitize_log_text(raw_detail, redact=True)
        code = f"HTTP_{status_code}"
        logger.warning(
            "HTTPException with client error status",
            extra={"error_code": code, "status_code": status_code, "http_path": request.url.path},
        )

    payload = ErrorResponse(
        error=ErrorBody(
            code=code,
            message=safe_message,
            request_id=request_id,
            details=None,
        )
    )
    return JSONResponse(
        status_code=status_code,
        content=payload.model_dump(mode="json"),
        headers=_response_headers(request_id, extra_headers=extra_headers),
    )


async def handle_unexpected_exception(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    """Catch-all handler that logs sanitized internal context and returns a generic 500 response."""
    request_id = _resolve_request_id(request)
    token = (
        set_request_id(request_id)
        if request_id and get_request_id() is None and is_valid_correlation_id(request_id)
        else None
    )
    try:
        logger.error(
            "Unhandled server exception",
            exc_info=exc,
            extra={
                "error_code": "INTERNAL_SERVER_ERROR",
                "http_path": request.url.path,
                "exception_type": type(exc).__name__,
            },
        )
    finally:
        if token is not None:
            reset_request_id(token)

    payload = ErrorResponse(
        error=ErrorBody(
            code="INTERNAL_SERVER_ERROR",
            message="An unexpected internal server error occurred.",
            request_id=request_id,
            details=None,
        )
    )
    return JSONResponse(
        status_code=500,
        content=payload.model_dump(mode="json"),
        headers=_response_headers(request_id),
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Attach standardized E-WITNESS exception handlers to ``app``."""
    app.add_exception_handler(
        RequestValidationError,
        handle_request_validation_error,  # type: ignore[arg-type]
    )
    app.add_exception_handler(
        AppError,
        handle_app_error,  # type: ignore[arg-type]
    )
    app.add_exception_handler(
        StarletteHTTPException,
        handle_http_exception,  # type: ignore[arg-type]
    )
    app.add_exception_handler(
        Exception,
        handle_unexpected_exception,
    )
