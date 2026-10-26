"""Pure ASGI request correlation and structured access logging middleware (Phase 08).

Responsibilities:
- Extract and validate incoming `X-Request-ID` header (or generate a fresh UUIDv4)
- Bind the verified correlation ID to `contextvars` and `scope["state"]["request_id"]`
- Guarantee `X-Request-ID` is returned in HTTP response headers
- Emit a structured, secret-free access log distinguishing 2xx/3xx, 4xx, and 5xx outcomes
- Deterministically reset `contextvars` state in a `finally` block upon completion
"""

from __future__ import annotations

import time

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from backend.app.core.context import (
    CORRELATION_ID_HEADER,
    reset_request_id,
    set_request_id,
    validate_or_generate_request_id,
)
from backend.app.core.logging import get_logger

_HEADER_BYTES = CORRELATION_ID_HEADER.lower().encode("latin1")
logger = get_logger("middleware.request_context")


def _extract_incoming_request_id(scope: Scope) -> str | None:
    """Extract the first `X-Request-ID` header value from ASGI scope headers."""
    raw_headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
    for key, val in raw_headers:
        if key.lower() == _HEADER_BYTES:
            try:
                return val.decode("latin1").strip()
            except UnicodeDecodeError:
                return None
    return None


class RequestTracingMiddleware:
    """Outermost ASGI middleware managing request correlation IDs and safe access logs."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming_id = _extract_incoming_request_id(scope)
        request_id, accepted_from_client = validate_or_generate_request_id(incoming_id)

        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        state["client_id_accepted"] = accepted_from_client

        token = set_request_id(request_id)
        start_ns = time.perf_counter_ns()
        status_code = 500

        async def send_with_correlation_id(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message.get("status", 500))
                existing_headers: list[tuple[bytes, bytes]] = [
                    (k, v) for k, v in message.get("headers", []) if k.lower() != _HEADER_BYTES
                ]
                existing_headers.append(
                    (CORRELATION_ID_HEADER.encode("latin1"), request_id.encode("ascii"))
                )
                message["headers"] = existing_headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_correlation_id)
        finally:
            duration_ms = round((time.perf_counter_ns() - start_ns) / 1_000_000, 3)
            method = str(scope.get("method", "UNKNOWN"))
            # Log only the request path — never log unrestricted query strings or bodies
            path = str(scope.get("path", ""))
            log_extra = {
                "http_method": method,
                "http_path": path,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "client_id_accepted": accepted_from_client,
            }
            if status_code >= 500:
                logger.error("HTTP request completed with server error", extra=log_extra)
            elif status_code >= 400:
                logger.warning("HTTP request completed with client error", extra=log_extra)
            else:
                logger.info("HTTP request completed", extra=log_extra)

            reset_request_id(token)
