"""Pure ASGI request body size limiting middleware (Phase 06 / SEC-014).

Enforces `MAX_REQUEST_BODY_BYTES` on incoming HTTP requests by inspecting both
the declared `Content-Length` header and actual streamed `http.request` body
chunks, returning a standardized 413 `ErrorResponse` when exceeded.
"""

from __future__ import annotations

import contextlib

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from backend.app.core.context import get_request_id
from backend.app.core.logging import get_logger
from backend.app.schemas.common import ErrorBody, ErrorResponse

logger = get_logger("middleware.body_size_limit")


def _build_413_payload(max_bytes: int) -> bytes:
    response = ErrorResponse(
        error=ErrorBody(
            code="PAYLOAD_TOO_LARGE",
            message=f"Request body exceeds maximum allowed size of {max_bytes} bytes.",
            request_id=get_request_id(),
            details=None,
        )
    )
    return response.model_dump_json().encode("utf-8")


async def _send_413_response(send: Send, max_bytes: int) -> None:
    body = _build_413_payload(max_bytes)
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


class _PayloadLimitExceeded(Exception):
    """Internal signal raised when streamed request chunks exceed `max_body_bytes`."""


class RequestBodyLimitMiddleware:
    """ASGI middleware enforcing a hard ceiling on incoming HTTP request body size."""

    def __init__(self, app: ASGIApp, *, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # 1. Fast rejection if Content-Length header exceeds ceiling
        for key, val in scope.get("headers", []):
            if key.lower() == b"content-length":
                try:
                    declared_length = int(val.decode("ascii").strip())
                except ValueError:
                    break
                if declared_length > self.max_body_bytes:
                    logger.warning(
                        "Rejected oversized request via Content-Length header",
                        extra={
                            "declared_bytes": declared_length,
                            "max_body_bytes": self.max_body_bytes,
                        },
                    )
                    await _send_413_response(send, self.max_body_bytes)
                    return

        # 2. Stream inspection for chunked or undeclared request bodies
        received_bytes = 0
        response_started = False
        limit_exceeded = False

        async def guarded_receive() -> Message:
            nonlocal received_bytes, limit_exceeded
            message = await receive()
            if message["type"] == "http.request":
                chunk = message.get("body", b"")
                received_bytes += len(chunk)
                if received_bytes > self.max_body_bytes:
                    limit_exceeded = True
                    logger.warning(
                        "Rejected oversized streaming request body",
                        extra={
                            "received_bytes": received_bytes,
                            "max_body_bytes": self.max_body_bytes,
                        },
                    )
                    raise _PayloadLimitExceeded
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if limit_exceeded:
                # Suppress any downstream 400 body-parse response so we emit 413
                return
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        with contextlib.suppress(_PayloadLimitExceeded):
            await self.app(scope, guarded_receive, tracking_send)

        if limit_exceeded and not response_started:
            await _send_413_response(send, self.max_body_bytes)
