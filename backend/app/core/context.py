"""Context-local request correlation and tracing state management (Phase 08).

Uses `contextvars.ContextVar` so concurrent asynchronous requests maintain
strictly isolated correlation IDs throughout their execution lifecycle and
clean up deterministically upon completion.
"""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar, Token

CORRELATION_ID_HEADER: str = "X-Request-ID"
MAX_CORRELATION_ID_LENGTH: int = 64
MIN_CORRELATION_ID_LENGTH: int = 8

# Safe ASCII pattern: alphanumeric, hyphens, underscores, and dots only.
# Strictly forbids whitespace, CR/LF newlines, quotes, or control characters
# to prevent HTTP response splitting and multiline log injection.
_SAFE_CORRELATION_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")

_request_id_ctx: ContextVar[str | None] = ContextVar("ewitness_request_id", default=None)


def is_valid_correlation_id(value: str | None) -> bool:
    """Return True if ``value`` conforms to the documented safe correlation ID policy."""
    if not value or not isinstance(value, str):
        return False
    if not (MIN_CORRELATION_ID_LENGTH <= len(value) <= MAX_CORRELATION_ID_LENGTH):
        return False
    return bool(_SAFE_CORRELATION_ID_RE.fullmatch(value))


def generate_correlation_id() -> str:
    """Generate a cryptographically random UUIDv4 correlation ID."""
    return str(uuid.uuid4())


def validate_or_generate_request_id(incoming_id: str | None) -> tuple[str, bool]:
    """Validate an incoming correlation ID or generate a fresh UUIDv4.

    Returns a tuple ``(effective_request_id, accepted_from_client)``.
    """
    if incoming_id is not None and is_valid_correlation_id(incoming_id):
        return incoming_id, True
    return generate_correlation_id(), False


def get_request_id() -> str | None:
    """Retrieve the active request correlation ID for the current async context."""
    return _request_id_ctx.get()


def set_request_id(request_id: str) -> Token[str | None]:
    """Bind ``request_id`` to the current async context and return its reset token."""
    if not is_valid_correlation_id(request_id):
        raise ValueError("Cannot bind an invalid or unsafe correlation ID to request context.")
    return _request_id_ctx.set(request_id)


def reset_request_id(token: Token[str | None]) -> None:
    """Restore the request correlation ID context variable using its token."""
    _request_id_ctx.reset(token)


def clear_request_id() -> None:
    """Explicitly clear the correlation ID in the current async context."""
    _request_id_ctx.set(None)
