"""Centralized, structured, secret-redacting logging configuration (Phase 08).

Provides:
- Single-line sanitization against CRLF / control-character log injection
- Automatic correlation ID (`request_id`) enrichment from `contextvars`
- Automatic secret, token, and DSN password scrubbing using `backend.app.core.secrets`
- Structured JSON formatter (`LOG_FORMAT="json"`) and safe console formatter (`LOG_FORMAT="console"`)
"""

from __future__ import annotations

import json
import logging
import re
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from backend.app.core.context import get_request_id
from backend.app.core.secrets import redact_mapping, redact_text, redact_url

if TYPE_CHECKING:
    from backend.app.config.settings import Settings

# Matches CR, LF, and other ASCII control characters (0x00-0x1F, 0x7F)
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]+")

# Standard LogRecord attributes excluded when extracting custom structured extra fields
_STANDARD_LOG_ATTRS: frozenset[str] = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
        "taskName",
        "request_id",
        "environment",
        "service",
    }
)


def sanitize_log_text(
    value: str,
    *,
    redact: bool = True,
    extra_secrets: Sequence[str] | None = None,
) -> str:
    """Neutralize multiline/control-character log injection and redact sensitive tokens."""
    if not value:
        return value

    # Replace CR and LF explicitly with visible escaped markers to prevent forged lines
    escaped = value.replace("\r", "\\r").replace("\n", "\\n").replace("\t", " ")
    escaped = _CONTROL_CHARS_RE.sub("", escaped)

    if not redact:
        return escaped

    step = redact_url(escaped) if "://" in escaped else escaped
    return redact_text(step, extra_secrets=extra_secrets)


def sanitize_log_extra(
    data: Mapping[str, Any],
    *,
    redact: bool = True,
    extra_secrets: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Sanitize a mapping of structured log context fields against secrets and CRLF injection."""
    base = redact_mapping(data, extra_secrets=extra_secrets) if redact else dict(data)
    cleaned: dict[str, Any] = {}
    for key, val in base.items():
        safe_key = sanitize_log_text(str(key), redact=False)
        if isinstance(val, str):
            cleaned[safe_key] = sanitize_log_text(val, redact=redact, extra_secrets=extra_secrets)
        elif isinstance(val, Mapping):
            cleaned[safe_key] = sanitize_log_extra(val, redact=redact, extra_secrets=extra_secrets)
        elif isinstance(val, list | tuple):
            cleaned[safe_key] = [
                sanitize_log_text(item, redact=redact, extra_secrets=extra_secrets)
                if isinstance(item, str)
                else item
                for item in val
            ]
        else:
            cleaned[safe_key] = val
    return cleaned


class RedactingCorrelationFilter(logging.Filter):
    """Logging filter that attaches `request_id` and scrubs secrets and CRLF injection."""

    def __init__(
        self,
        *,
        service_name: str = "E-WITNESS",
        environment: str = "development",
        redact_sensitive: bool = True,
        extra_secrets: Sequence[str] | None = None,
    ) -> None:
        super().__init__()
        self.service_name = service_name
        self.environment = environment
        self.redact_sensitive = redact_sensitive
        self.extra_secrets = tuple(extra_secrets) if extra_secrets else ()

    def filter(self, record: logging.LogRecord) -> bool:
        """Enrich and sanitize ``record`` in place before formatting."""
        record.request_id = get_request_id() or "-"
        record.environment = self.environment
        record.service = self.service_name

        # Render message with args safely, then scrub secrets and control characters
        raw_message = record.getMessage()
        record.msg = sanitize_log_text(
            raw_message,
            redact=self.redact_sensitive,
            extra_secrets=self.extra_secrets,
        )
        record.args = ()

        # Sanitize any custom extra attributes attached to the record
        extra_keys = set(record.__dict__.keys()) - _STANDARD_LOG_ATTRS
        if extra_keys:
            extra_map = {k: record.__dict__[k] for k in extra_keys}
            sanitized_extra = sanitize_log_extra(
                extra_map,
                redact=self.redact_sensitive,
                extra_secrets=self.extra_secrets,
            )
            for k, v in sanitized_extra.items():
                record.__dict__[k] = v

        return True


class StructuredJsonFormatter(logging.Formatter):
    """Single-line JSON log formatter for production and structured observability."""

    def __init__(
        self,
        *,
        redact_sensitive: bool = True,
        extra_secrets: Sequence[str] | None = None,
    ) -> None:
        super().__init__()
        self.redact_sensitive = redact_sensitive
        self.extra_secrets = tuple(extra_secrets) if extra_secrets else ()

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, tz=UTC).isoformat()
        request_id = getattr(record, "request_id", None) or get_request_id() or "-"
        environment = getattr(record, "environment", "development")
        service = getattr(record, "service", "E-WITNESS")

        message = sanitize_log_text(
            record.getMessage(),
            redact=self.redact_sensitive,
            extra_secrets=self.extra_secrets,
        )

        payload: dict[str, Any] = {
            "timestamp": timestamp,
            "level": record.levelname,
            "logger": record.name,
            "service": service,
            "environment": environment,
            "request_id": request_id,
            "message": message,
        }

        extra_keys = sorted(set(record.__dict__.keys()) - _STANDARD_LOG_ATTRS)
        if extra_keys:
            raw_extra = {k: record.__dict__[k] for k in extra_keys}
            payload["context"] = sanitize_log_extra(
                raw_extra,
                redact=self.redact_sensitive,
                extra_secrets=self.extra_secrets,
            )

        if record.exc_info and record.exc_info[0] is not None:
            exc_type = record.exc_info[0].__name__
            exc_val = str(record.exc_info[1]) if record.exc_info[1] is not None else ""
            payload["exception"] = {
                "type": exc_type,
                "message": sanitize_log_text(
                    exc_val,
                    redact=self.redact_sensitive,
                    extra_secrets=self.extra_secrets,
                ),
            }

        return json.dumps(payload, default=str, ensure_ascii=True)


class SafeConsoleFormatter(logging.Formatter):
    """Single-line human-readable formatter that prevents multiline log forgery."""

    def __init__(
        self,
        *,
        redact_sensitive: bool = True,
        extra_secrets: Sequence[str] | None = None,
    ) -> None:
        super().__init__()
        self.redact_sensitive = redact_sensitive
        self.extra_secrets = tuple(extra_secrets) if extra_secrets else ()

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, tz=UTC).isoformat()
        request_id = getattr(record, "request_id", None) or get_request_id() or "-"
        environment = getattr(record, "environment", "development")
        message = sanitize_log_text(
            record.getMessage(),
            redact=self.redact_sensitive,
            extra_secrets=self.extra_secrets,
        )

        extra_keys = sorted(set(record.__dict__.keys()) - _STANDARD_LOG_ATTRS)
        extra_suffix = ""
        if extra_keys:
            raw_extra = {k: record.__dict__[k] for k in extra_keys}
            safe_extra = sanitize_log_extra(
                raw_extra,
                redact=self.redact_sensitive,
                extra_secrets=self.extra_secrets,
            )
            pairs = " ".join(f"{k}={v!r}" for k, v in safe_extra.items())
            extra_suffix = f" | {pairs}"

        return (
            f"{timestamp} [{record.levelname}] [{environment}] "
            f"[req:{request_id}] {record.name}: {message}{extra_suffix}"
        )


def configure_logging(settings: Settings) -> logging.Logger:
    """Configure the E-WITNESS application logger hierarchy from validated Settings."""
    extra_secrets = settings._collect_raw_secrets()
    log_filter = RedactingCorrelationFilter(
        service_name=settings.APP_NAME,
        environment=str(settings.ENVIRONMENT),
        redact_sensitive=settings.LOG_REDACT_SENSITIVE,
        extra_secrets=extra_secrets,
    )

    formatter: logging.Formatter
    if settings.LOG_FORMAT == "json":
        formatter = StructuredJsonFormatter(
            redact_sensitive=settings.LOG_REDACT_SENSITIVE,
            extra_secrets=extra_secrets,
        )
    else:
        formatter = SafeConsoleFormatter(
            redact_sensitive=settings.LOG_REDACT_SENSITIVE,
            extra_secrets=extra_secrets,
        )

    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(formatter)
    handler.addFilter(log_filter)

    app_logger = logging.getLogger("ewitness")
    app_logger.setLevel(getattr(logging, str(settings.LOG_LEVEL), logging.INFO))
    app_logger.handlers.clear()
    app_logger.filters.clear()
    app_logger.addHandler(handler)
    app_logger.propagate = False

    return app_logger


def get_logger(name: str = "ewitness") -> logging.Logger:
    """Return a child logger under the ``ewitness`` namespace."""
    if name == "ewitness" or name.startswith("ewitness."):
        return logging.getLogger(name)
    return logging.getLogger(f"ewitness.{name}")
