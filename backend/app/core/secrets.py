"""Cryptographic secret validation and sensitive data redaction utilities.

This module enforces Phase 05 security requirements:
- Detection of weak, low-entropy, or placeholder secrets before startup completes
- Automatic redaction of credentials in connection URLs (PostgreSQL, Redis, HTTP)
- Recursive scrubbing of dictionaries, log payloads, and exception messages
- Safe formatting of Pydantic validation errors without leaking raw secret inputs
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import SecretStr, ValidationError

REDACTION_MASK: str = "***REDACTED***"

# Exact weak values and substrings forbidden in production secrets
FORBIDDEN_SECRET_PATTERNS: tuple[str, ...] = (
    "change-me",
    "changeme",
    "replace_with",
    "replace-with",
    "your-secret",
    "your_secret",
    "dev-secret",
    "dev_secret",
    "test-secret",
    "test_secret",
    "example",
    "placeholder",
    "dummy",
    "default",
    "minioadmin",
    "postgres",
    "password",
    "123456",
    "qwerty",
    "admin",
    "insecure",
    "secret-key",
    "secret_key",
)

# Dictionary keys whose values must always be masked in logs and dumps
SENSITIVE_KEY_SUBSTRINGS: tuple[str, ...] = (
    "secret",
    "password",
    "passwd",
    "pwd",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "signing_key",
    "authorization",
    "cookie",
    "credential",
    "session_id",
)

# Query parameters in URLs whose values must be masked
SENSITIVE_QUERY_PARAMS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "access_key",
        "secret_key",
        "key",
        "sig",
        "signature",
        "auth",
        "X-Amz-Signature",
        "X-Amz-Credential",
        "X-Amz-Security-Token",
    }
)

# Regex patterns for scrubbing free-form strings, log lines, and exception messages
_URL_USERINFO_RE = re.compile(
    r"(?P<prefix>[a-zA-Z][a-zA-Z0-9+.-]*://[^:/@\s]*:)(?P<secret>[^@\s]+)(?P<suffix>@)"
)
_AUTH_HEADER_RE = re.compile(
    r"(?i)(?P<prefix>\b(?:authorization\s*[:=]\s*)?(?:bearer|basic|token)\s+)"
    r"(?P<secret>[A-Za-z0-9._~+/=-]{6,})"
)
_KEY_VALUE_SECRET_RE = re.compile(
    r"(?i)(?P<prefix>\b(?:[a-z0-9_]*?(?:secret|password|passwd|pwd|token|api_key|apikey|access_key|private_key)[a-z0-9_]*)"
    r"\s*[:=]\s*['\"]?)"
    r"(?P<secret>[^'\"\s,;}{)(\]\[]+)"
)


def calculate_shannon_entropy(value: str) -> float:
    """Compute the Shannon entropy (in bits per character) of a string."""
    if not value:
        return 0.0
    length = len(value)
    counts = Counter(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_weak_or_placeholder_secret(
    value: str,
    *,
    min_length: int = 32,
    min_unique_chars: int = 8,
    min_entropy_bits: float = 3.0,
) -> tuple[bool, str]:
    """Evaluate whether a secret string is weak, short, or a known placeholder.

    Returns a tuple of ``(is_weak, reason)``. Never includes the raw secret value
    in the returned reason string.
    """
    stripped = value.strip()
    if not stripped:
        return True, "Secret value is empty or whitespace."

    if len(stripped) < min_length:
        return (
            True,
            f"Secret length ({len(stripped)}) is below the minimum required {min_length} characters.",
        )

    lower_val = stripped.lower()
    for pattern in FORBIDDEN_SECRET_PATTERNS:
        if pattern in lower_val:
            return (
                True,
                f"Secret contains forbidden placeholder or weak pattern '{pattern}'.",
            )

    unique_chars = len(set(stripped))
    if unique_chars < min_unique_chars:
        return (
            True,
            f"Secret has insufficient character diversity ({unique_chars} unique characters; "
            f"minimum {min_unique_chars} required).",
        )

    entropy = calculate_shannon_entropy(stripped)
    if entropy < min_entropy_bits:
        return (
            True,
            f"Secret has insufficient Shannon entropy ({entropy:.2f} bits/char; "
            f"minimum {min_entropy_bits:.2f} required).",
        )

    return False, "Secret meets length and entropy requirements."


def is_sensitive_key_name(key: str) -> bool:
    """Return True if a dictionary/attribute name represents a sensitive secret."""
    normalized = key.lower().strip()
    return any(marker in normalized for marker in SENSITIVE_KEY_SUBSTRINGS)


def redact_url(url: str) -> str:
    """Redact credentials embedded in a URL or database/Redis DSN string.

    Preserves the scheme, username (if present), hostname, port, and path while
    replacing any password in userinfo or sensitive query parameters with
    ``***REDACTED***``.
    """
    if not url or not isinstance(url, str):
        return url

    # First apply regex fallback for multiple or non-standard URLs inside strings
    redacted = _URL_USERINFO_RE.sub(rf"\g<prefix>{REDACTION_MASK}\g<suffix>", url)

    try:
        parts = urlsplit(redacted)
    except ValueError:
        return redacted

    if not parts.scheme or not parts.netloc:
        return redacted

    netloc = parts.netloc
    if "@" in netloc:
        userinfo, hostinfo = netloc.rsplit("@", 1)
        if ":" in userinfo:
            username, _ = userinfo.split(":", 1)
            netloc = f"{username}:{REDACTION_MASK}@{hostinfo}"

    query = parts.query
    if query:
        query_items = parse_qsl(query, keep_blank_values=True)
        sanitized_items = [
            (
                k,
                REDACTION_MASK
                if k in SENSITIVE_QUERY_PARAMS
                or k.lower() in {p.lower() for p in SENSITIVE_QUERY_PARAMS}
                or is_sensitive_key_name(k)
                else v,
            )
            for k, v in query_items
        ]
        query = urlencode(sanitized_items, safe="*")

    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))


def redact_text(text: str, *, extra_secrets: Sequence[str] | None = None) -> str:
    """Scrub credentials, bearer tokens, URL passwords, and known secrets from text."""
    if not text:
        return text

    result = text

    # 1. Scrub any caller-provided known secret values first
    if extra_secrets:
        for secret in extra_secrets:
            if secret and len(secret.strip()) >= 4:
                result = result.replace(secret, REDACTION_MASK)
                result = result.replace(secret.strip(), REDACTION_MASK)

    # 2. Scrub URL userinfo credentials
    result = _URL_USERINFO_RE.sub(rf"\g<prefix>{REDACTION_MASK}\g<suffix>", result)

    # 3. Scrub Authorization Bearer / Basic headers and tokens
    result = _AUTH_HEADER_RE.sub(rf"\g<prefix>{REDACTION_MASK}", result)

    # 4. Scrub key=value or key: value assignments for sensitive field names
    result = _KEY_VALUE_SECRET_RE.sub(rf"\g<prefix>{REDACTION_MASK}", result)

    return result


def redact_mapping(
    data: Mapping[str, Any],
    *,
    extra_secrets: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Recursively redact sensitive keys, SecretStr instances, and URLs in a mapping."""
    sanitized: dict[str, Any] = {}
    for key, value in data.items():
        key_str = str(key)
        if is_sensitive_key_name(key_str):
            sanitized[key_str] = REDACTION_MASK if value is not None else None
        else:
            sanitized[key_str] = _redact_value(value, extra_secrets=extra_secrets)
    return sanitized


def _redact_value(
    value: Any,
    *,
    extra_secrets: Sequence[str] | None = None,
) -> Any:
    """Recursively sanitize an arbitrary Python value for safe logging/serialization."""
    if isinstance(value, SecretStr):
        return REDACTION_MASK
    if isinstance(value, Mapping):
        return redact_mapping(value, extra_secrets=extra_secrets)
    if isinstance(value, list):
        return [_redact_value(item, extra_secrets=extra_secrets) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(item, extra_secrets=extra_secrets) for item in value)
    if isinstance(value, set | frozenset):
        return [_redact_value(item, extra_secrets=extra_secrets) for item in value]
    if isinstance(value, str):
        step = redact_url(value) if "://" in value else value
        return redact_text(step, extra_secrets=extra_secrets)
    return value


def sanitize_validation_errors(exc: ValidationError) -> list[dict[str, Any]]:
    """Return a sanitized list of Pydantic validation errors safe for logging.

    Ensures raw secret inputs or embedded DSN passwords are never exposed in
    validation failure outputs.
    """
    safe_errors: list[dict[str, Any]] = []
    for err in exc.errors(include_url=False, include_context=False):
        loc_tuple = tuple(str(part) for part in err.get("loc", ()))
        field_is_sensitive = any(is_sensitive_key_name(part) for part in loc_tuple)
        raw_input = err.get("input")

        if field_is_sensitive:
            safe_input: Any = REDACTION_MASK
        else:
            safe_input = _redact_value(raw_input)

        safe_errors.append(
            {
                "loc": loc_tuple,
                "msg": redact_text(str(err.get("msg", ""))),
                "type": str(err.get("type", "validation_error")),
                "input": safe_input,
            }
        )
    return safe_errors
