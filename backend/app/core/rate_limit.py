"""In-memory rate limiting and throttling abstraction (Phase 17 & Phase 28).

Provides request and action rate limiting for sensitive endpoints (login,
password recovery, verification, global API) with sliding time windows to prevent
brute-force credential guessing, enumeration, and denial of service.

Key guarantees:
- Thread-safe sliding window tracking using re-entrant or atomic locks.
- Accurate Retry-After calculation propagated in RateLimitExceededError.
- Clean backend protocol (RateLimiterProtocol).
- Fail-safe handling when distributed stores are unconfigured.
"""

from __future__ import annotations

import math
import threading
import time
from collections import defaultdict
from typing import Protocol

from backend.app.core.exceptions import RateLimitExceededError
from backend.app.core.logging import get_logger

logger = get_logger("core.rate_limit")


class RateLimiterProtocol(Protocol):
    """Protocol defining the rate limiter interface."""

    def check_rate_limit(
        self,
        key: str,
        action: str,
        *,
        max_requests: int,
        window_seconds: float,
    ) -> None:
        """Check if ``action`` for ``key`` exceeds ``max_requests`` in ``window_seconds``."""
        ...

    def reset(self, key: str, action: str) -> None:
        """Reset the request history for a specific ``(key, action)`` pair."""
        ...

    def clear(self) -> None:
        """Clear all rate limiting state."""
        ...


class InMemoryRateLimiter:
    """Thread-safe, in-memory sliding window rate limiter."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._history: dict[tuple[str, str], list[float]] = defaultdict(list)

    def check_rate_limit(
        self,
        key: str,
        action: str,
        *,
        max_requests: int,
        window_seconds: float,
    ) -> None:
        """Enforce request limits for ``(key, action)`` within ``window_seconds``.

        Raises:
            RateLimitExceededError: When request count exceeds ``max_requests``.
                Includes accurate ``retry_after`` integer seconds.
        """
        now = time.monotonic()
        cutoff = now - window_seconds
        dict_key = (key.strip().lower(), action.strip().lower())

        with self._lock:
            timestamps = self._history[dict_key]
            # Prune timestamps older than window
            valid_timestamps = [t for t in timestamps if t > cutoff]
            if len(valid_timestamps) >= max_requests:
                # Do not record new timestamp on rejection
                self._history[dict_key] = valid_timestamps
                oldest = valid_timestamps[0]
                retry_after = max(1, math.ceil(oldest + window_seconds - now))
                raise RateLimitExceededError(
                    f"Too many {action} requests. Please wait {retry_after} seconds before trying again.",
                    code="RATE_LIMIT_EXCEEDED",
                    retry_after=retry_after,
                )

            valid_timestamps.append(now)
            self._history[dict_key] = valid_timestamps

    def get_remaining_requests(
        self,
        key: str,
        action: str,
        *,
        max_requests: int,
        window_seconds: float,
    ) -> int:
        """Return the number of requests remaining in the current sliding window."""
        now = time.monotonic()
        cutoff = now - window_seconds
        dict_key = (key.strip().lower(), action.strip().lower())
        with self._lock:
            timestamps = self._history.get(dict_key, [])
            valid_count = sum(1 for t in timestamps if t > cutoff)
            return max(0, max_requests - valid_count)

    def reset(self, key: str, action: str) -> None:
        """Clear recorded requests for ``(key, action)`` (e.g. after successful auth)."""
        dict_key = (key.strip().lower(), action.strip().lower())
        with self._lock:
            self._history.pop(dict_key, None)

    def clear(self) -> None:
        """Clear all rate limit state across all keys (useful between test runs)."""
        with self._lock:
            self._history.clear()


def create_rate_limiter(
    backend: str = "memory",
    *,
    fail_open: bool = False,
) -> RateLimiterProtocol:
    """Factory to instantiate rate limiter based on configured backend.

    Falls back safely to InMemoryRateLimiter if a distributed backend is requested
    but not available in the single-process environment.
    """
    if backend == "redis":
        logger.warning(
            "Redis rate limiting backend requested but distributed store is unconfigured; "
            "falling back to in-memory sliding window rate limiter.",
            extra={"requested_backend": backend, "fail_open": fail_open},
        )
    return InMemoryRateLimiter()


# Default singleton instance
default_rate_limiter = InMemoryRateLimiter()
