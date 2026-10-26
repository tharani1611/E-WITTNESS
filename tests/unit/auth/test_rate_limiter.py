"""Unit tests for in-memory rate limiting and request throttling (Phase 17)."""

from __future__ import annotations

import concurrent.futures

import pytest

from backend.app.core.exceptions import RateLimitExceededError
from backend.app.core.rate_limit import InMemoryRateLimiter


@pytest.fixture
def limiter() -> InMemoryRateLimiter:
    """Return a fresh InMemoryRateLimiter instance."""
    return InMemoryRateLimiter()


class TestInMemoryRateLimiter:
    """Verify sliding-window throttling and abuse rejection."""

    def test_requests_within_limit_are_allowed(self, limiter: InMemoryRateLimiter) -> None:
        key = "192.168.1.100"
        for _ in range(5):
            limiter.check_rate_limit(key, "login", max_requests=5, window_seconds=10.0)

    def test_requests_exceeding_limit_raise_rate_limit_exceeded(
        self, limiter: InMemoryRateLimiter
    ) -> None:
        key = "10.0.0.5"
        for _ in range(3):
            limiter.check_rate_limit(key, "login", max_requests=3, window_seconds=10.0)

        with pytest.raises(RateLimitExceededError) as exc_info:
            limiter.check_rate_limit(key, "login", max_requests=3, window_seconds=10.0)
        assert exc_info.value.code == "RATE_LIMIT_EXCEEDED"
        assert exc_info.value.status_code == 429

    def test_reset_clears_recorded_requests_for_action(self, limiter: InMemoryRateLimiter) -> None:
        key = "user@test.edu"
        for _ in range(3):
            limiter.check_rate_limit(key, "login", max_requests=3, window_seconds=10.0)

        with pytest.raises(RateLimitExceededError):
            limiter.check_rate_limit(key, "login", max_requests=3, window_seconds=10.0)

        # Successful auth resets the bucket
        limiter.reset(key, "login")
        # Now a new attempt succeeds
        limiter.check_rate_limit(key, "login", max_requests=3, window_seconds=10.0)

    def test_distinct_actions_and_keys_do_not_interfere(self, limiter: InMemoryRateLimiter) -> None:
        limiter.check_rate_limit("1.1.1.1", "login", max_requests=1, window_seconds=10.0)
        with pytest.raises(RateLimitExceededError):
            limiter.check_rate_limit("1.1.1.1", "login", max_requests=1, window_seconds=10.0)

        # Different action on same IP allowed
        limiter.check_rate_limit("1.1.1.1", "password_reset", max_requests=1, window_seconds=10.0)
        # Different IP on same action allowed
        limiter.check_rate_limit("2.2.2.2", "login", max_requests=1, window_seconds=10.0)

    def test_thread_safe_concurrency(self, limiter: InMemoryRateLimiter) -> None:
        key = "concurrent_client_ip"
        max_reqs = 50

        def _worker() -> bool:
            try:
                limiter.check_rate_limit(key, "probe", max_requests=max_reqs, window_seconds=10.0)
                return True
            except RateLimitExceededError:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(_worker) for _ in range(100)]
            results = [f.result() for f in futures]

        allowed_count = sum(1 for r in results if r is True)
        rejected_count = sum(1 for r in results if r is False)

        assert allowed_count == max_reqs
        assert rejected_count == 50
