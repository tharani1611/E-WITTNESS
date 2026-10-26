"""Unit tests for Phase 28 rate limiting, sliding-window throttling, and abuse prevention."""

from __future__ import annotations

import concurrent.futures

import pytest

from backend.app.core.exceptions import RateLimitExceededError
from backend.app.core.rate_limit import (
    InMemoryRateLimiter,
    create_rate_limiter,
)


@pytest.mark.unit
class TestInMemoryRateLimiter:
    """Verify thread-safe sliding window rate limiter behaviors."""

    def test_requests_within_limit_pass(self) -> None:
        limiter = InMemoryRateLimiter()
        # Allow 3 requests per 10 seconds
        for _ in range(3):
            limiter.check_rate_limit("test_key", "action_a", max_requests=3, window_seconds=10.0)

        assert (
            limiter.get_remaining_requests(
                "test_key", "action_a", max_requests=3, window_seconds=10.0
            )
            == 0
        )

    def test_exceeding_limit_raises_rate_limit_exceeded_error_with_retry_after(self) -> None:
        limiter = InMemoryRateLimiter()
        # Send 2 requests
        limiter.check_rate_limit("test_user", "login", max_requests=2, window_seconds=5.0)
        limiter.check_rate_limit("test_user", "login", max_requests=2, window_seconds=5.0)

        # 3rd request should fail
        with pytest.raises(RateLimitExceededError) as exc_info:
            limiter.check_rate_limit("test_user", "login", max_requests=2, window_seconds=5.0)

        err = exc_info.value
        assert err.code == "RATE_LIMIT_EXCEEDED"
        assert err.retry_after is not None
        assert 1 <= err.retry_after <= 5

    def test_reset_clears_history_for_key(self) -> None:
        limiter = InMemoryRateLimiter()
        limiter.check_rate_limit("user_1", "login", max_requests=1, window_seconds=10.0)

        # Subsequent check fails
        with pytest.raises(RateLimitExceededError):
            limiter.check_rate_limit("user_1", "login", max_requests=1, window_seconds=10.0)

        # Reset user_1
        limiter.reset("user_1", "login")

        # Now passes
        limiter.check_rate_limit("user_1", "login", max_requests=1, window_seconds=10.0)

    def test_clear_resets_all_state(self) -> None:
        limiter = InMemoryRateLimiter()
        limiter.check_rate_limit("user_a", "login", max_requests=1, window_seconds=10.0)
        limiter.check_rate_limit("user_b", "login", max_requests=1, window_seconds=10.0)

        limiter.clear()

        # Both pass again
        limiter.check_rate_limit("user_a", "login", max_requests=1, window_seconds=10.0)
        limiter.check_rate_limit("user_b", "login", max_requests=1, window_seconds=10.0)

    def test_concurrent_access_is_thread_safe(self) -> None:
        limiter = InMemoryRateLimiter()
        max_reqs = 50
        num_threads = 10
        reqs_per_thread = 10
        # Total requests attempted = 100, limit = 50

        passed_count = 0
        rejected_count = 0

        def attempt_request() -> bool:
            try:
                limiter.check_rate_limit(
                    "thread_test", "flood", max_requests=max_reqs, window_seconds=10.0
                )
                return True
            except RateLimitExceededError:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [
                executor.submit(attempt_request) for _ in range(num_threads * reqs_per_thread)
            ]
            for f in concurrent.futures.as_completed(futures):
                if f.result():
                    passed_count += 1
                else:
                    rejected_count += 1

        assert passed_count == max_reqs
        assert rejected_count == (num_threads * reqs_per_thread) - max_reqs

    def test_factory_creates_memory_limiter_or_logs_redis_fallback(self) -> None:
        mem_limiter = create_rate_limiter("memory")
        assert isinstance(mem_limiter, InMemoryRateLimiter)

        fallback_limiter = create_rate_limiter("redis", fail_open=False)
        assert isinstance(fallback_limiter, InMemoryRateLimiter)
