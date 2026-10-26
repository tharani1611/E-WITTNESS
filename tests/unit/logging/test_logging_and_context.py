"""Unit tests for correlation ID validation, async context isolation, and log sanitization (Phase 08)."""

from __future__ import annotations

import asyncio
import io
import json
import logging
from collections.abc import Callable
from typing import Any

import pytest

from backend.app.config.settings import Settings
from backend.app.core.context import (
    clear_request_id,
    generate_correlation_id,
    get_request_id,
    is_valid_correlation_id,
    reset_request_id,
    set_request_id,
    validate_or_generate_request_id,
)
from backend.app.core.logging import (
    RedactingCorrelationFilter,
    SafeConsoleFormatter,
    StructuredJsonFormatter,
    configure_logging,
    get_logger,
    sanitize_log_extra,
    sanitize_log_text,
)
from backend.app.core.secrets import REDACTION_MASK


@pytest.mark.unit
class TestCorrelationIdValidationAndLifecycle:
    """Verify correlation ID policy validation, generation, and contextvars lifecycle."""

    @pytest.mark.parametrize(
        "valid_id",
        [
            "req-12345678",
            "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "trace_id.2026_10_13-ABCD1234",
            "X" * 64,
        ],
    )
    def test_valid_correlation_ids_are_accepted(self, valid_id: str) -> None:
        assert is_valid_correlation_id(valid_id) is True
        effective, accepted = validate_or_generate_request_id(valid_id)
        assert effective == valid_id
        assert accepted is True

    @pytest.mark.parametrize(
        "invalid_id",
        [
            None,
            "",
            "short77",
            "X" * 65,
            "invalid space in id",
            "forged\nINFO: fake log line",
            "forged\r\nSet-Cookie: evil=1",
            "bad$char#id!12345",
            "../path/traversal/id",
        ],
    )
    def test_invalid_or_malicious_correlation_ids_are_replaced(
        self, invalid_id: str | None
    ) -> None:
        assert is_valid_correlation_id(invalid_id) is False
        effective, accepted = validate_or_generate_request_id(invalid_id)
        assert accepted is False
        assert is_valid_correlation_id(effective) is True
        assert effective != invalid_id

    def test_set_and_reset_request_id_lifecycle(self) -> None:
        assert get_request_id() is None
        cid = generate_correlation_id()
        token = set_request_id(cid)
        assert get_request_id() == cid
        reset_request_id(token)
        assert get_request_id() is None

        set_request_id(cid)
        assert get_request_id() == cid
        clear_request_id()
        assert get_request_id() is None

    def test_set_request_id_rejects_unsafe_value(self) -> None:
        with pytest.raises(ValueError, match="Cannot bind an invalid or unsafe correlation ID"):
            set_request_id("bad\nrequest\nid")

    async def test_concurrent_async_tasks_maintain_isolated_correlation_context(self) -> None:
        async def worker(task_idx: int) -> tuple[str, str | None]:
            expected_id = f"concurrent-req-{task_idx:04d}"
            token = set_request_id(expected_id)
            try:
                await asyncio.sleep(0.005)
                observed = get_request_id()
                return expected_id, observed
            finally:
                reset_request_id(token)

        results = await asyncio.gather(*(worker(i) for i in range(30)))
        for expected, observed in results:
            assert observed == expected
        assert get_request_id() is None


@pytest.mark.unit
class TestStructuredLoggingAndSanitization:
    """Verify multiline log injection prevention, secret scrubbing, and formatters."""

    def test_sanitize_log_text_neutralizes_multiline_forgery_and_redacts_secrets(self) -> None:
        forged_input = (
            "User login failed for user=alice\r\n"
            "2026-10-13T00:00:00Z [INFO] Admin privilege granted to alice "
            "with Authorization: Bearer secret_jwt_token_123456"
        )
        sanitized = sanitize_log_text(forged_input, extra_secrets=["CustomSecretToken99"])
        assert "\n" not in sanitized
        assert "\r" not in sanitized
        assert "\\r\\n" in sanitized
        assert "secret_jwt_token_123456" not in sanitized
        assert REDACTION_MASK in sanitized

    def test_sanitize_log_extra_scrubs_nested_mappings_and_lists(self) -> None:
        raw_extra: dict[str, Any] = {
            "user_input": "line1\nline2",
            "auth_secret_key": "should_be_masked",
            "nested": {
                "db_url": "postgresql+asyncpg://u:HiddenPass123@localhost:5432/db",
                "items": ["safe_item", "forged\r\nitem", 100],
            },
        }
        cleaned = sanitize_log_extra(raw_extra)
        assert cleaned["user_input"] == "line1\\nline2"
        assert cleaned["auth_secret_key"] == REDACTION_MASK
        assert "HiddenPass123" not in cleaned["nested"]["db_url"]
        assert cleaned["nested"]["items"][1] == "forged\\r\\nitem"
        assert cleaned["nested"]["items"][2] == 100

    def test_structured_json_formatter_produces_single_line_redacted_json(
        self, test_settings: Settings
    ) -> None:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        extra_secrets = test_settings._collect_raw_secrets()
        handler.addFilter(
            RedactingCorrelationFilter(
                service_name=test_settings.APP_NAME,
                environment=str(test_settings.ENVIRONMENT),
                redact_sensitive=True,
                extra_secrets=extra_secrets,
            )
        )
        handler.setFormatter(
            StructuredJsonFormatter(redact_sensitive=True, extra_secrets=extra_secrets)
        )

        test_logger = logging.getLogger("ewitness.test.json")
        test_logger.handlers = [handler]
        test_logger.setLevel(logging.INFO)
        test_logger.propagate = False

        token = set_request_id("req-json-test-0001")
        try:
            try:
                raise RuntimeError(
                    "DB error on postgresql+asyncpg://admin:LeakDbPass99@host:5432/db\nFakeLine"
                )
            except RuntimeError:
                test_logger.error(
                    "Operation failed with token=%s\nInjectedLine",
                    "test_only_signing_key_with_sufficient_length_32_plus",
                    exc_info=True,
                    extra={"custom_field": "val\nwith\nnewlines", "api_key": "raw_api_key_val"},
                )
        finally:
            reset_request_id(token)

        raw_output = stream.getvalue().strip()
        # Must be strictly a single line of valid JSON
        assert "\n" not in raw_output
        parsed = json.loads(raw_output)
        assert parsed["request_id"] == "req-json-test-0001"
        assert parsed["level"] == "ERROR"
        assert parsed["environment"] == "testing"
        assert "test_only_signing_key_with_sufficient_length_32_plus" not in raw_output
        assert "LeakDbPass99" not in raw_output
        assert "raw_api_key_val" not in raw_output
        assert parsed["context"]["api_key"] == REDACTION_MASK
        assert parsed["context"]["custom_field"] == "val\\nwith\\nnewlines"
        assert parsed["exception"]["type"] == "RuntimeError"
        assert REDACTION_MASK in parsed["exception"]["message"]

    def test_safe_console_formatter_and_configure_logging(
        self, settings_factory: Callable[..., Settings]
    ) -> None:
        console_settings = settings_factory(LOG_FORMAT="console", LOG_LEVEL="DEBUG")
        app_logger = configure_logging(console_settings)
        assert app_logger.name == "ewitness"

        child_logger = get_logger("service.example")
        assert child_logger.name == "ewitness.service.example"
        assert get_logger("ewitness").name == "ewitness"

        stream = io.StringIO()
        assert len(app_logger.handlers) == 1
        stream_handler = app_logger.handlers[0]
        assert isinstance(stream_handler.formatter, SafeConsoleFormatter)
        if isinstance(stream_handler, logging.StreamHandler):
            stream_handler.setStream(stream)

        token = set_request_id("req-console-9999")
        try:
            child_logger.info(
                "Console test line1\nline2 password=MyConsolePassword123",
                extra={"step": "init\r\nstep"},
            )
        finally:
            reset_request_id(token)

        lines = stream.getvalue().splitlines()
        assert len(lines) == 1
        assert "[req:req-console-9999]" in lines[0]
        assert "MyConsolePassword123" not in lines[0]
        assert REDACTION_MASK in lines[0]
        assert "line1\\nline2" in lines[0]
