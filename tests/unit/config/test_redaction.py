"""Unit tests for cryptographic secret validation and sensitive data redaction utilities."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, Field, SecretStr, ValidationError

from backend.app.core.secrets import (
    REDACTION_MASK,
    calculate_shannon_entropy,
    is_sensitive_key_name,
    is_weak_or_placeholder_secret,
    redact_mapping,
    redact_text,
    redact_url,
    sanitize_validation_errors,
)


class TestEntropyAndWeakSecretDetection:
    """Verify Shannon entropy calculation and weak/placeholder secret rejection."""

    def test_shannon_entropy_empty_and_repeated_strings(self) -> None:
        assert calculate_shannon_entropy("") == 0.0
        assert calculate_shannon_entropy("a" * 40) == 0.0
        assert calculate_shannon_entropy("abababab") == pytest.approx(1.0)

    def test_shannon_entropy_high_diversity_string(self) -> None:
        high_entropy_key = "vN9#mK4$pL8@qW2!zX7&cB5*rT1^yU6%hJ3_gF0"
        assert calculate_shannon_entropy(high_entropy_key) > 4.0

    @pytest.mark.parametrize(
        "weak_value",
        [
            "",
            "   ",
            "short_key_under_32_chars",
            "REPLACE_WITH_HIGH_ENTROPY_SECRET_KEY_MIN_32_CHARS",
            "change-me-in-production-1234567890-abcdef",
            "my_super_secret_password_for_production_use",
            "a" * 48,
            "abcd" * 12,
        ],
    )
    def test_is_weak_or_placeholder_secret_rejects_weak_inputs(self, weak_value: str) -> None:
        is_weak, reason = is_weak_or_placeholder_secret(weak_value, min_length=32)
        assert is_weak is True
        assert reason
        # Ensure the raw secret value itself is never echoed back in the failure reason
        if len(weak_value.strip()) >= 16:
            assert weak_value.strip() not in reason

    def test_is_weak_or_placeholder_secret_accepts_strong_key(self) -> None:
        strong = "vN9#mK4$pL8@qW2!zX7&cB5*rT1^yU6%hJ3_gF0-dS8+aE5"
        is_weak, reason = is_weak_or_placeholder_secret(strong, min_length=32)
        assert is_weak is False
        assert "meets length and entropy requirements" in reason


class TestUrlAndTextRedaction:
    """Verify URL credential scrubbing, text scrubbing, and recursive mapping redaction."""

    def test_redact_url_masks_database_and_redis_passwords(self) -> None:
        raw_db = (
            "postgresql+asyncpg://ewitness_user:SuperSecretDbPass!99@db.example.edu:5432/ewitness"
        )
        redacted_db = redact_url(raw_db)
        assert "SuperSecretDbPass!99" not in redacted_db
        assert (
            redacted_db
            == f"postgresql+asyncpg://ewitness_user:{REDACTION_MASK}@db.example.edu:5432/ewitness"
        )

        raw_redis = "rediss://:RedisTopSecretToken88@redis.example.edu:6379/0"
        redacted_redis = redact_url(raw_redis)
        assert "RedisTopSecretToken88" not in redacted_redis
        assert redacted_redis == f"rediss://:{REDACTION_MASK}@redis.example.edu:6379/0"

    def test_redact_url_masks_sensitive_query_params(self) -> None:
        signed_url = (
            "https://s3.example.edu/bucket/item.bin"
            "?X-Amz-Signature=deadbeef12345&api_key=my_api_key_99&page=2"
        )
        redacted = redact_url(signed_url)
        assert "deadbeef12345" not in redacted
        assert "my_api_key_99" not in redacted
        assert "page=2" in redacted
        assert REDACTION_MASK in redacted

    def test_redact_text_masks_bearer_tokens_and_assignments(self) -> None:
        raw_log = (
            "Request failed with Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig "
            "and auth_secret_key='TopSecretValue12345' on postgresql://admin:DbPass987@host:5432/db"
        )
        scrubbed = redact_text(raw_log, extra_secrets=["CustomRawSecretXYZ"])
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in scrubbed
        assert "TopSecretValue12345" not in scrubbed
        assert "DbPass987" not in scrubbed
        assert REDACTION_MASK in scrubbed

    def test_redact_mapping_recursively_masks_nested_structures(self) -> None:
        payload = {
            "app_name": "E-WITNESS",
            "auth_secret_key": "raw_signing_secret_value",
            "nested": {
                "storage_secret_key": SecretStr("s3_raw_secret"),
                "database_url": "postgresql+asyncpg://u:MyDbPassword123@localhost:5432/db",
                "headers": ["Authorization: Bearer token_abc_123456", "Accept: application/json"],
            },
            "SafeCount": 42,
        }
        result = redact_mapping(payload)
        assert result["app_name"] == "E-WITNESS"
        assert result["auth_secret_key"] == REDACTION_MASK
        assert result["nested"]["storage_secret_key"] == REDACTION_MASK
        assert "MyDbPassword123" not in result["nested"]["database_url"]
        assert REDACTION_MASK in result["nested"]["database_url"]
        assert "token_abc_123456" not in result["nested"]["headers"][0]
        assert result["nested"]["headers"][1] == "Accept: application/json"
        assert result["SafeCount"] == 42

    def test_is_sensitive_key_name_identifies_expected_keys(self) -> None:
        assert is_sensitive_key_name("AUTH_SECRET_KEY") is True
        assert is_sensitive_key_name("user_password") is True
        assert is_sensitive_key_name("Authorization") is True
        assert is_sensitive_key_name("APP_NAME") is False
        assert is_sensitive_key_name("STORAGE_BUCKET_NAME") is False

    def test_sanitize_validation_errors_never_exposes_sensitive_inputs(self) -> None:
        class SampleConfig(BaseModel):
            auth_secret_key: str = Field(min_length=32)
            database_url: str = Field(pattern=r"^postgresql\+asyncpg://")

        with pytest.raises(ValidationError) as exc_info:
            SampleConfig(
                auth_secret_key="leaked_short_secret_value",
                database_url="mysql://admin:LeakedMysqlPass99@localhost/db",
            )

        sanitized = sanitize_validation_errors(exc_info.value)
        serialized = str(sanitized)
        assert "leaked_short_secret_value" not in serialized
        assert "LeakedMysqlPass99" not in serialized
        assert REDACTION_MASK in serialized
