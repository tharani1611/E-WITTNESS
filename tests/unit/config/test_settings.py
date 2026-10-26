"""Comprehensive unit tests for centralized configuration and secrets management (Phase 05)."""

from __future__ import annotations

import re
from typing import Any

import pytest
from pydantic import ValidationError

from backend.app.config import (
    AIProvider,
    Environment,
    LogFormat,
    LogLevel,
    Settings,
    get_settings,
    load_settings,
)
from backend.app.core.secrets import REDACTION_MASK


class TestValidConfigurationLoading:
    """Verify valid configuration loads across development, testing, and production."""

    def test_valid_testing_configuration_loads(
        self, valid_testing_config_dict: dict[str, Any]
    ) -> None:
        settings = load_settings(**valid_testing_config_dict)
        assert settings.APP_NAME == "E-WITNESS"
        assert settings.ENVIRONMENT == Environment.TESTING
        assert settings.DEBUG is False
        assert settings.API_V1_PREFIX == "/api/v1"
        assert settings.STORAGE_VERIFY_TLS is True
        assert settings.AI_ENABLED is False
        assert settings.AI_CONNECT_ON_STARTUP is False

    def test_valid_development_configuration_loads(
        self, valid_testing_config_dict: dict[str, Any]
    ) -> None:
        dev_config = {
            **valid_testing_config_dict,
            "ENVIRONMENT": "development",
            "DEBUG": True,
            "LOG_LEVEL": "DEBUG",
            "LOG_FORMAT": "console",
            "DATABASE_URL": "postgresql+asyncpg://dev_user:dev_local_pass@localhost:5432/ewitness_dev",
        }
        settings = load_settings(**dev_config)
        assert settings.ENVIRONMENT == Environment.DEVELOPMENT
        assert settings.DEBUG is True
        assert settings.LOG_LEVEL == LogLevel.DEBUG
        assert settings.LOG_FORMAT == LogFormat.CONSOLE

    def test_valid_production_configuration_loads(
        self, valid_production_config_dict: dict[str, Any]
    ) -> None:
        settings = load_settings(**valid_production_config_dict)
        assert settings.ENVIRONMENT == Environment.PRODUCTION
        assert settings.DEBUG is False
        assert settings.DB_ECHO is False
        assert settings.STORAGE_USE_SSL is True
        assert settings.STORAGE_VERIFY_TLS is True
        assert settings.CORS_ALLOWED_ORIGINS == [
            "https://portal.ewitness.edu",
            "https://admin.ewitness.edu",
        ]

    def test_cors_origins_and_mime_types_parse_from_json_and_csv(
        self, valid_testing_config_dict: dict[str, Any]
    ) -> None:
        cfg_json = {
            **valid_testing_config_dict,
            "CORS_ALLOWED_ORIGINS": '["https://a.example.edu", "https://b.example.edu"]',
            "ALLOWED_EVIDENCE_MIME_TYPES": '["application/pdf", "image/png"]',
        }
        s1 = load_settings(**cfg_json)
        assert s1.CORS_ALLOWED_ORIGINS == ["https://a.example.edu", "https://b.example.edu"]
        assert s1.ALLOWED_EVIDENCE_MIME_TYPES == ["application/pdf", "image/png"]

        cfg_csv = {
            **valid_testing_config_dict,
            "CORS_ALLOWED_ORIGINS": "https://a.example.edu, https://b.example.edu",
            "ALLOWED_EVIDENCE_MIME_TYPES": "application/pdf, image/jpeg",
        }
        s2 = load_settings(**cfg_csv)
        assert s2.CORS_ALLOWED_ORIGINS == ["https://a.example.edu", "https://b.example.edu"]
        assert s2.ALLOWED_EVIDENCE_MIME_TYPES == ["application/pdf", "image/jpeg"]


class TestMissingMandatoryConfiguration:
    """Verify missing mandatory configuration is rejected (no silent insecure defaults)."""

    @pytest.mark.parametrize(
        "missing_field",
        [
            "DATABASE_URL",
            "REDIS_URL",
            "STORAGE_ENDPOINT_URL",
            "STORAGE_BUCKET_NAME",
            "STORAGE_ACCESS_KEY",
            "STORAGE_SECRET_KEY",
            "AUTH_SECRET_KEY",
        ],
    )
    def test_missing_mandatory_field_raises_validation_error(
        self, valid_testing_config_dict: dict[str, Any], missing_field: str
    ) -> None:
        incomplete_cfg = dict(valid_testing_config_dict)
        incomplete_cfg.pop(missing_field)
        with pytest.raises(ValidationError) as exc_info:
            Settings(**incomplete_cfg)
        error_locs = [err["loc"] for err in exc_info.value.errors()]
        assert (missing_field,) in error_locs


class TestInvalidUrlsAndMalformedValues:
    """Verify invalid URLs, unsupported schemes, and malformed values are rejected."""

    @pytest.mark.parametrize(
        ("field_name", "invalid_value"),
        [
            ("APP_VERSION", "not-a-semver"),
            ("API_V1_PREFIX", "api/v1"),
            ("API_V1_PREFIX", "/api/v1/"),
            ("API_V1_PREFIX", "/api//v1"),
            ("DATABASE_URL", "mysql://user:pass@localhost:3306/db"),
            ("DATABASE_URL", "postgresql://user:pass@localhost:5432/db"),
            ("DATABASE_URL", "postgresql+asyncpg://user:pass@localhost:5432/"),
            ("REDIS_URL", "http://localhost:6379/0"),
            ("REDIS_URL", "redis:///0"),
            ("STORAGE_ENDPOINT_URL", "ftp://s3.example.com"),
            ("STORAGE_ENDPOINT_URL", "https://user:pass@s3.example.com"),
            ("STORAGE_BUCKET_NAME", "INVALID_UPPERCASE_BUCKET"),
            ("STORAGE_BUCKET_NAME", "ab"),
            ("STORAGE_BUCKET_NAME", "invalid..bucket"),
            ("AUTH_ALGORITHM", "none"),
            ("AUTH_ALGORITHM", "NONE"),
            ("AUTH_ALGORITHM", "HS128"),
            ("AUTH_SECRET_KEY", "too_short_under_32_characters"),
            ("STORAGE_ACCESS_KEY", "short"),
            ("STORAGE_SECRET_KEY", "short"),
            ("CORS_ALLOWED_ORIGINS", '["ftp://bad-scheme.com"]'),
            ("CORS_ALLOWED_ORIGINS", '["https://example.com/with/path"]'),
            ("CORS_ALLOWED_ORIGINS", "[malformed-json"),
            ("CORS_ALLOWED_ORIGINS", []),
            ("ALLOWED_EVIDENCE_MIME_TYPES", ["application/x-msdownload"]),
            ("ALLOWED_EVIDENCE_MIME_TYPES", ["text/html"]),
            ("ALLOWED_EVIDENCE_MIME_TYPES", ["not_a_mime_type"]),
            ("ALLOWED_EVIDENCE_MIME_TYPES", []),
            ("AI_BASE_URL", "ftp://invalid-ai-host"),
        ],
    )
    def test_invalid_field_values_are_rejected(
        self,
        valid_testing_config_dict: dict[str, Any],
        field_name: str,
        invalid_value: Any,
    ) -> None:
        bad_cfg = {**valid_testing_config_dict, field_name: invalid_value}
        with pytest.raises(ValidationError):
            Settings(**bad_cfg)

    def test_upload_chunk_larger_than_max_evidence_file_is_rejected(
        self, valid_testing_config_dict: dict[str, Any]
    ) -> None:
        bad_cfg = {
            **valid_testing_config_dict,
            "MAX_EVIDENCE_FILE_BYTES": 2_097_152,
            "UPLOAD_CHUNK_SIZE_BYTES": 4_194_304,
        }
        with pytest.raises(ValidationError, match="UPLOAD_CHUNK_SIZE_BYTES cannot exceed"):
            Settings(**bad_cfg)

    def test_unknown_extra_configuration_key_is_rejected(
        self, valid_testing_config_dict: dict[str, Any]
    ) -> None:
        bad_cfg = {**valid_testing_config_dict, "UNEXPECTED_EXTRA_KEY": "some_value"}
        with pytest.raises(ValidationError):
            Settings(**bad_cfg)


class TestUniversalAndProductionSecurityGates:
    """Verify universal invariants and strict production security rejections."""

    @pytest.mark.parametrize("env_name", ["development", "testing", "production"])
    def test_disabling_tls_verification_is_rejected_in_all_environments(
        self,
        valid_testing_config_dict: dict[str, Any],
        valid_production_config_dict: dict[str, Any],
        env_name: str,
    ) -> None:
        base = (
            valid_production_config_dict
            if env_name == "production"
            else {**valid_testing_config_dict, "ENVIRONMENT": env_name}
        )
        with pytest.raises(ValidationError, match="STORAGE_VERIFY_TLS cannot be disabled"):
            Settings(**{**base, "STORAGE_VERIFY_TLS": False})

    def test_ai_connect_on_startup_is_always_rejected(
        self, valid_testing_config_dict: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError, match="AI_CONNECT_ON_STARTUP must remain False"):
            Settings(**{**valid_testing_config_dict, "AI_CONNECT_ON_STARTUP": True})

    def test_ai_enabled_requires_provider_model_and_api_key(
        self, valid_testing_config_dict: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError, match="AI_PROVIDER cannot be 'disabled'"):
            Settings(**{**valid_testing_config_dict, "AI_ENABLED": True})

        with pytest.raises(ValidationError, match="AI_MODEL_NAME is required"):
            Settings(
                **{
                    **valid_testing_config_dict,
                    "AI_ENABLED": True,
                    "AI_PROVIDER": AIProvider.GEMINI,
                }
            )

        with pytest.raises(ValidationError, match="valid AI_API_KEY is required"):
            Settings(
                **{
                    **valid_testing_config_dict,
                    "AI_ENABLED": True,
                    "AI_PROVIDER": AIProvider.GEMINI,
                    "AI_MODEL_NAME": "gemini-2.5-flash",
                }
            )

        valid_ai = Settings(
            **{
                **valid_testing_config_dict,
                "AI_ENABLED": True,
                "AI_PROVIDER": AIProvider.GEMINI,
                "AI_MODEL_NAME": "gemini-2.5-flash",
                "AI_API_KEY": "valid_provider_api_key_value_12345",
            }
        )
        assert valid_ai.AI_ENABLED is True

    @pytest.mark.parametrize(
        ("override_dict", "expected_error_substring"),
        [
            ({"DEBUG": True}, "DEBUG=True is strictly forbidden in production"),
            ({"DB_ECHO": True}, "DB_ECHO=True is strictly forbidden in production"),
            ({"LOG_LEVEL": "DEBUG"}, "LOG_LEVEL='DEBUG' is forbidden in production"),
            ({"LOG_FORMAT": "console"}, "LOG_FORMAT must be 'json' in production"),
            (
                {"LOG_REDACT_SENSITIVE": False},
                "LOG_REDACT_SENSITIVE must be True in production",
            ),
            (
                {"AUTH_SECRET_KEY": "REPLACE_WITH_HIGH_ENTROPY_SECRET_KEY_MIN_32_CHARS"},
                "Insecure AUTH_SECRET_KEY for production",
            ),
            (
                {"AUTH_SECRET_KEY": "a" * 48},
                "Insecure AUTH_SECRET_KEY for production",
            ),
            (
                {"STORAGE_ACCESS_KEY": "REPLACE_WITH_LOCAL_STORAGE_ACCESS_KEY"},
                "Insecure STORAGE_ACCESS_KEY for production",
            ),
            (
                {"STORAGE_SECRET_KEY": "minioadmin_secret_key_value_1234"},
                "Insecure STORAGE_SECRET_KEY for production",
            ),
            (
                {"DATABASE_URL": "sqlite+aiosqlite:///:memory:"},
                "Production DATABASE_URL must use 'postgresql+asyncpg://'",
            ),
            (
                {
                    "DATABASE_URL": "postgresql+asyncpg://prod_u:K9mP2vL8nQ5!zR4~wX7@localhost:5432/prod_db"
                },
                "Production DATABASE_URL must not point to localhost",
            ),
            (
                {
                    "DATABASE_URL": "postgresql+asyncpg://prod_u:postgres_password_123@db.ewitness.edu:5432/prod_db"
                },
                "Insecure DATABASE_URL password for production",
            ),
            (
                {"REDIS_URL": "redis://:R8kM3pL9vN2!qW6~zX4@redis.internal.ewitness.edu:6379/0"},
                "Production REDIS_URL must use encrypted 'rediss://'",
            ),
            (
                {"REDIS_URL": "rediss://redis.internal.ewitness.edu:6379/0"},
                "Production REDIS_URL must include authentication credentials",
            ),
            (
                {
                    "REDIS_URL": "rediss://:redis_default_password_123@redis.internal.ewitness.edu:6379/0"
                },
                "Production REDIS_URL password contains forbidden placeholder",
            ),
            (
                {"STORAGE_USE_SSL": False},
                "STORAGE_USE_SSL must be True in production",
            ),
            (
                {"STORAGE_ENDPOINT_URL": "http://s3.us-east-1.amazonaws.com"},
                "Production STORAGE_ENDPOINT_URL must use 'https://'",
            ),
            (
                {"STORAGE_ENDPOINT_URL": "https://s3.localhost.localdomain:9000"},
                "Production STORAGE_ENDPOINT_URL must not use localhost or .localdomain",
            ),
            (
                {"CORS_ALLOWED_ORIGINS": ["*"]},
                "Wildcard '*' in CORS_ALLOWED_ORIGINS is forbidden in production",
            ),
            (
                {"CORS_ALLOWED_ORIGINS": ["http://portal.ewitness.edu"]},
                "must use 'https://'",
            ),
            (
                {"CORS_ALLOWED_ORIGINS": ["https://localhost:3000"]},
                "must not point to localhost",
            ),
            (
                {"AUTH_ACCESS_TOKEN_EXPIRE_MINUTES": 120},
                "Production AUTH_ACCESS_TOKEN_EXPIRE_MINUTES cannot exceed 60 minutes",
            ),
            (
                {"AUTH_REFRESH_TOKEN_EXPIRE_DAYS": 60},
                "Production AUTH_REFRESH_TOKEN_EXPIRE_DAYS cannot exceed 30 days",
            ),
            (
                {"ENFORCE_SSL": False},
                "ENFORCE_SSL must be True in production",
            ),
            (
                {"SECURITY_HEADERS_ENABLED": False},
                "SECURITY_HEADERS_ENABLED must be True in production",
            ),
        ],
    )
    def test_unsafe_production_settings_are_rejected(
        self,
        valid_production_config_dict: dict[str, Any],
        override_dict: dict[str, Any],
        expected_error_substring: str,
    ) -> None:
        unsafe_prod = {**valid_production_config_dict, **override_dict}
        with pytest.raises(ValidationError, match=re.escape(expected_error_substring)):
            Settings(**unsafe_prod)


class TestEnvironmentIsolationAndSafeRepresentations:
    """Verify environment isolation and ensure secrets never leak in repr/str/safe_dict."""

    def test_environment_variable_loading_and_isolation(
        self,
        monkeypatch: pytest.MonkeyPatch,
        valid_testing_config_dict: dict[str, Any],
    ) -> None:
        for key, value in valid_testing_config_dict.items():
            if not key.startswith("_"):
                monkeypatch.setenv(key, str(value.value if hasattr(value, "value") else value))

        loaded = get_settings()
        assert loaded.ENVIRONMENT == Environment.TESTING
        assert loaded.STORAGE_BUCKET_NAME == "ewitness-test-bucket"

        # Verify cache returns identical singleton until cleared
        assert get_settings() is loaded
        get_settings.cache_clear()

    def test_secret_values_are_excluded_from_safe_representations(
        self, valid_production_config_dict: dict[str, Any]
    ) -> None:
        cfg_with_ai = {
            **valid_production_config_dict,
            "AI_ENABLED": True,
            "AI_PROVIDER": "openai",
            "AI_MODEL_NAME": "gpt-4o-mini",
            "AI_API_KEY": "sk-proj-SuperSecretAiKeyValue99887766",
            "AI_BASE_URL": "https://api.openai.com/v1",
        }
        settings = Settings(**cfg_with_ai)

        raw_secrets = [
            "K9mP2vL8nQ5!zR4~wX7*bC1_yT6",  # DB password
            "R8kM3pL9vN2!qW6~zX4*cB7_jF5",  # Redis password
            "AKIA9X7P4M2L8Q5N3R6W",  # Storage access key
            "Zx8#Qp3$Lm9@Vn5!Kw2&Yr7*Bt4^Hc6%Jd1_Fg0",  # Storage secret key
            "vN9#mK4$pL8@qW2!zX7&cB5*rT1^yU6%hJ3_gF0-dS8+aE5",  # Auth secret key
            "sk-proj-SuperSecretAiKeyValue99887766",  # AI API key
        ]

        repr_str = repr(settings)
        str_val = str(settings)
        safe_dict = settings.to_safe_dict()
        safe_dict_str = str(safe_dict)

        for secret in raw_secrets:
            assert secret not in repr_str
            assert secret not in str_val
            assert secret not in safe_dict_str
            assert secret not in settings.redacted_database_url
            assert secret not in settings.redacted_redis_url

        assert safe_dict["AUTH_SECRET_KEY"] == REDACTION_MASK
        assert safe_dict["STORAGE_ACCESS_KEY"] == REDACTION_MASK
        assert safe_dict["STORAGE_SECRET_KEY"] == REDACTION_MASK
        assert safe_dict["AI_API_KEY"] == REDACTION_MASK
        assert REDACTION_MASK in safe_dict["DATABASE_URL"]
        assert REDACTION_MASK in safe_dict["REDIS_URL"]

    def test_package_versions_and_additional_parsers(
        self, valid_testing_config_dict: dict[str, Any]
    ) -> None:
        import ai_services
        import backend.app

        assert ai_services.__version__ == "0.1.0"
        assert backend.app.__version__ == "0.1.0"

        # Tuple input for StringList
        s = Settings(
            **{
                **valid_testing_config_dict,
                "CORS_ALLOWED_ORIGINS": ("https://one.example.edu", "https://two.example.edu"),
            }
        )
        assert len(s.CORS_ALLOWED_ORIGINS) == 2

        with pytest.raises(ValidationError, match="Expected a list of strings"):
            Settings(**{**valid_testing_config_dict, "CORS_ALLOWED_ORIGINS": 12345})
        with pytest.raises(ValidationError, match="must include a valid database hostname"):
            Settings(**{**valid_testing_config_dict, "DATABASE_URL": "postgresql+asyncpg:///db"})
        with pytest.raises(
            ValidationError,
            match="Production DATABASE_URL must include explicit username and password credentials",
        ):
            Settings(
                **{
                    **valid_testing_config_dict,
                    "ENVIRONMENT": "production",
                    "CORS_ALLOWED_ORIGINS": ["https://portal.ewitness.edu"],
                    "DATABASE_URL": "postgresql+asyncpg://db.internal.ewitness.edu:5432/prod_db",
                    "REDIS_URL": "rediss://:R8kM3pL9vN2!qW6~zX4*cB7_jF5@redis.internal.ewitness.edu:6379/0",
                    "STORAGE_ENDPOINT_URL": "https://s3.us-east-1.amazonaws.com",
                    "STORAGE_BUCKET_NAME": "ewitness-evidence-prod-vault",
                    "STORAGE_ACCESS_KEY": "AKIA9X7P4M2L8Q5N3R6W",
                    "STORAGE_SECRET_KEY": "Zx8#Qp3$Lm9@Vn5!Kw2&Yr7*Bt4^Hc6%Jd1_Fg0",
                    "AUTH_SECRET_KEY": "vN9#mK4$pL8@qW2!zX7&cB5*rT1^yU6%hJ3_gF0-dS8+aE5",
                }
            )
