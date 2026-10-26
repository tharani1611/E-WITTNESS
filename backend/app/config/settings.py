"""Centralized, validated application configuration and secret management for E-WITNESS.

Implements Phase 05 requirements:
- Strict typed settings using Pydantic v2 and pydantic-settings
- Environment separation across development, testing, and production
- Zero silent insecure defaults for mandatory credentials and endpoints
- Fail-fast startup checks rejecting weak/placeholder secrets, disabled TLS,
  wildcard/HTTP CORS origins, debug mode, or unsafe algorithms in production
- Safe serialization (`to_safe_dict()`, `__repr__`, `__str__`) that redacts
  all secrets and embedded URL credentials
"""

from __future__ import annotations

import json
import re
from enum import StrEnum
from functools import lru_cache
from typing import Annotated, Any
from urllib.parse import urlsplit

from pydantic import (
    BeforeValidator,
    Field,
    SecretStr,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from backend.app.core.secrets import (
    FORBIDDEN_SECRET_PATTERNS,
    REDACTION_MASK,
    is_weak_or_placeholder_secret,
    redact_mapping,
    redact_url,
)


class Environment(StrEnum):
    """Supported runtime execution environments."""

    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"


class LogLevel(StrEnum):
    """Supported structured logging levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogFormat(StrEnum):
    """Supported log output formats."""

    JSON = "json"
    CONSOLE = "console"


class AIProvider(StrEnum):
    """Supported isolated AI model providers."""

    DISABLED = "disabled"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    LOCAL = "local"


ALLOWED_AUTH_ALGORITHMS: frozenset[str] = frozenset({"HS256", "HS384", "HS512", "RS256", "ES256"})

DEFAULT_ALLOWED_MIME_TYPES: tuple[str, ...] = (
    "application/pdf",
    "image/jpeg",
    "image/png",
    "image/webp",
    "audio/mpeg",
    "audio/wav",
    "video/mp4",
    "text/plain",
)

FORBIDDEN_EVIDENCE_MIME_TYPES: frozenset[str] = frozenset(
    {
        "application/x-msdownload",
        "application/x-executable",
        "application/x-dosexec",
        "application/x-sh",
        "application/x-csh",
        "application/javascript",
        "text/javascript",
        "text/html",
        "application/xhtml+xml",
        "application/x-httpd-php",
    }
)

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_BUCKET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_MIME_TYPE_RE = re.compile(r"^[a-z0-9]+/[a-z0-9.+-]+$")


def _parse_string_list(value: Any) -> list[str]:
    """Parse a JSON array string, comma-separated string, or sequence into a list of strings."""
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, tuple | set | frozenset):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return []
        if raw.startswith("["):
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed JSON list in configuration value: {exc.msg}") from exc
            if not isinstance(parsed, list):
                raise ValueError("Expected a JSON array of strings.")
            return [str(item).strip() for item in parsed if str(item).strip()]
        return [part.strip() for part in raw.split(",") if part.strip()]
    raise ValueError("Expected a list of strings, JSON array string, or comma-separated string.")


StringList = Annotated[list[str], NoDecode, BeforeValidator(_parse_string_list)]


class Settings(BaseSettings):
    """Centralized, validated configuration model for E-WITNESS."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="forbid",
        validate_default=True,
    )

    # -------------------------------------------------------------------------
    # 1. Application & Runtime Environment
    # -------------------------------------------------------------------------
    APP_NAME: str = Field(default="E-WITNESS", min_length=2, max_length=100)
    APP_VERSION: str = Field(default="0.1.0")
    ENVIRONMENT: Environment = Field(default=Environment.DEVELOPMENT)
    DEBUG: bool = Field(default=False)
    API_V1_PREFIX: str = Field(default="/api/v1")

    # -------------------------------------------------------------------------
    # 2. Logging & Redaction
    # -------------------------------------------------------------------------
    LOG_LEVEL: LogLevel = Field(default=LogLevel.INFO)
    LOG_FORMAT: LogFormat = Field(default=LogFormat.JSON)
    LOG_REDACT_SENSITIVE: bool = Field(default=True)

    # -------------------------------------------------------------------------
    # 3. HTTP Security, Hosts, Proxies & CORS (Phases 26-28)
    # -------------------------------------------------------------------------
    CORS_ALLOWED_ORIGINS: StringList = Field(
        default_factory=lambda: ["http://localhost:3000", "http://127.0.0.1:3000"]
    )
    ALLOWED_HOSTS: StringList = Field(
        default_factory=lambda: ["localhost", "127.0.0.1", "testserver", "testserver.local"]
    )
    TRUSTED_PROXIES: StringList = Field(default_factory=lambda: ["127.0.0.1", "::1"])
    ENFORCE_SSL: bool = Field(default=False)
    SECURITY_HEADERS_ENABLED: bool = Field(default=True)

    # -------------------------------------------------------------------------
    # 3b. Rate Limiting & Abuse Prevention Policies (Phase 28)
    # -------------------------------------------------------------------------
    RATE_LIMIT_LOGIN_MAX_REQUESTS: int = Field(default=5, ge=1, le=100)
    RATE_LIMIT_LOGIN_WINDOW_SECONDS: float = Field(default=60.0, ge=1.0, le=3600.0)
    RATE_LIMIT_AUTH_MAX_REQUESTS: int = Field(default=10, ge=1, le=200)
    RATE_LIMIT_AUTH_WINDOW_SECONDS: float = Field(default=60.0, ge=1.0, le=3600.0)
    RATE_LIMIT_RESET_MAX_REQUESTS: int = Field(default=3, ge=1, le=50)
    RATE_LIMIT_RESET_WINDOW_SECONDS: float = Field(default=300.0, ge=1.0, le=3600.0)
    RATE_LIMIT_VERIFY_MAX_REQUESTS: int = Field(default=3, ge=1, le=50)
    RATE_LIMIT_VERIFY_WINDOW_SECONDS: float = Field(default=300.0, ge=1.0, le=3600.0)
    RATE_LIMIT_GLOBAL_MAX_REQUESTS: int = Field(default=100, ge=1, le=1000)
    RATE_LIMIT_GLOBAL_WINDOW_SECONDS: float = Field(default=60.0, ge=1.0, le=3600.0)
    RATE_LIMIT_BACKEND: str = Field(default="memory")
    RATE_LIMIT_FAIL_OPEN: bool = Field(default=False)

    # -------------------------------------------------------------------------
    # 4. Primary Database (PostgreSQL Async) — Mandatory Connection URL
    # -------------------------------------------------------------------------
    DATABASE_URL: str = Field(..., min_length=12)
    DB_POOL_SIZE: int = Field(default=10, ge=1, le=100)
    DB_MAX_OVERFLOW: int = Field(default=20, ge=0, le=100)
    DB_POOL_TIMEOUT_SECONDS: float = Field(default=30.0, ge=1.0, le=120.0)
    DB_CONNECT_TIMEOUT_SECONDS: float = Field(default=10.0, ge=1.0, le=60.0)
    DB_COMMAND_TIMEOUT_SECONDS: float = Field(default=60.0, ge=1.0, le=300.0)
    DB_POOL_RECYCLE_SECONDS: int = Field(default=1800, ge=60, le=86400)
    DB_POOL_PRE_PING: bool = Field(default=True)
    DB_ECHO: bool = Field(default=False)

    # -------------------------------------------------------------------------
    # 5. Redis Coordination & Caching — Mandatory Connection URL
    # -------------------------------------------------------------------------
    REDIS_URL: str = Field(..., min_length=8)
    REDIS_MAX_CONNECTIONS: int = Field(default=20, ge=1, le=500)
    REDIS_TIMEOUT_SECONDS: float = Field(default=5.0, ge=0.5, le=60.0)

    # -------------------------------------------------------------------------
    # 6. Evidence Object Storage (S3-Compatible) — Mandatory Settings
    # -------------------------------------------------------------------------
    STORAGE_ENDPOINT_URL: str = Field(..., min_length=8)
    STORAGE_BUCKET_NAME: str = Field(..., min_length=3, max_length=63)
    STORAGE_REGION: str = Field(default="us-east-1", min_length=2, max_length=64)
    STORAGE_ACCESS_KEY: SecretStr = Field(...)
    STORAGE_SECRET_KEY: SecretStr = Field(...)
    STORAGE_USE_SSL: bool = Field(default=True)
    STORAGE_VERIFY_TLS: bool = Field(default=True)
    STORAGE_TIMEOUT_SECONDS: float = Field(default=30.0, ge=1.0, le=300.0)

    # -------------------------------------------------------------------------
    # 7. Authentication & Token Signing — Mandatory Secret Key
    # -------------------------------------------------------------------------
    AUTH_SECRET_KEY: SecretStr = Field(...)
    AUTH_ALGORITHM: str = Field(default="HS256")
    AUTH_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=15, ge=1, le=1440)
    AUTH_REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, ge=1, le=90)
    AUTH_ISSUER: str = Field(default="ewitness-api", min_length=3, max_length=128)
    AUTH_AUDIENCE: str = Field(default="ewitness-client", min_length=3, max_length=128)

    # -------------------------------------------------------------------------
    # 8. Isolated AI Processing Boundary
    # -------------------------------------------------------------------------
    AI_ENABLED: bool = Field(default=False)
    AI_PROVIDER: AIProvider = Field(default=AIProvider.DISABLED)
    AI_MODEL_NAME: str = Field(default="")
    AI_API_KEY: SecretStr | None = Field(default=None)
    AI_BASE_URL: str | None = Field(default=None)
    AI_MAX_TOKENS: int = Field(default=2048, ge=64, le=32768)
    AI_TEMPERATURE: float = Field(default=0.1, ge=0.0, le=2.0)
    AI_REQUEST_TIMEOUT_SECONDS: float = Field(default=45.0, ge=1.0, le=300.0)
    AI_CONNECT_ON_STARTUP: bool = Field(default=False)

    # -------------------------------------------------------------------------
    # 8.1 Biometric Governance & Face Detection Boundary (Phases 71-75)
    # -------------------------------------------------------------------------
    BIOMETRIC_ANALYSIS_ENABLED: bool = Field(
        default=False,
        description="Master feature flag for biometric governance and face processing; disabled by default.",
    )
    BIOMETRIC_DETECTION_ENABLED: bool = Field(
        default=False,
        description="Enables face bounding-box detection; requires BIOMETRIC_ANALYSIS_ENABLED=True.",
    )
    BIOMETRIC_MATCHING_ENABLED: bool = Field(
        default=False,
        description="Biometric face matching / identification flag; strictly forbidden in production.",
    )
    BIOMETRIC_PROVIDER: str = Field(
        default="disabled",
        description="Active face detection provider: 'disabled', 'mock', or 'local'.",
    )
    BIOMETRIC_MAX_IMAGE_SIZE_BYTES: int = Field(
        default=10 * 1024 * 1024,
        ge=1024,
        le=50 * 1024 * 1024,
        description="Maximum byte size for single face detection image payload (1 KB to 50 MB).",
    )

    # -------------------------------------------------------------------------
    # 9. Request, Upload & External Timeout Guardrails
    # -------------------------------------------------------------------------
    MAX_REQUEST_BODY_BYTES: int = Field(
        default=2_097_152,
        ge=65_536,
        le=26_214_400,
        description="Maximum general HTTP request body size (64 KB to 25 MB).",
    )
    MAX_EVIDENCE_FILE_BYTES: int = Field(
        default=52_428_800,
        ge=1_048_576,
        le=524_288_000,
        description="Maximum single evidence file upload size (1 MB to 500 MB).",
    )
    UPLOAD_CHUNK_SIZE_BYTES: int = Field(
        default=1_048_576,
        ge=65_536,
        le=10_485_760,
        description="Streaming chunk size in bytes (64 KB to 10 MB).",
    )
    ALLOWED_EVIDENCE_MIME_TYPES: StringList = Field(
        default_factory=lambda: list(DEFAULT_ALLOWED_MIME_TYPES)
    )
    HTTP_TIMEOUT_SECONDS: float = Field(default=15.0, ge=1.0, le=120.0)

    # =========================================================================
    # Field Validators
    # =========================================================================

    @field_validator("APP_VERSION")
    @classmethod
    def validate_app_version(cls, value: str) -> str:
        cleaned = value.strip()
        if not _SEMVER_RE.match(cleaned):
            raise ValueError(
                f"APP_VERSION '{cleaned}' must follow semantic versioning (e.g., '0.1.0')."
            )
        return cleaned

    @field_validator("API_V1_PREFIX")
    @classmethod
    def validate_api_prefix(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned.startswith("/") or cleaned.endswith("/") or "//" in cleaned:
            raise ValueError(
                "API_V1_PREFIX must start with '/', must not end with '/', and cannot contain '//'."
            )
        return cleaned

    @field_validator("STORAGE_VERIFY_TLS")
    @classmethod
    def validate_tls_verification_never_disabled(cls, value: bool) -> bool:
        if not value:
            raise ValueError("STORAGE_VERIFY_TLS cannot be disabled in any environment (SEC-007).")
        return value

    @field_validator("AI_CONNECT_ON_STARTUP")
    @classmethod
    def validate_no_ai_startup_calls(cls, value: bool) -> bool:
        if value:
            raise ValueError(
                "AI_CONNECT_ON_STARTUP must remain False; external AI calls are prohibited "
                "during application startup (NFR-001)."
            )
        return value

    @field_validator("AUTH_ALGORITHM")
    @classmethod
    def validate_auth_algorithm(cls, value: str) -> str:
        cleaned = value.strip()
        if cleaned.lower() == "none":
            raise ValueError("AUTH_ALGORITHM 'none' is strictly forbidden (SEC-006).")
        if cleaned not in ALLOWED_AUTH_ALGORITHMS:
            allowed_str = ", ".join(sorted(ALLOWED_AUTH_ALGORITHMS))
            raise ValueError(
                f"Unsupported AUTH_ALGORITHM '{cleaned}'. Allowed values: {allowed_str}."
            )
        return cleaned

    @field_validator("AUTH_SECRET_KEY")
    @classmethod
    def validate_auth_secret_key_minimum(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value().strip()
        if len(raw) < 32:
            raise ValueError(
                f"AUTH_SECRET_KEY must be at least 32 characters long (got {len(raw)})."
            )
        return value

    @field_validator("STORAGE_ACCESS_KEY", "STORAGE_SECRET_KEY")
    @classmethod
    def validate_non_empty_storage_secrets(
        cls, value: SecretStr, info: ValidationInfo
    ) -> SecretStr:
        raw = value.get_secret_value().strip()
        if len(raw) < 8:
            raise ValueError(f"{info.field_name} must be at least 8 characters long.")
        return value

    @field_validator("STORAGE_BUCKET_NAME")
    @classmethod
    def validate_bucket_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not _BUCKET_NAME_RE.match(cleaned) or ".." in cleaned:
            raise ValueError(
                "STORAGE_BUCKET_NAME must be 3-63 characters, lowercase alphanumeric, "
                "dots, or hyphens, and start/end with an alphanumeric character."
            )
        return cleaned

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, value: str) -> str:
        cleaned = value.strip()
        parts = urlsplit(cleaned)
        allowed_schemes = {"postgresql+asyncpg", "sqlite+aiosqlite"}
        if parts.scheme not in allowed_schemes:
            raise ValueError(
                "DATABASE_URL must use 'postgresql+asyncpg://' (or 'sqlite+aiosqlite://' "
                "for isolated local/testing use)."
            )
        if parts.scheme == "postgresql+asyncpg":
            if not parts.hostname:
                raise ValueError("DATABASE_URL must include a valid database hostname.")
            db_name = parts.path.lstrip("/")
            if not db_name or "/" in db_name or " " in db_name:
                raise ValueError(
                    "DATABASE_URL must include a valid single database name in the path."
                )
        return cleaned

    @field_validator("REDIS_URL")
    @classmethod
    def validate_redis_url(cls, value: str) -> str:
        cleaned = value.strip()
        parts = urlsplit(cleaned)
        if parts.scheme not in {"redis", "rediss"}:
            raise ValueError("REDIS_URL must use the 'redis://' or 'rediss://' scheme.")
        if not parts.hostname:
            raise ValueError("REDIS_URL must include a valid hostname.")
        return cleaned

    @field_validator("STORAGE_ENDPOINT_URL")
    @classmethod
    def validate_storage_endpoint_url(cls, value: str) -> str:
        cleaned = value.strip()
        parts = urlsplit(cleaned)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError(
                "STORAGE_ENDPOINT_URL must be a valid 'http://' or 'https://' URL with a hostname."
            )
        if parts.username or parts.password:
            raise ValueError("STORAGE_ENDPOINT_URL must not embed credentials directly in the URL.")
        return cleaned

    @field_validator("AI_BASE_URL")
    @classmethod
    def validate_ai_base_url(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        cleaned = value.strip()
        parts = urlsplit(cleaned)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("AI_BASE_URL must be a valid 'http://' or 'https://' URL.")
        return cleaned

    @field_validator("CORS_ALLOWED_ORIGINS")
    @classmethod
    def validate_cors_origins(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("CORS_ALLOWED_ORIGINS must contain at least one allowed origin.")
        validated: list[str] = []
        for origin in value:
            item = origin.strip()
            if item == "*":
                validated.append(item)
                continue
            parts = urlsplit(item)
            if parts.scheme not in {"http", "https"} or not parts.hostname:
                raise ValueError(
                    f"Invalid CORS origin '{item}'. Must be '*' or a valid http(s)://host[:port] origin."
                )
            if parts.path not in {"", "/"} or parts.query or parts.fragment:
                raise ValueError(
                    f"CORS origin '{item}' must not contain path segments, query strings, or fragments."
                )
            validated.append(f"{parts.scheme}://{parts.netloc}")
        return validated

    @field_validator("ALLOWED_HOSTS")
    @classmethod
    def validate_allowed_hosts(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("ALLOWED_HOSTS must contain at least one allowed host.")
        validated: list[str] = []
        for raw in value:
            item = raw.strip().lower()
            if not item:
                continue
            validated.append(item)
        if not validated:
            raise ValueError("ALLOWED_HOSTS must contain at least one valid host.")
        return validated

    @field_validator("TRUSTED_PROXIES")
    @classmethod
    def validate_trusted_proxies(cls, value: list[str]) -> list[str]:
        return [ip.strip() for ip in value if ip.strip()]

    @field_validator("ALLOWED_EVIDENCE_MIME_TYPES")
    @classmethod
    def validate_allowed_mime_types(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("ALLOWED_EVIDENCE_MIME_TYPES must not be empty.")
        normalized_list: list[str] = []
        for mime in value:
            item = mime.strip().lower()
            if not _MIME_TYPE_RE.match(item):
                raise ValueError(f"Malformed MIME type '{mime}' in ALLOWED_EVIDENCE_MIME_TYPES.")
            if item in FORBIDDEN_EVIDENCE_MIME_TYPES:
                raise ValueError(
                    f"Executable or unsafe MIME type '{item}' is forbidden in evidence uploads (SEC-010)."
                )
            normalized_list.append(item)
        return normalized_list

    # =========================================================================
    # Cross-Field & Environment-Aware Security Validation
    # =========================================================================

    @model_validator(mode="after")
    def validate_cross_field_and_environment_rules(self) -> Settings:
        """Enforce upload invariants, AI boundary consistency, and strict production rules."""
        # 1. Upload chunk size must not exceed maximum evidence file size
        if self.UPLOAD_CHUNK_SIZE_BYTES > self.MAX_EVIDENCE_FILE_BYTES:
            raise ValueError("UPLOAD_CHUNK_SIZE_BYTES cannot exceed MAX_EVIDENCE_FILE_BYTES.")

        # 2. AI configuration consistency
        if self.AI_ENABLED:
            if self.AI_PROVIDER == AIProvider.DISABLED:
                raise ValueError("AI_PROVIDER cannot be 'disabled' when AI_ENABLED is True.")
            if not self.AI_MODEL_NAME.strip():
                raise ValueError("AI_MODEL_NAME is required when AI_ENABLED is True.")
            if self.AI_PROVIDER in {
                AIProvider.OPENAI,
                AIProvider.ANTHROPIC,
                AIProvider.GEMINI,
            }:
                api_key = (
                    self.AI_API_KEY.get_secret_value().strip()
                    if self.AI_API_KEY is not None
                    else ""
                )
                if len(api_key) < 16:
                    raise ValueError(
                        f"A valid AI_API_KEY is required when using external provider '{self.AI_PROVIDER}'."
                    )

        # 2.1 Biometric configuration consistency (Phases 71-75)
        if self.BIOMETRIC_DETECTION_ENABLED and not self.BIOMETRIC_ANALYSIS_ENABLED:
            raise ValueError(
                "BIOMETRIC_ANALYSIS_ENABLED must be True when BIOMETRIC_DETECTION_ENABLED is True."
            )
        if self.BIOMETRIC_PROVIDER not in {"disabled", "mock", "local"}:
            raise ValueError(
                f"Invalid BIOMETRIC_PROVIDER '{self.BIOMETRIC_PROVIDER}'. Must be 'disabled', 'mock', or 'local'."
            )

        # 3. Strict Testing Isolation Rule (ENVIRONMENT == "testing")
        if self.ENVIRONMENT == Environment.TESTING:
            db_parts = urlsplit(self.DATABASE_URL.lower())
            if "prod" in (db_parts.hostname or "") or "prod" in (db_parts.path or ""):
                raise ValueError(
                    "Testing DATABASE_URL must not reference a production database host or schema."
                )

        # 4. Strict Production Hardening Rules (ENVIRONMENT == "production")
        if self.ENVIRONMENT == Environment.PRODUCTION:
            self._enforce_production_security_gate()

        return self

    def _enforce_production_security_gate(self) -> None:
        """Reject any development defaults, weak keys, or unencrypted endpoints in production."""
        if self.DEBUG:
            raise ValueError("DEBUG=True is strictly forbidden in production (SEC-015).")

        if self.DB_ECHO:
            raise ValueError("DB_ECHO=True is strictly forbidden in production (SEC-015).")

        if self.LOG_LEVEL == LogLevel.DEBUG:
            raise ValueError(
                "LOG_LEVEL='DEBUG' is forbidden in production to prevent data leakage."
            )

        if self.LOG_FORMAT != LogFormat.JSON:
            raise ValueError("LOG_FORMAT must be 'json' in production for structured auditing.")

        if not self.LOG_REDACT_SENSITIVE:
            raise ValueError("LOG_REDACT_SENSITIVE must be True in production (SEC-008).")

        # Validate AUTH_SECRET_KEY strength and entropy
        is_weak, reason = is_weak_or_placeholder_secret(
            self.AUTH_SECRET_KEY.get_secret_value(),
            min_length=32,
            min_unique_chars=10,
            min_entropy_bits=3.2,
        )
        if is_weak:
            raise ValueError(f"Insecure AUTH_SECRET_KEY for production: {reason}")

        # Validate STORAGE_ACCESS_KEY & STORAGE_SECRET_KEY against placeholders
        for field_name, secret_val in (
            ("STORAGE_ACCESS_KEY", self.STORAGE_ACCESS_KEY.get_secret_value()),
            ("STORAGE_SECRET_KEY", self.STORAGE_SECRET_KEY.get_secret_value()),
        ):
            min_len = 12 if field_name == "STORAGE_ACCESS_KEY" else 20
            weak_storage, storage_reason = is_weak_or_placeholder_secret(
                secret_val,
                min_length=min_len,
                min_unique_chars=6,
                min_entropy_bits=2.5,
            )
            if weak_storage:
                raise ValueError(f"Insecure {field_name} for production: {storage_reason}")

        # Validate DATABASE_URL in production
        db_parts = urlsplit(self.DATABASE_URL)
        if db_parts.scheme != "postgresql+asyncpg":
            raise ValueError(
                "Production DATABASE_URL must use 'postgresql+asyncpg://' (SQLite is forbidden)."
            )
        if db_parts.hostname in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Production DATABASE_URL must not point to localhost/loopback.")
        if not db_parts.username or not db_parts.password:
            raise ValueError(
                "Production DATABASE_URL must include explicit username and password credentials."
            )
        weak_db_pw, db_pw_reason = is_weak_or_placeholder_secret(
            db_parts.password,
            min_length=12,
            min_unique_chars=6,
            min_entropy_bits=2.5,
        )
        if weak_db_pw:
            raise ValueError(f"Insecure DATABASE_URL password for production: {db_pw_reason}")

        # Validate REDIS_URL in production (TLS rediss:// required)
        redis_parts = urlsplit(self.REDIS_URL)
        if redis_parts.scheme != "rediss":
            raise ValueError(
                "Production REDIS_URL must use encrypted 'rediss://' TLS transport (SEC-007)."
            )
        if redis_parts.hostname in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Production REDIS_URL must not point to localhost/loopback.")
        if not redis_parts.password:
            raise ValueError("Production REDIS_URL must include authentication credentials.")
        for pattern in FORBIDDEN_SECRET_PATTERNS:
            if pattern in redis_parts.password.lower():
                raise ValueError(
                    f"Production REDIS_URL password contains forbidden placeholder '{pattern}'."
                )

        # Validate Object Storage TLS & Endpoint in production
        if not self.STORAGE_USE_SSL:
            raise ValueError("STORAGE_USE_SSL must be True in production (SEC-007).")
        storage_parts = urlsplit(self.STORAGE_ENDPOINT_URL)
        if storage_parts.scheme != "https":
            raise ValueError(
                "Production STORAGE_ENDPOINT_URL must use 'https://' scheme (SEC-007)."
            )
        if storage_parts.hostname and (
            storage_parts.hostname in {"localhost", "127.0.0.1", "::1"}
            or storage_parts.hostname.endswith(".localhost")
            or storage_parts.hostname.endswith(".localdomain")
        ):
            raise ValueError(
                "Production STORAGE_ENDPOINT_URL must not use localhost or .localdomain hosts."
            )

        # Validate CORS in production
        for origin in self.CORS_ALLOWED_ORIGINS:
            if origin == "*":
                raise ValueError(
                    "Wildcard '*' in CORS_ALLOWED_ORIGINS is forbidden in production (SEC-009)."
                )
            origin_parts = urlsplit(origin)
            if origin_parts.scheme != "https":
                raise ValueError(
                    f"Production CORS origin '{origin}' must use 'https://' (SEC-009)."
                )
            if origin_parts.hostname in {"localhost", "127.0.0.1", "::1"}:
                raise ValueError(
                    f"Production CORS origin '{origin}' must not point to localhost/loopback."
                )

        # Validate ALLOWED_HOSTS in production
        for host in self.ALLOWED_HOSTS:
            if host == "*":
                raise ValueError(
                    "Wildcard '*' in ALLOWED_HOSTS is forbidden in production (SEC-009)."
                )
            if (
                host in {"localhost", "127.0.0.1", "::1"}
                or host.endswith(".local")
                or host.endswith(".localdomain")
            ):
                raise ValueError(
                    f"Production ALLOWED_HOSTS '{host}' must not point to localhost/loopback."
                )

        if not self.ENFORCE_SSL:
            raise ValueError("ENFORCE_SSL must be True in production (SEC-007).")

        if not self.SECURITY_HEADERS_ENABLED:
            raise ValueError("SECURITY_HEADERS_ENABLED must be True in production (SEC-009).")

        # Validate token lifetime ceilings in production
        if self.AUTH_ACCESS_TOKEN_EXPIRE_MINUTES > 60:
            raise ValueError(
                "Production AUTH_ACCESS_TOKEN_EXPIRE_MINUTES cannot exceed 60 minutes."
            )
        if self.AUTH_REFRESH_TOKEN_EXPIRE_DAYS > 30:
            raise ValueError("Production AUTH_REFRESH_TOKEN_EXPIRE_DAYS cannot exceed 30 days.")

        # Biometric matching is strictly forbidden in production (Phase 71)
        if self.BIOMETRIC_MATCHING_ENABLED:
            raise ValueError(
                "BIOMETRIC_MATCHING_ENABLED=True is strictly forbidden in production. "
                "Automated biometric face matching or identification is prohibited."
            )

    # =========================================================================
    # Safe Redaction & Serialization Helpers (SEC-008)
    # =========================================================================

    @property
    def redacted_database_url(self) -> str:
        """Return DATABASE_URL with embedded password masked as ``***REDACTED***``."""
        return redact_url(self.DATABASE_URL)

    @property
    def redacted_redis_url(self) -> str:
        """Return REDIS_URL with embedded password masked as ``***REDACTED***``."""
        return redact_url(self.REDIS_URL)

    def _collect_raw_secrets(self) -> list[str]:
        """Gather active secret strings to ensure complete scrubbing in dumps."""
        secrets_list: list[str] = [
            self.AUTH_SECRET_KEY.get_secret_value(),
            self.STORAGE_ACCESS_KEY.get_secret_value(),
            self.STORAGE_SECRET_KEY.get_secret_value(),
        ]
        if self.AI_API_KEY is not None:
            secrets_list.append(self.AI_API_KEY.get_secret_value())
        for url_str in (self.DATABASE_URL, self.REDIS_URL):
            parts = urlsplit(url_str)
            if parts.password:
                secrets_list.append(parts.password)
        return [s for s in secrets_list if s]

    def to_safe_dict(self) -> dict[str, Any]:
        """Return a dictionary of all settings with secrets and URL credentials redacted."""
        raw_dump = self.model_dump(mode="python")
        raw_dump["DATABASE_URL"] = self.redacted_database_url
        raw_dump["REDIS_URL"] = self.redacted_redis_url
        raw_dump["AUTH_SECRET_KEY"] = REDACTION_MASK
        raw_dump["STORAGE_ACCESS_KEY"] = REDACTION_MASK
        raw_dump["STORAGE_SECRET_KEY"] = REDACTION_MASK
        raw_dump["AI_API_KEY"] = REDACTION_MASK if self.AI_API_KEY is not None else None
        return redact_mapping(raw_dump, extra_secrets=self._collect_raw_secrets())

    def __repr__(self) -> str:
        """Return a safe string representation that never exposes secrets or DSN passwords."""
        if not hasattr(self, "DATABASE_URL") or not hasattr(self, "AUTH_SECRET_KEY"):
            return "Settings(<uninitialized>)"
        safe = self.to_safe_dict()
        items = ", ".join(f"{k}={v!r}" for k, v in safe.items())
        return f"Settings({items})"

    def __str__(self) -> str:
        """Return a safe string representation identical to ``__repr__``."""
        return self.__repr__()


def load_settings(**overrides: Any) -> Settings:
    """Instantiate and validate ``Settings`` with optional keyword overrides."""
    return Settings(**overrides)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached singleton ``Settings`` instance for the current process."""
    return Settings()
