"""Unit tests for token issuance, PyJWT claim verification, and token digests (Phase 17)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest

from backend.app.config.settings import Settings
from backend.app.core.exceptions import AuthenticationError
from backend.app.core.tokens import (
    create_access_token,
    generate_opaque_token,
    hash_token,
    verify_and_decode_access_token,
)


@pytest.fixture
def auth_settings(settings_factory: Callable[..., Settings]) -> Settings:
    """Return Settings configured with verified HS256 auth keys."""
    return settings_factory(
        AUTH_ALGORITHM="HS256",
        AUTH_SECRET_KEY="test_secret_key_with_at_least_32_characters_length_ok",
        AUTH_ACCESS_TOKEN_EXPIRE_MINUTES=15,
        AUTH_ISSUER="ewitness-test-issuer",
        AUTH_AUDIENCE="ewitness-test-audience",
    )


class TestOpaqueTokenGenerationAndHashing:
    """Verify cryptographically secure token generation and SHA-256 digests."""

    def test_generate_opaque_token_properties(self) -> None:
        token = generate_opaque_token(32)
        assert isinstance(token, str)
        assert len(token) >= 40
        token_b = generate_opaque_token(32)
        assert token != token_b

    def test_hash_token_produces_deterministic_sha256(self) -> None:
        token = "test_raw_opaque_token_value_123"
        digest_1 = hash_token(token)
        digest_2 = hash_token(token)
        assert digest_1 == digest_2
        assert len(digest_1) == 64
        assert digest_1 == digest_1.lower()

    def test_hash_token_rejects_empty_input(self) -> None:
        with pytest.raises(ValueError, match="non-empty string"):
            hash_token("")
        with pytest.raises(ValueError, match="non-empty string"):
            hash_token("   ")
        with pytest.raises(ValueError, match="non-empty string"):
            hash_token(None)  # type: ignore[arg-type]


class TestJWTAccessTokenIssuanceAndVerification:
    """Verify signed access token generation, algorithm pinning, and claim boundaries."""

    def test_create_and_verify_valid_access_token(self, auth_settings: Settings) -> None:
        user_id = uuid4()
        session_id = uuid4()
        dept_id = uuid4()

        token_str, claims = create_access_token(
            user_id=user_id,
            session_id=session_id,
            role_code="ROLE_STUDENT",
            department_id=dept_id,
            settings=auth_settings,
        )

        assert isinstance(token_str, str)
        assert claims.sub == str(user_id)
        assert claims.sid == str(session_id)
        assert claims.role == "ROLE_STUDENT"
        assert claims.dept_id == str(dept_id)

        # Verification step
        decoded = verify_and_decode_access_token(token_str, auth_settings)
        assert decoded.sub == str(user_id)
        assert decoded.sid == str(session_id)
        assert decoded.role == "ROLE_STUDENT"
        assert decoded.dept_id == str(dept_id)
        assert decoded.iss == auth_settings.AUTH_ISSUER
        assert decoded.aud == auth_settings.AUTH_AUDIENCE

    def test_access_token_supports_none_department_for_super_admin(
        self, auth_settings: Settings
    ) -> None:
        user_id = uuid4()
        session_id = uuid4()

        token_str, _ = create_access_token(
            user_id=user_id,
            session_id=session_id,
            role_code="ROLE_SUPER_ADMIN",
            department_id=None,
            settings=auth_settings,
        )

        decoded = verify_and_decode_access_token(token_str, auth_settings)
        assert decoded.dept_id is None
        assert decoded.role == "ROLE_SUPER_ADMIN"

    def test_expired_token_rejected(self, auth_settings: Settings) -> None:
        past_time = datetime.now(UTC) - timedelta(minutes=30)
        token_str, _ = create_access_token(
            user_id=uuid4(),
            session_id=uuid4(),
            role_code="ROLE_STAFF",
            department_id=uuid4(),
            settings=auth_settings,
            now=past_time,
        )

        with pytest.raises(AuthenticationError) as exc_info:
            verify_and_decode_access_token(token_str, auth_settings)
        assert exc_info.value.code == "TOKEN_EXPIRED"

    def test_tampered_signature_rejected(self, auth_settings: Settings) -> None:
        token_str, _ = create_access_token(
            user_id=uuid4(),
            session_id=uuid4(),
            role_code="ROLE_STAFF",
            department_id=uuid4(),
            settings=auth_settings,
        )
        tampered = token_str[:-4] + ("AAAA" if not token_str.endswith("AAAA") else "BBBB")

        with pytest.raises(AuthenticationError) as exc_info:
            verify_and_decode_access_token(tampered, auth_settings)
        assert exc_info.value.code == "TOKEN_INVALID"

    def test_unsupported_or_none_algorithm_rejected(self, auth_settings: Settings) -> None:
        # Construct an unsigned 'none' algorithm token
        payload = {
            "sub": str(uuid4()),
            "sid": str(uuid4()),
            "jti": str(uuid4()),
            "iss": auth_settings.AUTH_ISSUER,
            "aud": auth_settings.AUTH_AUDIENCE,
            "role": "ROLE_STUDENT",
            "iat": int(datetime.now(UTC).timestamp()),
            "exp": int((datetime.now(UTC) + timedelta(minutes=15)).timestamp()),
        }
        none_token = jwt.encode(payload, key="", algorithm="none")

        with pytest.raises(AuthenticationError) as exc_info:
            verify_and_decode_access_token(none_token, auth_settings)
        assert exc_info.value.code in {"TOKEN_ALGORITHM_DISALLOWED", "TOKEN_INVALID"}

    def test_missing_required_claims_rejected(self, auth_settings: Settings) -> None:
        # Omit 'sid' claim
        incomplete_payload = {
            "sub": str(uuid4()),
            "iss": auth_settings.AUTH_ISSUER,
            "aud": auth_settings.AUTH_AUDIENCE,
            "iat": int(datetime.now(UTC).timestamp()),
            "exp": int((datetime.now(UTC) + timedelta(minutes=15)).timestamp()),
        }
        token = jwt.encode(
            incomplete_payload,
            auth_settings.AUTH_SECRET_KEY.get_secret_value(),
            algorithm="HS256",
        )

        with pytest.raises(AuthenticationError) as exc_info:
            verify_and_decode_access_token(token, auth_settings)
        assert exc_info.value.code == "TOKEN_INVALID"

    def test_empty_or_non_string_token_rejected(self, auth_settings: Settings) -> None:
        with pytest.raises(AuthenticationError) as exc_info:
            verify_and_decode_access_token("", auth_settings)
        assert exc_info.value.code == "TOKEN_MISSING"

        with pytest.raises(AuthenticationError) as exc_info:
            verify_and_decode_access_token(None, auth_settings)  # type: ignore[arg-type]
        assert exc_info.value.code == "TOKEN_MISSING"
