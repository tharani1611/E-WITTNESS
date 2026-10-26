"""Cryptographic token generation, hashing, and JWT encode/decode service (Phase 17).

Provides secure token primitives:
- Maintained PyJWT-backed signed access token creation and claim verification.
- Pinned cryptographic algorithm allowlists (rejecting `"none"` and unapproved algorithms).
- Issuer, audience, expiration, issued-at, subject, and session-binding validation.
- Cryptographically secure opaque refresh and one-time token generation (`secrets.token_urlsafe`).
- Deterministic SHA-256 digest hashing so raw tokens are never persisted in the database.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import jwt
from pydantic import BaseModel, ConfigDict

from backend.app.config.settings import Settings
from backend.app.core.exceptions import AuthenticationError

APPROVED_JWT_ALGORITHMS: frozenset[str] = frozenset(
    {"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
)


class AccessTokenClaims(BaseModel):
    """Verified access token claims schema."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sub: str  # User ID (UUID string)
    sid: str  # Session ID (UUID string)
    jti: str  # Token ID (UUID string)
    iss: str  # Issuer
    aud: str  # Audience
    role: str  # Primary role code
    dept_id: str | None  # Department ID (None for super-admin)
    iat: int  # Issued at (epoch seconds)
    exp: int  # Expiration (epoch seconds)


def generate_opaque_token(nbytes: int = 32) -> str:
    """Generate a high-entropy cryptographically secure opaque token string."""
    return secrets.token_urlsafe(nbytes)


def hash_token(raw_token: str) -> str:
    """Compute deterministic lowercase SHA-256 hex digest for opaque token storage.

    Never logs or persists raw tokens.
    """
    if not isinstance(raw_token, str) or not raw_token.strip():
        raise ValueError("Token must be a non-empty string.")
    return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()


def create_access_token(
    *,
    user_id: UUID,
    session_id: UUID,
    role_code: str,
    department_id: UUID | None,
    settings: Settings,
    now: datetime | None = None,
) -> tuple[str, AccessTokenClaims]:
    """Issue a signed JWT access token bound to a user and active session.

    Enforces configured algorithm pinning and secret entropy boundaries.
    """
    algorithm = settings.AUTH_ALGORITHM.strip().upper()
    if algorithm not in APPROVED_JWT_ALGORITHMS:
        raise AuthenticationError(
            f"Unsupported JWT signing algorithm '{algorithm}'.",
            code="CONFIG_ERROR",
        )

    signing_key = settings.AUTH_SECRET_KEY.get_secret_value()
    if not signing_key or len(signing_key) < 32:
        raise AuthenticationError(
            "JWT signing key is insufficiently configured.",
            code="CONFIG_ERROR",
        )

    current_time = (now or datetime.now(UTC)).replace(microsecond=0)
    expires_at = current_time + timedelta(minutes=settings.AUTH_ACCESS_TOKEN_EXPIRE_MINUTES)

    claims_dict: dict[str, Any] = {
        "sub": str(user_id),
        "sid": str(session_id),
        "jti": str(uuid4()),
        "iss": settings.AUTH_ISSUER,
        "aud": settings.AUTH_AUDIENCE,
        "role": role_code,
        "dept_id": str(department_id) if department_id is not None else None,
        "iat": int(current_time.timestamp()),
        "exp": int(expires_at.timestamp()),
    }

    token_str = jwt.encode(
        claims_dict,
        signing_key,
        algorithm=algorithm,
    )
    return token_str, AccessTokenClaims(**claims_dict)


def verify_and_decode_access_token(
    token: str,
    settings: Settings,
) -> AccessTokenClaims:
    """Verify and decode a signed JWT access token.

    Validates signature, algorithm, required claims, audience, issuer, and expiration.

    Raises:
        AuthenticationError: If token is expired, tampered, malformed, or missing claims.
    """
    if not isinstance(token, str) or not token.strip():
        raise AuthenticationError(
            "Authentication token is missing or empty.",
            code="TOKEN_MISSING",
        )

    algorithm = settings.AUTH_ALGORITHM.strip().upper()
    if algorithm not in APPROVED_JWT_ALGORITHMS:
        raise AuthenticationError(
            "Invalid JWT verification algorithm.",
            code="CONFIG_ERROR",
        )

    signing_key = settings.AUTH_SECRET_KEY.get_secret_value()

    try:
        payload = jwt.decode(
            token.strip(),
            signing_key,
            algorithms=[algorithm],
            issuer=settings.AUTH_ISSUER,
            audience=settings.AUTH_AUDIENCE,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
                "require": ["sub", "sid", "jti", "iss", "aud", "exp", "iat", "role"],
            },
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationError(
            "Authentication token has expired.",
            code="TOKEN_EXPIRED",
        ) from exc
    except jwt.InvalidAlgorithmError as exc:
        raise AuthenticationError(
            "Token algorithm is invalid or disallowed.",
            code="TOKEN_ALGORITHM_DISALLOWED",
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise AuthenticationError(
            "Authentication token is invalid or malformed.",
            code="TOKEN_INVALID",
        ) from exc

    try:
        # Validate UUID formats
        UUID(payload["sub"])
        UUID(payload["sid"])
        if payload.get("dept_id") is not None:
            UUID(payload["dept_id"])
        return AccessTokenClaims(**payload)
    except (ValueError, TypeError) as exc:
        raise AuthenticationError(
            "Token claims contain invalid identifier formats.",
            code="TOKEN_INVALID_CLAIMS",
        ) from exc
