"""Password hashing, policy validation, and verification service (Phase 16).

Implements memory-hard Argon2id (RFC 9106) hashing and verification, strict
input boundary validation, rejection of commonly compromised passwords, and safe
handling of malformed hashes without revealing internal exceptions or leaking
passwords into logs.
"""

from __future__ import annotations

import logging
from typing import Final

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from backend.app.core.exceptions import BusinessRuleError

logger = logging.getLogger("ewitness.security.password")

# Bounded password limits preventing both weak credentials and computational DoS
MIN_PASSWORD_LENGTH: Final[int] = 8
MAX_PASSWORD_LENGTH: Final[int] = 128

# Common weak passwords disallowed regardless of length or complexity
COMMONLY_COMPROMISED_PASSWORDS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "password1",
        "password12",
        "password123",
        "password1234",
        "12345678",
        "123456789",
        "1234567890",
        "qwertyuiop",
        "admin123",
        "admin1234",
        "administrator",
        "changeme",
        "changeme123",
        "letmein123",
        "welcome1",
        "welcome123",
        "iloveyou123",
        "football",
        "monkey123",
        "master123",
        "dragon123",
        "sunshine",
        "princess",
        "superman",
        "campus123",
        "university",
        "university123",
    }
)


class PasswordService:
    """Argon2id password hashing and verification service."""

    def __init__(
        self,
        *,
        time_cost: int = 2,
        memory_cost: int = 19456,  # 19 MiB (RFC 9106 recommended default)
        parallelism: int = 1,
        hash_len: int = 32,
    ) -> None:
        self._hasher = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=Type.ID,
        )

    def validate_password_policy(self, password: str) -> None:
        """Enforce length boundaries and block commonly compromised passwords.

        Raises:
            BusinessRuleError: If the password violates length or common-passwords rules.
            Never includes the submitted password string in exception details.
        """
        if not isinstance(password, str):
            raise BusinessRuleError(
                "Password must be a valid text string.",
                code="PASSWORD_INVALID_TYPE",
            )

        length = len(password)
        if length < MIN_PASSWORD_LENGTH:
            raise BusinessRuleError(
                f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.",
                code="PASSWORD_TOO_SHORT",
            )
        if length > MAX_PASSWORD_LENGTH:
            raise BusinessRuleError(
                f"Password exceeds maximum limit of {MAX_PASSWORD_LENGTH} characters.",
                code="PASSWORD_TOO_LONG",
            )

        if password.strip().lower() in COMMONLY_COMPROMISED_PASSWORDS:
            raise BusinessRuleError(
                "Password is too common and easily compromised. Please choose a more secure passphrase.",
                code="PASSWORD_COMMONLY_COMPROMISED",
            )

    def hash_password(self, password: str) -> str:
        """Validate policy and return an Argon2id formatted password hash.

        Never logs plaintext credentials or generated hashes.
        """
        self.validate_password_policy(password)
        try:
            return self._hasher.hash(password)
        except Exception as exc:  # pragma: no cover
            logger.error("Failed to compute Argon2id password hash")
            raise BusinessRuleError(
                "Unable to securely hash credential.",
                code="PASSWORD_HASHING_FAILED",
            ) from exc

    def verify_password(self, plain_password: str, hashed_password: str | None) -> bool:
        """Safely verify ``plain_password`` against an Argon2id ``hashed_password``.

        Returns ``False`` on mismatch, malformed hash string, empty input,
        or unsupported hashing algorithm without raising internal exceptions.
        """
        if not plain_password or not hashed_password:
            return False
        if not isinstance(plain_password, str) or not isinstance(hashed_password, str):
            return False
        if len(plain_password) > MAX_PASSWORD_LENGTH:
            return False

        try:
            return self._hasher.verify(hashed_password, plain_password)
        except (VerifyMismatchError, VerificationError, InvalidHashError, ValueError):
            return False
        except Exception:  # Defensive catch for unexpected native cffi errors
            return False

    def check_needs_rehash(self, hashed_password: str) -> bool:
        """Determine if stored hash was computed with older/weaker Argon2 parameters."""
        try:
            return self._hasher.check_needs_rehash(hashed_password)
        except Exception:
            return True
