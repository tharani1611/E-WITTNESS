"""Unit tests for password hashing, policy validation, and verification (Phase 16)."""

from __future__ import annotations

import pytest

from backend.app.core.exceptions import BusinessRuleError
from backend.app.services.password import (
    COMMONLY_COMPROMISED_PASSWORDS,
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    PasswordService,
)


@pytest.fixture
def password_service() -> PasswordService:
    """Provide a fast, memory-safe PasswordService instance for unit testing."""
    return PasswordService(time_cost=1, memory_cost=1024, parallelism=1)


class TestPasswordPolicyValidation:
    """Enforce length ceilings, minimum bounds, and common password rejections."""

    def test_valid_password_passes_policy(self, password_service: PasswordService) -> None:
        password_service.validate_password_policy("CorrectHorseBatteryStaple2026!")

    def test_password_shorter_than_minimum_rejected(
        self, password_service: PasswordService
    ) -> None:
        with pytest.raises(BusinessRuleError) as exc_info:
            password_service.validate_password_policy("short")
        assert exc_info.value.code == "PASSWORD_TOO_SHORT"
        assert f"at least {MIN_PASSWORD_LENGTH}" in exc_info.value.message

    def test_password_longer_than_maximum_rejected(self, password_service: PasswordService) -> None:
        oversized = "A" * (MAX_PASSWORD_LENGTH + 1)
        with pytest.raises(BusinessRuleError) as exc_info:
            password_service.validate_password_policy(oversized)
        assert exc_info.value.code == "PASSWORD_TOO_LONG"
        assert f"maximum limit of {MAX_PASSWORD_LENGTH}" in exc_info.value.message

    def test_non_string_password_rejected(self, password_service: PasswordService) -> None:
        with pytest.raises(BusinessRuleError) as exc_info:
            password_service.validate_password_policy(12345678)  # type: ignore[arg-type]
        assert exc_info.value.code == "PASSWORD_INVALID_TYPE"

    @pytest.mark.parametrize("compromised", list(COMMONLY_COMPROMISED_PASSWORDS)[:5])
    def test_commonly_compromised_passwords_rejected(
        self, password_service: PasswordService, compromised: str
    ) -> None:
        with pytest.raises(BusinessRuleError) as exc_info:
            password_service.validate_password_policy(compromised)
        assert exc_info.value.code == "PASSWORD_COMMONLY_COMPROMISED"
        # Password string must never appear in exception message
        assert compromised not in exc_info.value.message


class TestPasswordHashingAndVerification:
    """Verify Argon2id hashing, mismatch safety, and malformed hash handling."""

    def test_hashing_produces_argon2id_string(self, password_service: PasswordService) -> None:
        pwd = "SecureCampusPassword123!"
        hashed = password_service.hash_password(pwd)
        assert hashed.startswith("$argon2id$")
        assert len(hashed) >= 40
        # Password itself must not be in the hash
        assert pwd not in hashed

    def test_verification_succeeds_for_correct_password(
        self, password_service: PasswordService
    ) -> None:
        pwd = "CampusSafetyOfficer2026!"
        hashed = password_service.hash_password(pwd)
        assert password_service.verify_password(pwd, hashed) is True

    def test_verification_fails_for_incorrect_password(
        self, password_service: PasswordService
    ) -> None:
        pwd = "ValidPassword123!"
        hashed = password_service.hash_password(pwd)
        assert password_service.verify_password("WrongPassword999!", hashed) is False

    @pytest.mark.parametrize(
        "malformed_hash",
        [
            "",
            "   ",
            "not-a-hash",
            "$pbkdf2$invalid",
            "$argon2id$v=19$corrupted_payload_string",
            "$argon2id$v=99$m=0,t=0,p=0$xyz",
        ],
    )
    def test_verification_handles_malformed_hashes_safely(
        self, password_service: PasswordService, malformed_hash: str
    ) -> None:
        # Must return False without crashing or throwing internal exceptions
        assert password_service.verify_password("ValidPassword123!", malformed_hash) is False

    def test_verification_handles_none_or_empty_input_safely(
        self, password_service: PasswordService
    ) -> None:
        hashed = password_service.hash_password("ValidPassword123!")
        assert password_service.verify_password("", hashed) is False
        assert password_service.verify_password("ValidPassword123!", None) is False
        assert password_service.verify_password(None, hashed) is False  # type: ignore[arg-type]

    def test_verification_handles_oversized_plain_password(
        self, password_service: PasswordService
    ) -> None:
        hashed = password_service.hash_password("ValidPassword123!")
        oversized = "X" * 1000
        assert password_service.verify_password(oversized, hashed) is False

    def test_check_needs_rehash_returns_boolean(self, password_service: PasswordService) -> None:
        hashed = password_service.hash_password("ValidPassword123!")
        assert password_service.check_needs_rehash(hashed) is False
        assert password_service.check_needs_rehash("corrupted_hash") is True
