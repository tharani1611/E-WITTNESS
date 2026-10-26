"""Cryptographic key management and AES-256-GCM template encryption at rest (Phase 78).

Enforces:
- Standard AES-256-GCM authenticated encryption via cryptography.hazmat.
- Structured envelope format: v1:<key_id>:<base64(12_byte_nonce + ciphertext + 16_byte_tag)>.
- Explicit key lifecycle: active, rotated, revoked.
- Zero raw template or private key leakage: strict redaction and fail-closed security.
- Instant failure closed when encountering revoked or missing keys.
"""

from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.app.core.exceptions import BiometricKeyError, BiometricKeyRevokedError

ENVELOPE_VERSION: Final[str] = "v1"
NONCE_LENGTH_BYTES: Final[int] = 12
TAG_LENGTH_BYTES: Final[int] = 16
KEY_LENGTH_BYTES: Final[int] = 32  # 256 bits for AES-256


class KeyStatus(StrEnum):
    """Lifecycle state for biometric encryption keys."""

    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"


@dataclass(frozen=True)
class BiometricKeyMetadata:
    """Metadata describing a biometric encryption key without exposing raw key bytes."""

    key_id: str
    status: KeyStatus
    created_at: datetime
    algorithm: str = "AES-256-GCM"

    def __repr__(self) -> str:
        return (
            f"BiometricKeyMetadata(key_id={self.key_id!r}, "
            f"status={self.status.value!r}, algorithm={self.algorithm!r})"
        )


class _KeyEntry:
    """Internal key entry storing both metadata and raw key material."""

    def __init__(
        self, key_id: str, key_bytes: bytes, status: KeyStatus, created_at: datetime
    ) -> None:
        if len(key_bytes) != KEY_LENGTH_BYTES:
            raise ValueError(
                f"Biometric key must be exactly {KEY_LENGTH_BYTES} bytes (256 bits); got {len(key_bytes)}."
            )
        self.key_id = key_id
        self.key_bytes = key_bytes
        self.status = status
        self.created_at = created_at

    def to_metadata(self) -> BiometricKeyMetadata:
        return BiometricKeyMetadata(
            key_id=self.key_id,
            status=self.status,
            created_at=self.created_at,
        )

    def __repr__(self) -> str:
        return f"<_KeyEntry key_id={self.key_id!r} status={self.status.value!r} [KEY MATERIAL REDACTED]>"


class BiometricKeyManager:
    """Cryptographic key manager for AES-256-GCM biometric template encryption at rest (Phase 78)."""

    def __init__(
        self,
        default_key_bytes: bytes | None = None,
        default_key_id: str = "k1",
    ) -> None:
        self._keys: dict[str, _KeyEntry] = {}
        self._active_key_id: str | None = None

        if default_key_bytes is not None:
            self.register_key(default_key_id, default_key_bytes, status=KeyStatus.ACTIVE)
        else:
            self.generate_key(default_key_id, make_active=True)

    @property
    def active_key_id(self) -> str | None:
        """Currently active key ID used for new encryptions."""
        return self._active_key_id

    def register_key(
        self,
        key_id: str,
        key_bytes: bytes,
        *,
        status: KeyStatus = KeyStatus.ACTIVE,
    ) -> None:
        """Register a key with specified ID, bytes, and initial status."""
        cleaned_id = key_id.strip()
        if not cleaned_id:
            raise BiometricKeyError("Key ID cannot be empty.")

        now = datetime.now(UTC)
        entry = _KeyEntry(cleaned_id, key_bytes, status, now)
        self._keys[cleaned_id] = entry

        if status == KeyStatus.ACTIVE:
            if (
                self._active_key_id
                and self._active_key_id in self._keys
                and self._active_key_id != cleaned_id
            ):
                prev = self._keys[self._active_key_id]
                if prev.status == KeyStatus.ACTIVE:
                    prev.status = KeyStatus.ROTATED
            self._active_key_id = cleaned_id

    def generate_key(
        self,
        key_id: str | None = None,
        *,
        make_active: bool = True,
    ) -> str:
        """Generate a cryptographically secure 256-bit key and register it."""
        generated_id = key_id.strip() if key_id else f"key-{secrets.token_hex(4)}"
        key_bytes = secrets.token_bytes(KEY_LENGTH_BYTES)
        status = KeyStatus.ACTIVE if make_active else KeyStatus.ROTATED
        self.register_key(generated_id, key_bytes, status=status)
        return generated_id

    def rotate_key(self, new_key_id: str | None = None) -> str:
        """Rotate the active encryption key by generating and activating a new key."""
        return self.generate_key(new_key_id, make_active=True)

    def revoke_key(self, key_id: str) -> None:
        """Revoke a specific key. Any decryption attempt with this key will fail closed."""
        cleaned_id = key_id.strip()
        entry = self._keys.get(cleaned_id)
        if entry is None:
            raise BiometricKeyError(f"Cannot revoke unknown biometric key '{cleaned_id}'.")

        entry.status = KeyStatus.REVOKED
        if self._active_key_id == cleaned_id:
            self._active_key_id = None

    def get_key_metadata(self, key_id: str) -> BiometricKeyMetadata:
        """Get sanitized metadata for a registered key."""
        entry = self._keys.get(key_id.strip())
        if entry is None:
            raise BiometricKeyError(f"Biometric key '{key_id}' not found.")
        return entry.to_metadata()

    def list_keys(self) -> list[BiometricKeyMetadata]:
        """List metadata for all known keys."""
        return [entry.to_metadata() for entry in self._keys.values()]

    def encrypt(
        self,
        plaintext: bytes,
        *,
        key_id: str | None = None,
    ) -> str:
        """Encrypt biometric template bytes using AES-256-GCM.

        Returns envelope string: v1:<key_id>:<base64(12_byte_nonce + ciphertext + 16_byte_tag)>
        """
        if not plaintext:
            raise ValueError("Biometric template plaintext cannot be empty.")

        target_id = key_id.strip() if key_id else self._active_key_id
        if not target_id:
            raise BiometricKeyError(
                "No active biometric encryption key available. Cannot perform template encryption."
            )

        entry = self._keys.get(target_id)
        if entry is None:
            raise BiometricKeyError(f"Biometric key '{target_id}' not found.")

        if entry.status == KeyStatus.REVOKED:
            raise BiometricKeyRevokedError(
                f"Biometric key '{target_id}' is revoked and cannot be used for encryption."
            )

        nonce = os.urandom(NONCE_LENGTH_BYTES)
        aad = f"{ENVELOPE_VERSION}:{target_id}".encode()
        aesgcm = AESGCM(entry.key_bytes)

        try:
            ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, aad)
        except Exception as exc:
            raise BiometricKeyError("AES-256-GCM encryption failed.") from exc

        packed = nonce + ciphertext_and_tag
        b64_payload = base64.urlsafe_b64encode(packed).decode("ascii")
        return f"{ENVELOPE_VERSION}:{target_id}:{b64_payload}"

    def decrypt(self, envelope: str) -> bytes:
        """Decrypt a biometric template envelope using AES-256-GCM.

        Fails closed with typed exceptions if key is revoked, missing, or payload is tampered with.
        """
        if not envelope or not isinstance(envelope, str):
            raise BiometricKeyError("Invalid biometric ciphertext envelope.")

        parts = envelope.split(":")
        if len(parts) != 3 or parts[0] != ENVELOPE_VERSION:
            raise BiometricKeyError(
                f"Invalid biometric ciphertext envelope format; expected '{ENVELOPE_VERSION}:<key_id>:<payload>'."
            )

        target_id = parts[1]
        b64_payload = parts[2]

        entry = self._keys.get(target_id)
        if entry is None:
            raise BiometricKeyError(f"Biometric encryption key '{target_id}' not found in keyring.")

        if entry.status == KeyStatus.REVOKED:
            raise BiometricKeyRevokedError(
                f"Biometric encryption key '{target_id}' has been revoked. Decryption is forbidden."
            )

        try:
            packed = base64.urlsafe_b64decode(b64_payload)
        except Exception as exc:
            raise BiometricKeyError("Corrupted base64 payload in biometric envelope.") from exc

        min_len = NONCE_LENGTH_BYTES + TAG_LENGTH_BYTES
        if len(packed) < min_len:
            raise BiometricKeyError(
                f"Biometric envelope payload is too short ({len(packed)} bytes; minimum {min_len})."
            )

        nonce = packed[:NONCE_LENGTH_BYTES]
        ciphertext_and_tag = packed[NONCE_LENGTH_BYTES:]
        aad = f"{ENVELOPE_VERSION}:{target_id}".encode()
        aesgcm = AESGCM(entry.key_bytes)

        try:
            return aesgcm.decrypt(nonce, ciphertext_and_tag, aad)
        except Exception as exc:
            raise BiometricKeyError(
                "Biometric envelope authentication failed; ciphertext or authentication tag corrupted."
            ) from exc

    def reencrypt(self, envelope: str, *, new_key_id: str | None = None) -> str:
        """Decrypt an envelope and re-encrypt it under the active key or specified key."""
        plaintext = self.decrypt(envelope)
        return self.encrypt(plaintext, key_id=new_key_id)

    def __repr__(self) -> str:
        return f"<BiometricKeyManager active_key_id={self._active_key_id!r} total_keys={len(self._keys)}>"


# Default global / process-level key manager singleton
_global_key_manager: BiometricKeyManager | None = None


def get_biometric_key_manager() -> BiometricKeyManager:
    """Retrieve or lazily initialize the singleton BiometricKeyManager."""
    global _global_key_manager
    if _global_key_manager is None:
        _global_key_manager = BiometricKeyManager()
    return _global_key_manager


def set_biometric_key_manager(manager: BiometricKeyManager | None) -> None:
    """Override singleton BiometricKeyManager (used in tests or key injection)."""
    global _global_key_manager
    _global_key_manager = manager
