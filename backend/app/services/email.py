"""Email delivery abstraction and deterministic test fake (Phase 18).

Provides an abstract interface for delivering transaction-critical emails:
- Password recovery and reset tokens
- Account activation and email verification tokens

Security invariants:
- Raw tokens and reset links are NEVER emitted in production log statements.
- The `FakeEmailDeliveryService` records outbound messages in memory for test assertions.
- Safe fallback when no real SMTP provider is configured.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Protocol

logger = logging.getLogger("ewitness.services.email")


class EmailDeliveryService(Protocol):
    """Protocol for transactional email delivery."""

    async def send_password_reset_email(self, to_email: str, token: str) -> bool:
        """Send a password recovery token to the specified address."""
        ...

    async def send_verification_email(self, to_email: str, token: str) -> bool:
        """Send an email verification token to the specified address."""
        ...

    async def send_invitation_email(self, to_email: str, token: str) -> bool:
        """Send an account invitation token to the specified address."""
        ...


class FakeEmailDeliveryService:
    """Thread-safe, deterministic in-memory email delivery fake for automated testing."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.sent_messages: list[dict[str, Any]] = []

    async def send_password_reset_email(self, to_email: str, token: str) -> bool:
        """Record password reset message in test history."""
        with self._lock:
            self.sent_messages.append(
                {
                    "to": to_email,
                    "type": "password_reset",
                    "token": token,
                }
            )
        return True

    async def send_verification_email(self, to_email: str, token: str) -> bool:
        """Record verification message in test history."""
        with self._lock:
            self.sent_messages.append(
                {
                    "to": to_email,
                    "type": "email_verification",
                    "token": token,
                }
            )
        return True

    async def send_invitation_email(self, to_email: str, token: str) -> bool:
        """Record invitation message in test history."""
        with self._lock:
            self.sent_messages.append(
                {
                    "to": to_email,
                    "type": "invitation",
                    "token": token,
                }
            )
        return True

    def get_last_token_for(self, to_email: str, message_type: str | None = None) -> str | None:
        """Retrieve the most recent token recorded for ``to_email``."""
        with self._lock:
            for msg in reversed(self.sent_messages):
                if msg["to"] == to_email and (message_type is None or msg["type"] == message_type):
                    return str(msg["token"])
        return None

    def clear(self) -> None:
        """Clear recorded email history."""
        with self._lock:
            self.sent_messages.clear()


class LoggingEmailDeliveryService:
    """Development/fallback email delivery that logs delivery events with redacted tokens."""

    async def send_password_reset_email(self, to_email: str, token: str) -> bool:
        logger.info(
            "Dispatched password reset email to %s (token length: %d)",
            to_email,
            len(token),
        )
        return True

    async def send_verification_email(self, to_email: str, token: str) -> bool:
        logger.info(
            "Dispatched verification email to %s (token length: %d)",
            to_email,
            len(token),
        )
        return True

    async def send_invitation_email(self, to_email: str, token: str) -> bool:
        logger.info(
            "Dispatched invitation email to %s (token length: %d)",
            to_email,
            len(token),
        )
        return True
