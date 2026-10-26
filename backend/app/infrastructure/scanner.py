"""Malware and antivirus scanning infrastructure abstractions and hooks (Phase 47).

Enforces:
- Formal scanner abstraction with explicit scan lifecycle states.
- Mock scanner test double with configurable verdicts, EICAR detection, and failure simulation.
- Production ClamAV daemon client hook (`INSTREAM` protocol) with fail-closed security.
- Safe logging of scan outcomes without disclosing sensitive file contents or internal secrets.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final, Protocol, runtime_checkable

from backend.app.core.evidence import ScanStatus
from backend.app.core.logging import get_logger

logger = get_logger("infrastructure.scanner")

# EICAR standard anti-virus test file signature prefix
EICAR_STANDARD_TEST_SIGNATURE: Final[bytes] = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
EICAR_SIGNATURE: Final[bytes] = EICAR_STANDARD_TEST_SIGNATURE


@dataclass(frozen=True)
class ScanResult:
    """Outcome and metadata from a malware scan operation."""

    status: ScanStatus
    engine: str
    threat_name: str | None = None
    scanned_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    error_message: str | None = None


@runtime_checkable
class MalwareScanner(Protocol):
    """Protocol defining malware scanning operations for evidence objects."""

    async def scan_payload(
        self,
        storage_key: str,
        payload: bytes,
    ) -> ScanResult:
        """Scan a binary payload for malicious content and return a structured verdict."""
        ...

    async def ping(self) -> bool:
        """Verify availability and connectivity of the scanner backend."""
        ...


class MockMalwareScanner:
    """In-memory scanner test double supporting deterministic outcome simulation."""

    def __init__(
        self,
        default_status: ScanStatus = ScanStatus.CLEAN,
        engine_name: str = "MockScanner-1.0",
    ) -> None:
        self.default_status = default_status
        self.engine_name = engine_name
        self._infected_patterns: list[bytes] = [EICAR_STANDARD_TEST_SIGNATURE]
        self._infected_keys: set[str] = set()
        self._failing_keys: set[str] = set()
        self._timing_out_keys: set[str] = set()
        self._available = True

    def set_available(self, available: bool) -> None:
        """Simulate scanner service availability toggle."""
        self._available = available

    def add_infected_pattern(self, pattern: bytes) -> None:
        """Register a byte pattern that will trigger an INFECTED verdict."""
        self._infected_patterns.append(pattern)

    def mark_key_infected(self, storage_key: str) -> None:
        """Configure a specific storage key to always evaluate as INFECTED."""
        self._infected_keys.add(storage_key)

    def mark_key_failing(self, storage_key: str) -> None:
        """Configure a specific storage key to simulate an internal scanner error."""
        self._failing_keys.add(storage_key)

    def mark_key_timing_out(self, storage_key: str) -> None:
        """Configure a specific storage key to simulate a scan timeout."""
        self._timing_out_keys.add(storage_key)

    async def ping(self) -> bool:
        return self._available

    async def scan_payload(
        self,
        storage_key: str,
        payload: bytes,
    ) -> ScanResult:
        if not self._available:
            return ScanResult(
                status=ScanStatus.FAILED,
                engine=self.engine_name,
                error_message="Malware scanner daemon is unavailable.",
            )

        if storage_key in self._timing_out_keys:
            return ScanResult(
                status=ScanStatus.FAILED,
                engine=self.engine_name,
                error_message="Scanner operation timed out after 30.0s.",
            )

        if storage_key in self._failing_keys:
            return ScanResult(
                status=ScanStatus.FAILED,
                engine=self.engine_name,
                error_message="Internal engine scanning fault.",
            )

        if storage_key in self._infected_keys:
            return ScanResult(
                status=ScanStatus.INFECTED,
                engine=self.engine_name,
                threat_name="Win32.MockTestVirus.Exploit",
            )

        # Check payload against recognized malware patterns
        for pattern in self._infected_patterns:
            if pattern in payload:
                logger.warning(
                    "Malware signature detected in evidence payload",
                    extra={"storage_key": storage_key, "threat_signature": "EICAR-Test-Signature"},
                )
                return ScanResult(
                    status=ScanStatus.INFECTED,
                    engine=self.engine_name,
                    threat_name="EICAR-Test-Signature",
                )

        return ScanResult(
            status=self.default_status,
            engine=self.engine_name,
        )


class ClamAVScanner:
    """Production ClamAV daemon client implementing the `INSTREAM` TCP protocol."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 3310,
        timeout_seconds: float = 30.0,
        chunk_size: int = 262144,  # 256 KB streaming chunks
    ) -> None:
        self.host = host
        self.port = port
        self.timeout_seconds = timeout_seconds
        self.chunk_size = chunk_size
        self.engine_name = "ClamAV-Daemon"

    async def ping(self) -> bool:
        """Send `zPING\\0` to the ClamAV daemon and verify `PONG` response."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout_seconds,
            )
            try:
                writer.write(b"zPING\x00")
                await writer.drain()
                response = await asyncio.wait_for(
                    reader.read(64),
                    timeout=self.timeout_seconds,
                )
                return b"PONG" in response
            finally:
                writer.close()
                await writer.wait_closed()
        except (OSError, TimeoutError) as exc:
            logger.warning("ClamAV daemon health check failed", exc_info=exc)
            return False

    async def scan_payload(
        self,
        storage_key: str,
        payload: bytes,
    ) -> ScanResult:
        """Stream evidence payload to ClamAV via `zINSTREAM\\0` and parse the result."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout_seconds,
            )
        except (OSError, TimeoutError) as exc:
            logger.error("Failed to connect to ClamAV daemon", exc_info=exc)
            # Fail closed: never release unscanned evidence
            return ScanResult(
                status=ScanStatus.FAILED,
                engine=self.engine_name,
                error_message=f"Scanner connection failed: {exc}",
            )

        try:
            # 1. Send INSTREAM command
            writer.write(b"zINSTREAM\x00")
            await writer.drain()

            # 2. Stream payload in sized chunks: [4-byte big-endian length][chunk_data]
            offset = 0
            payload_len = len(payload)
            while offset < payload_len:
                chunk = payload[offset : offset + self.chunk_size]
                chunk_len = len(chunk)
                writer.write(chunk_len.to_bytes(4, byteorder="big"))
                writer.write(chunk)
                await writer.drain()
                offset += chunk_len

            # 3. Terminate stream with zero length chunk
            writer.write((0).to_bytes(4, byteorder="big"))
            await writer.drain()

            # 4. Read response from daemon
            raw_response = await asyncio.wait_for(
                reader.read(1024),
                timeout=self.timeout_seconds,
            )
            response_text = raw_response.decode("utf-8", errors="replace").strip(" \x00\r\n\t")

            # ClamAV response formats:
            # - Clean: `stream: OK`
            # - Infected: `stream: <virus_name> FOUND`
            # - Error: `stream: <error> ERROR`
            if "OK" in response_text:
                logger.info(
                    "ClamAV scan completed cleanly",
                    extra={"storage_key": storage_key, "engine": self.engine_name},
                )
                return ScanResult(
                    status=ScanStatus.CLEAN,
                    engine=self.engine_name,
                )

            if "FOUND" in response_text:
                parts = response_text.split(":")
                threat = "UnknownThreat"
                if len(parts) >= 2:
                    threat = parts[1].replace("FOUND", "").strip(" \x00\r\n\t")
                logger.warning(
                    "ClamAV detected infected content",
                    extra={"storage_key": storage_key, "threat": threat},
                )
                return ScanResult(
                    status=ScanStatus.INFECTED,
                    engine=self.engine_name,
                    threat_name=threat,
                )

            # Error or unknown response from daemon
            logger.error(
                "ClamAV daemon returned non-standard verdict",
                extra={"storage_key": storage_key, "verdict": response_text},
            )
            return ScanResult(
                status=ScanStatus.FAILED,
                engine=self.engine_name,
                error_message=f"Scanner returned error: {response_text}",
            )

        except (OSError, TimeoutError) as exc:
            logger.error("ClamAV scan stream communication timed out or failed", exc_info=exc)
            return ScanResult(
                status=ScanStatus.FAILED,
                engine=self.engine_name,
                error_message=f"Scanner execution timed out or failed: {exc}",
            )
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
