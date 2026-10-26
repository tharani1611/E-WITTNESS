"""Secure upload validation foundations and input hardening (Phase 29 / SEC-011).

Provides defense-in-depth file validation utilities for digital evidence custody:
- Strict magic-byte / file-signature inspection (PDF, PNG, JPEG, MP4, WAV, TXT, CSV).
- Forbidden dangerous extension blacklist and multi-extension attack rejection.
- Path-traversal and control character sanitization for file basenames.
- Content-Type to magic-byte correlation verification.
- Opaque, randomized UUID storage key generation to decouple physical paths
  from untrusted user input.

Architectural guarantee:
This module provides pure cryptographic and binary validation logic. It does NOT
implement premature HTTP endpoints or direct storage operations (reserved for
Phases 46-65).
"""

from __future__ import annotations

import re
import uuid
from pathlib import PurePosixPath, PureWindowsPath
from typing import Final
from uuid import UUID

from backend.app.core.exceptions import (
    BusinessRuleError,
    PayloadTooLargeError,
    UnsupportedMediaTypeError,
)
from backend.app.core.logging import get_logger

logger = get_logger("core.upload")

# Maximum permitted filename length in characters
MAX_FILENAME_LENGTH: Final[int] = 255

# Dangerous executable and script extensions forbidden under any circumstances
FORBIDDEN_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {
        ".exe",
        ".dll",
        ".bat",
        ".cmd",
        ".sh",
        ".bash",
        ".ps1",
        ".psm1",
        ".vbs",
        ".vbe",
        ".py",
        ".pyw",
        ".js",
        ".jse",
        ".mjs",
        ".php",
        ".phtml",
        ".php3",
        ".php4",
        ".php5",
        ".phps",
        ".jsp",
        ".jspx",
        ".asp",
        ".aspx",
        ".cgi",
        ".pl",
        ".jar",
        ".war",
        ".ear",
        ".elf",
        ".so",
        ".bin",
        ".msi",
        ".scr",
        ".pif",
        ".com",
        ".hta",
        ".cpl",
        ".wsf",
        ".scf",
        ".reg",
    }
)

# Permitted MIME types and their authorized file extensions
ALLOWED_MEDIA_TYPES: Final[dict[str, frozenset[str]]] = {
    "application/pdf": frozenset({".pdf"}),
    "image/png": frozenset({".png"}),
    "image/jpeg": frozenset({".jpg", ".jpeg"}),
    "image/webp": frozenset({".webp"}),
    "video/mp4": frozenset({".mp4"}),
    "audio/wav": frozenset({".wav"}),
    "audio/x-wav": frozenset({".wav"}),
    "audio/mpeg": frozenset({".mp3"}),
    "text/plain": frozenset({".txt"}),
    "text/csv": frozenset({".csv"}),
}

# Regex matching valid sanitized filename characters (alphanumeric, dot, underscore, hyphen)
_SAFE_FILENAME_REGEX: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9_\-\.]+$")


def sanitize_filename(filename: str) -> str:
    """Sanitize an untrusted user-supplied filename.

    Guarantees:
    - Strips path components across POSIX and Windows delimiters.
    - Strips null bytes and ASCII control characters.
    - Rejects directory traversal tokens (`..`).
    - Strips leading and trailing dots and whitespace.
    - Rejects double-extension attacks hiding forbidden executable suffixes.
    - Limits character set to `[a-zA-Z0-9_.-]`.
    - Enforces length bounds (1 to 255 characters).

    Raises:
        BusinessRuleError: When the filename is empty, malformed, or contains
            dangerous extension attacks.
    """
    if not filename or not isinstance(filename, str):
        raise BusinessRuleError("Filename must be a non-empty string.")

    # 1. Null byte and control char check
    if "\x00" in filename:
        raise BusinessRuleError("Filename must not contain null bytes.")
    for char in filename:
        if ord(char) < 32 or ord(char) == 127:
            raise BusinessRuleError("Filename contains invalid control characters.")

    # 2. Extract basename across both POSIX and Windows path separators
    clean_name = PureWindowsPath(filename).name
    clean_name = PurePosixPath(clean_name).name

    # 3. Strip leading/trailing dots and whitespace
    clean_name = clean_name.strip(" .\t\r\n")
    if not clean_name:
        raise BusinessRuleError("Sanitized filename resulted in empty string.")

    # 4. Check directory traversal remnants
    if ".." in clean_name or "/" in clean_name or "\\" in clean_name:
        raise BusinessRuleError("Filename contains prohibited directory traversal sequences.")

    # 5. Length verification
    if len(clean_name) > MAX_FILENAME_LENGTH:
        raise BusinessRuleError(
            f"Filename length ({len(clean_name)}) exceeds maximum limit of {MAX_FILENAME_LENGTH} characters."
        )

    # 6. Character set enforcement
    if not _SAFE_FILENAME_REGEX.match(clean_name):
        raise BusinessRuleError(
            "Filename contains prohibited special characters. Only alphanumeric, hyphen, underscore, and dot are permitted."
        )

    # 7. Check for forbidden extensions anywhere in the dot-separated parts
    parts = clean_name.lower().split(".")
    if len(parts) < 2:
        raise BusinessRuleError("Filename must include a valid file extension.")

    # Inspect all extension segments (e.g. 'doc.php.pdf')
    for part in parts[1:]:
        ext_candidate = f".{part}"
        if ext_candidate in FORBIDDEN_EXTENSIONS:
            raise BusinessRuleError(
                f"Filename contains forbidden executable or script extension: '{ext_candidate}'."
            )

    return clean_name


def detect_magic_bytes(header: bytes) -> str | None:
    """Inspect raw binary file header and return canonical MIME type if recognized.

    Inspects:
    - PDF: `%PDF-` at index 0
    - PNG: `\\x89PNG\\r\\n\\x1a\\n` at index 0
    - JPEG: `\\xff\\xd8\\xff` at index 0
    - WebP: `RIFF` at 0..4 and `WEBP` at 8..12
    - MP4: `ftyp` at bytes 4..8
    - WAV: `RIFF` at bytes 0..4 and `WAVE` at bytes 8..12
    - MP3: `ID3` tag or MPEG audio sync header
    - Plain text / CSV: Valid UTF-8 string with zero null bytes
    """
    if len(header) < 4:
        return None

    # PDF signature
    if header.startswith(b"%PDF-"):
        return "application/pdf"

    # PNG signature
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"

    # JPEG signature
    if header.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"

    # WebP signature: 'RIFF' at 0..4 and 'WEBP' at 8..12
    if len(header) >= 12 and header.startswith(b"RIFF") and header[8:12] == b"WEBP":
        return "image/webp"

    # MP4 signature: bytes 4-8 are 'ftyp'
    if len(header) >= 12 and header[4:8] == b"ftyp":
        return "video/mp4"

    # WAV signature: starts with 'RIFF' and contains 'WAVE' at offset 8-12
    if len(header) >= 12 and header.startswith(b"RIFF") and header[8:12] == b"WAVE":
        return "audio/wav"

    # MP3 signature: ID3v2 tag or MPEG audio frame sync word
    if header.startswith(b"ID3") or (
        len(header) >= 2 and header[0] == 0xFF and (header[1] & 0xE0) == 0xE0
    ):
        return "audio/mpeg"

    # Text / CSV check: must be valid UTF-8 and contain no null bytes
    if b"\x00" not in header:
        try:
            header.decode("utf-8")
            return "text/plain"
        except UnicodeDecodeError:
            pass

    return None


def validate_file_magic_bytes(
    data: bytes,
    expected_content_type: str | None = None,
) -> str:
    """Verify that binary data signature matches an authorized media type.

    Parameters
    ----------
    data:
        Raw file bytes (minimum first 16-512 bytes).
    expected_content_type:
        Optional declared Content-Type header to enforce MIME parity.

    Returns
    -------
    str:
        The verified MIME type.

    Raises
    ------
    BusinessRuleError:
        If data payload is empty.
    UnsupportedMediaTypeError:
        If magic bytes are unrecognized, not in allowed types, or mismatch declared type.
    """
    if not data:
        raise BusinessRuleError("Uploaded file payload is empty.")

    header = data[:512]
    detected_mime = detect_magic_bytes(header)

    if detected_mime is None or detected_mime not in ALLOWED_MEDIA_TYPES:
        raise UnsupportedMediaTypeError(
            "File signature (magic bytes) does not match any authorized media format.",
            code="UNSUPPORTED_MEDIA_TYPE",
        )

    if expected_content_type is not None:
        normalized_expected = expected_content_type.split(";")[0].strip().lower()
        # Allow audio/x-wav and audio/wav cross-compatibility
        is_wav_match = (
            normalized_expected in {"audio/wav", "audio/x-wav"} and detected_mime == "audio/wav"
        )
        # Allow text/csv and text/plain cross-compatibility for plain text formats
        is_text_match = (
            normalized_expected in {"text/plain", "text/csv"} and detected_mime == "text/plain"
        )

        if not (is_wav_match or is_text_match or normalized_expected == detected_mime):
            raise UnsupportedMediaTypeError(
                f"MIME type mismatch: declared '{normalized_expected}' but binary signature indicates '{detected_mime}'.",
                code="UNSUPPORTED_MEDIA_TYPE",
            )

    return detected_mime


def validate_upload_metadata(
    filename: str,
    content_type: str,
    file_size: int,
    max_file_size: int,
) -> str:
    """Validate upload metadata against policy bounds and return sanitized filename.

    Parameters
    ----------
    filename:
        User-provided filename string.
    content_type:
        Declared HTTP Content-Type.
    file_size:
        Declared or actual size in bytes.
    max_file_size:
        Upper bound allowed in bytes.

    Returns
    -------
    str:
        The sanitized, safe filename.

    Raises
    ------
    PayloadTooLargeError:
        If ``file_size > max_file_size``.
    BusinessRuleError:
        If ``file_size <= 0`` or filename is invalid.
    UnsupportedMediaTypeError:
        If ``content_type`` is not authorized or extension doesn't match content_type.
    """
    if file_size <= 0:
        raise BusinessRuleError("Uploaded file size must be greater than zero bytes.")

    if file_size > max_file_size:
        raise PayloadTooLargeError(
            f"Uploaded file size ({file_size} bytes) exceeds maximum limit of {max_file_size} bytes.",
            code="PAYLOAD_TOO_LARGE",
        )

    normalized_mime = content_type.split(";")[0].strip().lower()
    allowed_extensions = ALLOWED_MEDIA_TYPES.get(normalized_mime)
    if allowed_extensions is None:
        raise UnsupportedMediaTypeError(
            f"Content-Type '{normalized_mime}' is not authorized for evidence uploads.",
            code="UNSUPPORTED_MEDIA_TYPE",
        )

    clean_filename = sanitize_filename(filename)
    suffix = PurePosixPath(clean_filename).suffix.lower()

    if suffix not in allowed_extensions:
        raise UnsupportedMediaTypeError(
            f"File extension '{suffix}' does not match authorized extensions {sorted(allowed_extensions)} for '{normalized_mime}'.",
            code="UNSUPPORTED_MEDIA_TYPE",
        )

    return clean_filename


def generate_secure_storage_key(
    case_id: UUID | str,
    original_filename: str,
) -> str:
    """Generate a randomized, path-safe storage key decoupling storage from client filenames.

    Format: `cases/{case_id}/{uuid4()}{extension}`
    """
    clean_name = sanitize_filename(original_filename)
    suffix = PurePosixPath(clean_name).suffix.lower()
    unique_token = uuid.uuid4().hex
    return f"cases/{case_id}/{unique_token}{suffix}"


def validate_stream_chunk_and_size(
    chunk: bytes,
    total_bytes_read: int,
    max_allowed_bytes: int,
) -> int:
    """Enforce upload size limit incrementally during stream reception.

    Parameters
    ----------
    chunk:
        Current byte chunk received from stream.
    total_bytes_read:
        Cumulative bytes received before this chunk.
    max_allowed_bytes:
        Upper bound configured for evidence uploads.

    Returns
    -------
    int:
        New cumulative byte count (`total_bytes_read + len(chunk)`).

    Raises
    ------
    PayloadTooLargeError:
        If receiving ``chunk`` exceeds ``max_allowed_bytes``.
    """
    new_total = total_bytes_read + len(chunk)
    if new_total > max_allowed_bytes:
        raise PayloadTooLargeError(
            f"Streaming upload exceeded maximum allowed limit of {max_allowed_bytes} bytes.",
            code="PAYLOAD_TOO_LARGE",
        )
    return new_total
