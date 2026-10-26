"""Core analytics, reporting, and operational monitoring domain primitives (Phases 96-99).

Provides:
- Time bucketing and analytics granularity enums.
- Report types, export formats, and formula-injection sanitization for CSV/PDF.
- Operational worker statuses, monitoring alert severities, and thresholds.
- Pure-Python secure PDF generation with table layout and statutory AI disclaimers.
"""

from __future__ import annotations

import io
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

# =============================================================================
# Constants & Thresholds
# =============================================================================

MAX_ANALYTICS_RANGE_DAYS: int = 365
MAX_EXPORT_ROWS: int = 5000
WORKER_STALE_THRESHOLD_SECONDS: int = 300  # 5 minutes
ALERT_COOLDOWN_SECONDS: int = 900  # 15 minutes cooldown per alert type

STATUTORY_AI_ADVISORY_DISCLAIMER: str = (
    "STATUTORY ADVISORY: Candidate video segments, scores, and classifications produced "
    "by automated AI analysis are probabilistic and advisory only. They do not establish "
    "proof of identity, wrongdoing, or disciplinary culpability. All consequential decisions "
    "require authorized human review and corroborating evidence."
)


# =============================================================================
# Enums
# =============================================================================


class TimeBucket(StrEnum):
    """Aggregation bucket granularity for time-series analytics."""

    DAY = "day"
    WEEK = "week"
    MONTH = "month"


class ReportType(StrEnum):
    """Supported export report types."""

    INCIDENTS = "incidents"
    CASES = "cases"
    OPERATIONAL_SUMMARY = "operational_summary"
    HUMAN_REVIEWS = "human_reviews"


class ReportFormat(StrEnum):
    """Supported export document formats."""

    CSV = "csv"
    PDF = "pdf"


class ExportStatus(StrEnum):
    """Lifecycle status of an export request."""

    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"


class WorkerStatus(StrEnum):
    """Operational status of a background worker."""

    ACTIVE = "active"
    STALE = "stale"
    OFFLINE = "offline"


class OperationalAlertSeverity(StrEnum):
    """Severity tier for operational system alerts."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class OperationalAlertType(StrEnum):
    """Categories of operational health alerts."""

    QUEUE_BACKLOG = "queue_backlog"
    WORKER_STALE = "worker_stale"
    HIGH_FAILURE_RATE = "high_failure_rate"
    RETRY_EXHAUSTION = "retry_exhaustion"


# =============================================================================
# CSV Formula Injection Sanitization (Phase 98)
# =============================================================================

_FORMULA_PREFIX_CHARS: tuple[str, ...] = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_cell(value: Any) -> str:
    """Sanitize a cell value to prevent CSV / Spreadsheet Formula Injection (CWE-1236).

    Spreadsheet applications (Excel, Calc, Google Sheets) execute cells beginning
    with `=`, `+`, `-`, `@`, `\t`, or `\r` as formulas or macros.
    This function prepends an apostrophe `'` to neutralize formula evaluation
    if the stripped value starts with any hazardous character.
    """
    if value is None:
        return ""
    text = str(value)
    if any(text.startswith(char) for char in _FORMULA_PREFIX_CHARS):
        return f"'{text}"
    stripped = text.strip()
    if stripped and any(stripped.startswith(char) for char in _FORMULA_PREFIX_CHARS):
        # Prepend single quote to force spreadsheet software to treat as text
        return f"'{text}"
    return text


# =============================================================================
# Pure-Python Secure PDF Generator (Phase 98)
# =============================================================================


def _escape_pdf_text(text: str) -> str:
    """Escape text for safe inclusion in PDF literal strings."""
    # Replace backslash and parentheses
    text = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    # Strip non-ASCII or replace with safe equivalents
    return "".join(c if 32 <= ord(c) < 127 else "?" for c in text)


def generate_pdf_report(
    *,
    title: str,
    headers: list[str],
    rows: list[list[str]],
    metadata: dict[str, Any] | None = None,
) -> bytes:
    """Generate a clean, self-contained PDF document adhering strictly to PDF-1.4 specification.

    Guarantees:
    - Zero external network requests (no SSRF).
    - Zero HTML/JS evaluation (no XSS or RCE).
    - Strict text escaping and table bounding.
    - Embedded legal headers and statutory AI disclaimer.
    """
    meta = metadata or {}
    generated_at = meta.get("generated_at", datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"))
    department = meta.get("department", "All Departments / Global Scope")
    record_count = len(rows)

    # Document coordinates & layout (Standard Letter / A4: 612 x 792 pt)
    page_width = 612
    page_height = 792
    margin_x = 40
    content_width = page_width - (margin_x * 2)

    # Calculate column widths
    num_cols = max(len(headers), 1)
    col_width = content_width / num_cols

    pages: list[bytes] = []

    # Paginate rows (approx 28 rows per page)
    rows_per_page = 26
    row_chunks = [rows[i : i + rows_per_page] for i in range(0, max(len(rows), 1), rows_per_page)]
    total_pages = len(row_chunks)

    for page_idx, chunk in enumerate(row_chunks, start=1):
        stream_lines: list[str] = []

        # Header Bar
        stream_lines.append("0.1 0.2 0.4 rg")  # Dark Slate Blue
        stream_lines.append(f"{margin_x} {page_height - 65} {content_width} 35 re f")

        # Header Title
        stream_lines.append("1.0 1.0 1.0 rg")  # White
        stream_lines.append("BT")
        stream_lines.append("/F1 14 Tf")
        stream_lines.append(f"{margin_x + 10} {page_height - 52} Td")
        stream_lines.append(f"({_escape_pdf_text(f'E-WITNESS: {title}')}) Tj")
        stream_lines.append("ET")

        # Metadata Subheader
        stream_lines.append("0.2 0.2 0.2 rg")  # Dark gray
        stream_lines.append("BT")
        stream_lines.append("/F2 8 Tf")
        stream_lines.append(f"{margin_x} {page_height - 80} Td")
        meta_line = f"Generated: {generated_at} | Scope: {department} | Records: {record_count} | Page {page_idx} of {total_pages}"
        stream_lines.append(f"({_escape_pdf_text(meta_line)}) Tj")
        stream_lines.append("ET")

        # Table Header Row
        table_top = page_height - 105
        stream_lines.append("0.88 0.92 0.96 rg")  # Light blue header fill
        stream_lines.append(f"{margin_x} {table_top} {content_width} 18 re f")

        stream_lines.append("0.1 0.1 0.1 rg")
        stream_lines.append("BT")
        stream_lines.append("/F1 8 Tf")
        for col_idx, header in enumerate(headers):
            x = margin_x + (col_idx * col_width) + 4
            stream_lines.append(f"{x} {table_top + 5} Td")
            # Truncate header if too long
            clean_hdr = header[:18]
            stream_lines.append(f"({_escape_pdf_text(clean_hdr)}) Tj")
            stream_lines.append(f"{-x} {-table_top - 5} Td")
        stream_lines.append("ET")

        # Table Rows
        row_y = table_top - 18
        for r_idx, row in enumerate(chunk):
            # Alternating row background
            if r_idx % 2 == 1:
                stream_lines.append("0.96 0.97 0.98 rg")
                stream_lines.append(f"{margin_x} {row_y} {content_width} 16 re f")

            # Border line under row
            stream_lines.append("0.85 0.85 0.85 RG")
            stream_lines.append(f"{margin_x} {row_y} m {margin_x + content_width} {row_y} l S")

            stream_lines.append("0.1 0.1 0.1 rg")
            stream_lines.append("BT")
            stream_lines.append("/F2 7 Tf")
            for col_idx, cell in enumerate(row):
                if col_idx >= num_cols:
                    break
                x = margin_x + (col_idx * col_width) + 4
                stream_lines.append(f"{x} {row_y + 4} Td")
                cell_str = sanitize_csv_cell(cell)
                # Truncate cell text to fit column
                max_chars = max(int(col_width / 5.5), 8)
                clean_cell = cell_str[:max_chars]
                stream_lines.append(f"({_escape_pdf_text(clean_cell)}) Tj")
                stream_lines.append(f"{-x} {-row_y - 4} Td")
            stream_lines.append("ET")
            row_y -= 16

        # Footer Statutory Disclaimer (on all pages)
        stream_lines.append("0.8 0.2 0.2 RG")  # Red border
        stream_lines.append(f"{margin_x} 42 {content_width} 22 re S")

        stream_lines.append("0.4 0.1 0.1 rg")
        stream_lines.append("BT")
        stream_lines.append("/F2 6 Tf")
        stream_lines.append(f"{margin_x + 4} 54 Td")
        stream_lines.append(f"({_escape_pdf_text(STATUTORY_AI_ADVISORY_DISCLAIMER[:130])}) Tj")
        stream_lines.append("ET")
        stream_lines.append("BT")
        stream_lines.append("/F2 6 Tf")
        stream_lines.append(f"{margin_x + 4} 46 Td")
        stream_lines.append(f"({_escape_pdf_text(STATUTORY_AI_ADVISORY_DISCLAIMER[130:])}) Tj")
        stream_lines.append("ET")

        page_content = "\n".join(stream_lines).encode("latin-1")
        pages.append(page_content)

    # Build PDF Object Cross-Reference Structure
    # Obj 1: Catalog
    # Obj 2: Pages
    # Obj 3: Font Helvetica-Bold
    # Obj 4: Font Helvetica
    # Obj 5..: Page and Content streams
    objects: list[bytes] = []

    def add_object(body: bytes) -> int:
        objects.append(body)
        return len(objects)

    catalog_id = 1
    pages_id = 2
    font_bold_id = 3
    font_reg_id = 4

    page_obj_ids: list[int] = []
    content_obj_ids: list[int] = []

    # Pre-allocate IDs for page objects and their content streams
    next_id = 5
    for _ in pages:
        page_obj_ids.append(next_id)
        content_obj_ids.append(next_id + 1)
        next_id += 2

    # Obj 1: Catalog
    add_object(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode())

    # Obj 2: Pages root
    kids_str = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
    add_object(f"<< /Type /Pages /Kids [{kids_str}] /Count {len(pages)} >>".encode())

    # Obj 3 & 4: Standard Fonts
    add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
    add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    # Add Page and Content stream objects
    for i, content_bytes in enumerate(pages):
        # Page object
        page_body = (
            f"<< /Type /Page /Parent {pages_id} 0 R "
            f"/MediaBox [0 0 {page_width} {page_height}] "
            f"/Contents {content_obj_ids[i]} 0 R "
            f"/Resources << /Font << /F1 {font_bold_id} 0 R /F2 {font_reg_id} 0 R >> >> >>"
        ).encode()
        add_object(page_body)

        # Content stream object
        stream_header = f"<< /Length {len(content_bytes)} >>\nstream\n".encode()
        stream_footer = b"\nendstream"
        add_object(stream_header + content_bytes + stream_footer)

    # Assemble complete PDF buffer with xref table
    buf = io.BytesIO()
    buf.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

    xref_offsets = [0]
    for obj_idx, obj_bytes in enumerate(objects, start=1):
        xref_offsets.append(buf.tell())
        buf.write(f"{obj_idx} 0 obj\n".encode())
        buf.write(obj_bytes)
        buf.write(b"\nendobj\n")

    xref_pos = buf.tell()
    buf.write(f"xref\n0 {len(objects) + 1}\n".encode())
    buf.write(b"0000000000 65535 f \n")
    for offset in xref_offsets[1:]:
        buf.write(f"{offset:010d} 00000 n \n".encode())

    buf.write(
        f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode()
    )

    return buf.getvalue()
