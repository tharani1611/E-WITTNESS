"""Unit tests for Phase 96-98 analytics, report primitives, CSV formula sanitization, and PDF generation."""

from datetime import UTC, datetime, timedelta

import pytest

from backend.app.core.analytics import (
    MAX_EXPORT_ROWS,
    ReportFormat,
    ReportType,
    TimeBucket,
    generate_pdf_report,
    sanitize_csv_cell,
)
from backend.app.core.exceptions import BusinessRuleError
from backend.app.schemas.analytics import AnalyticsFilter, TimeSeriesBucket
from backend.app.schemas.report import ReportExportRequest


def test_sanitize_csv_cell_formula_injection() -> None:
    """Verify formula injection characters (=, +, -, @, \t, \r) are prefixed with a single quote."""
    assert sanitize_csv_cell("=1+1") == "'=1+1"
    assert sanitize_csv_cell("+cmd|'/c calc'!A0") == "'+cmd|'/c calc'!A0"
    assert sanitize_csv_cell("-2+3") == "'-2+3"
    assert sanitize_csv_cell("@SUM(A1:A10)") == "'@SUM(A1:A10)"
    assert sanitize_csv_cell("\tTAB_INJECTION") == "'\tTAB_INJECTION"
    assert sanitize_csv_cell("\rRETURN_INJECTION") == "'\rRETURN_INJECTION"
    # Leading whitespace before formula character
    assert sanitize_csv_cell("   =DDE(...)") == "'   =DDE(...)"
    assert sanitize_csv_cell("  +10") == "'  +10"


def test_sanitize_csv_cell_safe_values() -> None:
    """Verify normal text and numbers remain intact."""
    assert sanitize_csv_cell("Normal Incident Title") == "Normal Incident Title"
    assert sanitize_csv_cell(12345) == "12345"
    assert sanitize_csv_cell(None) == ""
    assert sanitize_csv_cell("") == ""


def test_generate_pdf_report_structure() -> None:
    """Verify pure-Python PDF generation creates valid PDF syntax with statutory disclaimers."""
    headers = ["Ref Number", "Category", "Status"]
    rows = [
        ["INC-001", "Security Breach", "Open"],
        ["INC-002", "Unsafe Behavior", "Resolved"],
    ]
    metadata = {
        "generated_at": "2026-10-21 12:00:00 UTC",
        "department": "Campus Security",
        "author": "Chief Inspector",
    }

    pdf_bytes = generate_pdf_report(
        title="Incident Test Report",
        headers=headers,
        rows=rows,
        metadata=metadata,
    )

    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-1.4\n")
    assert b"%%EOF\n" in pdf_bytes
    assert b"/Type /Catalog" in pdf_bytes
    assert b"/Type /Pages" in pdf_bytes
    assert b"/Type /Page " in pdf_bytes
    assert b"/Type /Font" in pdf_bytes

    # Verify Statutory AI Advisory Disclaimer is embedded in the PDF byte stream
    assert b"STATUTORY ADVISORY: Candidate video segments" in pdf_bytes
    assert b"advisory only. They do not establish proof of identity, wrongdoing" in pdf_bytes
    assert b"authorized human review and corroborating evidence" in pdf_bytes

    # Verify table content and metadata
    assert b"Incident Test Report" in pdf_bytes
    assert b"Campus Security" in pdf_bytes
    assert b"INC-001" in pdf_bytes
    assert b"INC-002" in pdf_bytes


def test_generate_pdf_report_multi_page_pagination() -> None:
    """Verify pagination when rows exceed the single-page limit (26 rows/page)."""
    headers = ["Item Index", "Description", "Value"]
    rows = [[f"ROW-{i:03d}", f"Synthetic Test Row {i}", str(i * 10)] for i in range(70)]

    pdf_bytes = generate_pdf_report(
        title="Multi-page Audit Report",
        headers=headers,
        rows=rows,
    )

    # 70 rows with 26 rows per page should generate 3 pages
    assert pdf_bytes.count(b"/Type /Page ") == 3
    assert b"Page 1 of 3" in pdf_bytes
    assert b"Page 2 of 3" in pdf_bytes
    assert b"Page 3 of 3" in pdf_bytes


def test_generate_pdf_report_empty_dataset() -> None:
    """Verify PDF generator handles empty table cleanly."""
    pdf_bytes = generate_pdf_report(
        title="Empty Dataset Report",
        headers=["Col A", "Col B"],
        rows=[],
    )
    assert b"Page 1 of 1" in pdf_bytes
    assert b"Empty Dataset Report" in pdf_bytes


def test_analytics_filter_schema_defaults_and_validation() -> None:
    """Verify AnalyticsFilter normalizes UTC and calculates 30-day default window."""
    f = AnalyticsFilter()
    assert f.start_date is not None
    assert f.end_date is not None
    assert f.bucket == TimeBucket.DAY
    assert (f.end_date - f.start_date).days in (29, 30, 31)

    # Inverted date range should raise BusinessRuleError
    now = datetime.now(UTC)
    with pytest.raises(BusinessRuleError, match="start_date must not be after end_date"):
        AnalyticsFilter(start_date=now, end_date=now - timedelta(days=5))

    # Range exceeding max days (365) should raise BusinessRuleError
    with pytest.raises(BusinessRuleError, match="exceeds maximum allowed limit"):
        AnalyticsFilter(start_date=now - timedelta(days=366), end_date=now)


def test_report_export_request_validation() -> None:
    """Verify ReportExportRequest date normalization and format defaults."""
    req = ReportExportRequest(
        report_type=ReportType.INCIDENTS,
        export_format=ReportFormat.CSV,
    )
    assert req.export_format == ReportFormat.CSV
    assert req.start_date is not None
    assert req.end_date is not None
    assert req.limit == MAX_EXPORT_ROWS

    # Explicit limit clamped to MAX_EXPORT_ROWS
    req2 = ReportExportRequest(
        report_type=ReportType.CASES,
        export_format=ReportFormat.PDF,
        limit=10000,
    )
    assert req2.limit == MAX_EXPORT_ROWS


def test_time_series_bucket_schema() -> None:
    """Verify TimeSeriesBucket schema creation and serialization."""
    now = datetime.now(UTC)
    b = TimeSeriesBucket(bucket_start=now, bucket_end=now + timedelta(days=1), count=42)
    assert b.count == 42
    assert b.bucket_start == now
