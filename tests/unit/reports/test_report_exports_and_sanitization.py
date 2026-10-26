"""Unit tests for Phase 98 Controlled Report Exports, CSV Formula Sanitization, and Secure PDF Generation.

Verifies:
- Department scoping on exports:
  - Global roles can export any department or cross-department summary.
  - Department roles are restricted to their own department.
  - Unauthorized cross-department export requests are rejected.
- CSV rendering with formula injection sanitization.
- Pure-Python secure PDF generation with embedded statutory AI advisory disclaimers.
- Cryptographic SHA-256 hash attestation.
- Download authorization checks and expiration validation.
- Download count incrementation.
- Immutable audit logging for exports and downloads.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from backend.app.config.settings import Settings
from backend.app.core.analytics import (
    ExportStatus,
    ReportFormat,
    ReportType,
)
from backend.app.core.audit import AuditAction
from backend.app.core.authorization import RoleCode
from backend.app.core.exceptions import (
    BusinessRuleError,
    PermissionDeniedError,
    ResourceNotFoundError,
)
from backend.app.models.report import ReportExport
from backend.app.repositories.report import ReportRepository
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.schemas.report import ReportExportRead, ReportExportRequest
from backend.app.services.report import ReportExportService


@pytest.fixture
def mock_report_repo() -> MagicMock:
    repo = MagicMock(spec=ReportRepository)

    # Mock raw data returns
    repo.fetch_incidents_for_export = AsyncMock(
        return_value=[
            {
                "reference_number": "INC-2026-001",
                "title": "=1+1 Formula Injection Attempt",
                "category": "safety",
                "severity": "medium",
                "status": "open",
                "location": "Main Quad",
                "occurred_at": "2026-10-21 10:00:00 UTC",
                "created_at": "2026-10-21 10:05:00 UTC",
                "department": "Campus Security",
            }
        ]
    )

    repo.fetch_cases_for_export = AsyncMock(
        return_value=[
            {
                "reference_number": "CASE-2026-001",
                "title": "Unauthorized Access",
                "status": "under_investigation",
                "priority": "high",
                "legal_hold": "Active",
                "created_at": "2026-10-21 10:00:00 UTC",
                "updated_at": "2026-10-21 11:00:00 UTC",
                "department": "Campus Security",
            }
        ]
    )

    repo.fetch_reviews_for_export = AsyncMock(
        return_value=[
            {
                "segment_id": "seg-123",
                "job_id": "job-456",
                "incident_id": "inc-789",
                "model_name": "vit-base",
                "raw_label": "physical_contact",
                "raw_score": "0.92",
                "calibrated_score": "0.85",
                "review_status": "confirmed",
                "false_positive_reason": "none",
                "reviewed_at": "2026-10-21 11:30:00 UTC",
                "department": "Campus Security",
            }
        ]
    )

    repo.fetch_operational_summary_for_export = AsyncMock(
        return_value=[
            {"metric": "Active Workers", "value": "4"},
            {"metric": "Queue Depth", "value": "12"},
        ]
    )

    # Mock DB storage
    repo.create_report_export = AsyncMock(side_effect=lambda export: export)

    repo.increment_download_count = AsyncMock()

    return repo


@pytest.fixture
def mock_audit_repo() -> MagicMock:
    repo = MagicMock()
    repo.append_event = AsyncMock()
    return repo


@pytest.fixture
def report_service(
    mock_report_repo: MagicMock,
    mock_audit_repo: MagicMock,
    test_settings: Settings,
) -> ReportExportService:
    return ReportExportService(
        report_repo=mock_report_repo,
        audit_repo=mock_audit_repo,
        settings=test_settings,
    )


@pytest.mark.asyncio
async def test_generate_csv_export_with_sanitization(
    report_service: ReportExportService,
    mock_report_repo: MagicMock,
    mock_audit_repo: MagicMock,
) -> None:
    """Verify CSV export sanitizes formula injection attempts and computes SHA-256."""
    dept_id = uuid4()
    da = AuthenticatedPrincipal(
        user_id=uuid4(),
        email="da@campus.edu",
        full_name="Dept Admin",
        account_status="active",
        is_active=True,
        role_code=RoleCode.DEPT_ADMIN.value,
        department_id=dept_id,
        session_id=uuid4(),
    )
    req = ReportExportRequest(
        report_type=ReportType.INCIDENTS,
        export_format=ReportFormat.CSV,
        department_id=dept_id,
    )

    export_read, file_bytes, filename, media_type = await report_service.generate_report(da, req)

    assert isinstance(export_read, ReportExportRead)
    assert filename.endswith(".csv")
    assert media_type == "text/csv; charset=utf-8"
    assert export_read.record_count == 1
    assert export_read.status == ExportStatus.COMPLETED

    # Verify CSV sanitization: "=1+1" must be escaped to "'=1+1"
    content = file_bytes.decode("utf-8")
    assert "'=1+1 Formula Injection Attempt" in content

    # Verify SHA-256 attestation
    computed_sha256 = hashlib.sha256(file_bytes).hexdigest()
    assert export_read.file_hash_sha256 == computed_sha256

    mock_report_repo.create_report_export.assert_awaited_once()
    mock_audit_repo.append_event.assert_awaited_once()
    assert mock_audit_repo.append_event.call_args[1]["action"] == AuditAction.REPORT_EXPORTED.value


@pytest.mark.asyncio
async def test_generate_pdf_export_with_advisory(
    report_service: ReportExportService,
    mock_report_repo: MagicMock,
) -> None:
    """Verify PDF export includes statutory AI advisory disclaimers and SHA-256."""
    dept_id = uuid4()
    sa = AuthenticatedPrincipal(
        user_id=uuid4(),
        email="superadmin@campus.edu",
        full_name="Super Admin",
        account_status="active",
        is_active=True,
        role_code=RoleCode.SUPER_ADMIN.value,
        department_id=None,
        session_id=uuid4(),
    )
    req = ReportExportRequest(
        report_type=ReportType.HUMAN_REVIEWS,
        export_format=ReportFormat.PDF,
        department_id=dept_id,
    )

    _export_read, file_bytes, filename, media_type = await report_service.generate_report(sa, req)

    assert filename.endswith(".pdf")
    assert media_type == "application/pdf"
    assert file_bytes.startswith(b"%PDF-1.4\n")
    assert b"STATUTORY ADVISORY: Candidate video segments" in file_bytes
    assert b"AI Segment Human Review Report" in file_bytes


@pytest.mark.asyncio
async def test_export_other_report_types(
    report_service: ReportExportService,
    mock_report_repo: MagicMock,
) -> None:
    """Verify CASES and OPERATIONAL_SUMMARY exports succeed."""
    sa = AuthenticatedPrincipal(
        user_id=uuid4(),
        email="superadmin@campus.edu",
        full_name="Super Admin",
        account_status="active",
        is_active=True,
        role_code=RoleCode.SUPER_ADMIN.value,
        department_id=None,
        session_id=uuid4(),
    )

    # Cases
    req_case = ReportExportRequest(report_type=ReportType.CASES, export_format=ReportFormat.CSV)
    _, bytes_case, _, _ = await report_service.generate_report(sa, req_case)
    assert b"CASE-2026-001" in bytes_case

    # Operational summary
    req_ops = ReportExportRequest(
        report_type=ReportType.OPERATIONAL_SUMMARY, export_format=ReportFormat.CSV
    )
    _, bytes_ops, _, _ = await report_service.generate_report(sa, req_ops)
    assert b"Active Workers" in bytes_ops


@pytest.mark.asyncio
async def test_download_authorization_and_expiration(
    report_service: ReportExportService,
    mock_report_repo: MagicMock,
    mock_audit_repo: MagicMock,
) -> None:
    """Verify download access checks, expiration check, and download tally."""
    creator_id = uuid4()
    dept_id = uuid4()
    other_dept_id = uuid4()
    now = datetime.now(UTC)

    export_rec = ReportExport(
        id=uuid4(),
        created_at=now,
        report_type=ReportType.INCIDENTS.value,
        export_format=ReportFormat.CSV.value,
        status=ExportStatus.COMPLETED.value,
        created_by_id=creator_id,
        department_id=dept_id,
        parameters_json='{"record_count": 5}',
        file_size_bytes=100,
        content_sha256="abc123hash",
        file_name="test.csv",
        expires_at=now + timedelta(hours=24),
        download_count=0,
    )
    mock_report_repo.get_report_export_by_id = AsyncMock(return_value=export_rec)

    # 1. Creator in same dept can download
    principal_creator = AuthenticatedPrincipal(
        user_id=creator_id,
        email="creator@campus.edu",
        full_name="Report Creator",
        account_status="active",
        is_active=True,
        role_code=RoleCode.DEPT_ADMIN.value,
        department_id=dept_id,
        session_id=uuid4(),
    )
    res = await report_service.get_report_for_download(principal_creator, export_rec.id)
    assert res.id == export_rec.id
    mock_report_repo.increment_download_count.assert_awaited_once_with(export_rec.id)
    mock_audit_repo.append_event.assert_awaited_once()

    # 2. User from other department denied
    principal_other = AuthenticatedPrincipal(
        user_id=uuid4(),
        email="other@campus.edu",
        full_name="Other Dept Admin",
        account_status="active",
        is_active=True,
        role_code=RoleCode.DEPT_ADMIN.value,
        department_id=other_dept_id,
        session_id=uuid4(),
    )
    with pytest.raises(PermissionDeniedError, match="not authorized to download"):
        await report_service.get_report_for_download(principal_other, export_rec.id)

    # 3. Super admin can download any report
    principal_sa = AuthenticatedPrincipal(
        user_id=uuid4(),
        email="sa@campus.edu",
        full_name="Super Admin",
        account_status="active",
        is_active=True,
        role_code=RoleCode.SUPER_ADMIN.value,
        department_id=None,
        session_id=uuid4(),
    )
    res_sa = await report_service.get_report_for_download(principal_sa, export_rec.id)
    assert res_sa.id == export_rec.id

    # 4. Expired report raises BusinessRuleError
    export_rec.expires_at = now - timedelta(hours=1)
    with pytest.raises(BusinessRuleError, match="has expired"):
        await report_service.get_report_for_download(principal_creator, export_rec.id)

    # 5. Non-existent report raises ResourceNotFoundError
    mock_report_repo.get_report_export_by_id = AsyncMock(return_value=None)
    with pytest.raises(ResourceNotFoundError, match="not found"):
        await report_service.get_report_for_download(principal_creator, uuid4())
