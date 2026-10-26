"""Unit tests for Phase 58 & 59: Security audit ledger, chain verification, search, and export."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from backend.app.config.settings import Settings
from backend.app.core.audit import (
    AUDIT_DISCLAIMER,
    AuditAction,
    AuditOutcome,
    AuditTargetType,
    compute_security_audit_event_hash,
)
from backend.app.core.exceptions import (
    PermissionDeniedError,
    ResourceNotFoundError,
    SecurityError,
)
from backend.app.core.identity import RoleCode
from backend.app.models.audit import EvidenceExport
from backend.app.models.evidence import EvidenceAttachment
from backend.app.models.incident import Incident
from backend.app.schemas.audit import (
    AuditSearchFilterParams,
    AuditVerificationReport,
    EvidenceExportRequest,
)
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.services.audit import AuditService


class TestSecurityAuditHashChaining:
    """Phase 58: Unit tests for deterministic SHA-256 hash chaining and canonical JSON formatting."""

    def test_canonical_json_key_order_invariance(self) -> None:
        now = datetime.now(UTC)
        actor_id = uuid4()
        dept_id = uuid4()

        details_a = {"beta": 2, "alpha": 1, "gamma": [3, 4]}
        details_b = {"alpha": 1, "gamma": [3, 4], "beta": 2}

        hash_a = compute_security_audit_event_hash(
            sequence_number=1,
            action=AuditAction.AUTH_LOGIN_SUCCESS.value,
            actor_id=actor_id,
            department_id=dept_id,
            target_type=AuditTargetType.USER.value,
            target_id=str(actor_id),
            outcome=AuditOutcome.SUCCESS.value,
            created_at=now,
            previous_event_hash=None,
            details=details_a,
        )

        hash_b = compute_security_audit_event_hash(
            sequence_number=1,
            action=AuditAction.AUTH_LOGIN_SUCCESS.value,
            actor_id=actor_id,
            department_id=dept_id,
            target_type=AuditTargetType.USER.value,
            target_id=str(actor_id),
            outcome=AuditOutcome.SUCCESS.value,
            created_at=now,
            previous_event_hash=None,
            details=details_b,
        )

        assert hash_a == hash_b
        assert len(hash_a) == 64

    def test_digest_changes_on_any_field_modification(self) -> None:
        now = datetime.now(UTC)
        actor_id = uuid4()
        dept_id = uuid4()

        base_hash = compute_security_audit_event_hash(
            sequence_number=10,
            action=AuditAction.INCIDENT_ASSIGNED.value,
            actor_id=actor_id,
            department_id=dept_id,
            target_type=AuditTargetType.INCIDENT.value,
            target_id="INC-001",
            outcome=AuditOutcome.SUCCESS.value,
            created_at=now,
            previous_event_hash="a" * 64,
            details={"case": "important"},
        )

        altered_seq = compute_security_audit_event_hash(
            sequence_number=11,
            action=AuditAction.INCIDENT_ASSIGNED.value,
            actor_id=actor_id,
            department_id=dept_id,
            target_type=AuditTargetType.INCIDENT.value,
            target_id="INC-001",
            outcome=AuditOutcome.SUCCESS.value,
            created_at=now,
            previous_event_hash="a" * 64,
            details={"case": "important"},
        )
        assert base_hash != altered_seq

        altered_outcome = compute_security_audit_event_hash(
            sequence_number=10,
            action=AuditAction.INCIDENT_ASSIGNED.value,
            actor_id=actor_id,
            department_id=dept_id,
            target_type=AuditTargetType.INCIDENT.value,
            target_id="INC-001",
            outcome=AuditOutcome.FAILURE.value,
            created_at=now,
            previous_event_hash="a" * 64,
            details={"case": "important"},
        )
        assert base_hash != altered_outcome


class TestAuditSchemasAndReport:
    """Phase 58 & 59: Unit tests for audit schemas and verification report structures."""

    def test_audit_verification_report_disclaimer(self) -> None:
        now = datetime.now(UTC)
        report = AuditVerificationReport(
            status="verified",
            chain_valid=True,
            total_events_verified=42,
            first_sequence_number=1,
            last_sequence_number=42,
            verified_at=now,
        )
        assert report.status == "verified"
        assert report.chain_valid is True
        assert report.disclaimer == AUDIT_DISCLAIMER
        assert "Cryptographic hash chaining detects" in report.disclaimer

    def test_search_filter_pagination_bounds(self) -> None:
        params = AuditSearchFilterParams(page=1, page_size=100)
        assert params.page_size == 100

        with pytest.raises(ValidationError):
            AuditSearchFilterParams(page=1, page_size=101)

        with pytest.raises(ValidationError):
            AuditSearchFilterParams(page=0, page_size=50)

    def test_evidence_export_request_validation(self) -> None:
        req = EvidenceExportRequest(export_scope="incident_package", export_format="zip")
        assert req.export_scope == "incident_package"
        assert req.export_format == "zip"

        with pytest.raises(ValidationError):
            EvidenceExportRequest(export_scope="invalid_scope")

        with pytest.raises(ValidationError):
            EvidenceExportRequest(export_format="invalid_format")


def _make_principal(
    *,
    user_id: UUID | None = None,
    role_code: str = RoleCode.INVESTIGATOR.value,
    department_id: UUID | None = None,
    email: str = "user@test.edu",
    full_name: str = "Test User",
) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        user_id=user_id or uuid4(),
        role_code=role_code,
        department_id=department_id,
        email=email,
        full_name=full_name,
        account_status="active",
        is_active=True,
        session_id=uuid4(),
    )


class TestAuditServiceOrchestration:
    """Phase 58 & 59: Unit tests for AuditService operations, security boundaries, and exports."""

    @pytest.fixture
    def mock_audit_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_incident_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def mock_evidence_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def audit_service(
        self,
        mock_audit_repo: AsyncMock,
        mock_incident_repo: AsyncMock,
        mock_evidence_repo: AsyncMock,
        test_settings: Settings,
    ) -> AuditService:
        return AuditService(
            audit_repo=mock_audit_repo,
            incident_repo=mock_incident_repo,
            evidence_repo=mock_evidence_repo,
            settings=test_settings,
        )

    @pytest.mark.asyncio
    async def test_record_security_event_fail_closed(
        self,
        audit_service: AuditService,
        mock_audit_repo: AsyncMock,
    ) -> None:
        mock_audit_repo.append_event.side_effect = RuntimeError("DB write error")

        with pytest.raises(SecurityError) as exc_info:
            await audit_service.record_security_event(
                action=AuditAction.AUTH_LOGIN_FAILED.value,
                actor_id=uuid4(),
                actor_role=RoleCode.STUDENT.value,
                target_type=AuditTargetType.USER.value,
                target_id="USER-123",
                outcome=AuditOutcome.FAILURE.value,
                fail_closed=True,
            )
        assert exc_info.value.code == "AUDIT_PERSISTENCE_FAILED"

    @pytest.mark.asyncio
    async def test_search_audit_events_investigator_scoped(
        self,
        audit_service: AuditService,
        mock_audit_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        principal = _make_principal(
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=dept_id,
            email="inv@test.edu",
        )
        mock_audit_repo.list_events_paginated.return_value = ([], 0)

        params = AuditSearchFilterParams(page=1, page_size=50)
        res = await audit_service.search_audit_events(params, principal)

        assert res.items == []
        mock_audit_repo.list_events_paginated.assert_awaited_once()
        _, kwargs = mock_audit_repo.list_events_paginated.call_args
        assert kwargs["department_id"] == dept_id

    @pytest.mark.asyncio
    async def test_search_audit_events_student_denied(
        self,
        audit_service: AuditService,
    ) -> None:
        principal = _make_principal(
            role_code=RoleCode.STUDENT.value,
            department_id=uuid4(),
            email="student@test.edu",
        )
        params = AuditSearchFilterParams(page=1, page_size=50)
        with pytest.raises(PermissionDeniedError):
            await audit_service.search_audit_events(params, principal)

    @pytest.mark.asyncio
    async def test_verify_audit_chain_orchestration(
        self,
        audit_service: AuditService,
        mock_audit_repo: AsyncMock,
    ) -> None:
        principal = _make_principal(
            role_code=RoleCode.DEPT_ADMIN.value,
            department_id=uuid4(),
            email="admin@test.edu",
        )
        now = datetime.now(UTC)
        mock_audit_repo.verify_chain.return_value = {
            "status": "verified",
            "chain_valid": True,
            "total_events_verified": 15,
            "first_sequence_number": 1,
            "last_sequence_number": 15,
            "tampered_event_ids": [],
            "tampered_sequence_numbers": [],
            "errors": [],
            "disclaimer": AUDIT_DISCLAIMER,
            "verified_at": now,
        }

        report = await audit_service.verify_audit_chain(principal, start_sequence=1, limit=500)
        assert report.status == "verified"
        assert report.chain_valid is True
        assert report.total_events_verified == 15

    @pytest.mark.asyncio
    async def test_export_incident_evidence_success(
        self,
        audit_service: AuditService,
        mock_incident_repo: AsyncMock,
        mock_evidence_repo: AsyncMock,
        mock_audit_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        inc_id = uuid4()
        user_id = uuid4()

        incident = Incident(
            id=inc_id,
            reference_number="INC-2026-EXP",
            title="Export Evidence Incident",
            description="Testing evidence packaging and manifest generation.",
            category="property_damage_theft",
            severity="medium",
            status="triaged",
            location="Warehouse B",
            occurred_at=datetime.now(UTC),
            reporter_id=uuid4(),
            department_id=dept_id,
        )
        mock_incident_repo.get_by_id.return_value = incident

        att = EvidenceAttachment(
            id=uuid4(),
            incident_id=inc_id,
            storage_key=f"evidence/{inc_id}/doc.pdf",
            original_filename="doc.pdf",
            file_size_bytes=1024,
            declared_mime_type="application/pdf",
            detected_mime_type="application/pdf",
            sha256_hash="e" * 64,
            evidence_status="verified",
            scan_status="clean",
        )
        mock_evidence_repo.list_attachments_by_incident.return_value = [att]

        mock_audit_repo.create_evidence_export.side_effect = lambda exp: exp

        principal = _make_principal(
            user_id=user_id,
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=dept_id,
            email="inv@test.edu",
        )

        res = await audit_service.export_incident_evidence(
            incident_id=inc_id,
            payload=EvidenceExportRequest(
                export_scope="incident_package", export_format="zip", reason="Court subpoena"
            ),
            principal=principal,
        )

        assert res.incident_id == inc_id
        assert res.evidence_count == 1
        assert len(res.manifest_sha256) == 64
        mock_audit_repo.create_evidence_export.assert_awaited_once()
        mock_audit_repo.append_event.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_list_evidence_exports_orchestration(
        self,
        audit_service: AuditService,
        mock_audit_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        principal_inv = _make_principal(
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=dept_id,
        )
        mock_export = EvidenceExport(
            id=uuid4(),
            incident_id=uuid4(),
            department_id=dept_id,
            exported_by_id=principal_inv.user_id,
            export_scope="incident_package",
            export_format="zip",
            manifest_sha256="m" * 64,
            evidence_count=1,
            reason="Hearing",
            status="completed",
            created_at=datetime.now(UTC),
        )
        mock_audit_repo.list_evidence_exports_paginated.return_value = ([mock_export], 1)

        res = await audit_service.list_evidence_exports(principal_inv, page=1, page_size=20)
        assert len(res.items) == 1
        assert res.items[0].id == mock_export.id
        _, kwargs = mock_audit_repo.list_evidence_exports_paginated.call_args
        assert kwargs["department_id"] == dept_id

        # Student denied
        principal_stud = _make_principal(role_code=RoleCode.STUDENT.value)
        with pytest.raises(PermissionDeniedError):
            await audit_service.list_evidence_exports(principal_stud)

    @pytest.mark.asyncio
    async def test_export_incident_evidence_denied_and_not_found(
        self,
        audit_service: AuditService,
        mock_incident_repo: AsyncMock,
    ) -> None:
        dept_id = uuid4()
        inc_id = uuid4()
        principal_inv = _make_principal(
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=dept_id,
        )

        # 1. Incident not found
        mock_incident_repo.get_by_id.return_value = None
        req = EvidenceExportRequest(export_scope="incident_package", export_format="zip")
        with pytest.raises(ResourceNotFoundError):
            await audit_service.export_incident_evidence(
                incident_id=inc_id, payload=req, principal=principal_inv
            )

        # 2. Incident in different department
        other_dept_inc = Incident(
            id=inc_id,
            reference_number="INC-DIFF-DEPT",
            title="Other Dept Inc",
            description="Different department incident report.",
            category="safety_hazard",
            severity="medium",
            status="submitted",
            location="Building C",
            occurred_at=datetime.now(UTC),
            reporter_id=uuid4(),
            department_id=uuid4(),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_incident_repo.get_by_id.return_value = other_dept_inc
        with pytest.raises(ResourceNotFoundError):
            await audit_service.export_incident_evidence(
                incident_id=inc_id, payload=req, principal=principal_inv
            )

        # 3. Student permission denied
        principal_stud = _make_principal(role_code=RoleCode.STUDENT.value)
        with pytest.raises(PermissionDeniedError):
            await audit_service.export_incident_evidence(
                incident_id=inc_id, payload=req, principal=principal_stud
            )

    @pytest.mark.asyncio
    async def test_verify_audit_chain_permission_denied(
        self,
        audit_service: AuditService,
    ) -> None:
        principal_stud = _make_principal(role_code=RoleCode.STUDENT.value)
        with pytest.raises(PermissionDeniedError):
            await audit_service.verify_audit_chain(principal_stud)

    @pytest.mark.asyncio
    async def test_search_audit_events_with_filter_enums(
        self,
        audit_service: AuditService,
        mock_audit_repo: AsyncMock,
    ) -> None:
        principal_admin = _make_principal(role_code=RoleCode.SUPER_ADMIN.value)
        mock_audit_repo.list_events_paginated.return_value = ([], 0)

        params = AuditSearchFilterParams(
            action=AuditAction.INCIDENT_ASSIGNED,
            target_type=AuditTargetType.INCIDENT,
            outcome=AuditOutcome.SUCCESS,
            page=2,
            page_size=25,
        )
        res = await audit_service.search_audit_events(params, principal_admin)
        assert res.items == []
        _, kwargs = mock_audit_repo.list_events_paginated.call_args
        assert kwargs["action"] == AuditAction.INCIDENT_ASSIGNED.value
        assert kwargs["target_type"] == AuditTargetType.INCIDENT.value
        assert kwargs["outcome"] == AuditOutcome.SUCCESS.value
        assert kwargs["offset"] == 25
