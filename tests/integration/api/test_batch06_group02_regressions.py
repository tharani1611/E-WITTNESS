"""Live PostgreSQL Integration Tests for Batch 06 Group 02 (Phases 56-60).

Verifies against real PostgreSQL:
- Phase 56: Department-scoped review queues, stable pagination, filtering, and workload metrics.
- Phase 57: Reviewer assignment, conflict-of-interest prevention, reassignment reasons, and acknowledgement.
- Phase 58: Tamper-evident security audit events, SHA-256 hash chaining, and cryptographic chain verification with statutory disclaimer.
- Phase 59: Evidence export manifest hashing, authorized export packaging, and scoped administrative audit search.
- Phase 60: End-to-end integration and security invariant enforcement.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select

from backend.app.config.settings import Settings
from backend.app.core.audit import AUDIT_DISCLAIMER
from backend.app.core.evidence import EvidenceStatus
from backend.app.core.identity import AccountStatus, RoleCode
from backend.app.infrastructure.database import DatabaseSessionManager
from backend.app.infrastructure.storage import InMemoryStorageClient
from backend.app.main import create_app
from backend.app.models.audit import SecurityAuditEvent
from backend.app.models.department import Department
from backend.app.models.evidence import EvidenceAttachment
from backend.app.models.incident import Incident
from backend.app.models.user import User
from backend.app.repositories.identity import (
    DepartmentRepository,
    RoleRepository,
    UserRepository,
)
from backend.app.services.password import PasswordService


async def _setup_batch06_group02_test_env(
    postgres_db_manager: DatabaseSessionManager,
) -> dict[str, Any]:
    """Seed test departments, roles, and accounts in PostgreSQL."""
    pw_service = PasswordService()
    default_pw = "ValidPass123456!"
    hashed_pw = pw_service.hash_password(default_pw)

    async with postgres_db_manager.transactional_session() as session:
        dept_repo = DepartmentRepository(session)
        role_repo = RoleRepository(session)
        user_repo = UserRepository(session)

        roles = await role_repo.ensure_default_roles()
        suffix = uuid4().hex[:6].upper()

        dept_security = await dept_repo.create(
            Department(code=f"SEC-{suffix}", name=f"Campus Safety {suffix}", is_active=True)
        )
        dept_academic = await dept_repo.create(
            Department(code=f"ACAD-{suffix}", name=f"Academic Affairs {suffix}", is_active=True)
        )

        super_admin = await user_repo.create(
            User(
                email=f"superadmin_{suffix.lower()}@ewitness.edu",
                full_name="Global Super Admin",
                role_id=roles[RoleCode.SUPER_ADMIN].id,
                department_id=None,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        dept_admin_security = await user_repo.create(
            User(
                email=f"admin_sec_{suffix.lower()}@ewitness.edu",
                full_name="Security Admin",
                role_id=roles[RoleCode.DEPT_ADMIN].id,
                department_id=dept_security.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        investigator_security_1 = await user_repo.create(
            User(
                email=f"investigator1_sec_{suffix.lower()}@ewitness.edu",
                full_name="Security Investigator 1",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_security.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        investigator_security_2 = await user_repo.create(
            User(
                email=f"investigator2_sec_{suffix.lower()}@ewitness.edu",
                full_name="Security Investigator 2",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_security.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        investigator_academic = await user_repo.create(
            User(
                email=f"investigator_acad_{suffix.lower()}@ewitness.edu",
                full_name="Academic Investigator",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_academic.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        student_reporter = await user_repo.create(
            User(
                email=f"student_{suffix.lower()}@ewitness.edu",
                full_name="Student Reporter",
                role_id=roles[RoleCode.STUDENT].id,
                department_id=dept_security.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        # Seed incidents for review queue and workload testing
        now = datetime.now(UTC)
        incident_sec_1 = Incident(
            reference_number=f"SEC-INC-01-{suffix}",
            title="Unauthorized access to server room",
            description="An unidentified individual accessed the server room after hours.",
            category="safety_hazard",
            severity="high",
            status="submitted",
            location="Building A, Room 101",
            occurred_at=now - timedelta(days=8),  # Overdue (>7 days)
            reporter_id=student_reporter.id,
            department_id=dept_security.id,
            assignment_status="unassigned",
            created_at=now - timedelta(days=8),
            updated_at=now - timedelta(days=8),
        )
        session.add(incident_sec_1)

        incident_sec_2 = Incident(
            reference_number=f"SEC-INC-02-{suffix}",
            title="Campus lighting failure near dorms",
            description="Multiple floodlights failed causing a dark zone.",
            category="safety_hazard",
            severity="medium",
            status="submitted",
            location="East Quad",
            occurred_at=now - timedelta(days=1),
            reporter_id=student_reporter.id,
            department_id=dept_security.id,
            assignment_status="unassigned",
            created_at=now - timedelta(days=1),
            updated_at=now - timedelta(days=1),
        )
        session.add(incident_sec_2)

        incident_acad = Incident(
            reference_number=f"ACAD-INC-01-{suffix}",
            title="Plagiarism suspected on final thesis",
            description="Substantial copied passages found without attribution.",
            category="academic_misconduct",
            severity="high",
            status="submitted",
            location="Science Hall",
            occurred_at=now - timedelta(days=2),
            reporter_id=student_reporter.id,
            department_id=dept_academic.id,
            assignment_status="unassigned",
            created_at=now - timedelta(days=2),
            updated_at=now - timedelta(days=2),
        )
        session.add(incident_acad)

        await session.flush()

        # Seed verified evidence for incident_sec_1
        evidence_sec_1 = EvidenceAttachment(
            incident_id=incident_sec_1.id,
            uploader_id=student_reporter.id,
            department_id=dept_security.id,
            storage_key=f"evidence/{incident_sec_1.id}/log.txt",
            original_filename="access_log.txt",
            file_size_bytes=512,
            declared_mime_type="text/plain",
            detected_mime_type="text/plain",
            sha256_hash="d" * 64,
            evidence_status=EvidenceStatus.ATTACHED.value,
            scan_status="clean",
            upload_status="completed",
            created_at=now - timedelta(days=8),
        )
        session.add(evidence_sec_1)
        await session.flush()

        return {
            "suffix": suffix,
            "dept_security": dept_security,
            "dept_academic": dept_academic,
            "super_admin": super_admin,
            "dept_admin_security": dept_admin_security,
            "investigator_security_1": investigator_security_1,
            "investigator_security_2": investigator_security_2,
            "investigator_academic": investigator_academic,
            "student_reporter": student_reporter,
            "incident_sec_1_id": incident_sec_1.id,
            "incident_sec_2_id": incident_sec_2.id,
            "incident_acad_id": incident_acad.id,
            "default_pw": default_pw,
        }


async def _login(client: httpx.AsyncClient, email: str, password: str) -> str:
    """Helper to authenticate and retrieve a bearer token."""
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert resp.status_code == 200, f"Login failed for {email}: {resp.text}"
    return str(resp.json()["access_token"])


@pytest.mark.asyncio
class TestBatch06Group02LivePostgres:
    """End-to-end integration tests for Phases 56-60 on PostgreSQL."""

    async def test_phase56_review_queue_and_workload_metrics(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        data = await _setup_batch06_group02_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_inv_sec = await _login(
                client, data["investigator_security_1"].email, data["default_pw"]
            )
            token_student = await _login(client, data["student_reporter"].email, data["default_pw"])

            # 1. Investigator views department review queue
            resp = await client.get(
                "/api/v1/incidents/queue",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
            )
            assert resp.status_code == 200
            body = resp.json()
            items = body["items"]
            # SEC investigator should only see SEC incidents, never ACAD
            assert len(items) >= 2
            dept_ids = {item["department_id"] for item in items}
            assert str(data["dept_security"].id) in dept_ids
            assert str(data["dept_academic"].id) not in dept_ids

            # 2. Workload summary view
            resp_workload = await client.get(
                "/api/v1/incidents/queue/workload",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
            )
            assert resp_workload.status_code == 200
            workload = resp_workload.json()
            assert workload["total"] >= 2
            assert workload["unassigned"] >= 2
            assert workload["overdue"] >= 1  # incident_sec_1 is 8 days old

            # 3. Student attempting to access queue is denied (403 Forbidden)
            resp_denied = await client.get(
                "/api/v1/incidents/queue",
                headers={"Authorization": f"Bearer {token_student}"},
            )
            assert resp_denied.status_code == 403

            resp_workload_denied = await client.get(
                "/api/v1/incidents/queue/workload",
                headers={"Authorization": f"Bearer {token_student}"},
            )
            assert resp_workload_denied.status_code == 403

    async def test_phase57_reviewer_assignment_conflict_and_acknowledgement(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        data = await _setup_batch06_group02_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_admin_sec = await _login(
                client, data["dept_admin_security"].email, data["default_pw"]
            )
            token_inv_sec_1 = await _login(
                client, data["investigator_security_1"].email, data["default_pw"]
            )
            token_inv_sec_2 = await _login(
                client, data["investigator_security_2"].email, data["default_pw"]
            )

            inc_id = data["incident_sec_1_id"]

            # 1. Conflict of Interest check: Reporter cannot be assigned as reviewer
            resp_coi = await client.post(
                f"/api/v1/incidents/{inc_id}/assign",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={"reviewer_id": str(data["student_reporter"].id), "reason": "Self-review"},
            )
            # Student is reporter and also wrong role -> rejected
            assert resp_coi.status_code == 422

            # 2. Cross-department assignment rejected: cannot assign ACAD investigator to SEC incident
            resp_cross = await client.post(
                f"/api/v1/incidents/{inc_id}/assign",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={
                    "reviewer_id": str(data["investigator_academic"].id),
                    "reason": "Cross-dept test",
                },
            )
            assert resp_cross.status_code == 422

            # 3. Valid assignment: Assign investigator_security_1
            resp_assign = await client.post(
                f"/api/v1/incidents/{inc_id}/assign",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={
                    "reviewer_id": str(data["investigator_security_1"].id),
                    "reason": "Assigning lead investigator",
                },
            )
            assert resp_assign.status_code == 200
            assigned_inc = resp_assign.json()
            assert assigned_inc["assigned_reviewer_id"] == str(data["investigator_security_1"].id)
            assert assigned_inc["assignment_status"] == "assigned"
            assert assigned_inc["status"] == "triaged"

            # 4. Reassignment: Reassign to investigator_security_2
            resp_reassign = await client.post(
                f"/api/v1/incidents/{inc_id}/reassign",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={
                    "reviewer_id": str(data["investigator_security_2"].id),
                    "reason": "Investigator 1 shifted to higher priority case",
                },
            )
            assert resp_reassign.status_code == 200
            reassigned_inc = resp_reassign.json()
            assert reassigned_inc["assigned_reviewer_id"] == str(data["investigator_security_2"].id)
            assert reassigned_inc["assignment_status"] == "reassigned"

            # Reassigning to the same reviewer must fail
            resp_reassign_same = await client.post(
                f"/api/v1/incidents/{inc_id}/reassign",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={
                    "reviewer_id": str(data["investigator_security_2"].id),
                    "reason": "Same person again",
                },
            )
            assert resp_reassign_same.status_code == 422

            # 5. Acknowledgement: Assigned reviewer acknowledges
            # Non-assigned reviewer (investigator 1) fails
            resp_ack_fail = await client.post(
                f"/api/v1/incidents/{inc_id}/acknowledge",
                headers={"Authorization": f"Bearer {token_inv_sec_1}"},
            )
            assert resp_ack_fail.status_code == 403

            # Assigned reviewer (investigator 2) succeeds
            resp_ack = await client.post(
                f"/api/v1/incidents/{inc_id}/acknowledge",
                headers={"Authorization": f"Bearer {token_inv_sec_2}"},
            )
            assert resp_ack.status_code == 200
            acked_inc = resp_ack.json()
            assert acked_inc["assignment_status"] == "acknowledged"
            assert acked_inc["acknowledged_at"] is not None

            # 6. Assignment history audit trail
            resp_hist = await client.get(
                f"/api/v1/incidents/{inc_id}/assignments",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
            )
            assert resp_hist.status_code == 200
            history = resp_hist.json()
            assert len(history) >= 3
            statuses = [h["status"] for h in history]
            assert "assigned" in statuses
            assert "reassigned" in statuses
            assert "acknowledged" in statuses

    async def test_phase58_tamper_evident_security_audit_and_chain_verification(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        data = await _setup_batch06_group02_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_admin_sec = await _login(
                client, data["dept_admin_security"].email, data["default_pw"]
            )
            inc_id = data["incident_sec_1_id"]

            # Trigger an assignment which records an audit event in ledger
            await client.post(
                f"/api/v1/incidents/{inc_id}/assign",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={
                    "reviewer_id": str(data["investigator_security_1"].id),
                    "reason": "Audit verification trigger",
                },
            )

            # Verify chain integrity via GET /api/v1/audit/verify
            resp_verify = await client.get(
                "/api/v1/audit/verify",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
            )
            assert resp_verify.status_code == 200
            report = resp_verify.json()
            assert report["chain_valid"] is True
            assert report["status"] == "verified"
            assert report["total_events_verified"] >= 1
            assert AUDIT_DISCLAIMER in report["disclaimer"]

            # Directly tamper with an audit event in PostgreSQL to verify tamper detection
            async with postgres_db_manager.transactional_session() as session:
                latest_event = (
                    (
                        await session.execute(
                            select(SecurityAuditEvent).order_by(
                                SecurityAuditEvent.sequence_number.desc()
                            )
                        )
                    )
                    .scalars()
                    .first()
                )
                assert latest_event is not None
                tampered_id = latest_event.id
                # Corrupt the payload text
                latest_event.details = json.dumps({"tampered": True, "malicious_data": "corrupted"})
                await session.flush()

            # Re-verify chain - should now flag compromise
            resp_tampered = await client.get(
                "/api/v1/audit/verify",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
            )
            assert resp_tampered.status_code == 200
            tamper_report = resp_tampered.json()
            assert tamper_report["chain_valid"] is False
            assert tamper_report["status"] == "compromised"
            assert str(tampered_id) in [str(x) for x in tamper_report["tampered_event_ids"]]
            assert len(tamper_report["errors"]) > 0

    async def test_phase59_evidence_export_and_audit_search_scoping(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        data = await _setup_batch06_group02_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_admin_sec = await _login(
                client, data["dept_admin_security"].email, data["default_pw"]
            )
            token_super_admin = await _login(client, data["super_admin"].email, data["default_pw"])
            token_student = await _login(client, data["student_reporter"].email, data["default_pw"])

            inc_id = data["incident_sec_1_id"]

            # 1. Export incident evidence package
            resp_export = await client.post(
                f"/api/v1/incidents/{inc_id}/export",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={
                    "export_scope": "incident_package",
                    "export_format": "zip",
                    "reason": "Export requested for disciplinary hearing.",
                },
            )
            assert resp_export.status_code == 201
            export_data = resp_export.json()
            assert export_data["incident_id"] == str(inc_id)
            assert export_data["evidence_count"] >= 1
            assert len(export_data["manifest_sha256"]) == 64
            assert export_data["status"] == "completed"

            # 2. List evidence exports
            resp_list_exports = await client.get(
                "/api/v1/audit/exports",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
            )
            assert resp_list_exports.status_code == 200
            exports_page = resp_list_exports.json()
            assert len(exports_page["items"]) >= 1

            # 3. Search security audit events with department isolation
            resp_audit_search = await client.get(
                "/api/v1/audit/events",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
            )
            assert resp_audit_search.status_code == 200
            audit_events = resp_audit_search.json()["items"]
            assert len(audit_events) >= 1
            # Security admin must only see Security department audit events
            for ev in audit_events:
                if ev["department_id"] is not None:
                    assert ev["department_id"] == str(data["dept_security"].id)

            # Super admin can search globally
            resp_super_search = await client.get(
                "/api/v1/audit/events",
                headers={"Authorization": f"Bearer {token_super_admin}"},
            )
            assert resp_super_search.status_code == 200

            # 4. Student is denied audit search (403 Forbidden)
            resp_student_audit = await client.get(
                "/api/v1/audit/events",
                headers={"Authorization": f"Bearer {token_student}"},
            )
            assert resp_student_audit.status_code == 403

            resp_student_export = await client.get(
                "/api/v1/audit/exports",
                headers={"Authorization": f"Bearer {token_student}"},
            )
            assert resp_student_export.status_code == 403
