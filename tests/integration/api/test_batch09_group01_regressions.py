"""Live PostgreSQL Integration Tests for Batch 09 Group 01 (Phases 81-85).

Verifies against real PostgreSQL:
- Phase 81: Case records, incident linkage, ownership, and department isolation.
- Phase 82: Assignment history, optimistic concurrency (version_id), and investigator capacity limit (max 10).
- Phase 83: Evidence inventory integrity metadata, zero storage credential leakage, and legal hold protections.
- Phase 84: AI candidate segment integration and non-authoritative advisory disclaimers.
- Phase 85: Human review workflow, classification correction, and reviewer conflict-of-interest prevention.
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
from backend.app.core.ai import AIJobStatus, SegmentReviewStatus
from backend.app.core.audit import AuditAction
from backend.app.core.case import (
    AI_ADVISORY_DISCLAIMER,
    INVESTIGATOR_DEFAULT_MAX_ACTIVE_CASES,
)
from backend.app.core.evidence import UploadStatus
from backend.app.core.identity import AccountStatus, RoleCode
from backend.app.infrastructure.database import DatabaseSessionManager
from backend.app.infrastructure.storage import InMemoryStorageClient
from backend.app.main import create_app
from backend.app.models.ai import AIAnalysisJob, AICandidateSegment
from backend.app.models.audit import SecurityAuditEvent
from backend.app.models.case import Case
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


async def _setup_batch09_group01_test_env(
    postgres_db_manager: DatabaseSessionManager,
) -> dict[str, Any]:
    """Seed test departments, roles, and users in real PostgreSQL."""
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
                email=f"superadmin_b9g1_{suffix.lower()}@ewitness.edu",
                full_name="Super Admin B9G1",
                role_id=roles[RoleCode.SUPER_ADMIN].id,
                department_id=None,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        dept_admin_sec = await user_repo.create(
            User(
                email=f"deptadmin_sec_{suffix.lower()}@ewitness.edu",
                full_name="Safety Admin B9G1",
                role_id=roles[RoleCode.DEPT_ADMIN].id,
                department_id=dept_security.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        investigator_sec = await user_repo.create(
            User(
                email=f"investigator_sec_{suffix.lower()}@ewitness.edu",
                full_name="Safety Investigator B9G1",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_security.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        investigator_sec_2 = await user_repo.create(
            User(
                email=f"investigator_sec2_{suffix.lower()}@ewitness.edu",
                full_name="Safety Investigator 2 B9G1",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_security.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        investigator_acad = await user_repo.create(
            User(
                email=f"investigator_acad_{suffix.lower()}@ewitness.edu",
                full_name="Academic Investigator B9G1",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_academic.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        student_sec = await user_repo.create(
            User(
                email=f"student_sec_{suffix.lower()}@ewitness.edu",
                full_name="Student User B9G1",
                role_id=roles[RoleCode.STUDENT].id,
                department_id=dept_security.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        return {
            "suffix": suffix,
            "dept_security": dept_security,
            "dept_academic": dept_academic,
            "super_admin": super_admin,
            "dept_admin_sec": dept_admin_sec,
            "investigator_sec": investigator_sec,
            "investigator_sec_2": investigator_sec_2,
            "investigator_acad": investigator_acad,
            "student_sec": student_sec,
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
class TestBatch09Group01LivePostgres:
    """End-to-end integration tests for Phases 81-85 on real PostgreSQL."""

    async def test_phase81_case_creation_and_department_isolation(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify case creation, reference numbers, incident linkage, and strict department isolation."""
        data = await _setup_batch09_group01_test_env(postgres_db_manager)

        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_inv_sec = await _login(client, data["investigator_sec"].email, data["default_pw"])
            token_inv_acad = await _login(
                client, data["investigator_acad"].email, data["default_pw"]
            )
            token_student = await _login(client, data["student_sec"].email, data["default_pw"])

            # 1. Student lacks CASE_CREATE permission -> 403 Forbidden
            resp_student = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_student}"},
                json={
                    "title": "Unauthorized Case Creation",
                    "summary": "This attempt must be blocked by RBAC.",
                },
            )
            assert resp_student.status_code == 403

            # 2. Safety Investigator creates case in Security department -> 201 Created
            create_payload = {
                "title": "Residence Hall Unauthorized Access Inquiry",
                "summary": "Investigating unauthorized late-night access to Residence Hall West.",
                "priority": "high",
            }
            resp_create = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json=create_payload,
            )
            assert resp_create.status_code == 201
            case_data = resp_create.json()
            case_id = case_data["id"]
            ref_num = case_data["reference_number"]

            assert ref_num.startswith("CASE-")
            assert case_data["title"] == create_payload["title"]
            assert case_data["status"] == "open"
            assert case_data["priority"] == "high"
            assert case_data["department_id"] == str(data["dept_security"].id)
            assert case_data["version_id"] == 1
            assert case_data["is_legal_hold"] is False

            # Verify audit event in PostgreSQL
            async with postgres_db_manager.transactional_session() as session:
                audit_res = await session.execute(
                    select(SecurityAuditEvent).where(
                        SecurityAuditEvent.action == AuditAction.CASE_CREATED,
                        SecurityAuditEvent.target_id == str(case_id),
                    )
                )
                audit_event = audit_res.scalars().first()
                assert audit_event is not None
                assert audit_event.target_type == "case"

            # 3. Academic Investigator attempts to read Security Case -> 404 Masked
            resp_acad_read = await client.get(
                f"/api/v1/cases/{case_id}",
                headers={"Authorization": f"Bearer {token_inv_acad}"},
            )
            assert resp_acad_read.status_code == 404

            # 4. Safety Investigator reads by ID and by reference number -> 200 OK
            resp_read_id = await client.get(
                f"/api/v1/cases/{case_id}",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
            )
            assert resp_read_id.status_code == 200
            assert resp_read_id.json()["id"] == case_id

            resp_read_ref = await client.get(
                f"/api/v1/cases/ref/{ref_num}",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
            )
            assert resp_read_ref.status_code == 200
            assert resp_read_ref.json()["reference_number"] == ref_num

            # 5. Incident linkage
            # Create incident in Security department
            async with postgres_db_manager.transactional_session() as session:
                incident_sec = Incident(
                    reference_number=f"INC-{data['suffix']}-0001",
                    title="Hallway Door Sensor Tamper",
                    description="Sensor on secondary exit door showed unexpected offline state.",
                    category="property_damage_theft",
                    severity="medium",
                    location="Residence Hall West Exit B",
                    occurred_at=datetime.now(UTC) - timedelta(minutes=10),
                    department_id=data["dept_security"].id,
                    reporter_id=data["investigator_sec"].id,
                )
                session.add(incident_sec)
                await session.flush()
                incident_sec_id = incident_sec.id

                incident_acad = Incident(
                    reference_number=f"INC-{data['suffix']}-0002",
                    title="Library Exam Disturbance",
                    description="Disturbance in reading room during study hours.",
                    category="academic_misconduct",
                    severity="low",
                    location="Central Library Floor 2",
                    occurred_at=datetime.now(UTC) - timedelta(minutes=10),
                    department_id=data["dept_academic"].id,
                    reporter_id=data["investigator_acad"].id,
                )
                session.add(incident_acad)
                await session.flush()
                incident_acad_id = incident_acad.id

            # Link Security Incident to Case -> 201 Created
            resp_link_inc = await client.post(
                f"/api/v1/cases/{case_id}/incidents",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={"incident_id": str(incident_sec_id), "link_type": "primary"},
            )
            assert resp_link_inc.status_code == 201
            assert resp_link_inc.json()["link_type"] == "primary"

            # Attempt to link Academic Incident to Security Case -> 400 Bad Request (DEPARTMENT_MISMATCH)
            resp_cross_inc = await client.post(
                f"/api/v1/cases/{case_id}/incidents",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={"incident_id": str(incident_acad_id), "link_type": "related"},
            )
            assert resp_cross_inc.status_code in {400, 422}
            assert "DEPARTMENT_MISMATCH" in resp_cross_inc.json().get("error", {}).get("code", "")

            # List incidents linked to case
            resp_list_inc = await client.get(
                f"/api/v1/cases/{case_id}/incidents",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
            )
            assert resp_list_inc.status_code == 200
            inc_list = resp_list_inc.json()
            assert len(inc_list) == 1
            assert inc_list[0]["incident_id"] == str(incident_sec_id)

    async def test_phase82_optimistic_locking_assignment_and_capacity_limits(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify version_id optimistic concurrency, investigator assignment history, and workload limits."""
        data = await _setup_batch09_group01_test_env(postgres_db_manager)

        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_admin = await _login(client, data["dept_admin_sec"].email, data["default_pw"])
            token_inv1 = await _login(client, data["investigator_sec"].email, data["default_pw"])

            # 1. Create initial case
            resp_create = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_inv1}"},
                json={
                    "title": "Lab Security Audit Findings",
                    "summary": "Formal review of physical access to chemistry storage room.",
                    "priority": "medium",
                },
            )
            assert resp_create.status_code == 201
            case_id = resp_create.json()["id"]
            assert resp_create.json()["version_id"] == 1

            # 2. Update with matching expected_version=1 -> version becomes 2
            resp_update_1 = await client.patch(
                f"/api/v1/cases/{case_id}",
                headers={"Authorization": f"Bearer {token_inv1}"},
                json={
                    "title": "Updated Lab Security Audit Findings",
                    "expected_version": 1,
                },
            )
            assert resp_update_1.status_code == 200
            assert resp_update_1.json()["version_id"] == 2
            assert resp_update_1.json()["title"] == "Updated Lab Security Audit Findings"

            # 3. Update with stale expected_version=1 -> 409 Conflict
            resp_stale = await client.patch(
                f"/api/v1/cases/{case_id}",
                headers={"Authorization": f"Bearer {token_inv1}"},
                json={
                    "title": "Concurrent Update Title",
                    "expected_version": 1,
                },
            )
            assert resp_stale.status_code == 409
            assert resp_stale.json().get("error", {}).get("code") == "CONCURRENCY_CONFLICT"

            # 4. Status transition to terminal requires documented rationale
            # Valid progression: open -> under_investigation -> pending_review
            resp_step1 = await client.patch(
                f"/api/v1/cases/{case_id}",
                headers={"Authorization": f"Bearer {token_inv1}"},
                json={"status": "under_investigation", "expected_version": 2},
            )
            assert resp_step1.status_code == 200
            assert resp_step1.json()["version_id"] == 3

            resp_step2 = await client.patch(
                f"/api/v1/cases/{case_id}",
                headers={"Authorization": f"Bearer {token_inv1}"},
                json={"status": "pending_review", "expected_version": 3},
            )
            assert resp_step2.status_code == 200
            assert resp_step2.json()["version_id"] == 4

            # Attempt pending_review -> resolved without status_reason -> 400 Bad Request
            resp_no_reason = await client.patch(
                f"/api/v1/cases/{case_id}",
                headers={"Authorization": f"Bearer {token_inv1}"},
                json={"status": "resolved", "expected_version": 4},
            )
            assert resp_no_reason.status_code in {400, 422}
            assert resp_no_reason.json().get("error", {}).get("code") == "STATUS_REASON_REQUIRED"

            # Valid resolution with reason
            resp_resolve = await client.patch(
                f"/api/v1/cases/{case_id}",
                headers={"Authorization": f"Bearer {token_inv1}"},
                json={
                    "status": "resolved",
                    "status_reason": "Audit recommendations accepted and implemented.",
                    "expected_version": 4,
                },
            )
            assert resp_resolve.status_code == 200
            assert resp_resolve.json()["status"] == "resolved"
            assert resp_resolve.json()["closed_at"] is not None
            assert resp_resolve.json()["version_id"] == 5

            # 5. Investigator Assignment & Workload Capacity
            # Create a new active open case to assign
            resp_new_case = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "title": "Dormitory Perimeter Patrol Case",
                    "summary": "Routine investigation into repeated perimeter sensor triggers.",
                    "priority": "low",
                },
            )
            assert resp_new_case.status_code == 201
            case_patrol_id = resp_new_case.json()["id"]

            # Assign lead investigator
            resp_assign = await client.post(
                f"/api/v1/cases/{case_patrol_id}/assignments",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "new_investigator_id": str(data["investigator_sec"].id),
                    "assignment_reason": "Assigned to shift lead investigator.",
                    "expected_version": 1,
                },
            )
            assert resp_assign.status_code == 200
            assert resp_assign.json()["lead_investigator_id"] == str(data["investigator_sec"].id)
            assert resp_assign.json()["version_id"] == 2

            # Check assignment history
            resp_hist = await client.get(
                f"/api/v1/cases/{case_patrol_id}/assignments",
                headers={"Authorization": f"Bearer {token_admin}"},
            )
            assert resp_hist.status_code == 200
            hist_list = resp_hist.json()
            assert len(hist_list) == 1
            assert hist_list[0]["new_investigator_id"] == str(data["investigator_sec"].id)

            # Check investigator workload endpoint
            resp_wl = await client.get(
                f"/api/v1/cases/investigators/{data['investigator_sec'].id}/workload",
                headers={"Authorization": f"Bearer {token_admin}"},
            )
            assert resp_wl.status_code == 200
            wl_data = resp_wl.json()
            assert wl_data["investigator_id"] == str(data["investigator_sec"].id)
            assert wl_data["max_active_cases"] == INVESTIGATOR_DEFAULT_MAX_ACTIVE_CASES
            assert wl_data["capacity_available"] is True

            # 6. Simulate workload limit: create 9 more active cases assigned to investigator_sec (reaching 10)
            async with postgres_db_manager.transactional_session() as session:
                for i in range(9):
                    c = Case(
                        reference_number=f"CASE-2026-CAP{i:05d}",
                        title=f"Capacity Pad Case {i}",
                        summary="Automated capacity test case record.",
                        status="open",
                        priority="medium",
                        department_id=data["dept_security"].id,
                        created_by_id=data["dept_admin_sec"].id,
                        lead_investigator_id=data["investigator_sec"].id,
                        version_id=1,
                    )
                    session.add(c)
                await session.flush()

            # Now investigator_sec has 10 active cases.
            # Attempt to assign another case to investigator_sec -> 422 Unprocessable Entity
            resp_another_case = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "title": "Exceeding Limit Inquiry Case",
                    "summary": "Should not be assignable to investigator_sec due to workload cap.",
                },
            )
            assert resp_another_case.status_code == 201
            case_overload_id = resp_another_case.json()["id"]

            resp_cap_exceeded = await client.post(
                f"/api/v1/cases/{case_overload_id}/assignments",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={
                    "new_investigator_id": str(data["investigator_sec"].id),
                    "assignment_reason": "Attempting to overload investigator.",
                    "expected_version": 1,
                },
            )
            assert resp_cap_exceeded.status_code == 422
            assert (
                resp_cap_exceeded.json().get("error", {}).get("code")
                == "INVESTIGATOR_CAPACITY_EXCEEDED"
            )

    async def test_phase83_evidence_inventory_integrity_and_legal_hold(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify evidence inventory enrichment, zero storage credential leakage, and legal hold lock."""
        data = await _setup_batch09_group01_test_env(postgres_db_manager)

        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_inv = await _login(client, data["investigator_sec"].email, data["default_pw"])

            # 1. Create Case and Evidence in PostgreSQL
            async with postgres_db_manager.transactional_session() as session:
                incident = Incident(
                    reference_number=f"INC-{data['suffix']}-0003",
                    title="Camera Footage Audit",
                    description="CCTV footage collected from north gate entrance.",
                    category="property_damage_theft",
                    severity="high",
                    location="North Gate",
                    occurred_at=datetime.now(UTC) - timedelta(minutes=10),
                    department_id=data["dept_security"].id,
                    reporter_id=data["investigator_sec"].id,
                )
                session.add(incident)
                await session.flush()

                ev_attachment = EvidenceAttachment(
                    incident_id=incident.id,
                    uploader_id=data["investigator_sec"].id,
                    department_id=data["dept_security"].id,
                    original_filename="north_gate_footage.mp4",
                    declared_mime_type="video/mp4",
                    file_size_bytes=10485760,
                    sha256_hash="4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
                    storage_key="sec/2026/north_gate_footage_super_secret_raw_key.mp4",
                    upload_status=UploadStatus.COMPLETED.value,
                )
                session.add(ev_attachment)
                await session.flush()
                evidence_id = ev_attachment.id

            resp_create_case = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_inv}"},
                json={
                    "title": "North Gate Surveillance Investigation",
                    "summary": "Detailed forensic inquiry into security gate footage.",
                    "priority": "high",
                },
            )
            assert resp_create_case.status_code == 201
            case_id = resp_create_case.json()["id"]

            # 2. Link Evidence to Case
            resp_link_ev = await client.post(
                f"/api/v1/cases/{case_id}/evidence",
                headers={"Authorization": f"Bearer {token_inv}"},
                json={
                    "evidence_id": str(evidence_id),
                    "notes": "Primary video exhibit covering gate perimeter.",
                    "is_exhibiting": True,
                },
            )
            assert resp_link_ev.status_code == 201
            linked_ev = resp_link_ev.json()
            assert linked_ev["file_name"] == "north_gate_footage.mp4"
            assert (
                linked_ev["sha256_hash"]
                == "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
            )
            assert linked_ev["integrity_status"] == "verified"
            # Verify ZERO storage credential leakage in JSON response
            assert "storage_key" not in linked_ev
            assert "super_secret" not in str(linked_ev)
            assert "bucket" not in linked_ev

            # 3. List Case Evidence
            resp_list_ev = await client.get(
                f"/api/v1/cases/{case_id}/evidence",
                headers={"Authorization": f"Bearer {token_inv}"},
            )
            assert resp_list_ev.status_code == 200
            items = resp_list_ev.json()
            assert len(items) == 1
            assert items[0]["file_name"] == "north_gate_footage.mp4"
            assert "storage_key" not in items[0]

            # 4. Legal Hold Protection
            # Toggle legal hold without reason -> 400 Bad Request
            resp_no_lh_reason = await client.patch(
                f"/api/v1/cases/{case_id}",
                headers={"Authorization": f"Bearer {token_inv}"},
                json={"is_legal_hold": True, "expected_version": 1},
            )
            assert resp_no_lh_reason.status_code in {400, 422}
            assert (
                resp_no_lh_reason.json().get("error", {}).get("code")
                == "LEGAL_HOLD_REASON_REQUIRED"
            )

            # Set legal hold with justification
            resp_set_lh = await client.patch(
                f"/api/v1/cases/{case_id}",
                headers={"Authorization": f"Bearer {token_inv}"},
                json={
                    "is_legal_hold": True,
                    "legal_hold_reason": "Formal preservation notice from Legal Counsel.",
                    "expected_version": 1,
                },
            )
            assert resp_set_lh.status_code == 200
            assert resp_set_lh.json()["is_legal_hold"] is True
            assert resp_set_lh.json()["version_id"] == 2

            # Attempt to unlink evidence under legal hold -> 409 Conflict (LEGAL_HOLD_ACTIVE)
            resp_del_lh = await client.delete(
                f"/api/v1/cases/{case_id}/evidence/{evidence_id}",
                headers={"Authorization": f"Bearer {token_inv}"},
            )
            assert resp_del_lh.status_code == 409
            assert resp_del_lh.json().get("error", {}).get("code") == "LEGAL_HOLD_ACTIVE"

            # Release legal hold
            resp_rel_lh = await client.patch(
                f"/api/v1/cases/{case_id}",
                headers={"Authorization": f"Bearer {token_inv}"},
                json={"is_legal_hold": False, "expected_version": 2},
            )
            assert resp_rel_lh.status_code == 200
            assert resp_rel_lh.json()["is_legal_hold"] is False
            assert resp_rel_lh.json()["version_id"] == 3

            # Now unlinking succeeds -> 204 No Content
            resp_unlink = await client.delete(
                f"/api/v1/cases/{case_id}/evidence/{evidence_id}",
                headers={"Authorization": f"Bearer {token_inv}"},
            )
            assert resp_unlink.status_code == 204

            # Verify evidence inventory is now empty
            resp_list_after = await client.get(
                f"/api/v1/cases/{case_id}/evidence",
                headers={"Authorization": f"Bearer {token_inv}"},
            )
            assert resp_list_after.status_code == 200
            assert len(resp_list_after.json()) == 0

    async def test_phase84_and_85_ai_candidate_segments_and_human_review_with_conflict_of_interest(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify AI candidate segment linking, advisory disclaimers, conflict-of-interest check, and human review."""
        data = await _setup_batch09_group01_test_env(postgres_db_manager)

        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_inv1 = await _login(client, data["investigator_sec"].email, data["default_pw"])
            token_inv2 = await _login(client, data["investigator_sec_2"].email, data["default_pw"])

            # 1. Create DB fixture for Incident, Evidence, AI Job, and Candidate Segment
            async with postgres_db_manager.transactional_session() as session:
                # The incident was reported by investigator_sec!
                incident = Incident(
                    reference_number=f"INC-{data['suffix']}-0004",
                    title="Courtyard Confrontation Incident",
                    description="Physical altercation observed near courtyard benches.",
                    category="physical_assault",
                    severity="critical",
                    location="Main Quad Courtyard",
                    occurred_at=datetime.now(UTC) - timedelta(minutes=10),
                    department_id=data["dept_security"].id,
                    reporter_id=data["investigator_sec"].id,  # Reporter is investigator_sec
                )
                session.add(incident)
                await session.flush()

                evidence = EvidenceAttachment(
                    incident_id=incident.id,
                    uploader_id=data["investigator_sec"].id,
                    department_id=data["dept_security"].id,
                    original_filename="courtyard_cam3.mp4",
                    declared_mime_type="video/mp4",
                    file_size_bytes=20971520,
                    sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    storage_key="sec/courtyard_cam3.mp4",
                    upload_status=UploadStatus.COMPLETED.value,
                )
                session.add(evidence)
                await session.flush()

                job = AIAnalysisJob(
                    evidence_id=evidence.id,
                    incident_id=incident.id,
                    department_id=data["dept_security"].id,
                    submitted_by_id=data["investigator_sec"].id,
                    status=AIJobStatus.SUCCEEDED.value,
                    model_name="violence_v1",
                    model_version="1.0.0",
                )
                session.add(job)
                await session.flush()

                segment = AICandidateSegment(
                    job_id=job.id,
                    evidence_id=evidence.id,
                    incident_id=incident.id,
                    department_id=data["dept_security"].id,
                    start_seconds=14.0,
                    end_seconds=22.0,
                    duration_seconds=8.0,
                    raw_score=0.89,
                    raw_label="violence",
                    model_name="violence_v1",
                    model_version="1.0.0",
                    review_status=SegmentReviewStatus.PENDING_REVIEW.value,
                )
                session.add(segment)
                await session.flush()
                segment_id = segment.id

            # 2. Create Case in Security Department
            resp_case = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_inv2}"},
                json={
                    "title": "Quad Courtyard Violence Investigation",
                    "summary": "Forensic review of AI candidate violence segments.",
                    "priority": "critical",
                },
            )
            assert resp_case.status_code == 201
            case_id = resp_case.json()["id"]

            # 3. Link AI Candidate Segment to Case
            resp_link_seg = await client.post(
                f"/api/v1/cases/{case_id}/ai-segments",
                headers={"Authorization": f"Bearer {token_inv2}"},
                json={
                    "segment_id": str(segment_id),
                    "investigative_relevance": "candidate_lead",
                    "relevance_notes": "Segment shows potential physical confrontation.",
                },
            )
            assert resp_link_seg.status_code == 201
            seg_data = resp_link_seg.json()
            assert seg_data["segment_id"] == str(segment_id)
            assert seg_data["investigative_relevance"] == "candidate_lead"
            # Non-negotiable principle: Mandatory advisory disclaimer must be returned!
            assert seg_data["advisory_disclaimer"] == AI_ADVISORY_DISCLAIMER
            assert "advisory" in seg_data["advisory_disclaimer"].lower()

            # 4. List AI Segments on Case
            resp_list_segs = await client.get(
                f"/api/v1/cases/{case_id}/ai-segments",
                headers={"Authorization": f"Bearer {token_inv2}"},
            )
            assert resp_list_segs.status_code == 200
            segs = resp_list_segs.json()
            assert len(segs) == 1
            assert segs[0]["advisory_disclaimer"] == AI_ADVISORY_DISCLAIMER

            # 5. Reviewer Conflict-of-Interest Check:
            # investigator_sec reported this incident!
            # investigator_sec attempts to perform human review -> 403 Forbidden (REVIEWER_CONFLICT_OF_INTEREST)
            resp_conflict = await client.post(
                f"/api/v1/cases/{case_id}/ai-segments/{segment_id}/review",
                headers={"Authorization": f"Bearer {token_inv1}"},
                json={
                    "review_status": "confirmed",
                    "review_rationale": "I reported this incident and observed it myself.",
                },
            )
            assert resp_conflict.status_code == 403
            err_code = resp_conflict.json().get("error", {}).get("code", "")
            assert err_code == "REVIEWER_CONFLICT_OF_INTEREST"

            # 6. Authorized Independent Human Review:
            # investigator_sec_2 did NOT report the incident. They perform independent review.
            resp_review_ok = await client.post(
                f"/api/v1/cases/{case_id}/ai-segments/{segment_id}/review",
                headers={"Authorization": f"Bearer {token_inv2}"},
                json={
                    "review_status": "confirmed",
                    "review_rationale": "Independent frame review verifies rapid aggressive physical contact.",
                    "corrected_label": "physical_assault",
                },
            )
            assert resp_review_ok.status_code == 200
            reviewed_data = resp_review_ok.json()
            assert reviewed_data["review_status"] == "confirmed"
            assert reviewed_data["label"] == "physical_assault"
            assert reviewed_data["reviewed_by_id"] == str(data["investigator_sec_2"].id)
            assert reviewed_data["reviewed_at"] is not None

            # 7. Verify security audit event in PostgreSQL
            async with postgres_db_manager.transactional_session() as session:
                audit_res = await session.execute(
                    select(SecurityAuditEvent).where(
                        SecurityAuditEvent.action == AuditAction.CASE_AI_SEGMENT_REVIEWED,
                        SecurityAuditEvent.target_id == str(case_id),
                    )
                )
                audit_event = audit_res.scalars().first()
                assert audit_event is not None
                assert audit_event.target_type == "case"
                audit_details = (
                    json.loads(audit_event.details)
                    if isinstance(audit_event.details, str)
                    else (audit_event.details or {})
                )
                assert audit_details["new_review_status"] == "confirmed"
                assert audit_details["new_classification_label"] == "physical_assault"
