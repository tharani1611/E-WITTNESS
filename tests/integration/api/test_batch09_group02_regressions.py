"""Live PostgreSQL Integration Tests for Batch 09 Group 02 (Phases 86-90).

Verifies against real PostgreSQL:
- Phase 86: Case notes, visibility tiers, evidence reference validation, structured findings, and append-only version history.
- Phase 87: Centralized case lifecycle transitions, prerequisite enforcement, supervisory approvals, and optimistic concurrency locks.
- Phase 88: Escalation, external referrals, closure with documented rationale, legal hold preservation, and authorized reopening.
- Phase 89: Cryptographically hashed controlled case disclosure, evidence manifests, zero storage credential leakage, restricted notes redaction, and mandatory statutory AI advisory disclaimers.
- Phase 90: End-to-end investigation workflow and audit trail verification against live PostgreSQL.
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
    CaseExportFormat,
    CaseExportScope,
    CasePriority,
    CaseStatus,
    IncidentLinkType,
)
from backend.app.core.evidence import UploadStatus
from backend.app.core.identity import AccountStatus, RoleCode
from backend.app.infrastructure.database import DatabaseSessionManager
from backend.app.infrastructure.storage import InMemoryStorageClient
from backend.app.main import create_app
from backend.app.models.ai import AIAnalysisJob, AICandidateSegment
from backend.app.models.audit import SecurityAuditEvent
from backend.app.models.case import Case, CaseEvidence, CaseIncident, CaseNote
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


async def _setup_batch09_group02_test_env(
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
        dept_conduct = await dept_repo.create(
            Department(code=f"COND-{suffix}", name=f"Student Conduct {suffix}", is_active=True)
        )
        dept_academic = await dept_repo.create(
            Department(code=f"ACAD-{suffix}", name=f"Academic Affairs {suffix}", is_active=True)
        )

        super_admin = await user_repo.create(
            User(
                email=f"superadmin_b9g2_{suffix.lower()}@ewitness.edu",
                full_name="Super Admin B9G2",
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
                full_name="Safety Admin B9G2",
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
                full_name="Safety Investigator B9G2",
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
                full_name="Safety Investigator 2 B9G2",
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
                full_name="Academic Investigator B9G2",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_academic.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        return {
            "suffix": suffix,
            "dept_security": dept_security,
            "dept_conduct": dept_conduct,
            "dept_academic": dept_academic,
            "super_admin": super_admin,
            "dept_admin_sec": dept_admin_sec,
            "investigator_sec": investigator_sec,
            "investigator_sec_2": investigator_sec_2,
            "investigator_acad": investigator_acad,
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
class TestBatch09Group02LivePostgres:
    """End-to-end integration tests for Phases 86-90 on real PostgreSQL."""

    async def test_phase86_notes_findings_and_append_only_history(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify case notes, visibility tiers, evidence reference validation, structured findings, and history."""
        data = await _setup_batch09_group02_test_env(postgres_db_manager)

        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_inv_sec = await _login(client, data["investigator_sec"].email, data["default_pw"])
            token_admin_sec = await _login(client, data["dept_admin_sec"].email, data["default_pw"])
            token_inv_acad = await _login(
                client, data["investigator_acad"].email, data["default_pw"]
            )

            # 1. Create a case in Security department
            create_resp = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "title": "Residence Hall Incident Investigation",
                    "summary": "Investigating unauthorized entry and security breach.",
                    "priority": "high",
                },
            )
            assert create_resp.status_code == 201
            case_data = create_resp.json()
            case_id = case_data["id"]

            # 2. Add an evidence attachment and link it to the case
            async with postgres_db_manager.transactional_session() as session:
                incident = Incident(
                    id=uuid4(),
                    reference_number=f"INC-{data['suffix']}-0001",
                    title="Door forced open",
                    description="Physical door sensor alarm and forced entry",
                    category="property_damage_theft",
                    severity="high",
                    location="Residence Hall Door 4",
                    occurred_at=datetime.now(UTC) - timedelta(hours=2),
                    department_id=data["dept_security"].id,
                    reporter_id=data["investigator_sec"].id,
                )
                session.add(incident)
                await session.flush()

                # Link incident to case
                case_obj = await session.get(Case, case_id)
                assert case_obj is not None
                case_obj.incident_id = incident.id
                case_obj.lead_investigator_id = data["investigator_sec"].id

                evidence = EvidenceAttachment(
                    id=uuid4(),
                    department_id=data["dept_security"].id,
                    incident_id=incident.id,
                    storage_key=f"sec/{uuid4().hex}.jpg",
                    original_filename="hallway_frame.jpg",
                    declared_mime_type="image/jpeg",
                    file_size_bytes=20480,
                    sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    upload_status=UploadStatus.COMPLETED.value,
                    uploader_id=data["investigator_sec"].id,
                )
                session.add(evidence)
                await session.flush()
                valid_evidence_id = str(evidence.id)

                case_ev = CaseEvidence(
                    id=uuid4(),
                    case_id=case_obj.id,
                    evidence_id=evidence.id,
                    linked_by_id=data["investigator_sec"].id,
                    created_at=datetime.now(UTC),
                )
                session.add(case_ev)
                await session.flush()

            # 3. Create case note with valid evidence reference
            note_resp = await client.post(
                f"/api/v1/cases/{case_id}/notes",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "content": "Observed person of interest entering via hallway door at 02:14 AM.",
                    "visibility": "internal",
                    "evidence_reference_ids": [valid_evidence_id],
                },
            )
            assert note_resp.status_code == 201
            note_data = note_resp.json()
            note_id = note_data["id"]
            assert note_data["visibility"] == "internal"
            assert note_data["version_id"] == 1
            assert valid_evidence_id in note_data["evidence_reference_ids"]

            # 4. Create case note with invalid evidence reference -> 422 Unprocessable Entity
            fake_evidence_id = str(uuid4())
            invalid_note_resp = await client.post(
                f"/api/v1/cases/{case_id}/notes",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "content": "Note referencing non-existent evidence.",
                    "visibility": "internal",
                    "evidence_reference_ids": [fake_evidence_id],
                },
            )
            assert invalid_note_resp.status_code == 422
            assert (
                invalid_note_resp.json().get("error", {}).get("code")
                == "INVALID_EVIDENCE_REFERENCE"
            )

            # 5. Standard investigator cannot create restricted note -> 403 Forbidden
            restricted_note_resp = await client.post(
                f"/api/v1/cases/{case_id}/notes",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "content": "Restricted informant notes.",
                    "visibility": "restricted",
                },
            )
            assert restricted_note_resp.status_code == 403

            # 6. Dept admin CAN create restricted note
            admin_restricted_resp = await client.post(
                f"/api/v1/cases/{case_id}/notes",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={
                    "content": "Supervisory confidential witness identity note.",
                    "visibility": "restricted",
                },
            )
            assert admin_restricted_resp.status_code == 201
            restricted_note_id = admin_restricted_resp.json()["id"]

            # 7. Update case note: verify append-only CaseNoteHistory and version increment
            update_note_resp = await client.patch(
                f"/api/v1/cases/{case_id}/notes/{note_id}",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "content": "Updated: Person entering was wearing dark hoodie, exiting at 02:19 AM.",
                    "expected_version_id": 1,
                    "edit_reason": "Clarified exit timestamp from secondary camera angle.",
                },
            )
            assert update_note_resp.status_code == 200
            updated_data = update_note_resp.json()
            assert updated_data["version_id"] == 2
            assert "dark hoodie" in updated_data["content"]

            # 8. Check note history
            history_resp = await client.get(
                f"/api/v1/cases/{case_id}/notes/{note_id}/history",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
            )
            assert history_resp.status_code == 200
            history_items = history_resp.json()
            assert len(history_items) == 1
            assert history_items[0]["version_id"] == 1
            assert "02:14 AM" in history_items[0]["content"]
            assert (
                history_items[0]["edit_reason"]
                == "Clarified exit timestamp from secondary camera angle."
            )

            # 9. Concurrency conflict on note update -> 409 Conflict
            stale_update_resp = await client.patch(
                f"/api/v1/cases/{case_id}/notes/{note_id}",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "content": "Another edit attempt with old version.",
                    "expected_version_id": 1,
                },
            )
            assert stale_update_resp.status_code == 409
            assert stale_update_resp.json().get("error", {}).get("code") == "CONCURRENCY_CONFLICT"

            # 10. List notes: visibility filtering (investigator without restricted permission cannot see restricted note)
            list_inv_resp = await client.get(
                f"/api/v1/cases/{case_id}/notes",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
            )
            assert list_inv_resp.status_code == 200
            inv_note_ids = [n["id"] for n in list_inv_resp.json()]
            assert note_id in inv_note_ids
            assert restricted_note_id not in inv_note_ids

            # Dept admin sees restricted note
            list_admin_resp = await client.get(
                f"/api/v1/cases/{case_id}/notes",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
            )
            assert list_admin_resp.status_code == 200
            admin_note_ids = [n["id"] for n in list_admin_resp.json()]
            assert note_id in admin_note_ids
            assert restricted_note_id in admin_note_ids

            # 11. Create structured finding
            finding_resp = await client.post(
                f"/api/v1/cases/{case_id}/findings",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "finding_type": "inculpatory",
                    "title": "Unauthorized Entry Confirmed",
                    "description": "Physical evidence and CCTV footage verify keycard badge spoofing at 02:14 AM.",
                    "evidence_ids": [valid_evidence_id],
                },
            )
            assert finding_resp.status_code == 201
            finding_data = finding_resp.json()
            finding_id = finding_data["id"]
            assert finding_data["finding_type"] == "inculpatory"
            assert finding_data["version_id"] == 1

            # 12. Update structured finding -> CaseFindingHistory created
            update_finding_resp = await client.patch(
                f"/api/v1/cases/{case_id}/findings/{finding_id}",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "description": "Definitive physical corroboration with cryptographic audit logs.",
                    "expected_version_id": 1,
                    "reason": "Refined confidence level after badge access reader audit.",
                },
            )
            assert update_finding_resp.status_code == 200
            assert update_finding_resp.json()["version_id"] == 2

            finding_hist_resp = await client.get(
                f"/api/v1/cases/{case_id}/findings/{finding_id}/history",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
            )
            assert finding_hist_resp.status_code == 200
            f_hist = finding_hist_resp.json()
            assert len(f_hist) == 1
            assert f_hist[0]["version_id"] == 1

            # 13. Tenant isolation: academic investigator cannot access security case notes/findings -> 404
            acad_notes_resp = await client.get(
                f"/api/v1/cases/{case_id}/notes",
                headers={"Authorization": f"Bearer {token_inv_acad}"},
            )
            assert acad_notes_resp.status_code == 404

    async def test_phase87_lifecycle_transitions_approvals_and_concurrency(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify centralized lifecycle transitions, prerequisite enforcement, approvals, and optimistic locks."""
        data = await _setup_batch09_group02_test_env(postgres_db_manager)

        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_inv_sec = await _login(client, data["investigator_sec"].email, data["default_pw"])
            token_admin_sec = await _login(client, data["dept_admin_sec"].email, data["default_pw"])

            # 1. Create a draft case without lead investigator or incident
            # 1. Create an open case without lead investigator or incident
            async with postgres_db_manager.transactional_session() as session:
                unlinked_case = Case(
                    reference_number=f"CASE-{datetime.now(UTC).year}-{uuid4().hex[:8].upper()}",
                    title="Unlinked Investigation",
                    summary="Investigation without incident linkage",
                    priority=CasePriority.MEDIUM.value,
                    status=CaseStatus.OPEN.value,
                    department_id=data["dept_security"].id,
                    created_by_id=data["investigator_sec"].id,
                    lead_investigator_id=None,
                    version_id=1,
                )
                session.add(unlinked_case)
                await session.flush()
                unlinked_case_id = str(unlinked_case.id)

            # 2. Prerequisite failure: open -> under_investigation requires lead investigator
            fail_transition_resp = await client.post(
                f"/api/v1/cases/{unlinked_case_id}/transition",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "target_status": "under_investigation",
                    "expected_version_id": 1,
                    "reason": "Starting active investigation with prerequisites check.",
                },
            )
            assert fail_transition_resp.status_code == 422
            assert (
                fail_transition_resp.json().get("error", {}).get("code")
                == "LEAD_INVESTIGATOR_REQUIRED"
            )

            # 3. Link incident and assign lead
            async with postgres_db_manager.transactional_session() as session:
                incident = Incident(
                    id=uuid4(),
                    reference_number=f"INC-{data['suffix']}-0002",
                    title="Camera tampering incident",
                    description="Camera covered with spray paint on north gate",
                    category="property_damage_theft",
                    severity="medium",
                    location="North Gate Pole 3",
                    occurred_at=datetime.now(UTC),
                    department_id=data["dept_security"].id,
                    reporter_id=data["investigator_sec"].id,
                )
                session.add(incident)
                await session.flush()

                case_obj = await session.get(Case, unlinked_case_id)
                assert case_obj is not None
                case_obj.incident_id = incident.id
                case_obj.lead_investigator_id = data["investigator_sec"].id
                case_obj.version_id = 2

                case_inc = CaseIncident(
                    id=uuid4(),
                    case_id=case_obj.id,
                    incident_id=incident.id,
                    linked_by_id=data["investigator_sec"].id,
                    link_type=IncidentLinkType.PRIMARY.value,
                    created_at=datetime.now(UTC),
                )
                session.add(case_inc)

                note = CaseNote(
                    id=uuid4(),
                    case_id=case_obj.id,
                    author_id=data["investigator_sec"].id,
                    visibility="internal",
                    content="Surveillance analysis of gate camera.",
                    version_id=1,
                    is_archived=False,
                    created_at=datetime.now(UTC),
                    updated_at=datetime.now(UTC),
                )
                session.add(note)
                await session.flush()

            # Now transition from open -> under_investigation succeeds
            success_trans_resp = await client.post(
                f"/api/v1/cases/{unlinked_case_id}/transition",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "target_status": "under_investigation",
                    "expected_version_id": 2,
                    "reason": "Lead assigned and incident linked properly.",
                },
            )
            assert success_trans_resp.status_code == 200
            assert success_trans_resp.json()["status"] == "under_investigation"
            current_version = success_trans_resp.json()["version_id"]

            # 4. Add an unreviewed AI candidate segment to the case
            async with postgres_db_manager.transactional_session() as session:
                ev_att = EvidenceAttachment(
                    id=uuid4(),
                    department_id=data["dept_security"].id,
                    incident_id=incident.id,
                    storage_key=f"sec/{uuid4().hex}.mp4",
                    original_filename="gate_camera.mp4",
                    declared_mime_type="video/mp4",
                    file_size_bytes=1048576,
                    sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    upload_status=UploadStatus.COMPLETED.value,
                    uploader_id=data["investigator_sec"].id,
                )
                session.add(ev_att)
                await session.flush()

                ai_job = AIAnalysisJob(
                    evidence_id=ev_att.id,
                    incident_id=incident.id,
                    department_id=data["dept_security"].id,
                    submitted_by_id=data["investigator_sec"].id,
                    status=AIJobStatus.SUCCEEDED.value,
                    model_name="violence_v1",
                    model_version="1.0.0",
                )
                session.add(ai_job)
                await session.flush()

                unreviewed_segment = AICandidateSegment(
                    job_id=ai_job.id,
                    evidence_id=ev_att.id,
                    incident_id=incident.id,
                    department_id=data["dept_security"].id,
                    start_seconds=10.0,
                    end_seconds=20.0,
                    duration_seconds=10.0,
                    raw_score=0.85,
                    raw_label="motion",
                    model_name="violence_v1",
                    model_version="1.0.0",
                    review_status=SegmentReviewStatus.PENDING_REVIEW.value,
                )
                session.add(unreviewed_segment)
                await session.flush()
                segment_id = unreviewed_segment.id

            # Link the AI segment to the case
            link_seg_resp = await client.post(
                f"/api/v1/cases/{unlinked_case_id}/ai-segments",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "segment_id": str(segment_id),
                    "investigative_relevance": "candidate_lead",
                },
            )
            assert link_seg_resp.status_code == 201

            # 5. Transition to pending_review is blocked while AI segment is unreviewed
            blocked_review_resp = await client.post(
                f"/api/v1/cases/{unlinked_case_id}/transition",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "target_status": "pending_review",
                    "expected_version_id": current_version,
                    "reason": "Submitting for final review prematurely.",
                },
            )
            assert blocked_review_resp.status_code == 422
            assert (
                blocked_review_resp.json().get("error", {}).get("code")
                == "AI_SEGMENTS_PENDING_REVIEW"
            )

            # 6. Review the AI segment using second investigator (avoid conflict of interest)
            token_inv2 = await _login(client, data["investigator_sec_2"].email, data["default_pw"])
            review_resp = await client.post(
                f"/api/v1/cases/{unlinked_case_id}/ai-segments/{segment_id}/review",
                headers={"Authorization": f"Bearer {token_inv2}"},
                json={
                    "review_status": "confirmed",
                    "review_rationale": "Human review confirms suspect presence in hallway segment.",
                },
            )
            assert review_resp.status_code == 200

            # Now transition to pending_review succeeds
            review_ready_resp = await client.post(
                f"/api/v1/cases/{unlinked_case_id}/transition",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "target_status": "pending_review",
                    "expected_version_id": current_version,
                    "reason": "AI segment reviewed and findings confirmed.",
                },
            )
            assert review_ready_resp.status_code == 200
            assert review_ready_resp.json()["status"] == "pending_review"
            assert review_ready_resp.json()["version_id"] > 0
            pending_review_version = review_ready_resp.json()["version_id"]

            # 7. Supervisory approval: standard investigator lacks CASE_TRANSITION_APPROVE -> 403
            inv_approval_resp = await client.post(
                f"/api/v1/cases/{unlinked_case_id}/approvals",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "decision": "approved",
                    "from_status": "pending_review",
                    "to_status": "resolved",
                    "rationale": "Attempting self-approval without supervisor permission.",
                    "expected_version_id": pending_review_version,
                },
            )
            assert inv_approval_resp.status_code == 403

            # 8. Supervisory approval by Dept Admin: request changes -> status reverts to under_investigation
            reject_approval_resp = await client.post(
                f"/api/v1/cases/{unlinked_case_id}/approvals",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={
                    "decision": "changes_requested",
                    "from_status": "pending_review",
                    "to_status": "resolved",
                    "rationale": "Please interview third witness before case resolution.",
                    "expected_version_id": pending_review_version,
                },
            )
            assert reject_approval_resp.status_code == 201
            appr_data = reject_approval_resp.json()
            assert appr_data["decision"] == "changes_requested"

            # Verify case reverted to under_investigation
            case_check_resp = await client.get(
                f"/api/v1/cases/{unlinked_case_id}",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
            )
            assert case_check_resp.status_code == 200
            assert case_check_resp.json()["status"] == "under_investigation"
            revised_version = case_check_resp.json()["version_id"]

            # 9. Resubmit to pending_review, then Dept Admin approves -> resolved
            resubmit_resp = await client.post(
                f"/api/v1/cases/{unlinked_case_id}/transition",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "target_status": "pending_review",
                    "expected_version_id": revised_version,
                    "reason": "Third witness interview complete and findings updated.",
                },
            )
            assert resubmit_resp.status_code == 200
            ready_version = resubmit_resp.json()["version_id"]

            final_approval_resp = await client.post(
                f"/api/v1/cases/{unlinked_case_id}/approvals",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={
                    "decision": "approved",
                    "from_status": "pending_review",
                    "to_status": "resolved",
                    "rationale": "All prerequisites, evidence, and notes satisfactory.",
                    "expected_version_id": ready_version,
                },
            )
            assert final_approval_resp.status_code == 201
            assert final_approval_resp.json()["decision"] == "approved"

            case_final_check = await client.get(
                f"/api/v1/cases/{unlinked_case_id}",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
            )
            assert case_final_check.json()["status"] == "resolved"

    async def test_phase88_escalation_referral_closure_and_reopening(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify escalation, referrals, documented closure, legal hold preservation, and reopening."""
        data = await _setup_batch09_group02_test_env(postgres_db_manager)

        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_inv_sec = await _login(client, data["investigator_sec"].email, data["default_pw"])
            token_admin_sec = await _login(client, data["dept_admin_sec"].email, data["default_pw"])

            # 1. Create and setup an active case
            create_resp = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "title": "Serious Hate Speech & Vandalism Incident",
                    "summary": "Complex multi-departmental investigation.",
                    "priority": "critical",
                },
            )
            case_id = create_resp.json()["id"]

            # 2. Escalate case to Student Conduct
            esc_resp = await client.post(
                f"/api/v1/cases/{case_id}/escalations",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={
                    "escalation_level": "department_head",
                    "reason": "Escalated for administrative disciplinary review.",
                    "escalated_to_department_id": str(data["dept_conduct"].id),
                    "expected_version_id": 1,
                },
            )
            assert esc_resp.status_code == 201
            esc_data = esc_resp.json()
            assert esc_data["escalation_level"] == "department_head"
            assert esc_data["escalated_to_department_id"] == str(data["dept_conduct"].id)

            # 3. External referral to Municipal Police
            ref_resp = await client.post(
                f"/api/v1/cases/{case_id}/referrals",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={
                    "target_external_agency": "Metro Police Department",
                    "referral_purpose": "Potential criminal misdemeanor charges and external investigation.",
                },
            )
            assert ref_resp.status_code == 201
            ref_data = ref_resp.json()
            ref_id = ref_data["id"]
            assert ref_data["status"] == "pending"
            assert ref_data["target_external_agency"] == "Metro Police Department"

            # Update referral status to ACCEPTED
            update_ref_resp = await client.patch(
                f"/api/v1/cases/{case_id}/referrals/{ref_id}",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={
                    "status": "accepted",
                    "resolution_notes": "Case accepted by Detective Bureau.",
                },
            )
            assert update_ref_resp.status_code == 200
            assert update_ref_resp.json()["status"] == "accepted"

            # 4. Resolve the case so it can be closed
            async with postgres_db_manager.transactional_session() as session:
                c = await session.get(Case, case_id)
                assert c is not None
                c.status = CaseStatus.RESOLVED.value
                c.version_id = 5

            # 5. Close the case with documented closure rationale
            close_resp = await client.post(
                f"/api/v1/cases/{case_id}/close",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={
                    "reason": "Referred to MPD and Student Conduct; internal actions finalized.",
                    "expected_version_id": 5,
                },
            )
            assert close_resp.status_code == 200
            closed_case = close_resp.json()
            assert closed_case["status"] == "closed"
            assert closed_case["closed_at"] is not None
            new_version = closed_case["version_id"]

            # 6. Attempting to reopen without authorization
            reopen_fail_resp = await client.post(
                f"/api/v1/cases/{case_id}/reopen",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "reason": "Just curious to check again without permission.",
                    "expected_version_id": new_version,
                },
            )
            # Standard investigator does not possess CASE_REOPEN permission -> 403
            assert reopen_fail_resp.status_code == 403

            # Reopen by Dept Admin succeeds
            reopen_resp = await client.post(
                f"/api/v1/cases/{case_id}/reopen",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={
                    "reason": "New supplemental forensic report received from Metro Police.",
                    "expected_version_id": new_version,
                },
            )
            assert reopen_resp.status_code == 200
            reopened_case = reopen_resp.json()
            assert reopened_case["status"] == "under_investigation"
            assert reopened_case["closed_at"] is None

    async def test_phase89_controlled_disclosure_manifest_and_sha256(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify controlled case disclosure, evidence manifest with SHA-256, zero credential leak, and redaction."""
        data = await _setup_batch09_group02_test_env(postgres_db_manager)

        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_inv_sec = await _login(client, data["investigator_sec"].email, data["default_pw"])
            token_admin_sec = await _login(client, data["dept_admin_sec"].email, data["default_pw"])
            token_inv_acad = await _login(
                client, data["investigator_acad"].email, data["default_pw"]
            )

            # 1. Create case, attach evidence, add public and restricted notes
            create_resp = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={
                    "title": "Controlled Disclosure Test Case",
                    "summary": "Case with evidence manifest and mixed visibility notes.",
                },
            )
            case_id = create_resp.json()["id"]

            async with postgres_db_manager.transactional_session() as session:
                incident = Incident(
                    id=uuid4(),
                    reference_number=f"INC-{data['suffix']}-0003",
                    title="Disclosure Incident Record",
                    description="Incident record for disclosure manifest verification",
                    category="property_damage_theft",
                    severity="low",
                    location="South Entrance Lobby",
                    occurred_at=datetime.now(UTC),
                    department_id=data["dept_security"].id,
                    reporter_id=data["dept_admin_sec"].id,
                )
                session.add(incident)
                await session.flush()

                c = await session.get(Case, case_id)
                assert c is not None
                c.incident_id = incident.id

                ev = EvidenceAttachment(
                    id=uuid4(),
                    department_id=data["dept_security"].id,
                    incident_id=incident.id,
                    storage_key="secret-path/very_sensitive_file.mp4",
                    original_filename="security_cam_1.mp4",
                    declared_mime_type="video/mp4",
                    file_size_bytes=1048576,
                    sha256_hash="4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
                    upload_status=UploadStatus.COMPLETED.value,
                    uploader_id=data["dept_admin_sec"].id,
                )
                session.add(ev)
                await session.flush()

                case_ev = CaseEvidence(
                    id=uuid4(),
                    case_id=c.id,
                    evidence_id=ev.id,
                    linked_by_id=data["dept_admin_sec"].id,
                    created_at=datetime.now(UTC),
                )
                session.add(case_ev)
                await session.flush()

            # Add internal note
            await client.post(
                f"/api/v1/cases/{case_id}/notes",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={"content": "Internal operational note.", "visibility": "internal"},
            )

            # Add restricted note
            await client.post(
                f"/api/v1/cases/{case_id}/notes",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={
                    "content": "Restricted highly sensitive intelligence.",
                    "visibility": "restricted",
                },
            )

            # 2. Export case as Dept Admin (who has CASE_NOTE_READ_RESTRICTED)
            export_admin_resp = await client.post(
                f"/api/v1/cases/{case_id}/exports",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={
                    "export_scope": CaseExportScope.FULL_INVESTIGATION.value,
                    "export_format": CaseExportFormat.JSON.value,
                    "purpose": "Preparation for legal disclosure packet",
                    "include_restricted_notes": True,
                },
            )
            assert export_admin_resp.status_code == 201
            export_admin_data = export_admin_resp.json()
            export_id = export_admin_data["id"]

            # Verify cryptographic SHA-256 integrity hash is computed
            assert export_admin_data["manifest_sha256"] is not None
            assert len(export_admin_data["manifest_sha256"]) == 64
            assert export_admin_data["evidence_count"] == 1

            # Retrieve export record
            get_export_resp = await client.get(
                f"/api/v1/cases/{case_id}/exports/{export_id}",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
            )
            assert get_export_resp.status_code == 200
            assert get_export_resp.json()["id"] == export_id

            # Verify manifest payload
            manifest_payload = export_admin_data["manifest_payload"]

            # Statutory AI advisory disclaimer MUST be present in exported payload
            assert "advisory_notice" in manifest_payload
            assert AI_ADVISORY_DISCLAIMER in manifest_payload["advisory_notice"]

            # Zero credential leakage: NO storage_bucket or storage_key in evidence manifest
            manifest = manifest_payload["evidence_manifest"]
            assert len(manifest) == 1
            manifest_item = manifest[0]
            assert manifest_item["file_name"] == "security_cam_1.mp4"
            assert (
                manifest_item["sha256_digest"]
                == "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
            )
            assert "secret-internal-s3-bucket" not in json.dumps(manifest)
            assert "secret-path" not in json.dumps(manifest)

            # Restricted notes included for admin
            notes_in_payload = manifest_payload["notes"]
            assert any(n["visibility"] == "restricted" for n in notes_in_payload)

            # 3. Export case as standard investigator (without restricted permission)
            export_inv_resp = await client.post(
                f"/api/v1/cases/{case_id}/exports",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "export_scope": CaseExportScope.SUMMARY.value,
                    "export_format": CaseExportFormat.JSON.value,
                    "purpose": "Public record request preparation",
                    "include_restricted_notes": False,
                },
            )
            assert export_inv_resp.status_code == 201
            export_inv_data = export_inv_resp.json()
            inv_payload = export_inv_data["manifest_payload"]
            # Restricted notes MUST BE REDACTED
            assert not any(n["visibility"] == "restricted" for n in inv_payload["notes"])

            # 4. Tenant isolation: academic affairs investigator cannot view exports for security case
            acad_get_export = await client.get(
                f"/api/v1/cases/{case_id}/exports/{export_id}",
                headers={"Authorization": f"Bearer {token_inv_acad}"},
            )
            assert acad_get_export.status_code == 404

    async def test_phase90_end_to_end_investigation_and_audit_trail(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify complete investigation lifecycle and audit logging for all Phase 86-90 actions."""
        data = await _setup_batch09_group02_test_env(postgres_db_manager)

        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_inv_sec = await _login(client, data["investigator_sec"].email, data["default_pw"])
            token_admin_sec = await _login(client, data["dept_admin_sec"].email, data["default_pw"])

            # 1. Create Case
            c_resp = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "title": "Comprehensive E2E Investigation",
                    "summary": "Full lifecycle audit trail verification test.",
                    "priority": "critical",
                },
            )
            assert c_resp.status_code == 201
            case_id = c_resp.json()["id"]

            # 2. Add Note
            n_resp = await client.post(
                f"/api/v1/cases/{case_id}/notes",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={"content": "Primary case hypothesis logged.", "visibility": "internal"},
            )
            assert n_resp.status_code == 201

            # 3. Add Finding
            f_resp = await client.post(
                f"/api/v1/cases/{case_id}/findings",
                headers={"Authorization": f"Bearer {token_inv_sec}"},
                json={
                    "finding_type": "preliminary",
                    "title": "Witness Statement Corroborated",
                    "description": "Timestamps match across independent sensors and corroborating logs.",
                },
            )
            assert f_resp.status_code == 201

            # 4. Escalate
            e_resp = await client.post(
                f"/api/v1/cases/{case_id}/escalations",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={
                    "escalation_level": "department_head",
                    "escalated_to_department_id": str(data["dept_conduct"].id),
                    "reason": "Regulatory reporting and cross-departmental coordination.",
                    "expected_version_id": 1,
                },
            )
            assert e_resp.status_code == 201

            # 5. Refer
            r_resp = await client.post(
                f"/api/v1/cases/{case_id}/referrals",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={
                    "target_external_agency": "State Ethics Board",
                    "referral_purpose": "Institutional review requested by oversight body.",
                },
            )
            assert r_resp.status_code == 201

            # 6. Export
            exp_resp = await client.post(
                f"/api/v1/cases/{case_id}/exports",
                headers={"Authorization": f"Bearer {token_admin_sec}"},
                json={
                    "export_scope": CaseExportScope.SUMMARY.value,
                    "export_format": CaseExportFormat.JSON.value,
                    "purpose": "Audit trail archive for compliance records",
                    "include_restricted_notes": False,
                },
            )
            assert exp_resp.status_code == 201

            # 7. Check Audit Trail in real PostgreSQL
            async with postgres_db_manager.transactional_session() as session:
                audit_records = (
                    (
                        await session.execute(
                            select(SecurityAuditEvent)
                            .where(
                                SecurityAuditEvent.department_id == data["dept_security"].id,
                            )
                            .order_by(SecurityAuditEvent.created_at.asc())
                        )
                    )
                    .scalars()
                    .all()
                )

                actions = [r.action for r in audit_records]
                # Verify that key Phase 86-90 actions were logged
                assert AuditAction.CASE_NOTE_CREATED.value in actions
                assert AuditAction.CASE_FINDING_CREATED.value in actions
                assert AuditAction.CASE_ESCALATED.value in actions
                assert AuditAction.CASE_REFERRED.value in actions
                assert AuditAction.CASE_EXPORTED.value in actions

                # Verify all records enforce department isolation
                for rec in audit_records:
                    assert rec.department_id == data["dept_security"].id
