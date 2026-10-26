"""Live PostgreSQL Integration Tests for Batch 06 Group 01 (Phases 51-55).

Tests:
- Phase 51: Server-side SHA-256 calculation, trusted hash persistence, object verification.
- Phase 52: Ingestion timestamps, uploader identity, network provenance, separating observed facts from user declarations.
- Phase 53: Append-only chain-of-custody ledger, monotonic sequence numbering, hash chaining, compensating events.
- Phase 54: Authorized integrity verification, tamper detection, missing storage handling, mandatory disclaimer.
- Phase 55: Severity levels, deterministic configurable routing, safe defaults, authorized department overrides, routing history.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest

from backend.app.config.settings import Settings
from backend.app.core.evidence import INTEGRITY_DISCLAIMER
from backend.app.core.identity import AccountStatus, RoleCode
from backend.app.infrastructure.database import DatabaseSessionManager
from backend.app.infrastructure.storage import InMemoryStorageClient
from backend.app.main import create_app
from backend.app.models.department import Department
from backend.app.models.user import User
from backend.app.repositories.identity import (
    DepartmentRepository,
    RoleRepository,
    UserRepository,
)
from backend.app.services.password import PasswordService


async def _setup_batch06_test_env(
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
        dept_conduct = await dept_repo.create(
            Department(code=f"COND-{suffix}", name=f"Student Conduct {suffix}", is_active=True)
        )
        dept_inactive = await dept_repo.create(
            Department(
                code=f"DIS-{suffix}",
                name=f"Deactivated Dept {suffix}",
                is_active=False,
                deactivated_at=datetime.now(UTC),
            )
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

        investigator_security = await user_repo.create(
            User(
                email=f"investigator_sec_{suffix.lower()}@ewitness.edu",
                full_name="Security Investigator",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_security.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        dept_admin_academic = await user_repo.create(
            User(
                email=f"admin_acad_{suffix.lower()}@ewitness.edu",
                full_name="Academic Admin",
                role_id=roles[RoleCode.DEPT_ADMIN].id,
                department_id=dept_academic.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        student_reporter = await user_repo.create(
            User(
                email=f"student_rep_{suffix.lower()}@ewitness.edu",
                full_name="Student Reporter",
                role_id=roles[RoleCode.STUDENT].id,
                department_id=dept_security.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        student_other = await user_repo.create(
            User(
                email=f"student_other_{suffix.lower()}@ewitness.edu",
                full_name="Unrelated Student",
                role_id=roles[RoleCode.STUDENT].id,
                department_id=dept_conduct.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        return {
            "password": default_pw,
            "dept_security": dept_security,
            "dept_academic": dept_academic,
            "dept_conduct": dept_conduct,
            "dept_inactive": dept_inactive,
            "super_admin": super_admin,
            "dept_admin_security": dept_admin_security,
            "investigator_security": investigator_security,
            "dept_admin_academic": dept_admin_academic,
            "student_reporter": student_reporter,
            "student_other": student_other,
        }


async def _get_token(client: httpx.AsyncClient, email: str, password: str) -> str:
    """Helper to authenticate and return a JWT access token."""
    resp = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, f"Login failed for {email}: {resp.text}"
    return str(resp.json()["access_token"])


@pytest.mark.integration
class TestBatch06Group01Integration:
    """Phases 51-55: Full live PostgreSQL integration tests for custody, provenance, integrity, and routing."""

    async def test_end_to_end_evidence_custody_provenance_and_integrity(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Phases 51-54: Verify SHA-256 calculation, provenance separation, custody ledger, and tamper report."""
        env = await _setup_batch06_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        shared_storage = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.storage_client = shared_storage

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
            headers={"User-Agent": "Batch06TestAgent/1.0", "X-Forwarded-For": "198.51.100.42"},
        ) as client:
            token_student = await _get_token(client, env["student_reporter"].email, env["password"])
            token_admin = await _get_token(
                client, env["dept_admin_security"].email, env["password"]
            )
            token_other = await _get_token(client, env["student_other"].email, env["password"])

            headers_student = {"Authorization": f"Bearer {token_student}"}
            headers_admin = {"Authorization": f"Bearer {token_admin}"}
            headers_other = {"Authorization": f"Bearer {token_other}"}

            # 1. Create incident with severity
            resp_inc = await client.post(
                "/api/v1/incidents",
                json={
                    "title": "Broken window in science building",
                    "description": "Vandalism observed with shattered double-pane glass.",
                    "category": "property_damage_theft",
                    "severity": "high",
                    "location": "Science Wing Floor 2",
                    "occurred_at": (datetime.now(UTC) - timedelta(minutes=45)).isoformat(),
                },
                headers=headers_student,
            )
            assert resp_inc.status_code == 201
            incident_data = resp_inc.json()
            assert incident_data["severity"] == "high"
            incident_id = incident_data["id"]

            # 2. Authorize single-part upload session with client_reported_at
            png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
            expected_hash = hashlib.sha256(png_bytes).hexdigest()
            client_reported_timestamp = (datetime.now(UTC) - timedelta(minutes=10)).isoformat()

            resp_sess = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/upload-session",
                json={
                    "filename": "broken_window.png",
                    "content_type": "image/png",
                    "file_size_bytes": len(png_bytes),
                    "client_reported_at": client_reported_timestamp,
                },
                headers=headers_student,
            )
            assert resp_sess.status_code == 201
            session_data = resp_sess.json()
            session_id = session_data["session_id"]
            storage_key = session_data["storage_key"]

            # Write genuine bytes to storage
            await shared_storage.put_object(storage_key, png_bytes, "image/png")

            # 3. Complete upload session (Phase 51 & 52: server-side sha256 + ingested_at + provenance)
            resp_comp = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/upload-sessions/{session_id}/complete",
                headers=headers_student,
            )
            assert resp_comp.status_code == 200
            comp_data = resp_comp.json()
            attachment_id = comp_data["id"]
            assert comp_data["sha256_hash"] == expected_hash

            # 4. Phase 52: Inspect provenance endpoint
            resp_prov = await client.get(
                f"/api/v1/incidents/{incident_id}/attachments/{attachment_id}/provenance",
                headers=headers_student,
            )
            assert resp_prov.status_code == 200
            prov_data = resp_prov.json()
            assert prov_data["attachment_id"] == attachment_id
            assert prov_data["observed_facts"]["sha256_hash"] == expected_hash
            assert prov_data["observed_facts"]["file_size_bytes"] == len(png_bytes)
            assert prov_data["observed_facts"]["uploader_ip"] in ("127.0.0.1", "198.51.100.42")
            assert "Batch06TestAgent" in prov_data["observed_facts"]["user_agent"]
            assert prov_data["observed_facts"]["ingested_at"] is not None
            assert prov_data["user_declarations"]["original_filename"] == "broken_window.png"
            assert prov_data["user_declarations"]["client_reported_at"] == client_reported_timestamp

            # Cross-tenant / unrelated student rejected from viewing provenance (anti-enumeration 404)
            resp_prov_unauthorized = await client.get(
                f"/api/v1/incidents/{incident_id}/attachments/{attachment_id}/provenance",
                headers=headers_other,
            )
            assert resp_prov_unauthorized.status_code == 404

            # 5. Phase 53: Chain of Custody ledger endpoint
            resp_custody = await client.get(
                f"/api/v1/incidents/{incident_id}/attachments/{attachment_id}/custody",
                headers=headers_student,
            )
            assert resp_custody.status_code == 200
            custody_events = resp_custody.json()
            # Expect INGESTED (seq 1) and SEALED (seq 2)
            assert len(custody_events) >= 2
            assert custody_events[0]["sequence_number"] == 1
            assert custody_events[0]["action_type"] == "ingested"
            assert custody_events[0]["previous_event_hash"] is None
            assert custody_events[0]["event_hash"] is not None

            assert custody_events[1]["sequence_number"] == 2
            assert custody_events[1]["action_type"] == "sealed"
            assert custody_events[1]["previous_event_hash"] == custody_events[0]["event_hash"]

            # 6. Phase 54: Authorized integrity verification (Clean match)
            resp_verify = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/{attachment_id}/verify-integrity",
                headers=headers_admin,
            )
            assert resp_verify.status_code == 200
            verify_data = resp_verify.json()
            assert verify_data["status"] == "verified_match"
            assert verify_data["computed_sha256"] == expected_hash
            assert verify_data["stored_sha256"] == expected_hash
            assert verify_data["is_tampered"] is False
            assert verify_data["disclaimer"] == INTEGRITY_DISCLAIMER

            # Verify that HASH_VERIFIED was appended to the custody ledger
            resp_custody2 = await client.get(
                f"/api/v1/incidents/{incident_id}/attachments/{attachment_id}/custody",
                headers=headers_admin,
            )
            custody_events2 = resp_custody2.json()
            assert len(custody_events2) == 3
            assert custody_events2[2]["sequence_number"] == 3
            assert custody_events2[2]["action_type"] == "hash_verified"
            assert custody_events2[2]["previous_event_hash"] == custody_events[1]["event_hash"]

            # 7. Phase 53: Compensating custody correction
            target_event_id = custody_events[0]["id"]
            # Student forbidden from creating compensating event
            resp_comp_student = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/{attachment_id}/custody/compensate",
                json={
                    "target_event_id": str(target_event_id),
                    "justification_reason": "Correcting metadata note error",
                    "details": "Added corrected incident reference note",
                },
                headers=headers_student,
            )
            assert resp_comp_student.status_code == 403

            # Department Admin can create compensating event
            resp_comp_admin = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/{attachment_id}/custody/compensate",
                json={
                    "target_event_id": str(target_event_id),
                    "justification_reason": "Administrative correction for initial timestamp verification",
                    "details": "Verified against physical police intake sheet",
                },
                headers=headers_admin,
            )
            assert resp_comp_admin.status_code == 201
            comp_event = resp_comp_admin.json()
            assert comp_event["sequence_number"] == 4
            assert comp_event["action_type"] == "compensating_correction"
            assert comp_event["compensates_event_id"] == str(target_event_id)
            assert (
                comp_event["compensation_reason"]
                == "Administrative correction for initial timestamp verification"
            )
            assert comp_event["previous_event_hash"] == custody_events2[2]["event_hash"]

            # 8. Phase 54: Tamper Detection (Modify bytes in storage directly)
            tampered_bytes = png_bytes + b"\x00TAMPERED"
            await shared_storage.put_object(storage_key, tampered_bytes, "image/png")

            resp_verify_tampered = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/{attachment_id}/verify-integrity",
                headers=headers_admin,
            )
            assert resp_verify_tampered.status_code == 200
            tamper_report = resp_verify_tampered.json()
            assert tamper_report["status"] == "tamper_detected"
            assert tamper_report["is_tampered"] is True
            assert tamper_report["computed_sha256"] != expected_hash
            assert tamper_report["computed_sha256"] == hashlib.sha256(tampered_bytes).hexdigest()

            # Custody ledger should now record TAMPER_DETECTED
            resp_custody3 = await client.get(
                f"/api/v1/incidents/{incident_id}/attachments/{attachment_id}/custody",
                headers=headers_admin,
            )
            custody_events3 = resp_custody3.json()
            assert len(custody_events3) == 5
            assert custody_events3[4]["sequence_number"] == 5
            assert custody_events3[4]["action_type"] == "tamper_detected"

            # 9. Phase 54: Storage Missing Detection (Delete object from storage)
            await shared_storage.delete_object(storage_key)

            resp_verify_missing = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/{attachment_id}/verify-integrity",
                headers=headers_admin,
            )
            assert resp_verify_missing.status_code == 200
            missing_report = resp_verify_missing.json()
            assert missing_report["status"] == "storage_missing"
            assert missing_report["computed_sha256"] is None

    async def test_deterministic_routing_override_and_history(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Phase 55: Verify deterministic intake routing, overrides, history, and filtering."""
        env = await _setup_batch06_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            token_student = await _get_token(client, env["student_reporter"].email, env["password"])
            token_sec_admin = await _get_token(
                client, env["dept_admin_security"].email, env["password"]
            )
            token_acad_admin = await _get_token(
                client, env["dept_admin_academic"].email, env["password"]
            )
            token_super = await _get_token(client, env["super_admin"].email, env["password"])

            headers_student = {"Authorization": f"Bearer {token_student}"}
            headers_sec_admin = {"Authorization": f"Bearer {token_sec_admin}"}
            headers_acad_admin = {"Authorization": f"Bearer {token_acad_admin}"}
            headers_super = {"Authorization": f"Bearer {token_super}"}

            # 1. Deterministic intake routing for safety hazard -> Security dept
            resp_sec = await client.post(
                "/api/v1/incidents",
                json={
                    "title": "Gas leak smell in dorm basement",
                    "description": "Strong sulfur odor near main boiler room.",
                    "category": "safety_hazard",
                    "severity": "critical",
                    "location": "Basement West",
                    "occurred_at": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
                },
                headers=headers_student,
            )
            assert resp_sec.status_code == 201
            sec_inc = resp_sec.json()
            assert sec_inc["department_id"] == str(env["dept_security"].id)
            assert sec_inc["severity"] == "critical"
            sec_inc_id = sec_inc["id"]

            # Inspect routing history
            resp_hist1 = await client.get(
                f"/api/v1/incidents/{sec_inc_id}/routing-history",
                headers=headers_sec_admin,
            )
            assert resp_hist1.status_code == 200
            hist1 = resp_hist1.json()
            assert len(hist1) == 1
            assert hist1[0]["routing_type"] == "system_rule"
            assert hist1[0]["target_department_id"] == str(env["dept_security"].id)

            # 2. Deterministic routing for academic misconduct -> Academic dept
            resp_acad = await client.post(
                "/api/v1/incidents",
                json={
                    "title": "Plagiarism allegation in final term paper",
                    "description": "Evidence of LLM copy-paste detected.",
                    "category": "academic_misconduct",
                    "severity": "low",
                    "location": "Online Submission",
                    "occurred_at": (datetime.now(UTC) - timedelta(hours=2)).isoformat(),
                },
                headers=headers_student,
            )
            assert resp_acad.status_code == 201
            acad_inc = resp_acad.json()
            assert acad_inc["department_id"] == str(env["dept_academic"].id)
            assert acad_inc["severity"] == "low"
            acad_inc_id = acad_inc["id"]

            # 3. Authorized override: Student is forbidden
            resp_override_student = await client.post(
                f"/api/v1/incidents/{sec_inc_id}/route",
                json={
                    "target_department_id": str(env["dept_conduct"].id),
                    "reason": "Re-routing to conduct office",
                },
                headers=headers_student,
            )
            assert resp_override_student.status_code == 403

            # 4. Authorized override: Security Admin routes to Student Conduct
            resp_override_sec = await client.post(
                f"/api/v1/incidents/{sec_inc_id}/route",
                json={
                    "target_department_id": str(env["dept_conduct"].id),
                    "reason": "Investigative findings indicate non-hazardous student prank",
                },
                headers=headers_sec_admin,
            )
            assert resp_override_sec.status_code == 200
            updated_inc = resp_override_sec.json()
            assert updated_inc["department_id"] == str(env["dept_conduct"].id)

            # Check routing history after override
            resp_hist2 = await client.get(
                f"/api/v1/incidents/{sec_inc_id}/routing-history",
                headers=headers_super,
            )
            assert resp_hist2.status_code == 200
            hist2 = resp_hist2.json()
            assert len(hist2) == 2
            assert hist2[1]["routing_type"] == "authorized_override"
            assert hist2[1]["source_department_id"] == str(env["dept_security"].id)
            assert hist2[1]["target_department_id"] == str(env["dept_conduct"].id)
            assert (
                hist2[1]["reason"] == "Investigative findings indicate non-hazardous student prank"
            )

            # 5. Reject re-routing to same department (422)
            resp_same = await client.post(
                f"/api/v1/incidents/{sec_inc_id}/route",
                json={
                    "target_department_id": str(env["dept_conduct"].id),
                    "reason": "Attempting redundant route",
                },
                headers=headers_super,
            )
            assert resp_same.status_code == 422
            assert resp_same.json()["error"]["code"] == "SAME_DEPARTMENT_ROUTING"
            assert "already assigned" in resp_same.json()["error"]["message"].lower()

            # 6. Reject re-routing to inactive department (422)
            resp_inactive = await client.post(
                f"/api/v1/incidents/{sec_inc_id}/route",
                json={
                    "target_department_id": str(env["dept_inactive"].id),
                    "reason": "Route to disabled department",
                },
                headers=headers_super,
            )
            assert resp_inactive.status_code == 422
            assert resp_inactive.json()["error"]["code"] == "INACTIVE_DEPARTMENT_TARGET"
            assert "inactive" in resp_inactive.json()["error"]["message"].lower()

            # 7. Department isolation: Academic Admin cannot route Security incident (403)
            resp_cross = await client.post(
                f"/api/v1/incidents/{sec_inc_id}/route",
                json={
                    "target_department_id": str(env["dept_academic"].id),
                    "reason": "Unauthorized cross-department takeover attempt",
                },
                headers=headers_acad_admin,
            )
            assert resp_cross.status_code == 403

            # 8. Incident listing query filter by severity
            resp_filter_crit = await client.get(
                "/api/v1/incidents?severity=critical",
                headers=headers_super,
            )
            assert resp_filter_crit.status_code == 200
            crit_items = resp_filter_crit.json()["items"]
            assert any(item["id"] == sec_inc_id for item in crit_items)
            assert not any(item["id"] == acad_inc_id for item in crit_items)

            resp_filter_low = await client.get(
                "/api/v1/incidents?severity=low",
                headers=headers_super,
            )
            assert resp_filter_low.status_code == 200
            low_items = resp_filter_low.json()["items"]
            assert any(item["id"] == acad_inc_id for item in low_items)
            assert not any(item["id"] == sec_inc_id for item in low_items)
