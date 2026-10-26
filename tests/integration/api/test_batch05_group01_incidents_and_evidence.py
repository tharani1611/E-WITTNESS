"""Live PostgreSQL Integration Tests for Batch 05 Group 01 (Phases 41-45).

Tests:
- Phase 41: Incident models, timestamps, location, valid categories, status lifecycle.
- Phase 42: Incident submission API, validation, reference numbers, ownership, isolation.
- Phase 43: Incident attachments and evidence metadata models.
- Phase 44: Secure upload authorization and upload-session generation.
- Phase 45: Object storage abstraction and private access policies.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest

from backend.app.config.settings import Settings
from backend.app.core.identity import AccountStatus, RoleCode
from backend.app.infrastructure.database import DatabaseSessionManager
from backend.app.main import create_app
from backend.app.models.department import Department
from backend.app.models.user import User
from backend.app.repositories.identity import (
    DepartmentRepository,
    RoleRepository,
    UserRepository,
)
from backend.app.services.password import PasswordService


async def _setup_batch05_test_env(
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

        dept_alpha = await dept_repo.create(
            Department(code=f"DEPT-A-{suffix}", name=f"Dept Alpha {suffix}", is_active=True)
        )
        dept_beta = await dept_repo.create(
            Department(code=f"DEPT-B-{suffix}", name=f"Dept Beta {suffix}", is_active=True)
        )
        dept_inactive = await dept_repo.create(
            Department(
                code=f"DEPT-INACT-{suffix}",
                name=f"Inactive Dept {suffix}",
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

        dept_admin_alpha = await user_repo.create(
            User(
                email=f"admin_alpha_{suffix.lower()}@ewitness.edu",
                full_name="Alpha Dept Admin",
                role_id=roles[RoleCode.DEPT_ADMIN].id,
                department_id=dept_alpha.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        dept_admin_beta = await user_repo.create(
            User(
                email=f"admin_beta_{suffix.lower()}@ewitness.edu",
                full_name="Beta Dept Admin",
                role_id=roles[RoleCode.DEPT_ADMIN].id,
                department_id=dept_beta.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        investigator_alpha = await user_repo.create(
            User(
                email=f"investigator_alpha_{suffix.lower()}@ewitness.edu",
                full_name="Alpha Investigator",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_alpha.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        student_alpha = await user_repo.create(
            User(
                email=f"student_alpha_{suffix.lower()}@ewitness.edu",
                full_name="Student Alpha",
                role_id=roles[RoleCode.STUDENT].id,
                department_id=dept_alpha.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        student_beta = await user_repo.create(
            User(
                email=f"student_beta_{suffix.lower()}@ewitness.edu",
                full_name="Student Beta",
                role_id=roles[RoleCode.STUDENT].id,
                department_id=dept_beta.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        return {
            "password": default_pw,
            "dept_alpha": dept_alpha,
            "dept_beta": dept_beta,
            "dept_inactive": dept_inactive,
            "super_admin": super_admin,
            "dept_admin_alpha": dept_admin_alpha,
            "dept_admin_beta": dept_admin_beta,
            "investigator_alpha": investigator_alpha,
            "student_alpha": student_alpha,
            "student_beta": student_beta,
        }


async def _get_token(client: httpx.AsyncClient, email: str, password: str) -> str:
    """Helper to authenticate and return a JWT access token."""
    resp = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, f"Login failed for {email}: {resp.text}"
    return str(resp.json()["access_token"])


@pytest.mark.integration
class TestIncidentSubmissionAndValidationIntegration:
    """Phases 41 & 42: Incident submission endpoints, validation, reference numbers, and scoping."""

    async def test_student_submits_incident_successfully(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_batch05_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            token = await _get_token(client, env["student_alpha"].email, env["password"])
            headers = {"Authorization": f"Bearer {token}"}

            occurred = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
            payload = {
                "title": "Lab microscope theft",
                "description": "Two high-resolution lenses were stolen from the physics laboratory.",
                "category": "property_damage_theft",
                "location": "Physics Hall, Room 302",
                "occurred_at": occurred,
            }

            resp = await client.post("/api/v1/incidents", json=payload, headers=headers)
            assert resp.status_code == 201, f"Submission failed: {resp.text}"
            data = resp.json()

            assert data["title"] == payload["title"]
            assert data["category"] == "property_damage_theft"
            assert data["status"] == "submitted"
            assert data["location"] == payload["location"]
            assert data["reporter_id"] == str(env["student_alpha"].id)
            assert data["department_id"] == str(env["dept_alpha"].id)
            assert re.match(r"^INC-\d{4}-[0-9A-F]{8}$", data["reference_number"])

    async def test_incident_submission_validation_rejects_invalid_inputs(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_batch05_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            token = await _get_token(client, env["student_alpha"].email, env["password"])
            headers = {"Authorization": f"Bearer {token}"}

            # 1. Future timestamp rejected
            future_time = (datetime.now(UTC) + timedelta(days=1)).isoformat()
            resp_future = await client.post(
                "/api/v1/incidents",
                json={
                    "title": "Future incident report",
                    "description": "This occurs tomorrow.",
                    "category": "other",
                    "location": "Campus Center",
                    "occurred_at": future_time,
                },
                headers=headers,
            )
            assert resp_future.status_code == 422

            # 2. Short title rejected
            resp_title = await client.post(
                "/api/v1/incidents",
                json={
                    "title": "Abc",
                    "description": "Valid long enough description.",
                    "category": "other",
                    "location": "Campus Center",
                    "occurred_at": datetime.now(UTC).isoformat(),
                },
                headers=headers,
            )
            assert resp_title.status_code == 422

            # 3. Invalid category rejected
            resp_cat = await client.post(
                "/api/v1/incidents",
                json={
                    "title": "Valid Incident Title",
                    "description": "Valid long enough description.",
                    "category": "fake_category",
                    "location": "Campus Center",
                    "occurred_at": datetime.now(UTC).isoformat(),
                },
                headers=headers,
            )
            assert resp_cat.status_code == 422

            # 4. Cross-department report without permission rejected
            resp_cross = await client.post(
                "/api/v1/incidents",
                json={
                    "title": "Cross dept report attempt",
                    "description": "Reporting for Department Beta.",
                    "category": "other",
                    "location": "Campus Center",
                    "occurred_at": datetime.now(UTC).isoformat(),
                    "department_id": str(env["dept_beta"].id),
                },
                headers=headers,
            )
            assert resp_cross.status_code in {400, 422}


@pytest.mark.integration
class TestIncidentScopingAndEnumerationDefenseIntegration:
    """Phase 42: Department isolation, submitter scoping, and 404 anti-enumeration."""

    async def test_cross_department_and_ownership_isolation(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_batch05_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            student_a_token = await _get_token(client, env["student_alpha"].email, env["password"])
            student_b_token = await _get_token(client, env["student_beta"].email, env["password"])
            admin_a_token = await _get_token(client, env["dept_admin_alpha"].email, env["password"])
            admin_b_token = await _get_token(client, env["dept_admin_beta"].email, env["password"])
            super_admin_token = await _get_token(client, env["super_admin"].email, env["password"])

            # 1. Student A submits incident in Dept Alpha
            resp_create = await client.post(
                "/api/v1/incidents",
                json={
                    "title": "Incident in Department Alpha",
                    "description": "Details regarding incident in department alpha.",
                    "category": "safety_hazard",
                    "location": "Alpha Building",
                    "occurred_at": datetime.now(UTC).isoformat(),
                },
                headers={"Authorization": f"Bearer {student_a_token}"},
            )
            assert resp_create.status_code == 201
            created_data = resp_create.json()
            incident_id = created_data["id"]
            reference_number = created_data["reference_number"]

            # 2. Student A sees the incident in their listing
            resp_list_a = await client.get(
                "/api/v1/incidents",
                headers={"Authorization": f"Bearer {student_a_token}"},
            )
            assert resp_list_a.status_code == 200
            items_a = resp_list_a.json()["items"]
            assert any(item["id"] == incident_id for item in items_a)

            # 3. Student B does NOT see Student A's incident in their listing
            resp_list_b = await client.get(
                "/api/v1/incidents",
                headers={"Authorization": f"Bearer {student_b_token}"},
            )
            assert resp_list_b.status_code == 200
            items_b = resp_list_b.json()["items"]
            assert not any(item["id"] == incident_id for item in items_b)

            # 4. Student B querying Student A's incident by ID receives 404 (Anti-enumeration)
            resp_get_b = await client.get(
                f"/api/v1/incidents/{incident_id}",
                headers={"Authorization": f"Bearer {student_b_token}"},
            )
            assert resp_get_b.status_code == 404

            # 5. Dept Admin Beta querying Student A's incident receives 404
            resp_admin_b = await client.get(
                f"/api/v1/incidents/{incident_id}",
                headers={"Authorization": f"Bearer {admin_b_token}"},
            )
            assert resp_admin_b.status_code == 404

            # 6. Dept Admin Beta looking up by reference number receives 404
            resp_ref_b = await client.get(
                f"/api/v1/incidents/reference/{reference_number}",
                headers={"Authorization": f"Bearer {admin_b_token}"},
            )
            assert resp_ref_b.status_code == 404

            # 7. Dept Admin Alpha CAN view Student A's incident
            resp_admin_a = await client.get(
                f"/api/v1/incidents/{incident_id}",
                headers={"Authorization": f"Bearer {admin_a_token}"},
            )
            assert resp_admin_a.status_code == 200
            assert resp_admin_a.json()["id"] == incident_id

            # 8. Super Admin CAN view Student A's incident
            resp_super = await client.get(
                f"/api/v1/incidents/{incident_id}",
                headers={"Authorization": f"Bearer {super_admin_token}"},
            )
            assert resp_super.status_code == 200
            assert resp_super.json()["id"] == incident_id


@pytest.mark.integration
class TestIncidentLifecycleAndEvidenceUploadIntegration:
    """Phases 42, 44 & 45: Status transitions, update lockouts, and upload sessions."""

    async def test_status_transitions_and_upload_session_lifecycle(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_batch05_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            student_token = await _get_token(client, env["student_alpha"].email, env["password"])
            admin_token = await _get_token(client, env["dept_admin_alpha"].email, env["password"])
            headers_student = {"Authorization": f"Bearer {student_token}"}
            headers_admin = {"Authorization": f"Bearer {admin_token}"}

            # 1. Create incident as student
            resp_inc = await client.post(
                "/api/v1/incidents",
                json={
                    "title": "Damage to dormitory entrance",
                    "description": "Graffiti painted on the north entrance door.",
                    "category": "property_damage_theft",
                    "location": "North Dormitory Entrance",
                    "occurred_at": datetime.now(UTC).isoformat(),
                },
                headers=headers_student,
            )
            assert resp_inc.status_code == 201
            incident_id = resp_inc.json()["id"]

            # 2. Submitter can update incident while in SUBMITTED status
            resp_patch = await client.patch(
                f"/api/v1/incidents/{incident_id}",
                json={"title": "Graffiti on north dormitory entrance"},
                headers=headers_student,
            )
            assert resp_patch.status_code == 200
            assert resp_patch.json()["title"] == "Graffiti on north dormitory entrance"

            # 3. Submitter requests upload session for evidence photo
            resp_upload = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/upload-session",
                json={
                    "filename": "graffiti_photo.jpg",
                    "content_type": "image/jpeg",
                    "file_size_bytes": 1048576,
                },
                headers=headers_student,
            )
            assert resp_upload.status_code == 201
            session_data = resp_upload.json()
            session_id = session_data["session_id"]
            assert session_data["upload_method"] == "PUT"
            assert "upload_url" in session_data
            assert session_data["original_filename"] == "graffiti_photo.jpg"

            # 4. Verify upload session inspection
            resp_check = await client.get(
                f"/api/v1/incidents/attachments/upload-sessions/{session_id}",
                headers=headers_student,
            )
            assert resp_check.status_code == 200
            assert resp_check.json()["session_id"] == session_id

            # 5. Non-admin (student) cannot transition status
            resp_denied = await client.post(
                f"/api/v1/incidents/{incident_id}/status",
                json={"status": "triaged", "reason": "Self-triage attempt"},
                headers=headers_student,
            )
            assert resp_denied.status_code == 403

            # 6. Dept Admin transitions: submitted -> triaged -> under_investigation -> closed
            resp_triage = await client.post(
                f"/api/v1/incidents/{incident_id}/status",
                json={"status": "triaged", "reason": "Reviewed by housing coordinator"},
                headers=headers_admin,
            )
            assert resp_triage.status_code == 200
            assert resp_triage.json()["status"] == "triaged"

            # 7. Submitter can no longer edit after status transition
            resp_patch_locked = await client.patch(
                f"/api/v1/incidents/{incident_id}",
                json={"title": "Should fail after triage"},
                headers=headers_student,
            )
            assert resp_patch_locked.status_code == 422
            assert resp_patch_locked.json()["error"]["code"] == "INCIDENT_UPDATE_LOCKED"

            # 8. Progress to closed
            resp_investigate = await client.post(
                f"/api/v1/incidents/{incident_id}/status",
                json={"status": "under_investigation"},
                headers=headers_admin,
            )
            assert resp_investigate.status_code == 200

            resp_close = await client.post(
                f"/api/v1/incidents/{incident_id}/status",
                json={"status": "closed", "reason": "Repair order completed"},
                headers=headers_admin,
            )
            assert resp_close.status_code == 200
            assert resp_close.json()["status"] == "closed"

            # 9. Closed incident rejects further status transitions
            resp_reopen = await client.post(
                f"/api/v1/incidents/{incident_id}/status",
                json={"status": "submitted"},
                headers=headers_admin,
            )
            assert resp_reopen.status_code == 422

            # 10. Closed incident rejects new upload sessions
            resp_upload_closed = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/upload-session",
                json={
                    "filename": "late_photo.jpg",
                    "content_type": "image/jpeg",
                    "file_size_bytes": 1024,
                },
                headers=headers_student,
            )
            assert resp_upload_closed.status_code == 422
            assert resp_upload_closed.json()["error"]["code"] == "INCIDENT_CLOSED_ATTACHMENT"

            # 11. Query attachments for the incident
            resp_atts = await client.get(
                f"/api/v1/incidents/{incident_id}/attachments",
                headers=headers_admin,
            )
            assert resp_atts.status_code == 200
            assert isinstance(resp_atts.json(), list)

            # 12. Query incident by reference number
            ref_num = resp_inc.json()["reference_number"]
            resp_by_ref = await client.get(
                f"/api/v1/incidents/reference/{ref_num}",
                headers=headers_student,
            )
            assert resp_by_ref.status_code == 200
            assert resp_by_ref.json()["id"] == incident_id

            # 13. Query incidents with filtering and search
            resp_filtered = await client.get(
                "/api/v1/incidents?status=closed&sort_by=created_at&sort_order=desc",
                headers=headers_admin,
            )
            assert resp_filtered.status_code == 200
            assert resp_filtered.json()["pagination"]["total_items"] >= 1

            # 14. Invalid sort order rejected with 422
            resp_bad_sort = await client.get(
                "/api/v1/incidents?sort_order=invalid_dir",
                headers=headers_admin,
            )
            assert resp_bad_sort.status_code == 422

            # 15. Invalid sort column rejected with 400
            resp_bad_col = await client.get(
                "/api/v1/incidents?sort_by=invalid_column",
                headers=headers_admin,
            )
            assert resp_bad_col.status_code == 400
            assert resp_bad_col.json()["error"]["code"] == "INVALID_SORT_FIELD"
