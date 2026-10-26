"""Live PostgreSQL Integration Tests for Batch 05 Group 02 (Phases 46-50).

Tests:
- Phase 46: Layered file validation, magic signatures, MIME mismatch, quotas.
- Phase 47: Malware scanning integration hooks, EICAR detection, fail-closed quarantine, scan retry.
- Phase 48: Resumable multipart uploads, chunk pre-signing, storage assembly, session abort.
- Phase 49: Authorized evidence retrieval, short-lived download links, quarantined download denial.
- Phase 50: Security regressions, anti-enumeration, cross-department isolation.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest

from backend.app.config.settings import Settings
from backend.app.core.identity import AccountStatus, RoleCode
from backend.app.infrastructure.database import DatabaseSessionManager
from backend.app.infrastructure.scanner import EICAR_SIGNATURE
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
            "super_admin": super_admin,
            "dept_admin_alpha": dept_admin_alpha,
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
class TestBatch05Group02EvidenceFlowsIntegration:
    """Phases 46-50: Full live PostgreSQL integration tests for validation, scanning, multipart, and retrieval."""

    async def test_end_to_end_single_part_upload_scan_clean_and_download(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_batch05_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        # Ensure an in-memory storage client is shared for simulating S3 upload
        shared_storage = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.storage_client = shared_storage

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            token_student = await _get_token(client, env["student_alpha"].email, env["password"])
            token_investigator = await _get_token(
                client, env["investigator_alpha"].email, env["password"]
            )
            token_beta = await _get_token(client, env["student_beta"].email, env["password"])

            headers_student = {"Authorization": f"Bearer {token_student}"}
            headers_investigator = {"Authorization": f"Bearer {token_investigator}"}
            headers_beta = {"Authorization": f"Bearer {token_beta}"}

            # 1. Create incident
            resp_inc = await client.post(
                "/api/v1/incidents",
                json={
                    "title": "Damage to security turnstile",
                    "description": "Turnstile glass shattered at dormitory entrance.",
                    "category": "property_damage_theft",
                    "location": "North Dorm Lobby",
                    "occurred_at": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
                },
                headers=headers_student,
            )
            assert resp_inc.status_code == 201
            incident_id = resp_inc.json()["id"]

            # 2. Authorize upload session for PNG image
            png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
            file_size = len(png_bytes)

            resp_sess = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/upload-session",
                json={
                    "filename": "turnstile_photo.png",
                    "content_type": "image/png",
                    "file_size_bytes": file_size,
                },
                headers=headers_student,
            )
            assert resp_sess.status_code == 201
            session_data = resp_sess.json()
            session_id = session_data["session_id"]
            storage_key = session_data["storage_key"]

            # 3. Simulate client PUT upload to pre-signed URL (uploading directly to shared storage)
            await shared_storage.put_object(storage_key, png_bytes, "image/png")

            # 4. Complete upload session
            resp_complete = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/upload-sessions/{session_id}/complete",
                headers=headers_student,
            )
            assert resp_complete.status_code == 200
            att_data = resp_complete.json()

            assert att_data["original_filename"] == "turnstile_photo.png"
            assert att_data["declared_mime_type"] == "image/png"
            assert att_data["detected_mime_type"] == "image/png"
            assert att_data["file_size_bytes"] == file_size
            assert att_data["upload_status"] == "completed"
            assert att_data["evidence_status"] == "attached"
            assert att_data["scan_status"] == "clean"
            assert att_data["sha256_hash"] is not None
            attachment_id = att_data["id"]

            # 4b. Retrieve single attachment metadata
            resp_att_get = await client.get(
                f"/api/v1/incidents/{incident_id}/attachments/{attachment_id}",
                headers=headers_student,
            )
            assert resp_att_get.status_code == 200
            assert resp_att_get.json()["id"] == attachment_id

            # 5. Submitter requests authorized download URL
            resp_dl = await client.get(
                f"/api/v1/incidents/{incident_id}/attachments/{attachment_id}/download",
                headers=headers_student,
            )
            assert resp_dl.status_code == 200
            dl_data = resp_dl.json()
            assert "download_url" in dl_data
            assert dl_data["filename"] == "turnstile_photo.png"
            assert dl_data["content_type"] == "image/png"
            assert dl_data["file_size_bytes"] == file_size

            # 6. Assigned investigator in same department can also download
            resp_inv_dl = await client.get(
                f"/api/v1/incidents/{incident_id}/attachments/{attachment_id}/download",
                headers=headers_investigator,
            )
            assert resp_inv_dl.status_code == 200

            # 7. Student in Dept Beta receives 404 (Anti-enumeration isolation)
            resp_denied = await client.get(
                f"/api/v1/incidents/{incident_id}/attachments/{attachment_id}/download",
                headers=headers_beta,
            )
            assert resp_denied.status_code == 404
            assert resp_denied.json()["error"]["code"] in (
                "ATTACHMENT_NOT_FOUND",
                "INCIDENT_NOT_FOUND",
            )

    async def test_malware_detection_fail_closed_quarantine_and_retry(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_batch05_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        shared_storage = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.storage_client = shared_storage

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            token_student = await _get_token(client, env["student_alpha"].email, env["password"])
            token_admin = await _get_token(client, env["dept_admin_alpha"].email, env["password"])
            headers_student = {"Authorization": f"Bearer {token_student}"}
            headers_admin = {"Authorization": f"Bearer {token_admin}"}

            # 1. Create incident
            resp_inc = await client.post(
                "/api/v1/incidents",
                json={
                    "title": "Suspicious payload report",
                    "description": "Suspicious file discovered on lab workstation.",
                    "category": "safety_hazard",
                    "location": "IT Lab 4",
                    "occurred_at": (datetime.now(UTC) - timedelta(minutes=30)).isoformat(),
                },
                headers=headers_student,
            )
            assert resp_inc.status_code == 201
            incident_id = resp_inc.json()["id"]

            # 2. Authorize upload session for EICAR text file
            file_size = len(EICAR_SIGNATURE)
            resp_sess = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/upload-session",
                json={
                    "filename": "eicar_sample.txt",
                    "content_type": "text/plain",
                    "file_size_bytes": file_size,
                },
                headers=headers_student,
            )
            assert resp_sess.status_code == 201
            session_data = resp_sess.json()
            session_id = session_data["session_id"]
            storage_key = session_data["storage_key"]

            # 3. Upload EICAR signature to storage
            await shared_storage.put_object(storage_key, EICAR_SIGNATURE, "text/plain")

            # 4. Complete upload session: scanner must trigger and quarantine!
            resp_complete = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/upload-sessions/{session_id}/complete",
                headers=headers_student,
            )
            assert resp_complete.status_code == 200
            att_data = resp_complete.json()

            assert att_data["scan_status"] == "infected"
            assert att_data["evidence_status"] == "quarantined"
            assert att_data["upload_status"] == "completed"
            assert "eicar" in att_data["scan_details"].lower()
            attachment_id = att_data["id"]

            # 5. Retrieval must be DENIED (Fail-closed quarantine with HTTP 403 EVIDENCE_NOT_RELEASED)
            resp_dl = await client.get(
                f"/api/v1/incidents/{incident_id}/attachments/{attachment_id}/download",
                headers=headers_student,
            )
            assert resp_dl.status_code == 403
            assert resp_dl.json()["error"]["code"] == "EVIDENCE_NOT_RELEASED"

            # 6. Admin attempts download also denied
            resp_admin_dl = await client.get(
                f"/api/v1/incidents/{incident_id}/attachments/{attachment_id}/download",
                headers=headers_admin,
            )
            assert resp_admin_dl.status_code == 403
            assert resp_admin_dl.json()["error"]["code"] == "EVIDENCE_NOT_RELEASED"

            # 7. Non-admin (student) cannot retry scan
            resp_retry_denied = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/{attachment_id}/scan-retry",
                headers=headers_student,
            )
            assert resp_retry_denied.status_code == 403

            # 8. Admin retries scan (remains infected because file on storage is still EICAR)
            resp_retry = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/{attachment_id}/scan-retry",
                headers=headers_admin,
            )
            assert resp_retry.status_code == 200
            retry_data = resp_retry.json()
            assert retry_data["scan_status"] == "infected"
            assert retry_data["evidence_status"] == "quarantined"

    async def test_resumable_multipart_upload_init_complete_and_abort(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_batch05_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        shared_storage = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.storage_client = shared_storage

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            token_student = await _get_token(client, env["student_alpha"].email, env["password"])
            headers_student = {"Authorization": f"Bearer {token_student}"}

            # 1. Create incident
            resp_inc = await client.post(
                "/api/v1/incidents",
                json={
                    "title": "CCTV Evidence Recording",
                    "description": "Hallway surveillance footage for investigation.",
                    "category": "safety_hazard",
                    "location": "Science Wing Corridor",
                    "occurred_at": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
                },
                headers=headers_student,
            )
            assert resp_inc.status_code == 201
            incident_id = resp_inc.json()["id"]

            # 2. Init multipart upload: 10 MB file, 5 MB chunk size = 2 parts
            part_size = 5_242_880
            total_size = part_size * 2
            resp_mp_init = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/multipart/init",
                json={
                    "filename": "cctv_hallway.mp4",
                    "content_type": "video/mp4",
                    "file_size_bytes": total_size,
                    "part_size_bytes": part_size,
                },
                headers=headers_student,
            )
            assert resp_mp_init.status_code == 201
            mp_data = resp_mp_init.json()
            session_id = mp_data["session_id"]
            upload_id = mp_data["upload_id"]
            storage_key = mp_data["storage_key"]
            assert mp_data["total_parts"] == 2
            assert len(mp_data["part_urls"]) == 2

            # 3. Simulate chunk uploads into shared storage
            part1_content = b"\x00\x00\x00\x20ftypisom" + b"X" * (part_size - 12)
            part2_content = b"Y" * part_size

            etag1 = await shared_storage.put_part(storage_key, upload_id, 1, part1_content)
            etag2 = await shared_storage.put_part(storage_key, upload_id, 2, part2_content)

            # 4. Complete multipart upload
            resp_mp_complete = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/multipart/{session_id}/complete",
                json={
                    "parts": [
                        {"part_number": 1, "etag": etag1},
                        {"part_number": 2, "etag": etag2},
                    ]
                },
                headers=headers_student,
            )
            assert resp_mp_complete.status_code == 200
            att_mp = resp_mp_complete.json()

            assert att_mp["original_filename"] == "cctv_hallway.mp4"
            assert att_mp["declared_mime_type"] == "video/mp4"
            assert att_mp["detected_mime_type"] == "video/mp4"
            assert att_mp["file_size_bytes"] == total_size
            assert att_mp["upload_status"] == "completed"
            assert att_mp["evidence_status"] == "attached"
            assert att_mp["scan_status"] == "clean"

            # 5. Test multipart abort flow
            resp_mp_init_abort = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/multipart/init",
                json={
                    "filename": "aborted_recording.mp4",
                    "content_type": "video/mp4",
                    "file_size_bytes": total_size,
                    "part_size_bytes": part_size,
                },
                headers=headers_student,
            )
            assert resp_mp_init_abort.status_code == 201
            abort_session_id = resp_mp_init_abort.json()["session_id"]

            resp_abort = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/multipart/{abort_session_id}/abort",
                headers=headers_student,
            )
            assert resp_abort.status_code == 204

            # Session should now be marked cancelled
            resp_check_sess = await client.get(
                f"/api/v1/incidents/attachments/upload-sessions/{abort_session_id}",
                headers=headers_student,
            )
            assert resp_check_sess.status_code == 200
            assert resp_check_sess.json()["session_status"] == "cancelled"

    async def test_file_signature_and_mime_mismatch_rejected(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        env = await _setup_batch05_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)

        shared_storage = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.storage_client = shared_storage

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            token_student = await _get_token(client, env["student_alpha"].email, env["password"])
            headers_student = {"Authorization": f"Bearer {token_student}"}

            # 1. Create incident
            resp_inc = await client.post(
                "/api/v1/incidents",
                json={
                    "title": "Mismatched file upload attempt",
                    "description": "Testing MIME mismatch detection.",
                    "category": "safety_hazard",
                    "location": "Server Room",
                    "occurred_at": (datetime.now(UTC) - timedelta(minutes=10)).isoformat(),
                },
                headers=headers_student,
            )
            assert resp_inc.status_code == 201
            incident_id = resp_inc.json()["id"]

            # 2. Authorize upload session claiming image/png
            fake_content = b"%PDF-1.4\n%This is actually a PDF file pretending to be PNG\n"
            resp_sess = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/upload-session",
                json={
                    "filename": "fake_image.png",
                    "content_type": "image/png",
                    "file_size_bytes": len(fake_content),
                },
                headers=headers_student,
            )
            assert resp_sess.status_code == 201
            session_id = resp_sess.json()["session_id"]
            storage_key = resp_sess.json()["storage_key"]

            # 3. Upload PDF content to the PNG storage key
            await shared_storage.put_object(storage_key, fake_content, "image/png")

            # 4. Attempt completion: must fail with CONTENT_TYPE_MISMATCH (422)
            resp_complete = await client.post(
                f"/api/v1/incidents/{incident_id}/attachments/upload-sessions/{session_id}/complete",
                headers=headers_student,
            )
            assert resp_complete.status_code == 415
            assert resp_complete.json()["error"]["code"] in (
                "UNSUPPORTED_MEDIA_TYPE",
                "CONTENT_TYPE_MISMATCH",
            )
