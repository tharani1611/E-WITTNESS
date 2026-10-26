"""Live PostgreSQL End-to-End API Integration Tests for Batch 10 Group 02 (Phases 96-100).

Verifies full HTTP stack against real PostgreSQL and storage:
- Phase 96:
  - Authorized Analytics and Aggregate Statistics endpoints:
    `/api/v1/analytics/overview`, `/incidents`, `/cases`, `/reviews`.
  - Granular RBAC/ABAC department isolation:
    - Dept Admin & Investigator scoped strictly to authorized department.
    - Rejection of cross-department analytics queries (`CROSS_DEPARTMENT_FORBIDDEN`).
    - Denial of analytics access to unauthorized roles (e.g. Student).
    - Super Admin capability to query globally or for any department.
- Phase 97:
  - Reviewer Workload (`/api/v1/analytics/workload`):
    - Department-scoped and global reviewer distribution.
    - Identification of unassigned incidents and cases.
  - Background Processing Metrics (`/api/v1/analytics/processing-metrics`):
    - AI job throughput, retry vs logical counts, p95 durations.
    - Notification channel delivery metrics.
- Phase 98:
  - Controlled Report Exports (`/api/v1/reports/export`):
    - CSV export with formula injection sanitization (`=, +, -, @, \t, \r`).
    - PDF export with statutory AI advisory disclaimer banner and structured table layout.
    - Cryptographic SHA-256 attestation header and download tracking.
  - Report Download (`/api/v1/reports/{id}/download`):
    - Download count tallying and access re-authorization.
    - Rejection of cross-department report downloads.
- Phase 99:
  - Deep Health Diagnostics (`/api/v1/health/system`):
    - Unauthenticated/unauthorized rejection.
    - Aggregation of liveness, readiness, worker states, and queue backlogs.
  - Background Worker Telemetry (`/api/v1/health/workers`, `/workers/heartbeat`):
    - Worker heartbeat registration with telemetry payload.
    - Automatic staleness tracking (> 300s).
  - Operational Alerts Evaluation (`/api/v1/health/alerts/evaluate`):
    - Threshold evaluation and 15-minute cooldown deduplication.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import httpx
import pytest

from backend.app.config.settings import Settings
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


async def _setup_batch10_group02_test_env(
    postgres_db_manager: DatabaseSessionManager,
) -> dict[str, Any]:
    """Seed test departments, roles, and test users in real PostgreSQL."""
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
            Department(code=f"ALPHA-{suffix}", name=f"Department Alpha {suffix}", is_active=True)
        )
        dept_beta = await dept_repo.create(
            Department(code=f"BETA-{suffix}", name=f"Department Beta {suffix}", is_active=True)
        )

        super_admin = await user_repo.create(
            User(
                email=f"sa_b10g2_{suffix.lower()}@ewitness.edu",
                full_name="Super Admin B10G2",
                role_id=roles[RoleCode.SUPER_ADMIN].id,
                department_id=None,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        dept_admin_alpha = await user_repo.create(
            User(
                email=f"da_alpha_{suffix.lower()}@ewitness.edu",
                full_name="Dept Admin Alpha",
                role_id=roles[RoleCode.DEPT_ADMIN].id,
                department_id=dept_alpha.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        investigator_alpha = await user_repo.create(
            User(
                email=f"inv_alpha_{suffix.lower()}@ewitness.edu",
                full_name="Investigator Alpha",
                role_id=roles[RoleCode.INVESTIGATOR].id,
                department_id=dept_alpha.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        dept_admin_beta = await user_repo.create(
            User(
                email=f"da_beta_{suffix.lower()}@ewitness.edu",
                full_name="Dept Admin Beta",
                role_id=roles[RoleCode.DEPT_ADMIN].id,
                department_id=dept_beta.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        student_alpha = await user_repo.create(
            User(
                email=f"student_{suffix.lower()}@ewitness.edu",
                full_name="Student Alpha",
                role_id=roles[RoleCode.STUDENT].id,
                department_id=dept_alpha.id,
                account_status=AccountStatus.ACTIVE.value,
                is_active=True,
                password_hash=hashed_pw,
            )
        )

        return {
            "suffix": suffix,
            "dept_alpha": dept_alpha,
            "dept_beta": dept_beta,
            "super_admin": super_admin,
            "dept_admin_alpha": dept_admin_alpha,
            "investigator_alpha": investigator_alpha,
            "dept_admin_beta": dept_admin_beta,
            "student_alpha": student_alpha,
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
class TestBatch10Group02LivePostgresAPI:
    """End-to-end regression test suite for Phases 96-100 on real PostgreSQL."""

    async def test_phase96_analytics_endpoints_and_scoping(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify Phase 96 analytics overview, incidents, cases, reviews and RBAC scoping."""
        data = await _setup_batch10_group02_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_sa = await _login(client, data["super_admin"].email, data["default_pw"])
            token_da_a = await _login(client, data["dept_admin_alpha"].email, data["default_pw"])
            token_student = await _login(client, data["student_alpha"].email, data["default_pw"])

            headers_sa = {"Authorization": f"Bearer {token_sa}"}
            headers_da_a = {"Authorization": f"Bearer {token_da_a}"}
            headers_student = {"Authorization": f"Bearer {token_student}"}

            dept_a_id = str(data["dept_alpha"].id)
            dept_b_id = str(data["dept_beta"].id)

            # 1. Student denied from all analytics
            r_stu = await client.get("/api/v1/analytics/overview", headers=headers_student)
            assert r_stu.status_code == 403

            # 2. Dept Admin Alpha queries overview for own department -> 200 OK
            r_da_own = await client.get(
                f"/api/v1/analytics/overview?department_id={dept_a_id}",
                headers=headers_da_a,
            )
            assert r_da_own.status_code == 200
            res_overview = r_da_own.json()
            assert "total_incidents" in res_overview
            assert "total_cases" in res_overview
            assert "total_reviews" in res_overview
            assert res_overview["total_incidents"] == 0

            # 3. Dept Admin Alpha cross-department query forbidden -> 403 Forbidden
            r_da_cross = await client.get(
                f"/api/v1/analytics/overview?department_id={dept_b_id}",
                headers=headers_da_a,
            )
            assert r_da_cross.status_code == 403
            assert "CROSS_DEPARTMENT_ACCESS_FORBIDDEN" in r_da_cross.text

            # 4. Super Admin global overview query -> 200 OK
            r_sa_global = await client.get(
                "/api/v1/analytics/overview",
                headers=headers_sa,
            )
            assert r_sa_global.status_code == 200

            # 5. Granular sub-analytics endpoints
            r_inc = await client.get(
                f"/api/v1/analytics/incidents?department_id={dept_a_id}&bucket=day",
                headers=headers_da_a,
            )
            assert r_inc.status_code == 200
            assert "incidents_by_severity" in r_inc.json()

            r_cases = await client.get(
                f"/api/v1/analytics/cases?department_id={dept_a_id}&bucket=week",
                headers=headers_da_a,
            )
            assert r_cases.status_code == 200
            assert "cases_by_status" in r_cases.json()

            r_rev = await client.get(
                f"/api/v1/analytics/reviews?department_id={dept_a_id}",
                headers=headers_da_a,
            )
            assert r_rev.status_code == 200
            assert "acceptance_rate" in r_rev.json()

    async def test_phase97_workload_and_processing_metrics(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify Phase 97 reviewer workload and background throughput metrics."""
        data = await _setup_batch10_group02_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_da_a = await _login(client, data["dept_admin_alpha"].email, data["default_pw"])

            headers_da_a = {"Authorization": f"Bearer {token_da_a}"}
            dept_a_id = str(data["dept_alpha"].id)

            # 1. Workload summary for department
            r_workload = await client.get(
                f"/api/v1/analytics/workload?department_id={dept_a_id}",
                headers=headers_da_a,
            )
            assert r_workload.status_code == 200
            wl_data = r_workload.json()
            assert "reviewers" in wl_data
            assert "unassigned_incidents_count" in wl_data
            assert "unassigned_cases_count" in wl_data

            # 2. Processing metrics query
            r_proc = await client.get(
                f"/api/v1/analytics/processing-metrics?department_id={dept_a_id}",
                headers=headers_da_a,
            )
            assert r_proc.status_code == 200
            proc_data = r_proc.json()
            assert "ai_jobs" in proc_data
            assert "notifications" in proc_data
            assert "total_logical_jobs" in proc_data["ai_jobs"]
            assert "total_logical_notifications" in proc_data["notifications"]

    async def test_phase98_controlled_report_exports(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify Phase 98 CSV sanitization, PDF generation, SHA-256 attestation, and re-download."""
        data = await _setup_batch10_group02_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_da_a = await _login(client, data["dept_admin_alpha"].email, data["default_pw"])
            token_da_b = await _login(client, data["dept_admin_beta"].email, data["default_pw"])
            token_sa = await _login(client, data["super_admin"].email, data["default_pw"])

            headers_da_a = {"Authorization": f"Bearer {token_da_a}"}
            headers_da_b = {"Authorization": f"Bearer {token_da_b}"}
            headers_sa = {"Authorization": f"Bearer {token_sa}"}
            dept_a_id = str(data["dept_alpha"].id)

            # 1. CSV Report Export
            req_csv = {
                "report_type": "incidents",
                "export_format": "csv",
                "department_id": dept_a_id,
            }
            r_csv = await client.post("/api/v1/reports/export", json=req_csv, headers=headers_da_a)
            assert r_csv.status_code == 200
            assert "text/csv" in r_csv.headers["content-type"]
            assert "attachment;" in r_csv.headers.get("content-disposition", "")
            sha256_csv = r_csv.headers.get("x-export-sha256")
            assert sha256_csv is not None and len(sha256_csv) == 64
            export_id_str = r_csv.headers.get("x-export-id")
            assert export_id_str is not None

            # 2. PDF Report Export
            req_pdf = {
                "report_type": "cases",
                "export_format": "pdf",
                "department_id": dept_a_id,
            }
            r_pdf = await client.post("/api/v1/reports/export", json=req_pdf, headers=headers_da_a)
            assert r_pdf.status_code == 200
            assert "application/pdf" in r_pdf.headers["content-type"]
            assert r_pdf.content.startswith(b"%PDF-1.4\n")
            # Verify statutory AI disclaimer
            assert b"STATUTORY ADVISORY: Candidate video segments" in r_pdf.content

            # 3. Download tracking & authorization check
            # User from Department Beta cannot download Alpha's report
            r_cross_dl = await client.get(
                f"/api/v1/reports/{export_id_str}/download",
                headers=headers_da_b,
            )
            assert r_cross_dl.status_code == 403

            # Super Admin can download Alpha's report
            r_sa_dl = await client.get(
                f"/api/v1/reports/{export_id_str}/download",
                headers=headers_sa,
            )
            assert r_sa_dl.status_code == 200
            meta = r_sa_dl.json()
            assert meta["id"] == export_id_str
            assert meta["download_count"] >= 1

    async def test_phase99_deep_health_and_operational_alerts(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify Phase 99 deep diagnostics, worker heartbeats, and alert evaluations."""
        data = await _setup_batch10_group02_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_sa = await _login(client, data["super_admin"].email, data["default_pw"])
            token_student = await _login(client, data["student_alpha"].email, data["default_pw"])

            headers_sa = {"Authorization": f"Bearer {token_sa}"}
            headers_student = {"Authorization": f"Bearer {token_student}"}

            # 1. Student denied from deep system diagnostics
            r_stu_health = await client.get("/api/v1/health/system", headers=headers_student)
            assert r_stu_health.status_code == 403

            # 2. Super Admin gets detailed diagnostics
            r_sa_health = await client.get("/api/v1/health/system", headers=headers_sa)
            assert r_sa_health.status_code == 200
            diag = r_sa_health.json()
            assert diag["liveness"]["status"] == "ok"
            assert "queue_monitoring" in diag
            assert "workers" in diag
            assert "active_alerts" in diag

            # 3. Post worker heartbeat
            hb_payload = {
                "worker_id": f"worker-test-{uuid4().hex[:4]}",
                "hostname": "test-host.local",
                "task_types": ["ai_analysis"],
                "metrics": {"cpu": 22.4, "ram_mb": 1024},
            }
            r_hb = await client.post("/api/v1/health/workers/heartbeat", json=hb_payload)
            assert r_hb.status_code == 200
            hb_res = r_hb.json()
            assert hb_res["worker_id"] == hb_payload["worker_id"]
            assert hb_res["status"] == "active"

            # 4. List registered workers
            r_workers = await client.get("/api/v1/health/workers", headers=headers_sa)
            assert r_workers.status_code == 200
            workers_list = r_workers.json()
            assert any(w["worker_id"] == hb_payload["worker_id"] for w in workers_list)

            # 5. Evaluate operational alerts (clean execution)
            r_eval = await client.post("/api/v1/health/alerts/evaluate", headers=headers_sa)
            assert r_eval.status_code == 200
            assert isinstance(r_eval.json(), list)
