"""Live PostgreSQL Integration Tests for Batch 10 Group 01 (Phases 91-95).

Verifies against real PostgreSQL:
- Phase 91: Notification delivery adapters and validated template rendering.
- Phase 92: In-app notifications, live unread counts, mark-as-read (single/batch),
            and strict recipient ownership scoping (cross-user isolation).
- Phase 93: Delivery tracking, deduplication idempotency, bounded retry handling,
            and delivery attempt records.
- Phase 94: User-configurable notification preferences, granular category/channel controls,
            and the non-negotiable invariant that security-critical alerts cannot be disabled.
- Phase 95: Operational dashboards backend aggregations (incidents, cases, operations),
            strict department isolation, Super Admin global/department views,
            bounded time filters, and security audit event logging.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select

from backend.app.config.settings import Settings
from backend.app.core.audit import AuditAction
from backend.app.core.identity import AccountStatus, RoleCode
from backend.app.core.notification import (
    DeliveryStatus,
    NotificationCategory,
)
from backend.app.infrastructure.database import DatabaseSessionManager
from backend.app.infrastructure.storage import InMemoryStorageClient
from backend.app.main import create_app
from backend.app.models.audit import SecurityAuditEvent
from backend.app.models.department import Department
from backend.app.models.notification import NotificationDeliveryAttempt
from backend.app.models.user import User
from backend.app.repositories.identity import (
    DepartmentRepository,
    RoleRepository,
    UserRepository,
)
from backend.app.services.password import PasswordService


async def _setup_batch10_test_env(
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
                email=f"superadmin_b10_{suffix.lower()}@ewitness.edu",
                full_name="Super Admin B10",
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
                full_name="Safety Admin B10",
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
                full_name="Safety Investigator B10",
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
                full_name="Academic Investigator B10",
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
                full_name="Student Safety B10",
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
class TestBatch10Group01LivePostgres:
    """End-to-end integration tests for Phases 91-95 on real PostgreSQL."""

    async def test_phases91_92_in_app_notifications_and_recipient_isolation(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify in-app notification dispatching, live unread count, reading, and recipient isolation."""
        data = await _setup_batch10_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_admin = await _login(client, data["dept_admin_sec"].email, data["default_pw"])
            token_inv_sec = await _login(client, data["investigator_sec"].email, data["default_pw"])
            token_inv_acad = await _login(
                client, data["investigator_acad"].email, data["default_pw"]
            )

            headers_admin = {"Authorization": f"Bearer {token_admin}"}
            headers_inv_sec = {"Authorization": f"Bearer {token_inv_sec}"}
            headers_inv_acad = {"Authorization": f"Bearer {token_inv_acad}"}

            # 1. Investigator starts with 0 unread notifications
            resp_unread_init = await client.get(
                "/api/v1/notifications/unread-count",
                headers=headers_inv_sec,
            )
            assert resp_unread_init.status_code == 200
            assert resp_unread_init.json()["unread_count"] == 0

            # 2. Dept Admin dispatches an in-app notification to Safety Investigator
            dispatch_payload = {
                "recipient_id": str(data["investigator_sec"].id),
                "channel": "in_app",
                "priority": "high",
                "template_name": "case_assigned",
                "template_vars": {
                    "case_reference": "CASE-2026-SEC-001",
                    "case_title": "Dormitory Access Violation",
                },
            }
            resp_dispatch = await client.post(
                "/api/v1/notifications/dispatch",
                headers=headers_admin,
                json=dispatch_payload,
            )
            assert resp_dispatch.status_code == 201
            notif_data = resp_dispatch.json()
            assert notif_data is not None
            notif_id = notif_data["id"]
            assert notif_data["title"] == "Case Assigned: CASE-2026-SEC-001"
            assert notif_data["is_read"] is False

            # 3. Safety Investigator checks unread count -> 1
            resp_unread = await client.get(
                "/api/v1/notifications/unread-count",
                headers=headers_inv_sec,
            )
            assert resp_unread.status_code == 200
            assert resp_unread.json()["unread_count"] == 1

            # 4. Safety Investigator lists notifications -> 1 item
            resp_list = await client.get("/api/v1/notifications", headers=headers_inv_sec)
            assert resp_list.status_code == 200
            list_data = resp_list.json()
            assert list_data["total"] == 1
            assert list_data["items"][0]["id"] == notif_id

            # 5. Cross-user isolation: Academic Investigator sees 0 notifications
            resp_acad_list = await client.get(
                "/api/v1/notifications",
                headers=headers_inv_acad,
            )
            assert resp_acad_list.status_code == 200
            assert resp_acad_list.json()["total"] == 0

            # Academic Investigator tries to mark Safety Investigator's notification as read -> 404 Not Found
            resp_acad_read = await client.post(
                f"/api/v1/notifications/{notif_id}/read",
                headers=headers_inv_acad,
            )
            assert resp_acad_read.status_code == 404

            # 6. Safety Investigator marks the notification as read -> 200 OK
            resp_read = await client.post(
                f"/api/v1/notifications/{notif_id}/read",
                headers=headers_inv_sec,
            )
            assert resp_read.status_code == 200
            assert resp_read.json()["is_read"] is True

            # 7. Unread count drops to 0
            resp_unread_after = await client.get(
                "/api/v1/notifications/unread-count",
                headers=headers_inv_sec,
            )
            assert resp_unread_after.json()["unread_count"] == 0

            # 8. Dispatch 2 additional notifications and verify batch mark-as-read
            d1 = await client.post(
                "/api/v1/notifications/dispatch",
                headers=headers_admin,
                json={
                    "recipient_id": str(data["investigator_sec"].id),
                    "channel": "in_app",
                    "priority": "low",
                    "template_name": "system_notice",
                    "template_vars": {
                        "notice_title": "Scheduled Maintenance",
                        "notice_body": "Routine server patching at midnight.",
                    },
                },
            )
            d2 = await client.post(
                "/api/v1/notifications/dispatch",
                headers=headers_admin,
                json={
                    "recipient_id": str(data["investigator_sec"].id),
                    "channel": "in_app",
                    "priority": "normal",
                    "template_name": "system_notice",
                    "template_vars": {
                        "notice_title": "Policy Update",
                        "notice_body": "New evidence retention rules published.",
                    },
                },
            )
            assert d1.status_code == 201 and d2.status_code == 201
            id1, id2 = d1.json()["id"], d2.json()["id"]

            resp_unread_two = await client.get(
                "/api/v1/notifications/unread-count",
                headers=headers_inv_sec,
            )
            assert resp_unread_two.json()["unread_count"] == 2

            # Batch mark-read
            resp_batch = await client.post(
                "/api/v1/notifications/mark-read",
                headers=headers_inv_sec,
                json={"notification_ids": [id1, id2]},
            )
            assert resp_batch.status_code == 200
            assert resp_batch.json()["marked_read"] == 2

            resp_unread_zero = await client.get(
                "/api/v1/notifications/unread-count",
                headers=headers_inv_sec,
            )
            assert resp_unread_zero.json()["unread_count"] == 0

    async def test_phase93_email_delivery_deduplication_and_tracking(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify email delivery tracking, deduplication idempotency, and delivery attempt persistence."""
        data = await _setup_batch10_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_admin = await _login(client, data["dept_admin_sec"].email, data["default_pw"])
            headers_admin = {"Authorization": f"Bearer {token_admin}"}

            custom_dedup = f"dedup-test-{uuid4().hex}"
            email_payload = {
                "recipient_id": str(data["investigator_sec"].id),
                "channel": "email",
                "priority": "normal",
                "template_name": "incident_assigned",
                "template_vars": {
                    "reference_number": "INC-2026-9001",
                    "department_name": "Campus Safety",
                },
                "correlation_id": custom_dedup,
            }

            # First dispatch
            resp1 = await client.post(
                "/api/v1/notifications/dispatch",
                headers=headers_admin,
                json=email_payload,
            )
            assert resp1.status_code == 201
            notif1 = resp1.json()
            assert notif1 is not None
            assert notif1["delivery_status"] == DeliveryStatus.DELIVERED.value
            notif_id = notif1["id"]

            # Second dispatch with identical deduplication key -> Returns same notification (idempotent)
            resp2 = await client.post(
                "/api/v1/notifications/dispatch",
                headers=headers_admin,
                json=email_payload,
            )
            assert resp2.status_code == 201
            notif2 = resp2.json()
            assert notif2["id"] == notif_id

            # Verify in PostgreSQL that delivery attempt was logged
            async with postgres_db_manager.transactional_session() as session:
                stmt = select(NotificationDeliveryAttempt).where(
                    NotificationDeliveryAttempt.notification_id == notif_id
                )
                res = await session.execute(stmt)
                attempts = list(res.scalars().all())
                assert len(attempts) >= 1
                assert attempts[0].status == DeliveryStatus.DELIVERED.value
                assert attempts[0].attempt_number == 1

    async def test_phase94_notification_preferences_and_security_critical_alerts(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify user preference management and non-negotiable security invariant enforcement."""
        data = await _setup_batch10_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_admin = await _login(client, data["dept_admin_sec"].email, data["default_pw"])
            token_inv_sec = await _login(client, data["investigator_sec"].email, data["default_pw"])

            headers_admin = {"Authorization": f"Bearer {token_admin}"}
            headers_inv_sec = {"Authorization": f"Bearer {token_inv_sec}"}

            # 1. Investigator retrieves default preferences
            resp_pref = await client.get(
                "/api/v1/notifications/preferences",
                headers=headers_inv_sec,
            )
            assert resp_pref.status_code == 200
            pref_data = resp_pref.json()
            assert pref_data["email_enabled"] is True
            assert pref_data["in_app_enabled"] is True
            assert pref_data["assignments_in_app"] is True

            # 2. Investigator disables in-app assignment notifications
            resp_update = await client.patch(
                "/api/v1/notifications/preferences",
                headers=headers_inv_sec,
                json={"assignments_in_app": False},
            )
            assert resp_update.status_code == 200
            assert resp_update.json()["assignments_in_app"] is False

            # 3. Dept Admin tries to dispatch an assignment notification -> suppressed by preference
            resp_suppressed = await client.post(
                "/api/v1/notifications/dispatch",
                headers=headers_admin,
                json={
                    "recipient_id": str(data["investigator_sec"].id),
                    "channel": "in_app",
                    "priority": "normal",
                    "template_name": "case_assigned",
                    "template_vars": {
                        "case_reference": "CASE-2026-SUPPRESSED",
                        "case_title": "Suppressed Case",
                    },
                },
            )
            assert resp_suppressed.status_code == 201
            assert resp_suppressed.json() is None

            # 4. Non-negotiable security invariant: Security-critical alerts bypass disabled preferences!
            # Investigator disables all in-app notifications
            await client.patch(
                "/api/v1/notifications/preferences",
                headers=headers_inv_sec,
                json={"in_app_enabled": False},
            )

            resp_sec_alert = await client.post(
                "/api/v1/notifications/dispatch",
                headers=headers_admin,
                json={
                    "recipient_id": str(data["investigator_sec"].id),
                    "channel": "in_app",
                    "priority": "urgent",
                    "template_name": "security_login_alert",
                    "template_vars": {
                        "ip_address": "198.51.100.42",
                        "timestamp": "2026-10-15 14:00:00 UTC",
                    },
                },
            )
            assert resp_sec_alert.status_code == 201
            sec_alert_data = resp_sec_alert.json()
            assert sec_alert_data is not None
            assert sec_alert_data["title"] == "Security Alert: New Sign-In"
            assert sec_alert_data["category"] == NotificationCategory.SECURITY_CRITICAL.value

            # Verify audit trail for preference update
            async with postgres_db_manager.transactional_session() as session:
                audit_res = await session.execute(
                    select(SecurityAuditEvent).where(
                        SecurityAuditEvent.action == AuditAction.NOTIFICATION_PREFERENCE_UPDATED,
                        SecurityAuditEvent.actor_id == data["investigator_sec"].id,
                    )
                )
                audit_event = audit_res.scalars().first()
                assert audit_event is not None
                assert audit_event.target_type == "notification_preference"

    async def test_phase95_dashboards_aggregations_and_department_isolation(
        self,
        postgres_settings: Settings,
        postgres_db_manager: DatabaseSessionManager,
    ) -> None:
        """Verify operational dashboard aggregations, department isolation, and date bounds."""
        data = await _setup_batch10_test_env(postgres_db_manager)
        app = create_app(postgres_settings, db_manager=postgres_db_manager)
        app.state.storage_client = InMemoryStorageClient(postgres_settings.STORAGE_ENDPOINT_URL)
        app.state.db_manager = postgres_db_manager

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token_super = await _login(client, data["super_admin"].email, data["default_pw"])
            token_admin = await _login(client, data["dept_admin_sec"].email, data["default_pw"])
            token_inv_sec = await _login(client, data["investigator_sec"].email, data["default_pw"])
            token_student = await _login(client, data["student_sec"].email, data["default_pw"])

            headers_super = {"Authorization": f"Bearer {token_super}"}
            headers_admin = {"Authorization": f"Bearer {token_admin}"}
            headers_inv = {"Authorization": f"Bearer {token_inv_sec}"}
            headers_student = {"Authorization": f"Bearer {token_student}"}

            sec_dept_id = str(data["dept_security"].id)
            acad_dept_id = str(data["dept_academic"].id)

            # 1. Seed a case in Security department via API
            resp_case = await client.post(
                "/api/v1/cases",
                headers=headers_inv,
                json={
                    "title": "Residence Hall Dashboard Test",
                    "summary": "Investigating incident for dashboard validation.",
                    "priority": "medium",
                },
            )
            assert resp_case.status_code == 201

            # 2. Super Admin queries global dashboards
            resp_incidents = await client.get(
                "/api/v1/dashboards/incidents",
                headers=headers_super,
            )
            assert resp_incidents.status_code == 200
            inc_data = resp_incidents.json()
            assert "total_incidents" in inc_data
            assert "incidents_by_status" in inc_data
            assert "incidents_by_severity" in inc_data

            resp_cases = await client.get("/api/v1/dashboards/cases", headers=headers_super)
            assert resp_cases.status_code == 200
            case_data = resp_cases.json()
            assert case_data["total_cases"] >= 1
            assert "cases_by_status" in case_data
            assert "cases_by_priority" in case_data

            resp_ops = await client.get("/api/v1/dashboards/operations", headers=headers_super)
            assert resp_ops.status_code == 200
            ops_data = resp_ops.json()
            assert "ai_jobs_total" in ops_data
            assert "notifications_total" in ops_data
            assert "delivery_attempts_total" in ops_data

            # 3. Dept Admin queries own department dashboard -> 200 OK
            resp_dept_dash = await client.get(
                f"/api/v1/dashboards/cases?department_id={sec_dept_id}",
                headers=headers_admin,
            )
            assert resp_dept_dash.status_code == 200
            assert resp_dept_dash.json()["total_cases"] >= 1

            # Dept Admin queries without department_id -> auto-scoped to own department
            resp_dept_auto = await client.get(
                "/api/v1/dashboards/cases",
                headers=headers_admin,
            )
            assert resp_dept_auto.status_code == 200

            # 4. Cross-department isolation: Dept Admin tries to query Academic department -> 403 Forbidden!
            resp_cross_dept = await client.get(
                f"/api/v1/dashboards/cases?department_id={acad_dept_id}",
                headers=headers_admin,
            )
            assert resp_cross_dept.status_code == 403

            # 5. Role access control: Student and Investigator have NO dashboard permission -> 403 Forbidden
            resp_student_dash = await client.get(
                "/api/v1/dashboards/cases",
                headers=headers_student,
            )
            assert resp_student_dash.status_code == 403

            resp_inv_dash = await client.get(
                "/api/v1/dashboards/cases",
                headers=headers_inv,
            )
            assert resp_inv_dash.status_code == 403

            # 6. Date bounds validation: start_date > end_date -> 422 Unprocessable Entity
            now = datetime.now(UTC)
            start_str = (now + timedelta(days=5)).isoformat()
            end_str = now.isoformat()
            resp_invalid_date = await client.get(
                f"/api/v1/dashboards/incidents?start_date={start_str}&end_date={end_str}",
                headers=headers_super,
            )
            assert resp_invalid_date.status_code == 422

            # 7. Date bounds validation: range > 365 days -> 422 Unprocessable Entity
            old_start = (now - timedelta(days=400)).isoformat()
            resp_excessive_date = await client.get(
                f"/api/v1/dashboards/incidents?start_date={old_start}&end_date={end_str}",
                headers=headers_super,
            )
            assert resp_excessive_date.status_code == 422

            # 8. Verify audit trail logged DASHBOARD_ACCESSED
            async with postgres_db_manager.transactional_session() as session:
                audit_res = await session.execute(
                    select(SecurityAuditEvent).where(
                        SecurityAuditEvent.action == AuditAction.DASHBOARD_ACCESSED,
                        SecurityAuditEvent.actor_id == data["super_admin"].id,
                    )
                )
                audit_events = list(audit_res.scalars().all())
                assert len(audit_events) >= 1
                assert audit_events[0].target_type == "dashboard"
