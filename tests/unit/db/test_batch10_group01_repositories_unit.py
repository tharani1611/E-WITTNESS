"""Unit tests for Batch 10 Group 01 repositories (Phases 91-95).

Tests:
- NotificationRepository: in-app notifications, recipients, preferences, delivery attempts, deduplication.
- DashboardRepository: metric aggregations for incidents, cases, and operations with department scoping.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.engine import Result

from backend.app.core.notification import (
    DeliveryStatus,
    NotificationCategory,
    NotificationChannel,
    NotificationPriority,
)
from backend.app.models.notification import (
    Notification,
    NotificationDeliveryAttempt,
    NotificationPreference,
)
from backend.app.repositories.dashboard import DashboardRepository
from backend.app.repositories.notification import NotificationRepository


class TestDashboardRepositoryUnit:
    """Isolated unit tests for DashboardRepository query generation and result aggregation."""

    @pytest.fixture
    def mock_session(self) -> AsyncMock:
        sess = AsyncMock()
        sess.execute = AsyncMock()
        return sess

    @pytest.fixture
    def dashboard_repo(self, mock_session: AsyncMock) -> DashboardRepository:
        return DashboardRepository(mock_session)

    async def test_get_incident_metrics_global_and_scoped(
        self, dashboard_repo: DashboardRepository, mock_session: AsyncMock
    ) -> None:
        start = datetime.now(UTC) - timedelta(days=7)
        end = datetime.now(UTC)

        # Mock results:
        # 1. total_res: scalar_one_or_none -> 10
        # 2. res_status: all -> [("submitted", 6), ("closed", 4)]
        # 3. res_sev: all -> [("high", 3), ("medium", 7)]
        # 4. res_dept: all -> [("Security", 10)]
        # 5. res_ev: scalar_one_or_none -> 25
        res1 = MagicMock(spec=Result)
        res1.scalar_one_or_none.return_value = 10

        res2 = MagicMock(spec=Result)
        res2.all.return_value = [("submitted", 6), ("closed", 4)]

        res3 = MagicMock(spec=Result)
        res3.all.return_value = [("high", 3), ("medium", 7)]

        res4 = MagicMock(spec=Result)
        res4.all.return_value = [("Security", 10)]

        res5 = MagicMock(spec=Result)
        res5.scalar_one_or_none.return_value = 25

        mock_session.execute.side_effect = [res1, res2, res3, res4, res5]

        # 1. Test global query (department_id=None)
        metrics = await dashboard_repo.get_incident_metrics(start, end, department_id=None)
        assert metrics["total_incidents"] == 10
        assert metrics["incidents_by_status"] == {"submitted": 6, "closed": 4}
        assert metrics["incidents_by_severity"] == {"high": 3, "medium": 7}
        assert metrics["incidents_by_department"] == {"Security": 10}
        assert metrics["total_evidence_items"] == 25
        assert metrics["department_id"] is None

        # 2. Test scoped query (department_id=UUID)
        dept_id = uuid4()
        mock_session.execute.side_effect = [res1, res2, res3, res4, res5]
        metrics_scoped = await dashboard_repo.get_incident_metrics(
            start, end, department_id=dept_id
        )
        assert metrics_scoped["total_incidents"] == 10
        assert metrics_scoped["department_id"] == dept_id

    async def test_get_case_metrics_global_and_scoped(
        self, dashboard_repo: DashboardRepository, mock_session: AsyncMock
    ) -> None:
        start = datetime.now(UTC) - timedelta(days=7)
        end = datetime.now(UTC)

        res1 = MagicMock(spec=Result)
        res1.scalar_one_or_none.return_value = 8

        res2 = MagicMock(spec=Result)
        res2.all.return_value = [("under_investigation", 5), ("closed", 3)]

        res3 = MagicMock(spec=Result)
        res3.all.return_value = [("critical", 2), ("high", 6)]

        res4 = MagicMock(spec=Result)
        res4.all.return_value = [("level_1", 2)]

        res5 = MagicMock(spec=Result)
        res5.scalar_one_or_none.return_value = 5

        res6 = MagicMock(spec=Result)
        res6.scalar_one_or_none.return_value = 1

        mock_session.execute.side_effect = [res1, res2, res3, res4, res5, res6]

        # Global
        metrics = await dashboard_repo.get_case_metrics(start, end, department_id=None)
        assert metrics["total_cases"] == 8
        assert metrics["cases_by_status"] == {"under_investigation": 5, "closed": 3}
        assert metrics["cases_by_priority"] == {"critical": 2, "high": 6}
        assert metrics["cases_by_escalation"] == {"level_1": 2}
        assert metrics["active_investigations_count"] == 5
        assert metrics["legal_hold_cases_count"] == 1

        # Scoped
        dept_id = uuid4()
        mock_session.execute.side_effect = [res1, res2, res3, res4, res5, res6]
        metrics_scoped = await dashboard_repo.get_case_metrics(start, end, department_id=dept_id)
        assert metrics_scoped["total_cases"] == 8
        assert metrics_scoped["department_id"] == dept_id

    async def test_get_operations_metrics_global_and_scoped(
        self, dashboard_repo: DashboardRepository, mock_session: AsyncMock
    ) -> None:
        start = datetime.now(UTC) - timedelta(days=7)
        end = datetime.now(UTC)

        res_ai_total = MagicMock(spec=Result)
        res_ai_total.scalar_one_or_none.return_value = 12

        res_ai_status = MagicMock(spec=Result)
        res_ai_status.all.return_value = [("completed", 10), ("failed", 2)]

        res_ai_step = MagicMock(spec=Result)
        res_ai_step.all.return_value = [("face_detection", 12)]

        res_notif_total = MagicMock(spec=Result)
        res_notif_total.scalar_one_or_none.return_value = 50

        res_notif_chan = MagicMock(spec=Result)
        res_notif_chan.all.return_value = [("in_app", 40), ("email", 10)]

        res_notif_status = MagicMock(spec=Result)
        res_notif_status.all.return_value = [("delivered", 48), ("failed", 2)]

        res_att_total = MagicMock(spec=Result)
        res_att_total.scalar_one_or_none.return_value = 52

        res_att_fail = MagicMock(spec=Result)
        res_att_fail.scalar_one_or_none.return_value = 2

        mock_session.execute.side_effect = [
            res_ai_total,
            res_ai_status,
            res_ai_step,
            res_notif_total,
            res_notif_chan,
            res_notif_status,
            res_att_total,
            res_att_fail,
        ]

        metrics = await dashboard_repo.get_operations_metrics(start, end, department_id=None)
        assert metrics["ai_jobs_total"] == 12
        assert metrics["ai_jobs_by_status"] == {"completed": 10, "failed": 2}
        assert metrics["ai_jobs_by_task_type"] == {"face_detection": 12}
        assert metrics["notifications_total"] == 50
        assert metrics["notifications_by_channel"] == {"in_app": 40, "email": 10}
        assert metrics["notifications_by_status"] == {"delivered": 48, "failed": 2}
        assert metrics["delivery_attempts_total"] == 52
        assert metrics["delivery_failures_total"] == 2

        # Scoped
        dept_id = uuid4()
        mock_session.execute.side_effect = [
            res_ai_total,
            res_ai_status,
            res_ai_step,
            res_notif_total,
            res_notif_chan,
            res_notif_status,
            res_att_total,
            res_att_fail,
        ]
        metrics_scoped = await dashboard_repo.get_operations_metrics(
            start, end, department_id=dept_id
        )
        assert metrics_scoped["ai_jobs_total"] == 12
        assert metrics_scoped["department_id"] == dept_id


class TestNotificationRepositoryUnit:
    """Isolated unit tests for NotificationRepository database operations."""

    @pytest.fixture
    def mock_session(self) -> AsyncMock:
        sess = AsyncMock()
        sess.add = MagicMock()
        sess.flush = AsyncMock()
        sess.execute = AsyncMock()
        return sess

    @pytest.fixture
    def notification_repo(self, mock_session: AsyncMock) -> NotificationRepository:
        return NotificationRepository(mock_session)

    async def test_create_and_get_by_id(
        self, notification_repo: NotificationRepository, mock_session: AsyncMock
    ) -> None:
        notif = Notification(
            id=uuid4(),
            recipient_id=uuid4(),
            channel=NotificationChannel.IN_APP.value,
            category=NotificationCategory.SYSTEM_NOTICE.value,
            priority=NotificationPriority.NORMAL.value,
            delivery_status=DeliveryStatus.DELIVERED.value,
            title="System Alert",
            body="Maintenance scheduled",
        )

        # Create
        created = await notification_repo.create(notif)
        assert created == notif
        mock_session.add.assert_called_with(notif)
        mock_session.flush.assert_awaited()

        # Get by ID
        res = MagicMock(spec=Result)
        scalars = MagicMock()
        scalars.first.return_value = notif
        res.scalars.return_value = scalars
        mock_session.execute.return_value = res

        found = await notification_repo.get_by_id(notif.id)
        assert found == notif

        # Get by ID and recipient
        found_scoped = await notification_repo.get_by_id_and_recipient(notif.id, notif.recipient_id)
        assert found_scoped == notif

        # Get by correlation ID
        found_corr = await notification_repo.get_by_correlation_id("corr-123", notif.recipient_id)
        assert found_corr == notif

    async def test_list_and_count_for_recipient(
        self, notification_repo: NotificationRepository, mock_session: AsyncMock
    ) -> None:
        recipient_id = uuid4()
        items = [
            Notification(id=uuid4(), recipient_id=recipient_id, title="Note 1"),
            Notification(id=uuid4(), recipient_id=recipient_id, title="Note 2"),
        ]

        res = MagicMock(spec=Result)
        scalars = MagicMock()
        scalars.all.return_value = items
        res.scalars.return_value = scalars
        mock_session.execute.return_value = res

        # List with no read filter
        res_list = await notification_repo.list_for_recipient(
            recipient_id, is_read=None, limit=10, offset=0
        )
        assert len(res_list) == 2

        # List with is_read=False
        res_unread = await notification_repo.list_for_recipient(recipient_id, is_read=False)
        assert len(res_unread) == 2

        # Count
        count_res = MagicMock(spec=Result)
        count_res.scalar_one_or_none.return_value = 5
        mock_session.execute.return_value = count_res

        total = await notification_repo.count_for_recipient(recipient_id, is_read=None)
        assert total == 5

        unread = await notification_repo.get_unread_count(recipient_id)
        assert unread == 5

    async def test_mark_as_read_and_mark_all(
        self, notification_repo: NotificationRepository, mock_session: AsyncMock
    ) -> None:
        recipient_id = uuid4()

        # Empty list returns 0 early without executing SQL
        assert await notification_repo.mark_as_read([], recipient_id) == 0

        # Mark specific IDs
        res = MagicMock(spec=Result)
        res.rowcount = 2
        mock_session.execute.return_value = res

        marked = await notification_repo.mark_as_read([uuid4(), uuid4()], recipient_id)
        assert marked == 2
        mock_session.flush.assert_awaited()

        # Mark all as read
        res_all = MagicMock(spec=Result)
        res_all.rowcount = 7
        mock_session.execute.return_value = res_all

        marked_all = await notification_repo.mark_all_as_read(recipient_id)
        assert marked_all == 7

    async def test_update_delivery_status(
        self, notification_repo: NotificationRepository, mock_session: AsyncMock
    ) -> None:
        notif_id = uuid4()
        await notification_repo.update_delivery_status(notif_id, DeliveryStatus.FAILED)
        mock_session.execute.assert_awaited()
        mock_session.flush.assert_awaited()

    async def test_preference_operations(
        self, notification_repo: NotificationRepository, mock_session: AsyncMock
    ) -> None:
        user_id = uuid4()
        pref = NotificationPreference(user_id=user_id, email_enabled=True)

        # 1. Found existing
        res = MagicMock(spec=Result)
        scalars = MagicMock()
        scalars.first.return_value = pref
        res.scalars.return_value = scalars
        mock_session.execute.return_value = res

        res_pref = await notification_repo.get_preference_by_user_id(user_id)
        assert res_pref == pref

        res_or_create = await notification_repo.get_or_create_preference(user_id)
        assert res_or_create == pref

        # 2. Not found -> creates default
        scalars.first.return_value = None
        new_pref = await notification_repo.get_or_create_preference(user_id)
        assert new_pref.user_id == user_id
        assert new_pref.email_enabled is True
        assert new_pref.in_app_enabled is True
        mock_session.add.assert_called()

        # 3. Save preference
        saved = await notification_repo.save_preference(new_pref)
        assert saved == new_pref

    async def test_delivery_attempt_operations(
        self, notification_repo: NotificationRepository, mock_session: AsyncMock
    ) -> None:
        notif_id = uuid4()
        attempt = NotificationDeliveryAttempt(
            notification_id=notif_id,
            attempt_number=1,
            channel=NotificationChannel.EMAIL.value,
            status=DeliveryStatus.DELIVERED.value,
            deduplication_key="dedup-key-123",
        )

        # Create
        created = await notification_repo.create_delivery_attempt(attempt)
        assert created == attempt
        mock_session.add.assert_called_with(attempt)
        mock_session.flush.assert_awaited()

        # Get by dedup key
        res = MagicMock(spec=Result)
        scalars = MagicMock()
        scalars.first.return_value = attempt
        res.scalars.return_value = scalars
        mock_session.execute.return_value = res

        found = await notification_repo.get_attempt_by_dedup_key("dedup-key-123")
        assert found == attempt

        # List attempts for notification
        scalars.all.return_value = [attempt]
        attempts = await notification_repo.list_attempts_for_notification(notif_id)
        assert len(attempts) == 1
        assert attempts[0] == attempt
