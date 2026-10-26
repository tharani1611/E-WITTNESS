"""Unit tests for Batch 06 Group 02 repositories (Phases 56-59).

Tests:
- AuditRepository: append_event, chain verification, tampering detection, export persistence, pagination.
- IncidentRepository: review queue queries, sorting, filtering, workload calculation, assignment history.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.engine import Result

from backend.app.core.audit import AUDIT_DISCLAIMER, compute_security_audit_event_hash
from backend.app.core.exceptions import BusinessRuleError
from backend.app.models.audit import EvidenceExport, SecurityAuditEvent
from backend.app.models.incident import Incident, IncidentAssignment
from backend.app.repositories.audit import AuditRepository
from backend.app.repositories.incident import IncidentRepository


class TestAuditRepositoryUnit:
    """Isolated unit tests for AuditRepository queries and ledger operations."""

    @pytest.fixture
    def mock_session(self) -> AsyncMock:
        sess = AsyncMock()
        sess.add = MagicMock()
        return sess

    @pytest.fixture
    def audit_repo(self, mock_session: AsyncMock) -> AuditRepository:
        return AuditRepository(mock_session)

    async def test_get_latest_event_empty_and_existing(
        self, audit_repo: AuditRepository, mock_session: AsyncMock
    ) -> None:
        mock_result = MagicMock(spec=Result)
        mock_scalars = MagicMock()
        mock_scalars.first.return_value = None
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        assert await audit_repo.get_latest_event() is None

        # Now with existing event
        mock_event = SecurityAuditEvent(id=uuid4(), sequence_number=42)
        mock_scalars.first.return_value = mock_event
        assert await audit_repo.get_latest_event() == mock_event

    async def test_get_next_sequence_number(
        self, audit_repo: AuditRepository, mock_session: AsyncMock
    ) -> None:
        mock_result = MagicMock(spec=Result)
        mock_result.scalar_one.return_value = 10
        mock_session.execute.return_value = mock_result

        assert await audit_repo.get_next_sequence_number() == 11

    async def test_append_event_first_and_subsequent(
        self, audit_repo: AuditRepository, mock_session: AsyncMock
    ) -> None:
        mock_res_empty = MagicMock(spec=Result)
        mock_scalars = MagicMock()
        mock_scalars.first.return_value = None
        mock_res_empty.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_res_empty

        actor_id = uuid4()
        dept_id = uuid4()
        event1 = await audit_repo.append_event(
            action="incident_assigned",
            actor_id=actor_id,
            actor_role="dept_admin",
            target_type="incident",
            target_id="INC-123",
            outcome="success",
            department_id=dept_id,
            details={"assigned_to": "investigator_1"},
        )
        assert event1.sequence_number == 1
        assert event1.previous_event_hash is None
        assert event1.event_hash is not None
        mock_session.add.assert_called_with(event1)
        mock_session.flush.assert_awaited()

        # Subsequent event chained to event1
        mock_scalars.first.return_value = event1
        event2 = await audit_repo.append_event(
            action="incident_reassigned",
            actor_id=actor_id,
            actor_role="dept_admin",
            target_type="incident",
            target_id="INC-123",
            outcome="success",
            department_id=dept_id,
        )
        assert event2.sequence_number == 2
        assert event2.previous_event_hash == event1.event_hash

    async def test_list_events_paginated_filtering_and_bounds(
        self, audit_repo: AuditRepository, mock_session: AsyncMock
    ) -> None:
        count_res = MagicMock(spec=Result)
        count_res.scalar_one.return_value = 0
        mock_session.execute.return_value = count_res

        # Test limit bounds clamping (<1 clamped to 1, >100 clamped to 100)
        items, total = await audit_repo.list_events_paginated(
            limit=500,
            actor_id=uuid4(),
            action="incident_assigned",
            target_type="incident",
            target_id="INC-001",
            department_id=uuid4(),
            outcome="success",
            start_time=datetime.now(UTC) - timedelta(days=1),
            end_time=datetime.now(UTC),
        )
        assert items == []
        assert total == 0

        # With items
        count_res.scalar_one.return_value = 1
        mock_item = SecurityAuditEvent(id=uuid4(), sequence_number=1, action="incident_assigned")
        items_res = MagicMock(spec=Result)
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [mock_item]
        items_res.scalars.return_value = mock_scalars
        mock_session.execute.side_effect = [count_res, items_res]

        items, total = await audit_repo.list_events_paginated(limit=-5)
        assert items == [mock_item]
        assert total == 1

    async def test_verify_chain_empty(
        self, audit_repo: AuditRepository, mock_session: AsyncMock
    ) -> None:
        mock_res = MagicMock(spec=Result)
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []
        mock_res.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_res

        report = await audit_repo.verify_chain()
        assert report["status"] == "empty"
        assert report["chain_valid"] is True
        assert report["total_events_verified"] == 0
        assert report["disclaimer"] == AUDIT_DISCLAIMER

    async def test_verify_chain_valid_and_tampered(
        self, audit_repo: AuditRepository, mock_session: AsyncMock
    ) -> None:
        now = datetime.now(UTC)
        actor_id = uuid4()
        dept_id = uuid4()

        hash1 = compute_security_audit_event_hash(
            sequence_number=1,
            action="incident_assigned",
            actor_id=actor_id,
            department_id=dept_id,
            target_type="incident",
            target_id="INC-01",
            outcome="success",
            created_at=now,
            previous_event_hash=None,
            details={"info": "valid"},
        )
        ev1 = SecurityAuditEvent(
            id=uuid4(),
            sequence_number=1,
            action="incident_assigned",
            actor_id=actor_id,
            department_id=dept_id,
            target_type="incident",
            target_id="INC-01",
            outcome="success",
            created_at=now,
            details=json.dumps({"info": "valid"}),
            previous_event_hash=None,
            event_hash=hash1,
        )

        hash2 = compute_security_audit_event_hash(
            sequence_number=2,
            action="incident_acknowledged",
            actor_id=actor_id,
            department_id=dept_id,
            target_type="incident",
            target_id="INC-01",
            outcome="success",
            created_at=now,
            previous_event_hash=hash1,
            details=None,
        )
        ev2 = SecurityAuditEvent(
            id=uuid4(),
            sequence_number=2,
            action="incident_acknowledged",
            actor_id=actor_id,
            department_id=dept_id,
            target_type="incident",
            target_id="INC-01",
            outcome="success",
            created_at=now,
            details=None,
            previous_event_hash=hash1,
            event_hash=hash2,
        )

        mock_res = MagicMock(spec=Result)
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [ev1, ev2]
        mock_res.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_res

        # 1. Valid chain verification
        report = await audit_repo.verify_chain()
        assert report["status"] == "verified"
        assert report["chain_valid"] is True
        assert report["total_events_verified"] == 2
        assert len(report["tampered_event_ids"]) == 0

        # 2. Tampered hash on ev2
        ev2.event_hash = "bad_hash_" + "0" * 55
        report_tampered = await audit_repo.verify_chain()
        assert report_tampered["status"] == "compromised"
        assert report_tampered["chain_valid"] is False
        assert ev2.id in report_tampered["tampered_event_ids"]

        # 3. Genesis event with non-null previous hash
        ev1.previous_event_hash = "non_null_hash"
        report_genesis = await audit_repo.verify_chain()
        assert report_genesis["status"] == "compromised"
        assert ev1.id in report_genesis["tampered_event_ids"]

    async def test_verify_chain_with_start_sequence_greater_than_one(
        self, audit_repo: AuditRepository, mock_session: AsyncMock
    ) -> None:
        now = datetime.now(UTC)
        pred_hash = "pred_hash_" + "1" * 54
        ev_pred = SecurityAuditEvent(id=uuid4(), sequence_number=4, event_hash=pred_hash)

        hash5 = compute_security_audit_event_hash(
            sequence_number=5,
            action="incident_assigned",
            actor_id=None,
            department_id=None,
            target_type="incident",
            target_id="INC-05",
            outcome="success",
            created_at=now,
            previous_event_hash=pred_hash,
            details="raw_text",  # tests non-json fallback
        )
        ev5 = SecurityAuditEvent(
            id=uuid4(),
            sequence_number=5,
            action="incident_assigned",
            actor_id=None,
            department_id=None,
            target_type="incident",
            target_id="INC-05",
            outcome="success",
            created_at=now,
            details="not-a-valid-json",
            previous_event_hash=pred_hash,
            event_hash=hash5,
        )

        mock_res_pred = MagicMock(spec=Result)
        mock_scalars_pred = MagicMock()
        mock_scalars_pred.first.return_value = ev_pred
        mock_res_pred.scalars.return_value = mock_scalars_pred

        mock_res_ev5 = MagicMock(spec=Result)
        mock_scalars_ev5 = MagicMock()
        mock_scalars_ev5.all.return_value = [ev5]
        mock_res_ev5.scalars.return_value = mock_scalars_ev5

        mock_session.execute.side_effect = [mock_res_ev5, mock_res_pred]

        report = await audit_repo.verify_chain(start_sequence=5)
        assert report["first_sequence_number"] == 5

    async def test_evidence_export_crud_and_pagination(
        self, audit_repo: AuditRepository, mock_session: AsyncMock
    ) -> None:
        export = EvidenceExport(
            id=uuid4(),
            incident_id=uuid4(),
            department_id=uuid4(),
            exported_by_id=uuid4(),
            export_scope="incident_package",
            export_format="zip",
            manifest_sha256="m" * 64,
            evidence_count=2,
            reason="Subpoena",
            status="completed",
        )
        created = await audit_repo.create_evidence_export(export)
        assert created == export
        mock_session.add.assert_called_with(export)
        mock_session.flush.assert_awaited()

        # get_by_id
        mock_res = MagicMock(spec=Result)
        mock_scalars = MagicMock()
        mock_scalars.first.return_value = export
        mock_res.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_res

        found = await audit_repo.get_evidence_export_by_id(export.id)
        assert found == export

        # list_paginated
        count_res = MagicMock(spec=Result)
        count_res.scalar_one.return_value = 1
        items_res = MagicMock(spec=Result)
        mock_scalars_items = MagicMock()
        mock_scalars_items.all.return_value = [export]
        items_res.scalars.return_value = mock_scalars_items

        mock_session.execute.side_effect = [count_res, items_res]
        items, total = await audit_repo.list_evidence_exports_paginated(
            department_id=export.department_id,
            incident_id=export.incident_id,
            exported_by_id=export.exported_by_id,
            limit=200,
        )
        assert items == [export]
        assert total == 1


class TestIncidentRepositoryQueueAndAssignmentsUnit:
    """Isolated unit tests for IncidentRepository queue, workload, and assignment operations."""

    @pytest.fixture
    def mock_session(self) -> AsyncMock:
        sess = AsyncMock()
        sess.add = MagicMock()
        return sess

    @pytest.fixture
    def incident_repo(self, mock_session: AsyncMock) -> IncidentRepository:
        return IncidentRepository(mock_session)

    async def test_list_review_queue_paginated_validation(
        self, incident_repo: IncidentRepository
    ) -> None:
        with pytest.raises(BusinessRuleError) as exc_field:
            await incident_repo.list_review_queue_paginated(sort_by="invalid_sort_field")
        assert exc_field.value.code == "INVALID_SORT_FIELD"

        with pytest.raises(BusinessRuleError) as exc_order:
            await incident_repo.list_review_queue_paginated(sort_order="diagonal")
        assert exc_order.value.code == "INVALID_SORT_ORDER"

    async def test_list_review_queue_paginated_filters_and_zero_items(
        self, incident_repo: IncidentRepository, mock_session: AsyncMock
    ) -> None:
        count_res = MagicMock(spec=Result)
        count_res.scalar_one.return_value = 0
        mock_session.execute.return_value = count_res

        items, total = await incident_repo.list_review_queue_paginated(
            department_id=uuid4(),
            status="submitted",
            severity="high",
            category="safety_hazard",
            assignment_status="unassigned",
            reviewer_id=uuid4(),
            search="server room",
            created_after=datetime.now(UTC) - timedelta(days=5),
            created_before=datetime.now(UTC),
            sort_by="occurred_at",
            sort_order="asc",
        )
        assert items == []
        assert total == 0

    async def test_list_review_queue_paginated_with_results(
        self, incident_repo: IncidentRepository, mock_session: AsyncMock
    ) -> None:
        inc = Incident(id=uuid4(), title="Queue item", reference_number="SEC-001")
        count_res = MagicMock(spec=Result)
        count_res.scalar_one.return_value = 1
        items_res = MagicMock(spec=Result)
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [inc]
        items_res.scalars.return_value = mock_scalars

        mock_session.execute.side_effect = [count_res, items_res]

        items, total = await incident_repo.list_review_queue_paginated(
            sort_by="severity",
            sort_order="desc",
        )
        assert items == [inc]
        assert total == 1

    async def test_get_workload_summary(
        self, incident_repo: IncidentRepository, mock_session: AsyncMock
    ) -> None:
        mock_row = MagicMock()
        mock_row.total = 10
        mock_row.unassigned = 4
        mock_row.assigned = 3
        mock_row.pending = 2
        mock_row.completed = 1
        mock_row.overdue = 2

        mock_res = MagicMock(spec=Result)
        mock_res.one.return_value = mock_row
        mock_session.execute.return_value = mock_res

        dept_id = uuid4()
        summary = await incident_repo.get_workload_summary(department_id=dept_id)
        assert summary["total"] == 10
        assert summary["unassigned"] == 4
        assert summary["assigned"] == 3
        assert summary["pending"] == 2
        assert summary["completed"] == 1
        assert summary["overdue"] == 2

    async def test_create_assignment_and_history(
        self, incident_repo: IncidentRepository, mock_session: AsyncMock
    ) -> None:
        assign = IncidentAssignment(
            id=uuid4(),
            incident_id=uuid4(),
            assigned_by_id=uuid4(),
            reviewer_id=uuid4(),
            status="assigned",
            reason="Lead reviewer assignment",
        )
        created = await incident_repo.create_assignment(assign)
        assert created == assign
        mock_session.add.assert_called_with(assign)
        mock_session.flush.assert_awaited()

        # get_assignment_history
        mock_res = MagicMock(spec=Result)
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [assign]
        mock_res.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_res

        history = await incident_repo.get_assignment_history(assign.incident_id)
        assert history == [assign]

        # get_latest_assignment
        mock_scalars.first.return_value = assign
        latest = await incident_repo.get_latest_assignment(assign.incident_id)
        assert latest == assign
