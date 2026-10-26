"""Unit tests for IncidentRepository and EvidenceRepository database operations (Phases 41-45)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.engine import Result

from backend.app.core.evidence import EvidenceStatus, UploadSessionStatus, UploadStatus
from backend.app.core.exceptions import BusinessRuleError
from backend.app.models.evidence import EvidenceAttachment, UploadSession
from backend.app.models.incident import Incident
from backend.app.repositories.evidence import EvidenceRepository
from backend.app.repositories.incident import IncidentRepository


class TestIncidentRepositoryUnit:
    """Isolated unit tests for IncidentRepository queries and filters."""

    @pytest.fixture
    def mock_session(self) -> AsyncMock:
        sess = AsyncMock()
        sess.add = MagicMock()
        return sess

    @pytest.fixture
    def incident_repo(self, mock_session: AsyncMock) -> IncidentRepository:
        return IncidentRepository(mock_session)

    async def test_create_incident(
        self, incident_repo: IncidentRepository, mock_session: AsyncMock
    ) -> None:
        incident = Incident(id=uuid4(), title="Test Report", reference_number="INC-2026-TEST1")
        res = await incident_repo.create(incident)
        assert res == incident
        mock_session.add.assert_called_once_with(incident)
        mock_session.flush.assert_awaited_once()

    async def test_get_by_id(
        self, incident_repo: IncidentRepository, mock_session: AsyncMock
    ) -> None:
        target_id = uuid4()
        mock_result = MagicMock(spec=Result)
        mock_scalars = MagicMock()
        mock_incident = Incident(id=target_id, title="Test Report")
        mock_scalars.first.return_value = mock_incident
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        found = await incident_repo.get_by_id(target_id)
        assert found == mock_incident
        mock_session.execute.assert_awaited_once()

    async def test_get_by_reference_number(
        self, incident_repo: IncidentRepository, mock_session: AsyncMock
    ) -> None:
        mock_result = MagicMock(spec=Result)
        mock_scalars = MagicMock()
        mock_incident = Incident(id=uuid4(), reference_number="INC-2026-REF1")
        mock_scalars.first.return_value = mock_incident
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        found = await incident_repo.get_by_reference_number("INC-2026-REF1")
        assert found == mock_incident

    async def test_update_incident(
        self, incident_repo: IncidentRepository, mock_session: AsyncMock
    ) -> None:
        incident = Incident(id=uuid4(), title="Updated")
        res = await incident_repo.update(incident)
        assert res == incident
        mock_session.add.assert_called_once_with(incident)
        mock_session.flush.assert_awaited_once()

    async def test_list_paginated_validation_errors(
        self, incident_repo: IncidentRepository
    ) -> None:
        with pytest.raises(BusinessRuleError) as exc_order:
            await incident_repo.list_paginated(sort_order="sideways")
        assert exc_order.value.code == "INVALID_SORT_ORDER"

        with pytest.raises(BusinessRuleError) as exc_field:
            await incident_repo.list_paginated(sort_by="secret_password")
        assert exc_field.value.code == "INVALID_SORT_FIELD"

    async def test_list_paginated_zero_results(
        self, incident_repo: IncidentRepository, mock_session: AsyncMock
    ) -> None:
        count_res = MagicMock(spec=Result)
        count_res.scalar_one.return_value = 0
        mock_session.execute.return_value = count_res

        items, total = await incident_repo.list_paginated(
            reporter_id=uuid4(),
            department_id=uuid4(),
            status="closed",
            category="other",
            search="dormitory entrance",
            sort_by="title",
            sort_order="asc",
        )
        assert items == []
        assert total == 0

    async def test_list_paginated_with_results(
        self, incident_repo: IncidentRepository, mock_session: AsyncMock
    ) -> None:
        count_res = MagicMock(spec=Result)
        count_res.scalar_one.return_value = 1

        mock_item = Incident(id=uuid4(), title="Graffiti report")
        items_res = MagicMock(spec=Result)
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [mock_item]
        items_res.scalars.return_value = mock_scalars

        mock_session.execute.side_effect = [count_res, items_res]

        items, total = await incident_repo.list_paginated(
            sort_by="occurred_at",
            sort_order="desc",
        )
        assert items == [mock_item]
        assert total == 1


class TestEvidenceRepositoryUnit:
    """Isolated unit tests for EvidenceRepository operations."""

    @pytest.fixture
    def mock_session(self) -> AsyncMock:
        sess = AsyncMock()
        sess.add = MagicMock()
        return sess

    @pytest.fixture
    def evidence_repo(self, mock_session: AsyncMock) -> EvidenceRepository:
        return EvidenceRepository(mock_session)

    async def test_create_and_update_attachment(
        self, evidence_repo: EvidenceRepository, mock_session: AsyncMock
    ) -> None:
        att = EvidenceAttachment(
            id=uuid4(),
            incident_id=uuid4(),
            uploader_id=uuid4(),
            department_id=uuid4(),
            storage_key="test-key",
            original_filename="notes.pdf",
            declared_mime_type="application/pdf",
            file_size_bytes=2048,
            evidence_status=EvidenceStatus.ATTACHED.value,
            upload_status=UploadStatus.COMPLETED.value,
        )
        res_create = await evidence_repo.create_attachment(att)
        assert res_create == att

        att.original_filename = "renamed.pdf"
        res_up = await evidence_repo.update_attachment(att)
        assert res_up == att

    async def test_get_attachment_by_id_and_key(
        self, evidence_repo: EvidenceRepository, mock_session: AsyncMock
    ) -> None:
        att_id = uuid4()
        att = EvidenceAttachment(id=att_id, storage_key="key/1/file.png")

        mock_res = MagicMock(spec=Result)
        mock_scalars = MagicMock()
        mock_scalars.first.return_value = att
        mock_res.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_res

        found_id = await evidence_repo.get_attachment_by_id(att_id)
        assert found_id == att

        found_key = await evidence_repo.get_attachment_by_storage_key("key/1/file.png")
        assert found_key == att

    async def test_list_attachments_by_incident(
        self, evidence_repo: EvidenceRepository, mock_session: AsyncMock
    ) -> None:
        att = EvidenceAttachment(id=uuid4())
        mock_res = MagicMock(spec=Result)
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [att]
        mock_res.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_res

        results = await evidence_repo.list_attachments_by_incident(uuid4())
        assert results == [att]

    async def test_upload_session_crud(
        self, evidence_repo: EvidenceRepository, mock_session: AsyncMock
    ) -> None:
        sess = UploadSession(
            id=uuid4(),
            incident_id=uuid4(),
            uploader_id=uuid4(),
            department_id=uuid4(),
            storage_key="sess-key",
            original_filename="upload.jpg",
            declared_mime_type="image/jpeg",
            expected_size_bytes=5000,
            expires_at=datetime.now(UTC),
            session_status=UploadSessionStatus.ACTIVE.value,
        )
        created = await evidence_repo.create_upload_session(sess)
        assert created == sess

        mock_res = MagicMock(spec=Result)
        mock_scalars = MagicMock()
        mock_scalars.first.return_value = sess
        mock_res.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_res

        found_id = await evidence_repo.get_upload_session(sess.id)
        assert found_id == sess

        found_key = await evidence_repo.get_upload_session_by_key("sess-key")
        assert found_key == sess

        sess.session_status = UploadSessionStatus.COMPLETED.value
        updated = await evidence_repo.update_upload_session(sess)
        assert updated == sess

    async def test_get_attachment_by_session_id(
        self, evidence_repo: EvidenceRepository, mock_session: AsyncMock
    ) -> None:
        att = EvidenceAttachment(id=uuid4(), upload_session_id=uuid4())
        mock_res = MagicMock(spec=Result)
        mock_scalars = MagicMock()
        mock_scalars.first.return_value = att
        mock_res.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_res

        found = await evidence_repo.get_attachment_by_session_id(uuid4())
        assert found == att

    async def test_get_upload_session_by_upload_id(
        self, evidence_repo: EvidenceRepository, mock_session: AsyncMock
    ) -> None:
        sess = UploadSession(id=uuid4(), upload_id="mp_upload_123")
        mock_res = MagicMock(spec=Result)
        mock_scalars = MagicMock()
        mock_scalars.first.return_value = sess
        mock_res.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_res

        found = await evidence_repo.get_upload_session_by_upload_id("mp_upload_123")
        assert found == sess

    async def test_cumulative_size_queries(
        self, evidence_repo: EvidenceRepository, mock_session: AsyncMock
    ) -> None:
        mock_res = MagicMock(spec=Result)
        mock_res.scalar_one.return_value = 1048576
        mock_session.execute.return_value = mock_res

        # Incident
        size_inc = await evidence_repo.get_cumulative_size_by_incident(uuid4())
        assert size_inc == 1048576

        # User
        size_user = await evidence_repo.get_cumulative_size_by_user(uuid4())
        assert size_user == 1048576

        # Department
        size_dept = await evidence_repo.get_cumulative_size_by_department(uuid4())
        assert size_dept == 1048576
