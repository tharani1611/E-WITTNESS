"""Unit tests for Phase 62: Dataset Ingestion, Provenance, Licensing, and Consent."""

from __future__ import annotations

from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from pydantic import ValidationError

from backend.app.core.ai import (
    APPROVED_DATASET_LICENSES,
    DatasetConsentStatus,
    DatasetStatus,
    DatasetType,
    compute_manifest_sha256,
)
from backend.app.core.audit import AuditAction
from backend.app.core.exceptions import (
    BusinessRuleError,
    ConflictError,
    PermissionDeniedError,
    ResourceNotFoundError,
)
from backend.app.core.identity import RoleCode
from backend.app.models.ai import AIDataset
from backend.app.schemas.ai import (
    DatasetManifestItem,
    DatasetRegisterRequest,
    DatasetReviewRequest,
)
from backend.app.schemas.auth import AuthenticatedPrincipal
from backend.app.services.ai_dataset import AIDatasetService


@pytest.mark.unit
class TestDatasetManifestAndLicensing:
    """Verify manifest cryptographic hashing and licensing allowlist."""

    def test_manifest_hashing_is_order_independent_and_deterministic(self) -> None:
        """Verify sorting ensures identical hash regardless of input order."""
        item1 = {"path": "videos/clip_b.mp4", "sha256_hash": "a" * 64, "label": "violence"}
        item2 = {"path": "videos/clip_a.mp4", "sha256_hash": "b" * 64, "label": "non_violence"}

        hash_order1 = compute_manifest_sha256([item1, item2])
        hash_order2 = compute_manifest_sha256([item2, item1])

        assert hash_order1 == hash_order2
        assert len(hash_order1) == 64

    def test_manifest_item_validation(self) -> None:
        """Verify item validates 64-char hex SHA-256."""
        valid_item = DatasetManifestItem(
            path="clip1.mp4",
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            label="violence",
            file_size_bytes=1024,
        )
        assert valid_item.path == "clip1.mp4"

        # Invalid length
        with pytest.raises(ValidationError):
            DatasetManifestItem(path="clip.mp4", sha256_hash="invalid")

        # Non-hex characters
        with pytest.raises(ValidationError):
            DatasetManifestItem(path="clip.mp4", sha256_hash="z" * 64)

    def test_approved_licenses_contains_standard_spdx(self) -> None:
        """Verify approved license set includes CC-BY-4.0, MIT, Apache-2.0, etc."""
        assert "CC-BY-4.0" in APPROVED_DATASET_LICENSES
        assert "Apache-2.0" in APPROVED_DATASET_LICENSES
        assert "MIT" in APPROVED_DATASET_LICENSES
        assert "CC0-1.0" in APPROVED_DATASET_LICENSES

    def test_register_request_rejects_unapproved_license(self) -> None:
        """Verify schema rejects proprietary or prohibited licenses."""
        with pytest.raises(ValidationError, match="not in approved dataset licenses"):
            DatasetRegisterRequest(
                name="benchmark-v1",
                version="1.0.0",
                license_id="PROPRIETARY_UNAPPROVED_COMMERCIAL",
                manifest_items=[DatasetManifestItem(path="c1.mp4", sha256_hash="a" * 64)],
            )


@pytest.mark.unit
class TestAIDatasetService:
    """Verify AIDatasetService domain logic and security invariants."""

    @pytest.fixture
    def mock_repo(self) -> AsyncMock:
        repo = AsyncMock()
        repo.create.side_effect = lambda d: d
        repo.update.side_effect = lambda d: d
        repo.get_by_name_and_version.return_value = None
        repo.get_by_id.return_value = None
        repo.list_datasets.return_value = []
        repo.count_datasets.return_value = 0
        return repo

    @pytest.fixture
    def mock_audit_repo(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def principal_investigator(self) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            user_id=uuid4(),
            email="investigator@campus.edu",
            full_name="Investigator Alice",
            account_status="active",
            is_active=True,
            role_code=RoleCode.INVESTIGATOR.value,
            department_id=uuid4(),
            session_id=uuid4(),
        )

    @pytest.fixture
    def principal_super_admin(self) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            user_id=uuid4(),
            email="admin@campus.edu",
            full_name="Super Admin Bob",
            account_status="active",
            is_active=True,
            role_code=RoleCode.SUPER_ADMIN.value,
            department_id=None,
            session_id=uuid4(),
        )

    @pytest.fixture
    def principal_student(self) -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            user_id=uuid4(),
            email="student@campus.edu",
            full_name="Student Charlie",
            account_status="active",
            is_active=True,
            role_code=RoleCode.STUDENT.value,
            department_id=uuid4(),
            session_id=uuid4(),
        )

    async def test_register_dataset_success(
        self,
        mock_repo: AsyncMock,
        mock_audit_repo: AsyncMock,
        principal_investigator: AuthenticatedPrincipal,
    ) -> None:
        service = AIDatasetService(dataset_repo=mock_repo, audit_repo=mock_audit_repo)

        payload = DatasetRegisterRequest(
            name="violence-benchmark-eval",
            version="1.0.0",
            dataset_type=DatasetType.BENCHMARK,
            source_uri="https://zenodo.org/record/12345",
            license_id="CC-BY-4.0",
            consent_status=DatasetConsentStatus.CONSENTED,
            provenance_details={"donor": "Research Lab", "year": 2026},
            manifest_items=[
                DatasetManifestItem(path="bench1.mp4", sha256_hash="a" * 64, label="violence"),
                DatasetManifestItem(path="bench2.mp4", sha256_hash="b" * 64, label="non_violence"),
            ],
        )

        result = await service.register_dataset(payload, principal_investigator)

        assert result.name == "violence-benchmark-eval"
        assert result.version == "1.0.0"
        assert result.license_id == "CC-BY-4.0"
        assert result.status == DatasetStatus.PENDING_REVIEW.value
        assert result.manifest_item_count == 2
        assert len(result.manifest_sha256) == 64

        mock_repo.create.assert_awaited_once()
        mock_audit_repo.append_event.assert_awaited_once()
        assert (
            mock_audit_repo.append_event.call_args.kwargs["action"]
            == AuditAction.AI_DATASET_REGISTERED.value
        )

    async def test_register_dataset_rejects_operational_evidence_paths(
        self,
        mock_repo: AsyncMock,
        mock_audit_repo: AsyncMock,
        principal_investigator: AuthenticatedPrincipal,
    ) -> None:
        """Verify strict isolation: operational incident evidence cannot be imported into dataset."""
        service = AIDatasetService(dataset_repo=mock_repo, audit_repo=mock_audit_repo)

        payload = DatasetRegisterRequest(
            name="tainted-dataset",
            version="1.0.0",
            license_id="MIT",
            manifest_items=[
                DatasetManifestItem(
                    path="evidence/dept_123/incident_456/live_video.mp4",
                    sha256_hash="a" * 64,
                )
            ],
        )

        with pytest.raises(BusinessRuleError, match="cannot be imported into an AI dataset"):
            await service.register_dataset(payload, principal_investigator)

    async def test_register_dataset_conflict_on_duplicate_name_version(
        self,
        mock_repo: AsyncMock,
        mock_audit_repo: AsyncMock,
        principal_investigator: AuthenticatedPrincipal,
    ) -> None:
        mock_repo.get_by_name_and_version.return_value = AIDataset(
            name="existing-dataset",
            version="1.0.0",
            license_id="MIT",
            manifest_sha256="c" * 64,
            created_by_id=uuid4(),
        )
        service = AIDatasetService(dataset_repo=mock_repo, audit_repo=mock_audit_repo)

        payload = DatasetRegisterRequest(
            name="existing-dataset",
            version="1.0.0",
            license_id="MIT",
            manifest_items=[DatasetManifestItem(path="c.mp4", sha256_hash="a" * 64)],
        )

        with pytest.raises(ConflictError, match="already registered"):
            await service.register_dataset(payload, principal_investigator)

    async def test_student_cannot_register_dataset(
        self,
        mock_repo: AsyncMock,
        mock_audit_repo: AsyncMock,
        principal_student: AuthenticatedPrincipal,
    ) -> None:
        service = AIDatasetService(dataset_repo=mock_repo, audit_repo=mock_audit_repo)
        payload = DatasetRegisterRequest(
            name="student-dataset",
            version="1.0.0",
            license_id="MIT",
            manifest_items=[DatasetManifestItem(path="c.mp4", sha256_hash="a" * 64)],
        )

        with pytest.raises(PermissionDeniedError):
            await service.register_dataset(payload, principal_student)

    async def test_review_dataset_state_transitions(
        self,
        mock_repo: AsyncMock,
        mock_audit_repo: AsyncMock,
        principal_super_admin: AuthenticatedPrincipal,
        principal_investigator: AuthenticatedPrincipal,
    ) -> None:
        dataset = AIDataset(
            id=uuid4(),
            name="benchmark-dataset",
            version="1.0.0",
            license_id="MIT",
            manifest_sha256="d" * 64,
            status=DatasetStatus.PENDING_REVIEW.value,
            created_by_id=uuid4(),
        )
        mock_repo.get_by_id.return_value = dataset

        service = AIDatasetService(dataset_repo=mock_repo, audit_repo=mock_audit_repo)

        # Investigator lacks AI_DATASET_MANAGE
        with pytest.raises(PermissionDeniedError):
            await service.review_dataset(
                dataset.id,
                DatasetReviewRequest(decision="approved"),
                principal_investigator,
            )

        # Super admin approves
        approved = await service.review_dataset(
            dataset.id,
            DatasetReviewRequest(decision="approved", review_notes="Ethics verified"),
            principal_super_admin,
        )
        assert approved.status == DatasetStatus.APPROVED.value
        assert approved.review_notes == "Ethics verified"

        # Approved dataset can be withdrawn
        withdrawn = await service.review_dataset(
            dataset.id,
            DatasetReviewRequest(decision="withdrawn", review_notes="Deprecated"),
            principal_super_admin,
        )
        assert withdrawn.status == DatasetStatus.WITHDRAWN.value

        # Terminal state cannot be transitioned further
        with pytest.raises(BusinessRuleError, match="cannot be transitioned"):
            await service.review_dataset(
                dataset.id,
                DatasetReviewRequest(decision="approved"),
                principal_super_admin,
            )

    async def test_get_and_list_datasets(
        self,
        mock_repo: AsyncMock,
        principal_investigator: AuthenticatedPrincipal,
    ) -> None:
        dataset = AIDataset(
            id=uuid4(),
            name="list-test",
            version="2.0.0",
            license_id="Apache-2.0",
            manifest_sha256="e" * 64,
            status=DatasetStatus.APPROVED.value,
            created_by_id=uuid4(),
        )
        mock_repo.get_by_id.return_value = dataset
        mock_repo.list_datasets.return_value = [dataset]
        mock_repo.count_datasets.return_value = 1

        service = AIDatasetService(dataset_repo=mock_repo)

        read = await service.get_dataset(dataset.id, principal_investigator)
        assert read.name == "list-test"

        items, total = await service.list_datasets(principal_investigator, limit=10, offset=0)
        assert len(items) == 1
        assert total == 1

        # Non-existent dataset
        mock_repo.get_by_id.return_value = None
        with pytest.raises(ResourceNotFoundError):
            await service.get_dataset(uuid4(), principal_investigator)
