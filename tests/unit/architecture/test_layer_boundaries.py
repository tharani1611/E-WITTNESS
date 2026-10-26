"""Automated architectural boundary, protocol, and isolation tests (Phase 07 & 09)."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest

from backend.app.config.settings import Settings
from backend.app.core.architecture import (
    check_source_architecture,
    infer_layer_for_path,
    scan_project_architecture,
)
from backend.app.core.exceptions import (
    AppError,
    AuthenticationError,
    BusinessRuleError,
    ConflictError,
    PayloadTooLargeError,
    PermissionDeniedError,
    ResourceNotFoundError,
    ServiceUnavailableError,
)
from backend.app.repositories.base import (
    AppendOnlyLedgerRepositoryProtocol,
    TenantScopedRepositoryProtocol,
)
from tests.conftest import assert_test_resource_isolation

ROOT_DIR = Path(__file__).resolve().parents[3]


@pytest.mark.unit
class TestProjectArchitectureCompliance:
    """Verify the actual E-WITNESS repository passes all AST architectural rules."""

    def test_entire_codebase_has_zero_architecture_violations(self) -> None:
        violations = scan_project_architecture(ROOT_DIR)
        assert violations == [], f"Architectural violations detected: {violations}"

    def test_infer_layer_for_path_maps_expected_directories(self) -> None:
        assert infer_layer_for_path(ROOT_DIR / "backend/app/api/v1/health.py", ROOT_DIR) == "api"
        assert (
            infer_layer_for_path(ROOT_DIR / "backend/app/services/health.py", ROOT_DIR)
            == "services"
        )
        assert infer_layer_for_path(ROOT_DIR / "ai_services/__init__.py", ROOT_DIR) == "ai_services"
        assert infer_layer_for_path(ROOT_DIR / "backend/app/main.py", ROOT_DIR) is None


@pytest.mark.unit
class TestForbiddenDependencyDetection:
    """Verify AST checker catches forbidden cross-layer imports, env access, and blocking calls."""

    @pytest.mark.parametrize(
        ("layer", "bad_code", "expected_rule_id"),
        [
            (
                "api",
                "from backend.app.models import User\n",
                "ARCH-LAYER-IMPORT",
            ),
            (
                "api",
                "import backend.app.repositories.base\n",
                "ARCH-LAYER-IMPORT",
            ),
            (
                "api",
                "from sqlalchemy import select\n",
                "ARCH-LAYER-IMPORT",
            ),
            (
                "services",
                "from fastapi import HTTPException\n",
                "ARCH-LAYER-IMPORT",
            ),
            (
                "services",
                "from backend.app.api.dependencies import get_app_settings\n",
                "ARCH-LAYER-IMPORT",
            ),
            (
                "repositories",
                "from backend.app.services.health import HealthService\n",
                "ARCH-LAYER-IMPORT",
            ),
            (
                "models",
                "from backend.app.schemas.common import ErrorResponse\n",
                "ARCH-LAYER-IMPORT",
            ),
            (
                "schemas",
                "import sqlalchemy\n",
                "ARCH-LAYER-IMPORT",
            ),
            (
                "core",
                "from backend.app.services.health import HealthService\n",
                "ARCH-LAYER-IMPORT",
            ),
            (
                "ai_services",
                "from backend.app.repositories.base import TenantScopedRepositoryProtocol\n",
                "ARCH-LAYER-IMPORT",
            ),
            (
                "services",
                "import os\nx = os.getenv('SECRET_KEY')\n",
                "ARCH-SEC-ENV",
            ),
            (
                "api",
                "from os import environ\nval = environ.get('DB_PASS')\n",
                "ARCH-SEC-ENV",
            ),
            (
                "services",
                "import time\nasync def run_job() -> None:\n    time.sleep(1)\n",
                "ARCH-ASYNC-BLOCK",
            ),
        ],
    )
    def test_detector_flags_forbidden_patterns(
        self,
        layer: str,
        bad_code: str,
        expected_rule_id: str,
    ) -> None:
        violations = check_source_architecture(
            bad_code,
            layer=layer,
            module_path=f"synthetic/{layer}_violation.py",
        )
        assert len(violations) >= 1
        assert any(v.rule_id == expected_rule_id for v in violations)

    def test_type_checking_only_imports_are_permitted(self) -> None:
        safe_code = (
            "from typing import TYPE_CHECKING\n"
            "if TYPE_CHECKING:\n"
            "    from backend.app.config.settings import Settings\n"
        )
        violations = check_source_architecture(safe_code, layer="core")
        assert violations == []


@pytest.mark.unit
class TestDomainExceptionsAndProtocols:
    """Verify domain exception hierarchy, structural protocols, and test safety guards."""

    def test_domain_exception_status_codes_and_defaults(self) -> None:
        not_found = ResourceNotFoundError("Case not found")
        assert not_found.status_code == 404
        assert not_found.code == "RESOURCE_NOT_FOUND"

        conflict = ConflictError("Duplicate evidence hash")
        assert conflict.status_code == 409
        assert conflict.code == "RESOURCE_CONFLICT"

        rule_err = BusinessRuleError("Cannot close unassigned case")
        assert rule_err.status_code == 422
        assert rule_err.code == "BUSINESS_RULE_VIOLATION"

        auth_err = AuthenticationError("Token expired")
        assert auth_err.status_code == 401
        assert auth_err.code == "AUTHENTICATION_REQUIRED"

        perm_err = PermissionDeniedError("Cross-department access denied")
        assert perm_err.status_code == 403
        assert perm_err.code == "PERMISSION_DENIED"

        large_err = PayloadTooLargeError("Payload exceeds limit")
        assert large_err.status_code == 413
        assert large_err.code == "PAYLOAD_TOO_LARGE"

        unavail_err = ServiceUnavailableError("Database unreachable")
        assert unavail_err.status_code == 503
        assert unavail_err.code == "DEPENDENCY_UNAVAILABLE"

        custom = AppError(
            "Custom domain error",
            code="CUSTOM_CODE",
            status_code=418,
            details=[{"field": "status", "message": "Invalid state"}],
        )
        assert custom.code == "CUSTOM_CODE"
        assert custom.status_code == 418
        assert custom.details is not None

    async def test_repository_structural_protocols_runtime_checking(self) -> None:
        class InMemoryCaseRepo:
            async def get_by_id(
                self, entity_id: UUID, *, department_id: UUID
            ) -> dict[str, UUID] | None:
                return {"id": entity_id, "department_id": department_id}

            async def list_for_department(
                self, *, department_id: UUID, limit: int = 50, offset: int = 0
            ) -> Sequence[dict[str, UUID]]:
                return [{"department_id": department_id}]

        class InMemoryAuditRepo:
            async def append(self, entry: str) -> str:
                return entry

            async def list_by_department(
                self, *, department_id: UUID, limit: int = 100, offset: int = 0
            ) -> Sequence[str]:
                return [str(department_id)]

        case_repo = InMemoryCaseRepo()
        audit_repo = InMemoryAuditRepo()
        assert isinstance(case_repo, TenantScopedRepositoryProtocol)
        assert isinstance(audit_repo, AppendOnlyLedgerRepositoryProtocol)

        dept_id = uuid4()
        entity = await case_repo.get_by_id(uuid4(), department_id=dept_id)
        assert entity is not None and entity["department_id"] == dept_id
        assert len(await case_repo.list_for_department(department_id=dept_id)) == 1
        assert await audit_repo.append("evt-1") == "evt-1"
        assert len(await audit_repo.list_by_department(department_id=dept_id)) == 1

    def test_assert_test_resource_isolation_blocks_production_targets(
        self,
        valid_testing_config_dict: dict[str, Any],
        valid_production_config_dict: dict[str, Any],
    ) -> None:
        prod_settings = Settings(**valid_production_config_dict)
        with pytest.raises(RuntimeError, match="ENVIRONMENT='production'"):
            assert_test_resource_isolation(prod_settings)

        non_test_db = Settings(
            **{
                **valid_testing_config_dict,
                "DATABASE_URL": "postgresql+asyncpg://u:pass12345678@localhost:5432/ewitness_live",
            }
        )
        with pytest.raises(RuntimeError, match="Test DATABASE_URL"):
            assert_test_resource_isolation(non_test_db)

        non_test_bucket = Settings(
            **{
                **valid_testing_config_dict,
                "STORAGE_BUCKET_NAME": "ewitness-live-bucket",
            }
        )
        with pytest.raises(RuntimeError, match="Test STORAGE_BUCKET_NAME"):
            assert_test_resource_isolation(non_test_bucket)

        prod_redis = Settings(
            **{
                **valid_testing_config_dict,
                "REDIS_URL": "redis://redis-prod.internal:6379/0",
            }
        )
        with pytest.raises(RuntimeError, match="Test REDIS_URL"):
            assert_test_resource_isolation(prod_redis)
