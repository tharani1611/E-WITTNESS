"""Infrastructure adapters package for E-WITNESS (Phases 11-13)."""

from __future__ import annotations

from backend.app.infrastructure.database import (
    AsyncDatabaseSession,
    DatabaseSessionManager,
    create_database_readiness_probe,
    create_db_engine,
    create_session_factory,
    translate_database_error,
    validate_database_target_isolation,
    verify_database_connectivity,
)
from backend.app.infrastructure.migrations import (
    build_alembic_config,
    detect_schema_drift,
    get_current_database_revision,
    get_expected_head_revision,
    run_migrations_downgrade,
    run_migrations_upgrade,
)
from backend.app.infrastructure.scanner import (
    ClamAVScanner,
    MalwareScanner,
    MockMalwareScanner,
    ScanResult,
)
from backend.app.infrastructure.storage import (
    InMemoryStorageClient,
    ObjectStorageClient,
    PresignedUploadData,
    S3StorageClient,
    StorageObjectMetadata,
)

__all__ = [
    "AsyncDatabaseSession",
    "ClamAVScanner",
    "DatabaseSessionManager",
    "InMemoryStorageClient",
    "MalwareScanner",
    "MockMalwareScanner",
    "ObjectStorageClient",
    "PresignedUploadData",
    "S3StorageClient",
    "ScanResult",
    "StorageObjectMetadata",
    "build_alembic_config",
    "create_database_readiness_probe",
    "create_db_engine",
    "create_session_factory",
    "detect_schema_drift",
    "get_current_database_revision",
    "get_expected_head_revision",
    "run_migrations_downgrade",
    "run_migrations_upgrade",
    "translate_database_error",
    "validate_database_target_isolation",
    "verify_database_connectivity",
]
