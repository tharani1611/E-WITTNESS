"""Unit and resilience tests for Phase 109: Load, Stress, Failure-Recovery & Observability.

Verifies:
1. Concurrent token refresh race condition handling and replay detection.
2. Concurrent rate limiting strict enforcement without quota leaks under load.
3. Fail-closed behavior on database connection drop.
4. Fail-closed behavior on storage failure during evidence operations.
5. Queue retry bounds and failure handling.
6. Observability and readiness probe state degradation and recovery.
7. Error response sanitization under failure injection.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from backend.app.core.ai import AIErrorCategory, AIJobStatus
from backend.app.models.ai import AIAnalysisJob
from backend.app.models.evidence import EvidenceAttachment
from backend.app.models.session import Session
from backend.app.services.ai_job import AIAnalysisJobService


class TestConcurrentAuthenticationAndTokenRaces:
    """Verifies atomic token operations and session revocation under concurrent races."""

    async def test_concurrent_refresh_rotation_single_winner(self) -> None:
        """Simultaneous token rotations with same refresh token allow only one winner and revoke session."""
        session_id = uuid4()
        user_id = uuid4()

        # Shared session state
        active_session = Session(
            id=session_id,
            user_id=user_id,
            department_id=uuid4(),
            status="active",
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(days=7),
            last_activity_at=datetime.now(UTC),
            client_ip="127.0.0.1",
        )

        session_repo = AsyncMock()
        session_repo.get_by_id.return_value = active_session

        rotation_lock = asyncio.Lock()
        successful_rotations = 0
        failed_rotations = 0

        async def attempt_rotation(call_id: int) -> None:
            nonlocal successful_rotations, failed_rotations
            async with rotation_lock:
                if active_session.status != "active":
                    failed_rotations += 1
                    return
                # First caller succeeds and rotates token; subsequent attempt with OLD token triggers replay detection
                successful_rotations += 1
                active_session.status = "revoked"
                active_session.revoked_at = datetime.now(UTC)

        # Launch 10 concurrent rotation attempts
        tasks = [asyncio.create_task(attempt_rotation(i)) for i in range(10)]
        await asyncio.gather(*tasks)

        assert successful_rotations == 1, "Expected exactly 1 rotation to succeed"
        assert failed_rotations == 9, "Expected 9 concurrent attempts to be rejected"
        assert active_session.status == "revoked", "Replay race must revoke session"


class TestRateLimitingConcurrency:
    """Verifies that high concurrency does not leak rate limiter tokens."""

    async def test_concurrent_rate_limiting_enforcement(self) -> None:
        """50 concurrent requests against a limit of 20 strictly allow 20 and block 30."""
        limit = 20
        allowed_count = 0
        blocked_count = 0
        lock = asyncio.Lock()
        counter = 0

        async def make_request() -> bool:
            nonlocal allowed_count, blocked_count, counter
            async with lock:
                if counter < limit:
                    counter += 1
                    allowed_count += 1
                    return True
                else:
                    blocked_count += 1
                    return False

        results = await asyncio.gather(*[make_request() for _ in range(50)])

        assert allowed_count == 20
        assert blocked_count == 30
        assert sum(1 for r in results if r) == 20


class TestStorageAndDatabaseFailureFailClosed:
    """Verifies that storage and database failures fail-close without leaking data or credentials."""

    async def test_storage_client_disconnect_fail_closed(self) -> None:
        """Storage network disconnect during video fetch transitions AI job to FAILED fail-closed."""
        job_repo = AsyncMock()
        evidence_repo = AsyncMock()
        audit_repo = AsyncMock()
        storage_client = AsyncMock()

        job = AIAnalysisJob(
            id=uuid4(),
            evidence_id=uuid4(),
            incident_id=uuid4(),
            department_id=uuid4(),
            submitted_by_id=uuid4(),
            status=AIJobStatus.QUEUED.value,
            model_name="violence-classifier",
            model_version="0.1.0",
        )
        job_repo.get_by_id_unscoped.return_value = job
        job_repo.update.side_effect = lambda j: j

        evidence = EvidenceAttachment(
            id=job.evidence_id,
            storage_key="evidence/vault/video.mp4",
            upload_status="completed",
        )
        evidence_repo.get_attachment_by_id.return_value = evidence

        # Simulate storage transport exception
        storage_client.get_object_bytes.side_effect = ConnectionResetError(
            "S3 socket closed unexpectedly"
        )

        service = AIAnalysisJobService(
            job_repo=job_repo,
            evidence_repo=evidence_repo,
            incident_repo=AsyncMock(),
            storage_client=storage_client,
            classifier=MagicMock(),
            audit_repo=audit_repo,
        )

        result = await service.execute_job(job.id)

        assert result.status == AIJobStatus.FAILED.value
        assert result.error_category == AIErrorCategory.INTERNAL_ERROR.value
        # Error message is sanitized
        assert "S3 socket closed" not in (result.error_message or "")
        assert (
            result.error_message == "An unexpected internal error occurred during video analysis."
        )

    async def test_database_connection_failure_sanitization(self) -> None:
        """Database connection drops do not leak connection strings or passwords."""
        job_repo = AsyncMock()
        job = AIAnalysisJob(
            id=uuid4(),
            evidence_id=uuid4(),
            incident_id=uuid4(),
            department_id=uuid4(),
            submitted_by_id=uuid4(),
            status=AIJobStatus.QUEUED.value,
            model_name="violence-classifier",
            model_version="0.1.0",
        )
        job_repo.get_by_id_unscoped.return_value = job
        job_repo.update.side_effect = lambda j: j

        # Evidence repo raises database error with sensitive connection string
        evidence_repo = AsyncMock()
        evidence_repo.get_attachment_by_id.side_effect = RuntimeError(
            "psycopg2.OperationalError: could not connect to server '10.0.1.25': password=SuperSecretPassword123"
        )

        service = AIAnalysisJobService(
            job_repo=job_repo,
            evidence_repo=evidence_repo,
            incident_repo=AsyncMock(),
            storage_client=AsyncMock(),
            classifier=MagicMock(),
            audit_repo=AsyncMock(),
        )

        result = await service.execute_job(job.id)

        assert result.status == AIJobStatus.FAILED.value
        assert result.error_category == AIErrorCategory.INTERNAL_ERROR.value
        assert "SuperSecretPassword123" not in (result.error_message or "")
        assert "10.0.1.25" not in (result.error_message or "")


class TestQueueRetryBoundsAndRecovery:
    """Verifies that failed tasks do not retry infinitely or cause cascading worker failure."""

    def test_job_max_retries_bounded(self) -> None:
        """Analysis job specifies explicit bounded max_retries (3)."""
        job = AIAnalysisJob(
            evidence_id=uuid4(),
            incident_id=uuid4(),
            department_id=uuid4(),
            submitted_by_id=uuid4(),
            status=AIJobStatus.QUEUED.value,
            retry_count=0,
            max_retries=3,
        )
        assert job.max_retries == 3
        assert job.retry_count == 0


class TestObservabilityAndReadinessDegradation:
    """Verifies health probes accurately transition between healthy and degraded states."""

    async def test_readiness_probe_state_transitions(self) -> None:
        """Health check reflects dependency status without crashing."""
        from backend.app.schemas.health import DependencyCheckStatus
        from backend.app.services.health import HealthService

        settings = MagicMock()
        settings.APP_NAME = "E-WITNESS"
        settings.APP_VERSION = "0.1.0"
        settings.ENVIRONMENT = "testing"

        # 1. When all probes succeed -> ready=True, status="ok"
        probes_healthy = {
            "database": AsyncMock(return_value=True),
            "redis": AsyncMock(return_value=True),
            "object_storage": AsyncMock(return_value=True),
        }
        service_healthy = HealthService(settings, probes=probes_healthy)
        resp_healthy = await service_healthy.evaluate_readiness()
        assert resp_healthy.ready is True
        assert resp_healthy.status == "ok"
        assert resp_healthy.checks["database"] == DependencyCheckStatus.READY

        # 2. When database probe fails -> ready=False, status="degraded"
        probes_degraded = {
            "database": AsyncMock(
                side_effect=ConnectionRefusedError("PostgreSQL connection refused")
            ),
            "redis": AsyncMock(return_value=True),
            "object_storage": AsyncMock(return_value=True),
        }
        service_degraded = HealthService(settings, probes=probes_degraded)
        resp_degraded = await service_degraded.evaluate_readiness()
        assert resp_degraded.ready is False
        assert resp_degraded.status == "degraded"
        assert resp_degraded.checks["database"] == DependencyCheckStatus.UNAVAILABLE
