"""Integration tests for FastAPI bootstrap, health/readiness, middleware, and error handling (Phases 06-09)."""

from __future__ import annotations

import asyncio
import importlib
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from backend.app.api.dependencies import CorrelationIdDep, SettingsDep
from backend.app.config.settings import Settings
from backend.app.core.context import (
    CORRELATION_ID_HEADER,
    get_request_id,
    is_valid_correlation_id,
)
from backend.app.core.exceptions import (
    AppError,
    PermissionDeniedError,
    ResourceNotFoundError,
)
from backend.app.core.secrets import REDACTION_MASK
from backend.app.main import _app_lifespan, create_app


@pytest.mark.integration
class TestApplicationBootstrapAndLifespan:
    """Verify safe module import, application factory, OpenAPI toggling, and lifespan."""

    def test_importing_main_module_does_not_connect_or_require_env_vars(self) -> None:
        # isolate_environment autouse fixture has cleared all MANAGED_ENV_VARS;
        # reloading backend.app.main must succeed without side effects or network calls.
        reloaded = importlib.reload(importlib.import_module("backend.app.main"))
        assert hasattr(reloaded, "create_app")

    async def test_app_lifespan_transitions_running_state(self, test_app: FastAPI) -> None:
        assert test_app.state.is_running is False
        async with _app_lifespan(test_app):
            assert test_app.state.is_running is True
        assert test_app.state.is_running is False

    async def test_api_version_prefix_is_respected(
        self, app_factory: Callable[..., FastAPI]
    ) -> None:
        custom_app = app_factory(API_V1_PREFIX="/api/v2")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=custom_app),
            base_url="http://testserver.local",
        ) as client:
            resp_v2 = await client.get("/api/v2/health/live")
            assert resp_v2.status_code == 200
            resp_v1 = await client.get("/api/v1/health/live")
            assert resp_v1.status_code == 404

    async def test_openapi_and_docs_enabled_in_test_and_disabled_in_production(
        self,
        async_client: httpx.AsyncClient,
        valid_production_config_dict: dict[str, Any],
    ) -> None:
        # Enabled in testing
        openapi_resp = await async_client.get("/api/v1/openapi.json")
        assert openapi_resp.status_code == 200
        assert openapi_resp.json()["info"]["title"] == "E-WITNESS"

        # Disabled in production
        prod_settings = Settings(**valid_production_config_dict)
        prod_app = create_app(prod_settings)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=prod_app),
            base_url="https://portal.ewitness.edu",
        ) as prod_client:
            assert (await prod_client.get("/api/v1/openapi.json")).status_code == 404
            assert (await prod_client.get("/docs")).status_code == 404
            assert (await prod_client.get("/redoc")).status_code == 404


@pytest.mark.integration
class TestLivenessAndReadinessEndpoints:
    """Verify liveness and readiness endpoints separate concerns and never fabricate checks."""

    async def test_root_and_v1_liveness_return_safe_metadata(
        self, async_client: httpx.AsyncClient
    ) -> None:
        for path in ("/health", "/api/v1/health/live"):
            response = await async_client.get(path)
            assert response.status_code == 200
            body = response.json()
            assert body == {
                "status": "ok",
                "service": "E-WITNESS",
                "version": "0.1.0",
                "environment": "testing",
            }
            raw_text = response.text
            assert "test_only_signing_key" not in raw_text
            assert "test_secret_key" not in raw_text
            assert "sqlite" not in raw_text

    async def test_readiness_reports_unverified_when_no_probes_registered(
        self, async_client: httpx.AsyncClient
    ) -> None:
        response = await async_client.get("/api/v1/health/ready")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "unverified"
        assert body["ready"] is True
        assert body["checks"] == {
            "database": "not_checked",
            "redis": "not_checked",
            "object_storage": "not_checked",
        }

    async def test_readiness_reports_ok_when_all_registered_probes_pass(
        self, app_factory: Callable[..., FastAPI]
    ) -> None:
        async def ok_probe() -> bool:
            return True

        app = app_factory(
            readiness_probes={
                "database": ok_probe,
                "redis": ok_probe,
                "object_storage": ok_probe,
            }
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            resp = await client.get("/api/v1/health/ready")
            assert resp.status_code == 200
            body = resp.json()
            assert body["status"] == "ok"
            assert body["ready"] is True
            assert body["checks"] == {
                "database": "ready",
                "redis": "ready",
                "object_storage": "ready",
            }

    async def test_readiness_returns_503_degraded_when_any_probe_fails_or_raises(
        self, app_factory: Callable[..., FastAPI]
    ) -> None:
        async def ok_probe() -> bool:
            return True

        async def false_probe() -> bool:
            return False

        async def raising_probe() -> bool:
            raise ConnectionError("Connection refused to object storage")

        app = app_factory(
            readiness_probes={
                "database": ok_probe,
                "redis": false_probe,
                "object_storage": raising_probe,
                "custom_worker": ok_probe,
            }
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            resp = await client.get("/api/v1/health/ready")
            assert resp.status_code == 503
            body = resp.json()
            assert body["status"] == "degraded"
            assert body["ready"] is False
            assert body["checks"]["database"] == "ready"
            assert body["checks"]["redis"] == "unavailable"
            assert body["checks"]["object_storage"] == "unavailable"
            assert body["checks"]["custom_worker"] == "ready"


@pytest.mark.integration
class TestCorsAndRequestCorrelationMiddleware:
    """Verify CORS policy enforcement, correlation ID propagation, and concurrency isolation."""

    async def test_cors_allows_configured_origin_and_blocks_unlisted_origin(
        self, app_factory: Callable[..., FastAPI]
    ) -> None:
        app = app_factory(CORS_ALLOWED_ORIGINS=["https://allowed.ewitness.edu"])
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:
            allowed_resp = await client.options(
                "/api/v1/health/live",
                headers={
                    "Origin": "https://allowed.ewitness.edu",
                    "Access-Control-Request-Method": "GET",
                },
            )
            assert (
                allowed_resp.headers.get("access-control-allow-origin")
                == "https://allowed.ewitness.edu"
            )
            assert CORRELATION_ID_HEADER in allowed_resp.headers

            blocked_resp = await client.options(
                "/api/v1/health/live",
                headers={
                    "Origin": "https://evil.example.com",
                    "Access-Control-Request-Method": "GET",
                },
            )
            assert "access-control-allow-origin" not in blocked_resp.headers

    async def test_correlation_id_generation_acceptance_and_replacement(
        self, async_client: httpx.AsyncClient
    ) -> None:
        # 1. Missing header -> generates valid UUIDv4
        r1 = await async_client.get("/health")
        cid1 = r1.headers.get(CORRELATION_ID_HEADER)
        assert is_valid_correlation_id(cid1)

        # 2. Valid incoming header -> preserved
        valid_incoming = "client-trace-2026-abcdef12"
        r2 = await async_client.get(
            "/health",
            headers={CORRELATION_ID_HEADER: valid_incoming},
        )
        assert r2.headers.get(CORRELATION_ID_HEADER) == valid_incoming

        # 3. Malformed / oversized incoming header -> replaced with fresh safe ID
        for bad_header in ("short", "X" * 90, "bad space id", "evil$char#12345"):
            r_bad = await async_client.get(
                "/health",
                headers={CORRELATION_ID_HEADER: bad_header},
            )
            replaced = r_bad.headers.get(CORRELATION_ID_HEADER)
            assert is_valid_correlation_id(replaced)
            assert replaced != bad_header

        # 4. Context must be cleaned up after request completion
        assert get_request_id() is None

    async def test_concurrent_http_requests_do_not_leak_correlation_ids(
        self, app_factory: Callable[..., FastAPI]
    ) -> None:
        app = app_factory()

        @app.get("/api/v1/echo-context")
        async def echo_context(
            cid: CorrelationIdDep,
            settings: SettingsDep,
        ) -> dict[str, str | None]:
            await asyncio.sleep(0.005)
            return {
                "dep_cid": cid,
                "ctx_cid": get_request_id(),
                "env": str(settings.ENVIRONMENT),
            }

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver.local",
        ) as client:

            async def make_call(idx: int) -> None:
                sent_id = f"concurrent-http-id-{idx:04d}"
                resp = await client.get(
                    "/api/v1/echo-context",
                    headers={CORRELATION_ID_HEADER: sent_id},
                )
                assert resp.status_code == 200
                assert resp.headers.get(CORRELATION_ID_HEADER) == sent_id
                payload = resp.json()
                assert payload["dep_cid"] == sent_id
                assert payload["ctx_cid"] == sent_id

            await asyncio.gather(*(make_call(i) for i in range(25)))

        assert get_request_id() is None


class SampleInput(BaseModel):
    """Module-level test schema for FastAPI body validation verification."""

    title: str = Field(min_length=5, max_length=50)
    count: int = Field(ge=1, le=10)


@pytest.mark.integration
class TestExceptionHandlingAndPayloadLimits:
    """Verify validation errors, domain errors, 500 error sanitization, and 413 body limits."""

    async def test_validation_domain_http_and_unexpected_exception_handlers(
        self, app_factory: Callable[..., FastAPI]
    ) -> None:
        app = app_factory(MAX_REQUEST_BODY_BYTES=65_536)

        @app.post("/api/v1/test-validation")
        async def route_validation(
            payload: SampleInput,
            limit: int = Query(default=5, ge=1, le=20),
        ) -> dict[str, Any]:
            return {"title": payload.title, "count": payload.count, "limit": limit}

        @app.get("/api/v1/test-not-found")
        async def route_not_found() -> None:
            raise ResourceNotFoundError("Requested case record does not exist.")

        @app.get("/api/v1/test-permission-denied")
        async def route_forbidden() -> None:
            raise PermissionDeniedError(
                "Access denied for token Authorization: Bearer secret_token_xyz",
                details=[{"field": "department_id", "message": "Department mismatch"}],
            )

        @app.get("/api/v1/test-app-500")
        async def route_app_500() -> None:
            raise AppError(
                "Downstream service failed on postgresql+asyncpg://u:Pass123@host:5432/db",
                code="DOWNSTREAM_FAILURE",
                status_code=502,
            )

        @app.get("/api/v1/test-http-500")
        async def route_http_500() -> None:
            raise HTTPException(
                status_code=500,
                detail="Internal SQL error: SELECT * FROM users WHERE secret='top_secret'",
            )

        @app.get("/api/v1/test-crash")
        async def route_unhandled_crash() -> None:
            raise RuntimeError(
                "Fatal crash at C:\\secret\\path.py with DATABASE_URL=postgresql+asyncpg://u:SecretPass99@db:5432/prod"
            )

        # Configure transport with raise_app_exceptions=False so 500 handler response is returned
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver.local",
        ) as client:
            # 1. Valid request succeeds
            ok_resp = await client.post(
                "/api/v1/test-validation?limit=10",
                json={"title": "Valid Incident Title", "count": 3},
            )
            assert ok_resp.status_code == 200

            # 2. Validation failure (422) uses standardized ErrorResponse structure
            val_resp = await client.post(
                "/api/v1/test-validation?limit=99",
                json={"title": "bad", "count": 0},
                headers={CORRELATION_ID_HEADER: "req-val-error-0001"},
            )
            assert val_resp.status_code == 422
            val_body = val_resp.json()
            assert val_body["error"]["code"] == "REQUEST_VALIDATION_ERROR"
            assert val_body["error"]["request_id"] == "req-val-error-0001"
            assert len(val_body["error"]["details"]) >= 2

            # 3. Domain 404 (ResourceNotFoundError)
            nf_resp = await client.get("/api/v1/test-not-found")
            assert nf_resp.status_code == 404
            assert nf_resp.json()["error"]["code"] == "RESOURCE_NOT_FOUND"

            # 4. Domain 403 (PermissionDeniedError) with token redaction and details
            forb_resp = await client.get("/api/v1/test-permission-denied")
            assert forb_resp.status_code == 403
            forb_json = forb_resp.json()
            assert forb_json["error"]["code"] == "PERMISSION_DENIED"
            assert "secret_token_xyz" not in forb_resp.text
            assert REDACTION_MASK in forb_json["error"]["message"]
            assert forb_json["error"]["details"][0]["field"] == "department_id"

            # 5. Domain 502 (AppError >= 500) redacts DSN password
            app502_resp = await client.get("/api/v1/test-app-500")
            assert app502_resp.status_code == 502
            assert "Pass123" not in app502_resp.text
            assert REDACTION_MASK in app502_resp.json()["error"]["message"]

            # 6. Framework 404 route not found
            r404 = await client.get("/api/v1/nonexistent-endpoint")
            assert r404.status_code == 404
            assert r404.json()["error"]["code"] == "HTTP_404"

            # 7. Framework 500 HTTPException hides raw detail
            r_http500 = await client.get("/api/v1/test-http-500")
            assert r_http500.status_code == 500
            assert "SELECT * FROM users" not in r_http500.text
            assert "top_secret" not in r_http500.text
            assert r_http500.json()["error"]["code"] == "INTERNAL_SERVER_ERROR"

            # 8. Unhandled RuntimeError (500) hides tracebacks, paths, and DB credentials
            crash_resp = await client.get(
                "/api/v1/test-crash",
                headers={CORRELATION_ID_HEADER: "req-crash-test-0001"},
            )
            assert crash_resp.status_code == 500
            assert crash_resp.headers.get(CORRELATION_ID_HEADER) == "req-crash-test-0001"
            crash_text = crash_resp.text
            assert "SecretPass99" not in crash_text
            assert "C:\\secret\\path.py" not in crash_text
            assert "RuntimeError" not in crash_text
            assert crash_resp.json() == {
                "error": {
                    "code": "INTERNAL_SERVER_ERROR",
                    "message": "An unexpected internal server error occurred.",
                    "request_id": "req-crash-test-0001",
                    "details": None,
                }
            }

            # 9. Oversized payload via Content-Length rejected with 413
            oversized_bytes = b"A" * 70_000
            r413 = await client.post(
                "/api/v1/test-validation",
                content=oversized_bytes,
                headers={
                    "Content-Type": "application/json",
                    CORRELATION_ID_HEADER: "req-413-limit-0001",
                },
            )
            assert r413.status_code == 413
            assert r413.headers.get(CORRELATION_ID_HEADER) == "req-413-limit-0001"
            assert r413.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"

            # 10. Oversized streaming payload (chunked without Content-Length) rejected with 413
            async def chunk_generator() -> AsyncIterator[bytes]:
                for _ in range(8):
                    yield b"X" * 10_000

            r413_stream = await client.post(
                "/api/v1/test-validation",
                content=chunk_generator(),
                headers={"Content-Type": "application/json"},
            )
            assert r413_stream.status_code == 413
            assert r413_stream.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"
