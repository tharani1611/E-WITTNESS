"""Unit tests for Phase 27 HTTP security headers, trusted host validation, and proxy resolution."""

from __future__ import annotations

import httpx
import pytest
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import PlainTextResponse
from starlette.types import Receive, Scope, Send

from backend.app.core.proxy import resolve_client_ip
from backend.app.middleware.security_headers import SecurityHeadersMiddleware


@pytest.mark.unit
class TestSecurityHeadersMiddleware:
    """Verify SecurityHeadersMiddleware injects required defense-in-depth headers."""

    async def test_standard_security_headers_injected(self) -> None:
        async def dummy_app(scope: Scope, receive: Receive, send: Send) -> None:
            response = PlainTextResponse("OK")
            await response(scope, receive, send)

        middleware = SecurityHeadersMiddleware(dummy_app, enforce_ssl=False)
        transport = httpx.ASGITransport(app=middleware)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/api/v1/test")
            assert resp.status_code == 200

            assert resp.headers.get("x-content-type-options") == "nosniff"
            assert resp.headers.get("x-frame-options") == "DENY"
            assert (
                resp.headers.get("content-security-policy")
                == "default-src 'none'; frame-ancestors 'none'"
            )
            assert resp.headers.get("referrer-policy") == "no-referrer"
            assert "camera=()" in resp.headers.get("permissions-policy", "")
            assert resp.headers.get("cache-control") == "no-store, max-age=0"
            assert resp.headers.get("pragma") == "no-cache"
            # HSTS should NOT be present on plain HTTP when enforce_ssl is False
            assert "strict-transport-security" not in resp.headers

    async def test_hsts_injected_when_enforce_ssl_is_true(self) -> None:
        async def dummy_app(scope: Scope, receive: Receive, send: Send) -> None:
            response = PlainTextResponse("OK")
            await response(scope, receive, send)

        middleware = SecurityHeadersMiddleware(dummy_app, enforce_ssl=True)
        transport = httpx.ASGITransport(app=middleware)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/api/v1/test")
            assert resp.status_code == 200
            assert "strict-transport-security" in resp.headers
            assert "includeSubDomains" in resp.headers["strict-transport-security"]

    async def test_cache_control_omitted_for_non_api_routes(self) -> None:
        async def dummy_app(scope: Scope, receive: Receive, send: Send) -> None:
            response = PlainTextResponse("OK")
            await response(scope, receive, send)

        middleware = SecurityHeadersMiddleware(dummy_app, enable_cache_control=True)
        transport = httpx.ASGITransport(app=middleware)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/static/image.png")
            assert resp.status_code == 200
            assert resp.headers.get("x-content-type-options") == "nosniff"
            assert "cache-control" not in resp.headers


@pytest.mark.unit
class TestTrustedHostValidation:
    """Verify TrustedHostMiddleware rejects unauthorized Host headers."""

    async def test_valid_host_accepted(self) -> None:
        async def dummy_app(scope: Scope, receive: Receive, send: Send) -> None:
            response = PlainTextResponse("OK")
            await response(scope, receive, send)

        app = TrustedHostMiddleware(dummy_app, allowed_hosts=["api.ewitness.edu", "localhost"])
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(
            transport=transport, base_url="http://api.ewitness.edu"
        ) as client:
            resp = await client.get("/")
            assert resp.status_code == 200

    async def test_unauthorized_host_rejected_with_400(self) -> None:
        async def dummy_app(scope: Scope, receive: Receive, send: Send) -> None:
            response = PlainTextResponse("OK")
            await response(scope, receive, send)

        app = TrustedHostMiddleware(dummy_app, allowed_hosts=["api.ewitness.edu"])
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(
            transport=transport, base_url="http://malicious-site.com"
        ) as client:
            resp = await client.get("/")
            assert resp.status_code == 400
            assert "Invalid host header" in resp.text


@pytest.mark.unit
class TestClientIpResolutionAndAntiSpoofing:
    """Verify reverse proxy client IP resolution and X-Forwarded-For anti-spoofing."""

    def test_untrusted_peer_ignores_forwarded_for_header(self) -> None:
        # Untrusted client sends spoofed header
        resolved = resolve_client_ip(
            peer_ip="203.0.113.195",
            x_forwarded_for="198.51.100.1, 10.0.0.1",
            trusted_proxies=["127.0.0.1", "10.0.0.1"],
        )
        # Should return connecting socket peer IP, discarding spoofed header
        assert resolved == "203.0.113.195"

    def test_trusted_proxy_resolves_valid_client_ip(self) -> None:
        # Request comes from trusted proxy
        resolved = resolve_client_ip(
            peer_ip="127.0.0.1",
            x_forwarded_for="198.51.100.42",
            trusted_proxies=["127.0.0.1"],
        )
        assert resolved == "198.51.100.42"

    def test_multi_hop_proxy_chain_extracts_rightmost_untrusted_hop(self) -> None:
        # Client -> Proxy 1 (untrusted) -> LB 1 (trusted) -> LB 2 (trusted) -> App
        resolved = resolve_client_ip(
            peer_ip="10.0.0.2",
            x_forwarded_for="192.0.2.1, 198.51.100.99, 10.0.0.1",
            trusted_proxies=["10.0.0.1", "10.0.0.2"],
        )
        assert resolved == "198.51.100.99"

    def test_invalid_or_missing_ips_safely_handled(self) -> None:
        assert resolve_client_ip(None, None) is None
        assert resolve_client_ip("not-an-ip", "also-not-ip") == "not-an-ip"
        assert resolve_client_ip("127.0.0.1", None, trusted_proxies=["127.0.0.1"]) == "127.0.0.1"
        assert resolve_client_ip("127.0.0.1", "", trusted_proxies=["127.0.0.1"]) == "127.0.0.1"
        assert resolve_client_ip("127.0.0.1", "   ", trusted_proxies=["127.0.0.1"]) == "127.0.0.1"
