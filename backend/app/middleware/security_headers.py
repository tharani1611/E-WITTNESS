"""Pure ASGI HTTP security headers and transport protection middleware (Phase 27).

Enforces essential defense-in-depth HTTP security headers across all API responses:
- `X-Content-Type-Options: nosniff` (MIME-sniffing protection)
- `X-Frame-Options: DENY` (clickjacking protection)
- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` (restricted framing/execution)
- `Referrer-Policy: no-referrer` (information leakage protection)
- `Permissions-Policy` (disables unnecessary browser device features)
- `Cache-Control: no-store, max-age=0` and `Pragma: no-cache` (prevents caching of sensitive data)
- `Strict-Transport-Security` (HSTS enabled conditionally when SSL is enforced or request is HTTPS)
"""

from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from backend.app.core.logging import get_logger

logger = get_logger("middleware.security_headers")

# Static security headers injected on every HTTP response
_STATIC_SECURITY_HEADERS: list[tuple[bytes, bytes]] = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"referrer-policy", b"no-referrer"),
    (
        b"permissions-policy",
        b"accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
    ),
]

_CACHE_CONTROL_HEADERS: list[tuple[bytes, bytes]] = [
    (b"cache-control", b"no-store, max-age=0"),
    (b"pragma", b"no-cache"),
]

_HSTS_HEADER: tuple[bytes, bytes] = (
    b"strict-transport-security",
    b"max-age=31536000; includeSubDomains",
)


class SecurityHeadersMiddleware:
    """ASGI middleware injecting standardized HTTP security and transport headers."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        enforce_ssl: bool = False,
        enable_cache_control: bool = True,
    ) -> None:
        self.app = app
        self.enforce_ssl = enforce_ssl
        self.enable_cache_control = enable_cache_control

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        is_https = scope.get("scheme") == "https" or self.enforce_ssl
        path = str(scope.get("path", ""))

        async def send_with_security_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                existing_headers: list[tuple[bytes, bytes]] = list(message.get("headers", []))
                existing_keys = {k.lower() for k, _ in existing_headers}

                # 1. Inject static security headers if not already provided
                for header_name, header_val in _STATIC_SECURITY_HEADERS:
                    if header_name not in existing_keys:
                        existing_headers.append((header_name, header_val))
                        existing_keys.add(header_name)

                # 2. Inject cache control on API responses if enabled and not already provided
                if self.enable_cache_control and (path.startswith("/api/") or "/auth" in path):
                    for header_name, header_val in _CACHE_CONTROL_HEADERS:
                        if header_name not in existing_keys:
                            existing_headers.append((header_name, header_val))
                            existing_keys.add(header_name)

                # 3. Inject HSTS if HTTPS or enforce_ssl is True
                if is_https and _HSTS_HEADER[0] not in existing_keys:
                    existing_headers.append(_HSTS_HEADER)
                    existing_keys.add(_HSTS_HEADER[0])

                message["headers"] = existing_headers
            await send(message)

        await self.app(scope, receive, send_with_security_headers)
