"""Reverse proxy and client IP extraction utilities (Phase 27 / SEC-009).

Ensures IP-based security controls, access logging, and rate-limiting keys
cannot be trivially spoofed by untrusted clients supplying arbitrary
`X-Forwarded-For` or `X-Forwarded-Host` headers.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence

from backend.app.core.logging import get_logger

logger = get_logger("core.proxy")


def _is_valid_ip(address_str: str) -> bool:
    """Return True if ``address_str`` is a valid IPv4 or IPv6 string."""
    try:
        ipaddress.ip_address(address_str.strip())
        return True
    except ValueError:
        return False


def resolve_client_ip(
    peer_ip: str | None,
    x_forwarded_for: str | None,
    *,
    trusted_proxies: Sequence[str] | None = None,
) -> str | None:
    """Safely extract client IP address enforcing trusted proxy verification.

    Parameters
    ----------
    peer_ip:
        Immediate connecting socket IP address (e.g. ``request.client.host``).
    x_forwarded_for:
        Raw ``X-Forwarded-For`` header string, if provided by the client.
    trusted_proxies:
        List of known, verified reverse proxy / load balancer IP addresses.
        Forwarded headers are ONLY evaluated if ``peer_ip`` matches a trusted proxy.

    Returns
    -------
    str | None
        The verified client IP address. When ``peer_ip`` is not trusted, returns
        ``peer_ip`` and discards any spoofed ``X-Forwarded-For`` values.
    """
    if not peer_ip or not _is_valid_ip(peer_ip):
        return peer_ip

    normalized_peer = peer_ip.strip()
    trusted_set = {p.strip() for p in trusted_proxies} if trusted_proxies else set()

    # If the connecting peer is not an explicitly trusted proxy, discard X-Forwarded-For completely
    if normalized_peer not in trusted_set:
        return normalized_peer

    # If no forwarded header was supplied, fall back to peer IP
    if not x_forwarded_for or not x_forwarded_for.strip():
        return normalized_peer

    # Traverse forwarded hops from right to left (reverse proxy chain)
    hops = [h.strip() for h in x_forwarded_for.split(",") if h.strip()]
    if not hops:
        return normalized_peer

    # Find the rightmost hop that is NOT in the trusted proxy set
    for hop in reversed(hops):
        if _is_valid_ip(hop) and hop not in trusted_set:
            return hop

    # If all hops are trusted proxies, return the leftmost valid hop
    for hop in hops:
        if _is_valid_ip(hop):
            return hop

    return normalized_peer
