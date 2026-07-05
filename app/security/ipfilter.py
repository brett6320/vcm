"""Proxy-aware source-IP resolution and allowlist enforcement.

Behind Cloudflare Tunnel / Traefik / NGINX the socket peer is the proxy, not the
client. We only honour a forwarded header when the *direct* peer is a configured
trusted proxy — otherwise a client could spoof its IP and bypass the allowlist.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable

from fastapi import Request

from ..config import Settings, get_settings


def _in_any(ip: str, cidrs: Iterable[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def client_ip(request: Request, settings: Settings | None = None) -> str:
    """Resolve the real client IP, trusting forward headers only from proxies."""
    settings = settings or get_settings()
    peer = request.client.host if request.client else "0.0.0.0"

    trusted = settings.trusted_proxy_list
    if trusted and _in_any(peer, trusted):
        for header in settings.real_ip_header_list:
            val = request.headers.get(header)
            if not val:
                continue
            # X-Forwarded-For may be a list; the left-most is the origin client.
            candidate = val.split(",")[0].strip()
            if candidate:
                return candidate
    return peer


def ip_allowed(ip: str, allow_cidrs: list[str], settings: Settings | None = None) -> bool:
    settings = settings or get_settings()
    if not settings.enforce_ip_allowlist:
        return True
    # Fail-safe: with enforcement on and an empty allowlist, permit loopback only
    # (lets a fresh install be reached to add the first rule).
    if not allow_cidrs:
        return _in_any(ip, ["127.0.0.0/8", "::1/128"])
    return _in_any(ip, allow_cidrs)
