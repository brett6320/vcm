from __future__ import annotations

import base64
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VCM_", env_file=".env", extra="ignore")

    app_name: str = "VCM — VPN & Certificate Manager"
    database_url: str = "sqlite:///./vcm.db"

    # "prod" (default) enforces MFA enrollment before any privileged action.
    # "dev" skips forced enrollment for convenience. Never use "dev" in production.
    mode: str = "prod"

    @property
    def is_dev(self) -> bool:
        return self.mode.lower() == "dev"

    # Cookie signing / session secret. MUST be set in production.
    secret_key: str = "dev-insecure-change-me"
    session_cookie: str = "vcm_session"
    session_ttl_minutes: int = 60
    cookie_secure: bool = False  # set True behind TLS/HTTPS

    # Key-encryption key (KEK) used to wrap CA private keys at rest (AES-256-GCM).
    # Provide 32 raw bytes base64-encoded. If unset, derived from secret_key (dev only).
    kek_b64: str | None = None

    # --- Reverse-proxy / source-IP trust ---------------------------------
    # When the app runs behind Cloudflare Tunnel, Traefik, or NGINX, the real
    # client IP arrives in a header. We only trust that header when the direct
    # peer (proxy) is in trusted_proxies. Otherwise we use the socket peer.
    trusted_proxies: str = ""  # comma-separated CIDRs, e.g. "127.0.0.1/32,10.0.0.0/8"
    # Header priority order to read the client IP from (first match wins).
    real_ip_headers: str = "cf-connecting-ip,x-forwarded-for,x-real-ip"

    # Global IP allowlist enforcement. If empty allowlist + this True => deny all
    # except loopback (fail-safe). Set False to disable IP filtering entirely.
    enforce_ip_allowlist: bool = True
    # Comma-separated CIDRs seeded into the allowlist on first run (empty table
    # only). Prevents lockout on proxy deploys where the client is never loopback.
    # Default: all RFC1918 private ranges + loopback.
    initial_allow: str = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128"

    @property
    def initial_allow_list(self) -> list[str]:
        return [c.strip() for c in self.initial_allow.split(",") if c.strip()]

    # WebAuthn / Passkey relying party
    rp_id: str = "localhost"
    rp_name: str = "VCM"
    rp_origin: str = "http://localhost:8000"

    # PKI defaults
    default_key_type: str = "ec"  # "ec" or "rsa"
    default_ec_curve: str = "secp384r1"
    default_rsa_bits: int = 3072

    def kek_bytes(self) -> bytes:
        if self.kek_b64:
            raw = base64.b64decode(self.kek_b64)
            if len(raw) != 32:
                raise ValueError("VCM_KEK_B64 must decode to exactly 32 bytes")
            return raw
        # Dev fallback: derive a 32-byte key from secret_key. NOT for production.
        import hashlib

        return hashlib.sha256(("kek:" + self.secret_key).encode()).digest()

    @property
    def trusted_proxy_list(self) -> list[str]:
        return [c.strip() for c in self.trusted_proxies.split(",") if c.strip()]

    @property
    def real_ip_header_list(self) -> list[str]:
        return [h.strip().lower() for h in self.real_ip_headers.split(",") if h.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
