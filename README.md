# VCM — VPN & Certificate Manager

MFA-protected web app to run a PKI for VPN appliances and generate/validate
IPSec VPN configurations for **Juniper SRX (200–300 series)**, **Digi**,
**Cradlepoint**, and **pfSense** (strongSwan) devices.

## Features

- **AuthN/AuthZ**
  - Password + **MFA**: TOTP *or* **Passkey (WebAuthn)**. MFA enrollment enforced.
  - **operator** and **admin** privilege levels (RBAC).
  - **Source-IP restriction** (allowlist, per-CIDR), proxy-aware: forwarded IPs
    are trusted only from configured trusted proxies (Cloudflare/Traefik/NGINX).
  - Full **audit log**.
- **PKI**
  - Multi-level CA hierarchy: **root → intermediate(s) → issuing** CA.
  - Stores CA certs (public) + private keys **AES-256-GCM encrypted at rest**.
  - **CA private keys are never exported** through any API — signing only.
  - Accepts **CSRs** and issues appliance (end-entity) certificates.
  - Download cert / full chain (PEM).
- **VPN config generation**
  - Builds connection profiles across all available **IKE/IPSec proposals**.
  - **Warns on insecure protocol use** (DES/3DES/MD5/SHA1/weak DH/IKEv1/PSK),
    with severity ratings; annotated inline in generated config.
  - App-wide **defaults** for all parameters (editable, applied to new sites).
  - Per-vendor generators: Juniper SRX (set-style), Digi, Cradlepoint (NCOS),
    pfSense (swanctl.conf / strongSwan).
  - **Both-sides generation**: mirror crypto to produce a guaranteed-compatible
    far-end config (update existing firewall + new firewall config).
  - **Import** existing configs to seed the "existing site" database, then
    generate a compatible peer.
- **UI**: light / dark / **system (default)** theme.
- **Packaging**: Docker image + compose, ready behind Cloudflare Tunnel,
  Traefik, or NGINX.

## Quick start (local, no proxy)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

export VCM_SECRET_KEY=$(openssl rand -hex 32)
export VCM_KEK_B64=$(python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")
export VCM_BOOTSTRAP_ADMIN=admin:changeme

uvicorn app.main:app --reload
# open http://localhost:8000  → log in as admin/changeme → enroll MFA
```

> First run: the source-IP allowlist is empty, so only loopback is allowed
> (fail-safe). Add your CIDRs under **Admin → Source-IP allowlist**.

## Docker

```bash
cp .env.example .env    # fill in VCM_KEK_B64 etc.
docker compose up -d --build
```

Reverse-proxy overlays:

```bash
docker compose -f docker-compose.yml -f deploy/traefik.yml up -d       # Traefik + LE
docker compose -f docker-compose.yml -f deploy/cloudflared.yml up -d   # Cloudflare Tunnel
# NGINX: see deploy/nginx.conf
```

See `deploy/cloudflared.md` for why trusted-proxy configuration is critical to
keep the IP allowlist un-spoofable.

## Security notes

- `VCM_KEK_B64` wraps every CA private key. **Back it up separately** — losing it
  makes the CAs unrecoverable; leaking it defeats at-rest encryption.
- Set `VCM_COOKIE_SECURE=true` and a correct `VCM_RP_ID`/`VCM_RP_ORIGIN` behind TLS.
- Issuing CAs are created with `pathlen:0`; roots never sign leaf certs directly.
- Appliance private keys, if generated server-side, are returned once and never
  stored; CSR-based issuance (device-generated key) is preferred.

## Layout

```
app/
  config.py            settings (env-driven)
  models.py            SQLAlchemy models
  security/            crypto (KEK), passwords, sessions, MFA, IP filter, deps
  pki/                 key gen, CA hierarchy + signing, CSR
  srx/                 proposals catalog, vendor-neutral model, generators, importer, defaults
  routers/             auth, pki, sites, admin, ui
  templates/ static/   Jinja UI + theme + WebAuthn JS
deploy/                traefik / nginx / cloudflared overlays
```
