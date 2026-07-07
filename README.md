# VCM — VPN & Certificate Manager

[![CI](https://github.com/brett6320/vcm/actions/workflows/ci.yml/badge.svg)](https://github.com/brett6320/vcm/actions/workflows/ci.yml)
[![Release](https://github.com/brett6320/vcm/actions/workflows/release.yml/badge.svg)](https://github.com/brett6320/vcm/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/brett6320/vcm?sort=semver)](https://github.com/brett6320/vcm/releases/latest)

VCM is an MFA-protected FastAPI web application that does two jobs for a fleet of
network appliances:

1. **Runs a private PKI** — a multi-level Certificate Authority hierarchy whose
   private keys are envelope-encrypted at rest and **never exported** through any
   API. It imports existing CAs, issues appliance certificates from CSRs, and
   downloads certs / chains.
2. **Generates and validates site-to-site IPSec VPN configurations** — from a
   single vendor-neutral connection profile it emits ready-to-paste config for a
   range of firewall/router platforms, rates the chosen crypto against current
   guidance, mirrors a guaranteed-compatible far-end, and imports existing
   configs to seed a compatible peer.

Everything is behind a session login with **password + MFA** (TOTP *or* a
WebAuthn passkey), role-based access control, a source-IP allowlist, and a full
audit log.

> **Vendor support at a glance.** Config is generated for Juniper SRX, Digi,
> Cradlepoint, pfSense, Cisco Firepower/FTD, Fortinet, Palo Alto, strongSwan and
> MikroTik. AWS and Azure VPN gateways are **import-only** (you import their
> provider-managed config and generate the on-prem far end). Only **Juniper SRX**
> and **Cradlepoint** are validated end-to-end; the rest are generated
> best-effort and labelled *"(untested)"* in the UI. See
> [`docs/vendors.md`](docs/vendors.md).

---

## Table of contents

- [Features](#features)
- [Quick start (local, no proxy)](#quick-start-local-no-proxy)
- [Docker & compose overlays](#docker--compose-overlays)
- [Configuration](#configuration)
- [How it works](#how-it-works)
  - [Authentication & the login flow](#authentication--the-login-flow)
  - [PKI](#pki)
  - [VPN configuration](#vpn-configuration)
  - [Backups](#backups)
  - [Notifications](#notifications)
- [HTTP routes](#http-routes)
- [Data model](#data-model)
- [Encryption in flight & at rest](#encryption-in-flight--at-rest)
- [Security notes](#security-notes)
- [Project layout](#project-layout)
- [Testing](#testing)
- [Further reading](#further-reading)

---

## Features

### Authentication & authorization
- **Password login** — passwords are hashed with **Argon2id** (`argon2-cffi`),
  never stored reversibly.
- **Multi-factor authentication** — **TOTP** (RFC 6238, via `pyotp`, with a
  scannable QR code) *or* a **WebAuthn passkey** (via the `webauthn` library).
  A user may enrol several passkeys and keep TOTP as well. In **prod** mode MFA
  enrollment is *forced* before any privileged action.
- **Forced first-login password change** — admin-created accounts get
  `must_change_password=True` and must set a new password before reaching MFA or
  the app.
- **RBAC** — two roles, `operator` and `admin`. Admin-only actions include user
  management, the IP allowlist, defaults, backups, the audit log, and all
  delete operations. The last remaining active admin cannot be demoted, disabled
  by self, or deleted.
- **Source-IP allowlist** — per-CIDR allowlist enforced on the login/auth path
  and on every authenticated request. It is **proxy-aware**: a forwarded client
  IP header is trusted *only* when the direct TCP peer is a configured trusted
  proxy, so a client behind (or bypassing) the proxy cannot spoof its address.
  Fail-safe: with enforcement on and an empty allowlist, only loopback is
  admitted (so a fresh install is still reachable to add the first rule).
- **Sessions** — server-side, random-token sessions with a TTL; a user can view
  and revoke their other sessions from their profile.
- **Full audit log** — every meaningful action (logins, MFA events, PKI/VPN/user
  changes, backups) is recorded with user, action, detail and resolved client IP.

### PKI
- Multi-level CA hierarchy: **root → intermediate(s) → issuing** CA.
- CA private keys are stored **AES-256-GCM encrypted** with the app KEK and are
  **never returned** by any route — a key is decrypted transiently in memory for
  one signing operation only.
- **Import** an existing CA from pasted PEM, a PEM bundle, or a **PKCS#12
  (.p12/.pfx)** file — cert-only or cert+key. Imported cert-only CAs cannot sign.
- **Create** root / intermediate / issuing CAs (EC or RSA).
- **Sign CSRs** into end-entity (appliance) certificates with SAN support.
- **Lock/unlock** delete-protection on CAs and certs; typed-confirmation and
  cascade rules guard deletion.
- Download a CA cert, a full chain, a leaf cert, or a leaf + chain (PEM); browse
  the hierarchy as JSON (`/pki/tree.json`) — public data only.

### VPN configuration
- One **vendor-neutral profile** (Phase 1 / Phase 2 crypto, endpoints, protected
  subnets, IKE IDs, interfaces, optional BGP) drives every generator.
- **Crypto rating & inline warnings** — DES/3DES/MD5/SHA-1, weak DH groups,
  IKEv1 and PSK auth are flagged with a severity (`broken`/`weak`) both as
  structured warnings and as an inline comment banner in the generated config.
- **App-wide defaults** for all parameters, editable by an admin and applied to
  new connections.
- **Both-sides generation** — mirror the crypto to produce a guaranteed-compatible
  far-end config, either as a throwaway view or persisted as a paired connection
  (create a new far-end, or update an existing one).
- **Peer & BGP inference** — VCM suggests likely peers by matching public IPs and
  protected subnets (you confirm the pairing), and can infer BGP-over-tunnel
  peering from tunnel addresses.
- **Import** existing configs (paste or upload) to seed the "existing site"
  database; PSKs and encrypted passwords are **redacted before storage**.
- **Edit / rename** connections; renaming emits the device's in-place rename
  syntax where the platform supports it.

### Operations & packaging
- **Encrypted, versioned backup/restore** of all application state (AES-256-GCM
  via the KEK), downloadable and re-importable only on an instance with the same
  KEK.
- **Notifications** — optional email (SMTP or Mailgun) and SMS (Twilio) backends,
  used e.g. to send a new user their temporary credentials.
- **UI** — server-rendered Jinja templates with light / dark / **system**
  (default) theme. On panel-heavy pages each panel heading is click-collapsible
  (state persists per page). **Non-essential panels start collapsed** by default
  — action/creation forms and advanced/danger sections — while the primary read
  view stays open; a saved expand/collapse choice is always respected. Currently
  default-collapsed: PKI *Create CA*, *Import existing CA*, *Import leaf
  certificate*, *Sign appliance CSR* (hierarchy + recent-certs stay open);
  Connection *Rename*, *Far-end configuration*, *Danger zone* (proposals/status
  stay open); Site *Add a connection*, *Danger zone* (connection list stays open).
- **Docker image + compose overlays** — ready to run standalone, or behind
  Traefik, NGINX, or a Cloudflare Tunnel, with an optional TLS-encrypted Postgres.

---

## Quick start (local, no proxy)

Requires Python **3.11+**.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

export VCM_SECRET_KEY=$(openssl rand -hex 32)
export VCM_KEK_B64=$(python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")
export VCM_BOOTSTRAP_ADMIN=admin:changeme

uvicorn app.main:app --reload
# open http://localhost:8000  → log in as admin/changeme → enroll MFA
```

> **First run.** The IP allowlist is seeded from `VCM_INITIAL_ALLOW` (default: all
> RFC1918 ranges + loopback) the first time the table is empty. If you set
> `VCM_INITIAL_ALLOW=` empty and leave enforcement on, only loopback is allowed
> until you add a CIDR under **Admin → Source-IP allowlist**.

The database defaults to a local SQLite file (`./vcm.db`). Tables are created
automatically on startup, and new nullable/defaulted columns from newer releases
are added in place (a lightweight, additive schema sync — no separate migration
step; existing columns are never altered or dropped).

---

## Docker & compose overlays

```bash
cp .env.example .env    # fill in VCM_SECRET_KEY, VCM_KEK_B64, etc.
docker compose up -d --build
```

The base `docker-compose.yml` publishes **no ports** (front it with a reverse
proxy) and stores data on the `vcm-data` volume. Which extras are active is
driven by the `COMPOSE_FILE` variable in `.env` (order matters — later wins):

| Goal | `COMPOSE_FILE` value | Effect |
| --- | --- | --- |
| **Prod (default)** | *unset* — base file only | No published ports; `VCM_MODE=prod`. Front with a proxy. |
| **Local dev** | `docker-compose.yml:docker-compose.dev.yml` | Publishes `${VCM_DEV_PORT:-8000}:8000`; sets `VCM_MODE=dev` (skips forced MFA enrollment). |
| **Traefik (public HTTPS)** | `docker-compose.yml:docker-compose.traefik.yml` | Joins an existing external Traefik network via labels; TLS + HSTS + secure headers; sets `VCM_RP_ID`/`VCM_RP_ORIGIN` and `VCM_COOKIE_SECURE=true`. |
| **+ Postgres** | append `:docker-compose.postgres.yml` | Adds a TLS-enabled Postgres (`vcm-db`) on an internal-only network; builds `VCM_DATABASE_URL` from `POSTGRES_*`. |

There are also two self-contained proxy overlays under `deploy/` that bundle the
proxy container itself (useful when you don't already run one):

```bash
docker compose -f docker-compose.yml -f deploy/traefik.yml up -d       # Traefik + Let's Encrypt
docker compose -f docker-compose.yml -f deploy/cloudflared.yml up -d   # Cloudflare Tunnel sidecar
# NGINX: see deploy/nginx.conf
```

> `deploy/cloudflared.yml` is documented — with its ready-to-copy contents — in
> [`deploy/cloudflared.md`](deploy/cloudflared.md), which also explains **why
> trusted-proxy configuration is critical** to keep the IP allowlist un-spoofable.

Full deployment details, the two Traefik variants, the Postgres TLS setup, and
CI/release image publishing are in [`docs/deployment.md`](docs/deployment.md).

---

## Configuration

All settings are read from environment variables with the **`VCM_`** prefix (and
from a `.env` file). Below is the complete list from `app/config.py`; see
[`docs/configuration.md`](docs/configuration.md) for the exhaustive reference
including the notification backends.

| Variable | Default | Meaning |
| --- | --- | --- |
| `VCM_APP_NAME` | `VCM — VPN & Certificate Manager` | Display name / WebAuthn issuer context. |
| `VCM_DATABASE_URL` | `sqlite:///./vcm.db` | SQLAlchemy URL. Postgres example: `postgresql+psycopg://…?sslmode=require`. |
| `VCM_MODE` | `prod` | `prod` forces MFA enrollment before privileged actions; `dev` skips it. Never use `dev` in production. |
| `VCM_SECRET_KEY` | `dev-insecure-change-me` | Session/signing secret. **Must** be set to a long random value in production. |
| `VCM_SESSION_COOKIE` | `vcm_session` | Session cookie name. |
| `VCM_SESSION_TTL_MINUTES` | `60` | Session lifetime. |
| `VCM_COOKIE_SECURE` | `false` | Set `true` behind TLS so the session cookie is `Secure`. |
| `VCM_KEK_B64` | *(unset)* | Base64 of **32 raw bytes** — the Key-Encryption Key that wraps CA private keys, TOTP seeds, and backups (AES-256-GCM). If unset, a key is derived from `VCM_SECRET_KEY` (**dev only**). |
| `VCM_TRUSTED_PROXIES` | `""` | Comma-separated CIDRs whose forwarded IP headers are trusted (e.g. `127.0.0.1/32,10.0.0.0/8`). |
| `VCM_REAL_IP_HEADERS` | `cf-connecting-ip,x-forwarded-for,x-real-ip` | Header priority for resolving the real client IP (first match wins) — only honoured from a trusted proxy. |
| `VCM_ENFORCE_IP_ALLOWLIST` | `true` | Master switch for source-IP filtering. `false` disables it entirely. |
| `VCM_INITIAL_ALLOW` | `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128` | CIDRs seeded into the allowlist on first run (only when the table is empty). |
| `VCM_RP_ID` | `localhost` | WebAuthn Relying Party ID — must match the public hostname. |
| `VCM_RP_NAME` | `VCM` | WebAuthn RP display name (also the TOTP issuer). |
| `VCM_RP_ORIGIN` | `http://localhost:8000` | WebAuthn expected origin — must match the public origin exactly. |
| `VCM_EMAIL_BACKEND` | `none` | `none` \| `smtp` \| `mailgun`. |
| `VCM_SMS_BACKEND` | `none` | `none` \| `twilio`. |
| `VCM_NOTIFY_FROM_EMAIL` | `vcm@localhost` | From-address for outbound email. |
| `VCM_NOTIFY_FROM_NAME` | `VCM` | From-name for outbound email. |
| `VCM_DEFAULT_KEY_TYPE` | `ec` | Default PKI key type (`ec` or `rsa`). |
| `VCM_DEFAULT_EC_CURVE` | `secp384r1` | Default EC curve. |
| `VCM_DEFAULT_RSA_BITS` | `3072` | Default RSA key size. |

SMTP / Mailgun / Twilio settings (`VCM_SMTP_*`, `VCM_MAILGUN_*`, `VCM_TWILIO_*`)
are listed in [`docs/configuration.md`](docs/configuration.md). Non-`VCM_`
variables used only at bootstrap or by the Docker overlays:

| Variable | Used by | Meaning |
| --- | --- | --- |
| `VCM_BOOTSTRAP_ADMIN` | app startup | `user:pass` — creates an initial **admin** on first run if that username doesn't exist. Remove after first login. |
| `COMPOSE_FILE`, `VCM_DEV_PORT` | compose | Overlay selection and dev port (see the table above). |
| `VCM_HOST`, `TRAEFIK_NETWORK`, `VCM_TRAEFIK_IPV4`, `TRAEFIK_CERTRESOLVER` | Traefik overlay | Public hostname and Traefik routing. |
| `POSTGRES_USER`, `POSTGRES_DB`, `POSTGRES_PASSWORD`, `POSTGRES_SSLMODE` | Postgres overlay | DB credentials; the URL is assembled from these (the password is never written into a compose file). |

---

## How it works

### Authentication & the login flow

`POST /login` verifies the password (Argon2id). What happens next is a small
state machine, all gated by the source-IP allowlist:

1. If the user **must change their password** → `/account/first-password`
   (blocks everything else, including MFA).
2. Else if the user **has MFA enrolled** → `/mfa` (verify a TOTP code or a
   passkey assertion).
3. Else in **prod** → `/mfa/enroll` (forced enrollment); in **dev** → straight
   to the app.

The originally-requested page is remembered as a `next` target and the user is
returned to it after auth (open redirects are rejected). A user cannot remove
their only remaining MFA factor. See [`docs/authentication.md`](docs/authentication.md)
for the passkey (WebAuthn) request/response details and admin MFA reset.

### PKI

CAs and issued certs live in the database; every CA private key is stored as
`nonce || AES-256-GCM(ciphertext||tag)` wrapped by the KEK. Key invariants,
verified in code and tests:

- **Keys never leave the process** — no route serialises a CA or appliance
  *private* key. (Appliance keys can be generated server-side for a CSR and are
  returned to the caller exactly once, never persisted.)
- **Issuing CAs are `pathlen:0`**; a **root refuses to sign leaf certificates**
  directly.
- **Import** accepts PEM or PKCS#12; a supplied private key must match the
  certificate's public key, and an imported CA is auto-linked to a parent whose
  subject matches its issuer. Cert-only imports can't sign, and creating a child
  under a keyless parent fails with a clear error.
- **Deletion** is guarded: certs need their **serial** re-typed, CAs need their
  **name** re-typed; a non-empty CA needs explicit **cascade**; and a **locked**
  CA/cert (or a locked item anywhere in a cascade subtree) blocks deletion until
  unlocked.

Full detail — key types/curves, extensions set, chain building, the hierarchy
JSON — is in [`docs/pki.md`](docs/pki.md).

### VPN configuration

A `VpnProfile` (see `app/srx/model.py`) is the single source of truth. Generators
in `app/srx/generators.py` translate it to each platform's syntax; importers in
`app/srx/importer.py` parse a config back into a profile.

- **Crypto catalog & ratings** live in `app/srx/proposals.py`, which also holds
  the per-vendor keyword mapping (how each platform spells `aes-256-gcm`,
  `group20`, etc.) so menus show the platform's own terms while the backend stays
  neutral.
- **SRX traffic selectors** are chosen by the far-end platform: route-based VTI
  peers (SRX, Fortinet, Palo Alto) omit selectors; policy-based peers
  (pfSense/strongSwan, AWS, Azure, Cisco, MikroTik, Digi, Cradlepoint) get
  `proxy-identity` (one subnet pair) or `traffic-selector` stanzas (multiple),
  with an inline note that they must match the peer's Phase 2.
- **Mirroring** swaps local/remote endpoints and BGP ASNs/addresses while keeping
  crypto identical, guaranteeing a compatible far end.
- **BGP over the tunnel** is optional and emitted only for platforms that support
  it (Juniper, Cisco, Fortinet, Palo Alto, MikroTik, pfSense/FRR); others get a
  note.

The vendor matrix, the SRX selector logic, importer coverage (including the
structured-Junos and pfSense `config.xml` parsers), and PSK redaction are
documented in [`docs/vendors.md`](docs/vendors.md).

### Backups

`app/backup.py` dumps every data table (except backups, sessions and WebAuthn
challenges) to JSON, records a plaintext SHA-256 for integrity, and stores it
**AES-256-GCM encrypted** under the KEK — so a backup is only restorable on an
instance holding the **same `VCM_KEK_B64`**. Backups are versioned and never
overwrite each other. Restore takes a safety snapshot first, wipes data tables
(preserving backup history), re-inserts the snapshot, and **clears all sessions**
(forcing re-auth). You can download a `.vcmbak` and re-upload it to restore
elsewhere.

### Notifications

`app/notify.py` provides best-effort email (SMTP or Mailgun) and SMS (Twilio)
using only the Python standard library — no extra runtime dependencies. Backends
are off by default (`none`) and selected via `VCM_EMAIL_BACKEND` /
`VCM_SMS_BACKEND`. Every call returns an `(ok, detail)` tuple so the caller
decides whether a failure should surface. Currently wired into new-user creation
(optionally emailing the temporary password) and designed to underpin future
flows such as password reset.

---

## HTTP routes

Grouped by router module. Unless noted, routes require a fully authenticated
(MFA-passed) session; **(admin)** marks admin-only routes. All authenticated
routes also pass the source-IP allowlist.

**Auth (`app/routers/auth.py`)** — `GET/POST /login`, `GET /logout`,
`GET/POST /account/first-password`, `GET /mfa`, `POST /mfa/totp`,
`POST /mfa/passkey/{options,verify}`, `GET /mfa/enroll`, `POST /mfa/enroll/totp`,
`POST /mfa/enroll/passkey/{options,verify}`.

**UI / health (`app/routers/ui.py`, `app/main.py`)** — `GET /` (dashboard),
`GET /healthz` (unauthenticated JSON health check).

**PKI (`app/routers/pki.py`, prefix `/pki`)** — `GET /pki`, `GET /pki/tree.json`,
`POST /pki/ca` (admin), `POST /pki/ca/import` (admin),
`POST /pki/ca/{id}/delete` (admin), `POST /pki/ca/{id}/lock` (admin),
`GET /pki/ca/{id}/chain`, `GET /pki/ca/{id}/cert`, `POST /pki/sign`,
`GET /pki/cert/{id}`, `GET /pki/cert/{id}/pem`, `POST /pki/cert/{id}/delete`
(admin), `POST /pki/cert/{id}/lock` (admin).

**Sites (`app/routers/sites.py`, prefix `/sites`)** — `GET /sites`,
`POST /sites/generate`, `GET/POST /sites/import`, `GET /sites/{id}`,
`POST /sites/{id}/connections`, `POST /sites/{id}/delete` (admin).

**Connections (`app/routers/sites.py`, prefix `/connections`)** —
`GET /connections/{id}`, `GET/POST /connections/{id}/edit`,
`GET /connections/{id}/config`, `GET /connections/{id}/far-end[.txt]`,
`POST /connections/{id}/peer`, `POST /connections/{id}/rename`,
`POST /connections/{id}/pair-confirm`, `POST /connections/{id}/apply-bgp`,
`POST /connections/{id}/unpair`, `POST /connections/{id}/delete` (admin).

**Profile (`app/routers/profile.py`, prefix `/profile`)** — `GET /profile`,
`POST /profile/contact`, `POST /profile/password`,
`POST /profile/passkey/{id}/{rename,delete}`, `POST /profile/totp/reset`,
`POST /profile/sessions/revoke-others`, and API-token management
(`POST /profile/tokens/create`, `POST /profile/tokens/{id}/revoke`).

**REST API (`app/routers/api.py`, prefix `/api`)** — a JSON surface
authenticated with API **bearer tokens** (not the session cookie): `GET /api/whoami`,
`GET /api/sites`, `GET /api/sites/{id}`, `GET /api/certificates`,
`GET /api/pki/tree`, `GET /api/audit` (admin scope), and
`POST /api/tokens/{id}/revoke` (write scope). Full reference — auth, scopes,
the IP-allowlist caveat, per-endpoint curl/JSON examples and errors — is in
[`docs/api.md`](docs/api.md).

**Admin (`app/routers/admin.py`, prefix `/admin`, all admin-only)** — `GET /admin`,
user management (`POST /admin/users`, `.../toggle`, `.../reset-mfa`,
`GET /admin/users/{id}`, `.../role`, `.../password`, `.../delete`), IP allowlist
(`POST /admin/ip`, `.../ip/{id}/delete`), defaults (`GET/POST /admin/defaults`),
backups (`GET /admin/backups`, `.../create`, `.../{id}/download`,
`.../{id}/restore`, `.../upload-restore`, `.../{id}/delete`), and
`GET /admin/audit`.

---

## Data model

SQLAlchemy models in `app/models.py`:

| Table | Purpose |
| --- | --- |
| `users` | Accounts: username, Argon2id hash, role, contact fields, `must_change_password`, encrypted TOTP secret, `disabled`. |
| `webauthn_credentials` | Registered passkeys (credential id, public key, sign count, transports) per user. |
| `webauthn_challenges` | Short-lived registration/authentication challenges. |
| `sessions` | Server-side sessions: token id, user, expiry, `mfa_ok`, client IP, remembered `next_url`. |
| `ip_allowlist` | Source-IP allow entries (CIDR, description, enabled). |
| `cert_authorities` | CAs: type (root/intermediate/issuing), parent, subject, cert PEM, **KEK-encrypted key**, key type/params, serial counter, validity, `path_len`, `locked`. |
| `certificates` | Issued end-entity certs: CA ref, optional site ref, serial, subject, SAN, cert & CSR PEM, status, `locked`, validity. |
| `defaults` | Key/value JSON store for app-wide VPN defaults. |
| `sites` | A device/firewall: name, vendor, model, source (generated/imported). |
| `vpn_connections` | A tunnel on a site: params JSON, generated config, source, `needs_review`, optional `peer_connection_id`. |
| `backups` | Versioned, encrypted state snapshots (SHA-256 of plaintext, size, payload). |
| `audit_log` | Timestamped action log (user, action, detail, IP). |

---

## Encryption in flight & at rest

**In flight**
- **Client → app**: TLS is terminated at the reverse proxy (Traefik overlay adds
  HTTP→HTTPS redirect, HSTS and secure headers) with `VCM_COOKIE_SECURE=true`.
  The same TLS guarantee applies behind Cloudflare Tunnel or NGINX.
- **App → Postgres**: `sslmode=require` (the Postgres overlay runs with `ssl=on`
  and an auto-generated server cert). Use `sslmode=verify-full` with a mounted CA
  to also pin the DB identity.

**At rest**
- **CA private keys**, **TOTP seeds** and **backups** are AES-256-GCM encrypted
  with the KEK and are never returned by any API.
- **Passwords** are Argon2id hashes (not reversible).
- **Imported configs** have PSKs / `encrypted-password` / `pre-shared-key`
  redacted before storage.
- The database volume itself relies on host/volume encryption (LUKS, encrypted
  EBS/EFS, …) — enable it on `vcm-data` / `pg-data` in production. The most
  sensitive material is app-encrypted regardless.
- Prefer **certificate auth** over PSK so no shared secret is stored.

---

## Security notes

- `VCM_KEK_B64` wraps every CA private key, TOTP seed and backup. **Back it up
  separately** — losing it makes the CAs and backups unrecoverable; leaking it
  defeats at-rest encryption.
- Set `VCM_COOKIE_SECURE=true` and a correct `VCM_RP_ID` / `VCM_RP_ORIGIN` behind
  TLS, or passkeys and secure cookies won't work.
- The source-IP allowlist is **fail-safe** (empty + enforced ⇒ loopback only) and
  only trusts forwarded IP headers from configured trusted proxies. Keep the app
  container's ports closed behind a proxy so headers can't be spoofed.
- Issuing CAs are `pathlen:0`; roots never sign leaf certs directly.
- Appliance private keys, if generated server-side, are returned once and never
  stored; CSR-based issuance (device-generated key) is preferred.

---

## Project layout

```
app/
  config.py            settings (env-driven, VCM_ prefix)
  db.py                engine/session + additive schema sync
  main.py              FastAPI app, lifespan bootstrap, error handling
  models.py            SQLAlchemy models + Vendor enum
  backup.py            encrypted versioned backup/restore
  notify.py            SMTP / Mailgun / Twilio backends
  templates_env.py     Jinja environment
  security/            crypto (KEK), passwords (Argon2), sessions, MFA, IP filter, deps
  pki/                 key gen, CA hierarchy + signing, CSR, PEM/PKCS#12 import
  srx/                 proposals catalog, vendor-neutral model, generators, importer,
                       defaults, BGP, rename, peer/BGP inference
  routers/             auth, pki, sites, profile, admin, ui
  templates/ static/   Jinja UI + theme + WebAuthn JS
deploy/                traefik / nginx / cloudflared overlays + notes
docs/                  extended documentation (this README links into it)
tests/                 pytest suite (tests/test_core.py)
docker-compose*.yml    base + dev / traefik / postgres overlays
Dockerfile             slim python:3.12 image, non-root, uvicorn
```

---

## Testing

```bash
.venv/bin/pytest            # or: pytest -q
.venv/bin/pytest tests/test_core.py
```

`tests/test_core.py` covers the crypto rating & de-duplication logic, per-vendor
generation and generate→import round-trips, SRX identity/selector rules,
structured-Junos and pfSense `config.xml` imports (asserting PSKs are **not**
persisted), AWS import-only + far-end generation, peer/BGP inference, the PKI
hierarchy and CSR signing (asserting private keys are never exported), CA/cert
import (PEM + PKCS#12), lock/cascade delete rules, backup/restore round-trips,
the additive schema sync, and end-to-end HTTP flows (login → MFA → generate/edit,
forced password change, next-URL redirect, admin cert delete). CI runs the suite
and a container smoke test on every PR; merges to `main` build a multi-arch image
and publish a release.

---

## Further reading

- [`docs/configuration.md`](docs/configuration.md) — every environment variable, in full.
- [`docs/authentication.md`](docs/authentication.md) — login state machine, MFA, RBAC, IP allowlist.
- [`docs/pki.md`](docs/pki.md) — CA hierarchy, KEK envelope, import, signing, deletion rules.
- [`docs/vendors.md`](docs/vendors.md) — vendor matrix, crypto catalog, SRX selectors, importer coverage.
- [`docs/deployment.md`](docs/deployment.md) — Docker, compose overlays, proxies, Postgres TLS, CI/release.
- [`docs/api.md`](docs/api.md) — the JSON REST API: bearer tokens, scopes, endpoint reference.
</content>
</invoke>
