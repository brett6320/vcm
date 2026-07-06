# Deployment

## Container image

`Dockerfile` builds a slim `python:3.12-slim` image, installs the package, runs
as a **non-root** `vcm` user, exposes `8000`, and starts:

```
uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips *
```

Prebuilt multi-arch images (linux/amd64 + linux/arm64) are published to GHCR on
merge to `main`:

```bash
docker pull ghcr.io/brett6320/vcm:latest
```

## Compose files

| File | Role |
| --- | --- |
| `docker-compose.yml` | **Base.** Builds the image, mounts the `vcm-data` volume, sets required env, publishes **no ports**. Defaults to SQLite at `/data/vcm.db`. |
| `docker-compose.dev.yml` | Dev overlay: publishes `${VCM_DEV_PORT:-8000}:8000` and forces `VCM_MODE=dev`. |
| `docker-compose.traefik.yml` | **Inclusion** overlay: attaches the app to an **existing** external Traefik network via labels (HTTP→HTTPS redirect, HSTS + secure headers, cert resolver). Sets `VCM_RP_ID`/`VCM_RP_ORIGIN`/`VCM_COOKIE_SECURE=true`. |
| `docker-compose.postgres.yml` | Adds a TLS-enabled `vcm-db` Postgres 16 on an **internal-only** network and builds `VCM_DATABASE_URL` from `POSTGRES_*`. |
| `deploy/traefik.yml` | **Self-contained** overlay that also runs a Traefik container (Let's Encrypt TLS-ALPN). Use when you don't already run Traefik. |
| `deploy/cloudflared.yml` | Cloudflare Tunnel sidecar (contents shown in `deploy/cloudflared.md`). |
| `deploy/nginx.conf` | Sample NGINX reverse-proxy config (TLS termination, forwards real client IP). |

### Selecting overlays

The base file publishes nothing, so which extras apply is driven by
`COMPOSE_FILE` in `.env` (order matters — later wins):

```dotenv
# Local dev (publishes a port):
COMPOSE_FILE=docker-compose.yml:docker-compose.dev.yml

# Public HTTPS via an existing Traefik, with Postgres:
COMPOSE_FILE=docker-compose.yml:docker-compose.traefik.yml:docker-compose.postgres.yml

# Prod default: leave COMPOSE_FILE unset → base file only → no ports, front with a proxy.
```

A plain `docker compose up -d` then does the right thing for the selected profile.

## Reverse proxies & the real client IP

VCM only trusts a forwarded client-IP header when the direct TCP peer is in
`VCM_TRUSTED_PROXIES`, so **each proxy setup must set both** `VCM_TRUSTED_PROXIES`
(the proxy's address range) and `VCM_REAL_IP_HEADERS` (the header the proxy sets):

| Proxy | Header | Notes |
| --- | --- | --- |
| Cloudflare Tunnel | `cf-connecting-ip` | `deploy/cloudflared.md`. No published ports — cloudflared is the only reachable path, so the header can't be spoofed. |
| Traefik | `x-forwarded-for` | `docker-compose.traefik.yml` (inclusion) or `deploy/traefik.yml` (bundled). |
| NGINX | `x-forwarded-for` / `x-real-ip` | `deploy/nginx.conf`. |

Behind TLS, also set `VCM_COOKIE_SECURE=true` and matching
`VCM_RP_ID`/`VCM_RP_ORIGIN` (the Traefik/Cloudflare overlays do this for you).

Keeping the app container's ports closed behind the proxy is what makes the
source-IP allowlist un-spoofable — see `deploy/cloudflared.md`.

## Postgres with TLS

`docker-compose.postgres.yml` runs Postgres 16 with `ssl=on` using a self-signed
server cert generated on each start (outside the data dir so it doesn't block
`initdb`). The app connects with `?sslmode=require` (encrypt without verifying the
cert). For identity pinning, mount a CA and use `POSTGRES_SSLMODE=verify-full`.
The DB sits on an `internal: true` network with no external egress — only the app
can reach it — and the password is provided only via `.env` (never written into a
compose file).

## Database schema management

`app/db.py` creates tables on startup and runs `add_missing_columns()` — a
lightweight, **additive** schema sync that `ALTER TABLE … ADD COLUMN` for any
mapped column the DB is missing (applying scalar defaults). It never drops or
alters existing columns, so newer releases can add nullable/defaulted columns
without a separate migration. (Alembic is a listed dependency but there is no
migration directory in the repo; the additive sync is what runs.)

## CI / release

- **CI** (`.github/workflows/ci.yml`) runs on PRs and non-`main` pushes: installs
  the package, runs `ruff` (non-blocking) and `pytest`, builds the image, and
  smoke-tests the container's `/healthz`.
- **Release** (`.github/workflows/release.yml`) runs on merge to `main`: tests,
  builds amd64 + arm64 on native runners, stitches them into one multi-arch GHCR
  manifest (`:latest`, `:v0.1.<run>`, `:<sha>`), and publishes a GitHub Release.
</content>
