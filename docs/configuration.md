# Configuration reference

Every setting lives in `app/config.py` (`Settings`, a `pydantic-settings`
model). Values are read from environment variables with the **`VCM_`** prefix and
from a `.env` file in the working directory; unknown keys are ignored.

```python
model_config = SettingsConfigDict(env_prefix="VCM_", env_file=".env", extra="ignore")
```

So the field `smtp_host` is set by `VCM_SMTP_HOST`, `rp_id` by `VCM_RP_ID`, and
so on.

## Core

| Variable | Field | Default | Meaning |
| --- | --- | --- | --- |
| `VCM_APP_NAME` | `app_name` | `VCM — VPN & Certificate Manager` | Application display name. |
| `VCM_DATABASE_URL` | `database_url` | `sqlite:///./vcm.db` | SQLAlchemy database URL. SQLite (incl. `:memory:`) and Postgres (`postgresql+psycopg://…`) are used in the codebase; in-memory SQLite uses a shared `StaticPool`. |
| `VCM_MODE` | `mode` | `prod` | `prod` forces MFA enrollment before any privileged action; `dev` skips forced enrollment. `is_dev` is `mode.lower() == "dev"`. |

## Sessions & signing

| Variable | Field | Default | Meaning |
| --- | --- | --- | --- |
| `VCM_SECRET_KEY` | `secret_key` | `dev-insecure-change-me` | Cookie signing / session secret. **Must** be a long random value in production. Also the fallback source for the KEK when `VCM_KEK_B64` is unset (dev only). |
| `VCM_SESSION_COOKIE` | `session_cookie` | `vcm_session` | Session cookie name. |
| `VCM_SESSION_TTL_MINUTES` | `session_ttl_minutes` | `60` | Session lifetime in minutes; also the cookie `max-age`. |
| `VCM_COOKIE_SECURE` | `cookie_secure` | `false` | Marks the session cookie `Secure`; set `true` behind TLS. |

## Key-encryption key (KEK)

| Variable | Field | Default | Meaning |
| --- | --- | --- | --- |
| `VCM_KEK_B64` | `kek_b64` | *(unset)* | Base64 of **exactly 32 raw bytes**. Used to AES-256-GCM-wrap CA private keys, TOTP seeds and backups. |

`kek_bytes()` base64-decodes the value and requires it to be 32 bytes, raising
`ValueError` otherwise. **If unset**, a key is derived as
`sha256("kek:" + secret_key)` — acceptable for development only. Generate one
with:

```bash
python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
```

**Losing the KEK makes every CA and every backup unrecoverable; leaking it
defeats at-rest encryption.** Back it up separately from the database.

## Reverse-proxy / source-IP trust

| Variable | Field | Default | Meaning |
| --- | --- | --- | --- |
| `VCM_TRUSTED_PROXIES` | `trusted_proxies` | `""` | Comma-separated CIDRs. A forwarded client-IP header is trusted **only** when the direct TCP peer falls in one of these. `trusted_proxy_list` parses it. |
| `VCM_REAL_IP_HEADERS` | `real_ip_headers` | `cf-connecting-ip,x-forwarded-for,x-real-ip` | Ordered header names to read the client IP from (first non-empty wins; for `x-forwarded-for` the left-most entry is used). Lower-cased into `real_ip_header_list`. |
| `VCM_ENFORCE_IP_ALLOWLIST` | `enforce_ip_allowlist` | `true` | Master switch. When `false`, IP filtering is disabled entirely. |
| `VCM_INITIAL_ALLOW` | `initial_allow` | `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128` | CIDRs seeded into the allowlist on first run **only when the table is empty**. Parsed into `initial_allow_list`. |

Fail-safe behaviour (`app/security/ipfilter.py`): with enforcement on and an
**empty** allowlist, only loopback (`127.0.0.0/8`, `::1/128`) is admitted, so a
fresh install stays reachable to add the first rule.

## WebAuthn / passkeys

| Variable | Field | Default | Meaning |
| --- | --- | --- | --- |
| `VCM_RP_ID` | `rp_id` | `localhost` | WebAuthn Relying Party ID — must match the public hostname (no scheme/port). |
| `VCM_RP_NAME` | `rp_name` | `VCM` | RP display name; also used as the TOTP issuer. |
| `VCM_RP_ORIGIN` | `rp_origin` | `http://localhost:8000` | Expected WebAuthn origin — must match the browser's origin exactly (scheme + host + port). |

Behind TLS these must reflect the public origin, e.g. `VCM_RP_ID=vcm.example.com`
and `VCM_RP_ORIGIN=https://vcm.example.com`.

## Notifications

| Variable | Field | Default | Meaning |
| --- | --- | --- | --- |
| `VCM_EMAIL_BACKEND` | `email_backend` | `none` | `none` \| `smtp` \| `mailgun`. |
| `VCM_SMS_BACKEND` | `sms_backend` | `none` | `none` \| `twilio`. |
| `VCM_NOTIFY_FROM_EMAIL` | `notify_from_email` | `vcm@localhost` | From-address for email. |
| `VCM_NOTIFY_FROM_NAME` | `notify_from_name` | `VCM` | From-name for email. |
| `VCM_SMTP_HOST` | `smtp_host` | `""` | SMTP server host (required for the `smtp` backend). |
| `VCM_SMTP_PORT` | `smtp_port` | `587` | SMTP port. |
| `VCM_SMTP_USER` | `smtp_user` | `""` | SMTP username (login is skipped if empty). |
| `VCM_SMTP_PASSWORD` | `smtp_password` | `""` | SMTP password. |
| `VCM_SMTP_STARTTLS` | `smtp_starttls` | `true` | Issue `STARTTLS` before sending. |
| `VCM_MAILGUN_DOMAIN` | `mailgun_domain` | `""` | Mailgun sending domain. |
| `VCM_MAILGUN_API_KEY` | `mailgun_api_key` | `""` | Mailgun API key (HTTP basic `api:<key>`). |
| `VCM_MAILGUN_BASE_URL` | `mailgun_base_url` | `https://api.mailgun.net` | Mailgun API base (use the EU base if applicable). |
| `VCM_TWILIO_ACCOUNT_SID` | `twilio_account_sid` | `""` | Twilio account SID. |
| `VCM_TWILIO_AUTH_TOKEN` | `twilio_auth_token` | `""` | Twilio auth token. |
| `VCM_TWILIO_FROM_NUMBER` | `twilio_from_number` | `""` | Twilio sender number (E.164). |

Backends are implemented with the Python standard library only (`smtplib`,
`urllib`) — no extra runtime dependencies. Each send returns `(ok, detail)`.

## PKI defaults

| Variable | Field | Default | Meaning |
| --- | --- | --- | --- |
| `VCM_DEFAULT_KEY_TYPE` | `default_key_type` | `ec` | Default key type for new CAs (`ec` or `rsa`). |
| `VCM_DEFAULT_EC_CURVE` | `default_ec_curve` | `secp384r1` | Default EC curve. Supported: `secp256r1`, `secp384r1`, `secp521r1`. |
| `VCM_DEFAULT_RSA_BITS` | `default_rsa_bits` | `3072` | Default RSA key size. |

## Non-`VCM_` variables

These are not part of `Settings` but influence startup or the Docker overlays:

| Variable | Consumed by | Meaning |
| --- | --- | --- |
| `VCM_BOOTSTRAP_ADMIN` | `app/main.py` `_bootstrap_admin()` | `username:password`. On first run, creates that user as **admin** if it doesn't already exist. (Note: bootstrap admins are created **without** `must_change_password`, unlike admin-created users.) |
| `COMPOSE_FILE` | Docker Compose | Selects which overlay files are active (see `docs/deployment.md`). |
| `VCM_DEV_PORT` | `docker-compose.dev.yml` | Host port published in dev (default `8000`). |
| `VCM_HOST` | `docker-compose.traefik.yml` | Public hostname for Traefik routing and RP settings. |
| `TRAEFIK_NETWORK` | Traefik overlay | Name of the external Traefik network. |
| `VCM_TRAEFIK_IPV4` | Traefik overlay | Optional static IP on the Traefik network (unset ⇒ auto-assign). |
| `TRAEFIK_CERTRESOLVER` | Traefik overlay | Traefik cert resolver name. |
| `POSTGRES_USER` / `POSTGRES_DB` / `POSTGRES_PASSWORD` / `POSTGRES_SSLMODE` | Postgres overlay | Assemble `VCM_DATABASE_URL`; the password is set only in `.env`, never in a compose file. |
</content>
