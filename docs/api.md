# REST API

VCM exposes a small, read-first JSON REST surface under the `/api/` prefix,
authenticated with **API bearer tokens** (not the browser session/MFA cookie).
It is intended for automation — CI jobs, monitoring, inventory scripts — that
needs to read VPN, certificate and PKI state, and to rotate its own credentials.

The router is `app/routers/api.py`, mounted in `app/main.py`
(`app.include_router(api.router)` with `prefix="/api"`). Token issuance,
hashing and authentication live in `app/security/apitokens.py`; the
`ApiToken` / `TokenScope` models are in `app/models.py`.

> **Everything the API can read is public-safe.** No endpoint ever returns a CA
> or leaf **private key** — private keys are AES-256-GCM encrypted at rest under
> the KEK and are never serialised by any route. See
> [Security notes](#security-notes).

---

## Table of contents

- [Authentication](#authentication)
  - [Obtaining a token (UI)](#obtaining-a-token-ui)
  - [Using the bearer header](#using-the-bearer-header)
- [Scopes & permissions](#scopes--permissions)
- [The IP-allowlist caveat](#the-ip-allowlist-caveat)
- [Error responses](#error-responses)
- [Endpoint reference](#endpoint-reference)
  - [GET /api/whoami](#get-apiwhoami)
  - [GET /api/sites](#get-apisites)
  - [GET /api/sites/{site_id}](#get-apisitessite_id)
  - [GET /api/certificates](#get-apicertificates)
  - [GET /api/pki/tree](#get-apipkitree)
  - [GET /api/audit](#get-apiaudit)
  - [POST /api/tokens/{token_id}/revoke](#post-apitokenstoken_idrevoke)
- [Audit logging](#audit-logging)
- [Security notes](#security-notes)

---

## Authentication

Every `/api/**` request must present an API token as an
`Authorization: Bearer <token>` header. There are no anonymous API endpoints and
no cookie-based access to `/api`.

A token is a high-entropy random secret:

```
vcm_<43-char url-safe base64 of 32 random bytes>
```

The `vcm_` prefix (`TOKEN_PREFIX`) makes tokens recognisable; the body is
`secrets.token_urlsafe(32)` (~256 bits of entropy). **Only the SHA-256 hex
digest of the token is stored** in the database (`api_tokens.token_hash`) — the
plaintext is shown to you exactly once at creation and is never persisted or
logged. A short non-secret display identifier — the first 12 characters, e.g.
`vcm_ab12cd34` — is stored as `prefix` so you can recognise a token in the UI
and in audit entries without exposing the secret.

Because the secret is high-entropy, a fast one-way hash (SHA-256) is used rather
than a slow password KDF; lookup is a single indexed digest comparison.

### Obtaining a token (UI)

Tokens are created and managed from your **profile** page (`GET /profile`,
`app/templates/profile.html`), in the **"API tokens"** card:

1. Sign in to the web UI and open **My profile**.
2. Scroll to **API tokens** and use the **create** form at the bottom:
   - **Name** — a human label (e.g. `ci-automation`), required, max 64 chars.
   - **Scope** — a dropdown; the choices are capped by your role
     (see [Scopes & permissions](#scopes--permissions)).
   - **Expires in days** — optional; leave blank for a token that never
     expires, or enter a positive integer number of days.
3. Submit **Create API token**. The plaintext token is then displayed **once**
   in a highlighted box with the warning *"copy it now; it won't be shown
   again."* Copy it immediately — after you navigate away it cannot be
   retrieved, only revoked and replaced.

The token table lists each token's **name, prefix, scope, created date, last
used, expiry and status** (`active` / `expired` / `revoked`), with a **Revoke**
button per non-revoked token. Revocation is immediate and permanent.

Behind the UI: `POST /profile/tokens/create` validates the label and scope,
rejects a scope above your role cap, computes the optional `expires_at`,
generates the plaintext, stores only its hash + prefix, and audits
`apitoken.create` (label + scope + prefix — never the secret).
`POST /profile/tokens/{id}/revoke` sets `revoked = True` and audits
`apitoken.revoke`.

### Using the bearer header

```bash
curl -sS https://vcm.example.com/api/whoami \
  -H "Authorization: Bearer vcm_EXAMPLEtokenREDACTEDdoNotUseThisValue"
```

The scheme is case-insensitive (`Bearer`); the value must be non-empty. A
missing, malformed or empty header is a JSON **401** (see
[Error responses](#error-responses)).

---

## Scopes & permissions

Each token carries exactly one **scope** (`TokenScope`), independent of the
owner's UI role. Scopes are strictly ordered — a token satisfies an endpoint's
requirement when its scope rank is **greater than or equal to** the required
rank:

| Scope   | Rank | Grants                                                    |
| ------- | ---- | --------------------------------------------------------- |
| `read`  | 0    | All read endpoints.                                       |
| `write` | 1    | Everything `read` can do, **plus** revoking your own tokens. |
| `admin` | 2    | Everything `write` can do, **plus** the audit log.        |

The scope a user may **mint** is capped by their UI role
(`_MAX_SCOPE_FOR_ROLE`):

| UI role    | Maximum token scope |
| ---------- | ------------------- |
| `operator` | `write`             |
| `admin`    | `admin`             |

So an `operator` can create `read` or `write` tokens but not `admin` tokens; an
`admin` can create any scope. The create form only offers the scopes allowed for
your role, and `POST /profile/tokens/create` re-checks the cap server-side
(*"Your role cannot mint a '<scope>' token"*).

A request whose token scope is below what the endpoint requires is a JSON
**403** (see [Error responses](#error-responses)).

---

## The IP-allowlist caveat

A bearer token is a **credential, not a network-ACL bypass.** API authentication
still enforces the source-IP allowlist (`enforce_ip`) *before* the token is even
looked up. If the resolved client IP is not in the allowlist, the request is
rejected with a JSON **403** — `{"detail": "Source IP <ip> not allowed"}` —
regardless of how valid the token is.

Practical consequences:

- Your automation's egress IP (as seen by VCM, resolved proxy-aware from the
  configured real-IP headers when the direct peer is a trusted proxy) must fall
  inside a CIDR in **Admin → Source-IP allowlist**.
- With enforcement on and an empty allowlist, only loopback is admitted.
- A `403 "Source IP … not allowed"` is distinct from a `403` for **insufficient
  scope** — check the `detail` string to tell them apart.

---

## Error responses

All `/api/**` errors are returned as JSON — the `StarletteHTTPException` handler
in `app/main.py` emits `{"detail": "..."}` for JSON-speaking paths (`/api` is
one) rather than an HTML page or a login redirect. The body shape is always:

```json
{ "detail": "human-readable reason" }
```

| Status | `detail`                                                     | When |
| ------ | ------------------------------------------------------------ | ---- |
| `401`  | `Missing or malformed bearer token`                          | No `Authorization: Bearer` header, or an empty/garbled one. |
| `401`  | `Invalid or revoked token`                                   | Token doesn't match any stored hash, or has been revoked. |
| `401`  | `Token has expired`                                          | `expires_at` is in the past. |
| `401`  | `Token owner is inactive`                                    | The owning user was disabled. |
| `403`  | `Source IP <ip> not allowed`                                 | Caller IP is outside the allowlist (checked before the token). |
| `403`  | `Token scope '<have>' is insufficient; '<need>' scope required` | Valid token, but its scope is below the endpoint's requirement. |
| `404`  | `Site not found` / `Token not found`                         | Referenced resource doesn't exist (or, for tokens, isn't yours). |

All `401` responses also carry a `WWW-Authenticate: Bearer` header.

---

## Endpoint reference

Base URL in examples: `https://vcm.example.com`. Replace the bearer value with
your own token. Timestamps are ISO-8601 (UTC); a null timestamp is `null`.

### GET /api/whoami

Identify the calling token and its owner.

- **Scope:** `read`
- **Params:** none

```bash
curl -sS https://vcm.example.com/api/whoami \
  -H "Authorization: Bearer vcm_EXAMPLEtokenREDACTED"
```

```json
{
  "user": "ci-bot",
  "role": "operator",
  "token": {
    "id": 7,
    "name": "ci-automation",
    "prefix": "vcm_ab12cd34",
    "scope": "read",
    "status": "active",
    "created_at": "2026-07-01T14:22:05+00:00",
    "last_used_at": "2026-07-06T09:15:41+00:00",
    "expires_at": null,
    "revoked": false
  }
}
```

The `token` object is the standard token serialisation (`_token_public`): `id`,
`name`, `prefix`, `scope`, `status` (`active` | `expired` | `revoked`),
`created_at`, `last_used_at`, `expires_at`, `revoked`.

### GET /api/sites

List all sites (devices/firewalls) with a connection count.

- **Scope:** `read`
- **Params:** none

```bash
curl -sS https://vcm.example.com/api/sites \
  -H "Authorization: Bearer vcm_EXAMPLEtokenREDACTED"
```

```json
{
  "sites": [
    {
      "id": 1,
      "name": "hq-srx",
      "vendor": "juniper_srx",
      "model": "SRX345",
      "source": "generated",
      "connection_count": 2,
      "created_at": "2026-05-10T11:03:22+00:00",
      "updated_at": "2026-06-28T16:41:09+00:00"
    }
  ]
}
```

`vendor` is the enum value (e.g. `juniper_srx`, `cradlepoint`, `aws`);
`source` is `generated` or `imported`.

### GET /api/sites/{site_id}

A single site with its connections, generated config, and per-connection crypto
warnings.

- **Scope:** `read`
- **Path params:** `site_id` (int)
- **Errors:** `404 "Site not found"`

```bash
curl -sS https://vcm.example.com/api/sites/1 \
  -H "Authorization: Bearer vcm_EXAMPLEtokenREDACTED"
```

```json
{
  "id": 1,
  "name": "hq-srx",
  "vendor": "juniper_srx",
  "model": "SRX345",
  "source": "generated",
  "connections": [
    {
      "id": 10,
      "name": "to-branch-01",
      "source": "generated",
      "needs_review": false,
      "review_note": null,
      "peer_connection_id": 25,
      "params": { "phase1": "…", "phase2": "…", "endpoints": "…" },
      "warnings": [
        { "field": "phase1.dh_group", "severity": "weak", "message": "DH group 2 is weak" }
      ],
      "generated_config": "set security ike proposal …"
    }
  ]
}
```

Each connection (`_conn_public`) includes the vendor-neutral `params`
(the `VpnProfile`), structured crypto `warnings`, and the rendered
`generated_config` (may be `null` for import-only vendors).

### GET /api/certificates

All tracked certificates with expiry classification. **Never includes private
keys** (or even the certificate PEM — only metadata).

- **Scope:** `read`
- **Params:** none

```bash
curl -sS https://vcm.example.com/api/certificates \
  -H "Authorization: Bearer vcm_EXAMPLEtokenREDACTED"
```

```json
{
  "certificates": [
    {
      "id": 42,
      "serial": "1A2B3C",
      "subject_dn": "CN=branch-01.vpn.example.com",
      "san": "DNS:branch-01.vpn.example.com",
      "status": "active",
      "managed": true,
      "source": "issued",
      "ca_id": 3,
      "site_id": 12,
      "expiry_status": "ok",
      "days_until_expiry": 210,
      "is_superseded": false,
      "not_before": "2026-01-15T00:00:00+00:00",
      "not_after": "2027-01-15T00:00:00+00:00"
    }
  ]
}
```

`status` is `active` | `revoked` | `expired`; `expiry_status` is
`ok` | `warning` | `critical` | `expired` (thresholds: ≤30 days critical,
≤90 days warning). `source` is `issued` or `imported`; `managed` is `true` for
certs this instance can renew/revoke.

### GET /api/pki/tree

The full PKI hierarchy (CAs and their relationships) as public data.

- **Scope:** `read`
- **Query params:**
  - `include_pem` (bool, default `false`) — when `true`, include the CA
    **certificate** PEM (public) for each node. **Private keys are never
    included**, with or without this flag.

```bash
curl -sS "https://vcm.example.com/api/pki/tree?include_pem=false" \
  -H "Authorization: Bearer vcm_EXAMPLEtokenREDACTED"
```

```json
{
  "hierarchy": [
    {
      "id": 1,
      "name": "Example Root CA",
      "ca_type": "root",
      "subject_dn": "CN=Example Root CA",
      "children": [
        {
          "id": 2,
          "name": "Example Issuing CA",
          "ca_type": "issuing",
          "subject_dn": "CN=Example Issuing CA",
          "children": []
        }
      ]
    }
  ]
}
```

The exact per-node fields come from `ca_ops.build_hierarchy(...)`
(`app/pki/ca.py`); the top-level key is always `hierarchy`.

### GET /api/audit

Recent audit-log entries. **Admin-scoped** — this is privileged operational
data (it records users, actions, details and client IPs).

- **Scope:** `admin`
- **Query params:**
  - `limit` (int, default `100`) — clamped to the range **1–500**.

```bash
curl -sS "https://vcm.example.com/api/audit?limit=50" \
  -H "Authorization: Bearer vcm_ADMINtokenREDACTED"
```

```json
{
  "entries": [
    {
      "id": 9021,
      "ts": "2026-07-06T09:15:41+00:00",
      "username": "ci-bot",
      "action": "api.call",
      "detail": "token=vcm_ab12cd34 GET /api/certificates",
      "ip": "203.0.113.10"
    }
  ]
}
```

Entries are newest-first. A `read` or `write` token calling this endpoint gets a
`403` insufficient-scope error.

### POST /api/tokens/{token_id}/revoke

Revoke one of the **caller's own** API tokens. This is self-service so automation
can rotate its credentials without a browser session.

- **Scope:** `write`
- **Path params:** `token_id` (int) — must belong to the calling token's owner.
- **Body:** none
- **Errors:** `404 "Token not found"` if the id doesn't exist **or** is owned by
  a different user (you cannot revoke someone else's token, and the not-found
  response deliberately doesn't distinguish the two).

Revoking an already-revoked token is idempotent — it still returns `200` with
`revoked: true`. A token may revoke itself.

```bash
curl -sS -X POST https://vcm.example.com/api/tokens/7/revoke \
  -H "Authorization: Bearer vcm_WRITEtokenREDACTED"
```

```json
{
  "revoked": true,
  "token": {
    "id": 7,
    "name": "ci-automation",
    "prefix": "vcm_ab12cd34",
    "scope": "write",
    "status": "revoked",
    "created_at": "2026-07-01T14:22:05+00:00",
    "last_used_at": "2026-07-06T09:15:41+00:00",
    "expires_at": null,
    "revoked": true
  }
}
```

A successful revoke is audited as `apitoken.revoke`.

---

## Audit logging

**Every authenticated API call is audit-logged.** On successful authentication,
`api_principal` records an `api.call` entry attributed to the token's owner, with
detail `token=<prefix> <METHOD> <path>` and the resolved client IP — for
example `token=vcm_ab12cd34 GET /api/certificates`. This happens for *all* `/api`
endpoints, before the handler runs, so the audit log is a complete record of API
activity. Token lifecycle events are logged too: `apitoken.create` and
`apitoken.revoke` (whether revoked via the UI or via
`POST /api/tokens/{id}/revoke`).

Each authenticated call also updates the token's **`last_used_at`** timestamp
(visible in `whoami` and in the profile UI), so you can spot stale or unused
tokens.

---

## Security notes

- **Plaintext shown once.** A token's plaintext is displayed a single time at
  creation and never again. If you lose it, revoke and re-create.
- **Hash-only storage.** Only the SHA-256 digest is stored (`token_hash`), plus a
  non-secret 12-char `prefix` for display. The secret cannot be recovered from
  the database.
- **Private keys are never exposed.** No API endpoint returns a CA or appliance
  **private key**. `pki/tree` (even with `include_pem=true`) and
  `certificates` return public certificate metadata / PEM only; private keys stay
  KEK-encrypted at rest and are never serialised by any route.
- **Scope is least-privilege.** Prefer `read` tokens for monitoring/inventory;
  use `write` only where credential rotation is needed and `admin` only for the
  audit log. The role→scope cap prevents privilege escalation at creation time.
- **IP allowlist still applies.** Tokens don't bypass the source-IP allowlist
  (see [the caveat](#the-ip-allowlist-caveat)).
- **Expiry & revocation.** Set an expiry (`expires_days`) for short-lived
  automation. Revoke immediately if a token is exposed — revocation and expiry
  are both enforced at authentication time (JSON `401`). Disabling the owning
  user also invalidates all their tokens (`401 "Token owner is inactive"`).
- **Bearer bypasses cookies/MFA by design.** The token *is* the credential; it
  does not carry a session or MFA state. Treat it like a password: transmit only
  over TLS, store it in a secret manager, and scope it narrowly.
