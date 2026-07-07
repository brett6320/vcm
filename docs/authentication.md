# Authentication, MFA, RBAC & IP allowlist

Source: `app/routers/auth.py`, `app/routers/profile.py`, `app/security/*`.

## The login state machine

`POST /login` (`app/routers/auth.py`) verifies the username/password with
Argon2id (`app/security/passwords.py`). A session is created immediately (with
`mfa_ok` set to `True` only when the user has **no** MFA factor yet), and the
originally-requested `next` page is remembered on the session. The redirect
target is then chosen:

1. **`must_change_password`** → `/account/first-password`. The forced-change form
   requires the current password, a new password of ≥ 8 chars that differs from
   the old one, and confirmation. Until it's cleared, `current_user` redirects
   every protected page here.
2. Otherwise, if the user **has MFA** (`totp_confirmed` or ≥ 1 passkey) → `/mfa`.
3. Otherwise, in **prod** → `/mfa/enroll` (forced enrollment); in **dev** →
   straight to the remembered `next` (or the dashboard).

`current_user` (`app/security/deps.py`) re-checks this on every authenticated
request, so the gates can't be skipped by navigating directly.

### Safe redirects

`safe_next()` only accepts same-site absolute paths — anything starting with
`//`, containing `://`, or not starting with `/` is dropped, preventing open
redirects. Only safe `GET` targets are remembered as `?next=`.

## TOTP

`app/security/mfa.py` wraps `pyotp`:

- `new_totp_secret()` generates a base32 secret; it is stored **AES-256-GCM
  encrypted** (`totp_secret_enc`) via the KEK and decrypted transiently to verify.
- Enrollment (`GET /mfa/enroll`) shows a QR code (rendered as an inline SVG data
  URI, so Pillow is not required) plus the secret text; `POST /mfa/enroll/totp`
  confirms a code and sets `totp_confirmed`.
- Verification (`POST /mfa/totp`) allows a ±1 step window.

## WebAuthn passkeys

Wraps the `webauthn` package. Registration and authentication each mint a
short-lived challenge stored in `webauthn_challenges`:

- **Enroll**: `POST /mfa/enroll/passkey/options` → browser creates a credential →
  `POST /mfa/enroll/passkey/verify` stores the credential (id, public key, sign
  count, optional name). Resident key and user verification are both *preferred*.
- **Authenticate**: `POST /mfa/passkey/options` → browser signs → `POST
  /mfa/passkey/verify` checks the assertion against the stored public key and
  updates the sign count. On success it returns a JSON `redirect` to the
  remembered next page.

On the **MFA step** (`mfa.html`), when the user has a passkey enrolled the page
**auto-attempts the passkey assertion** on load (a hidden `#passkey-auto` marker
drives `webauthn.js`, showing *"Waiting for your passkey…"*), with a **Use
passkey** button to retry and the TOTP form still available as a fallback.

A user may register several passkeys (`webauthn_credentials` is one-to-many).
The passkey endpoints speak JSON (see `_JSON_PREFIXES` in `app/main.py`).

## Managing your own account (`/profile`)

- Update contact details (name, email, phone).
- Change password (current + new ≥ 8 + confirm).
- Rename or delete passkeys — **but not your last remaining MFA factor** (if you
  have no TOTP and only one passkey, deletion is refused).
- Reset TOTP — only allowed if you still have a passkey.
- View active sessions and **revoke all others** (keeps the current one).

## Admin MFA reset

An admin can reset another user's MFA (`POST /admin/users/{id}/reset-mfa`), which
clears the TOTP secret and deletes all their passkeys; the user is forced to
re-enroll on next login (prod).

## RBAC

Two roles (`app/models.py` `Role`): `operator` and `admin`. `require_admin`
(`app/security/deps.py`) gates admin-only routes (user management, IP allowlist,
defaults, backups, audit log, and all delete operations). Safeguards in
`app/routers/admin.py`:

- The **last active admin** cannot be demoted (`.../role`), and cannot be deleted.
- You cannot delete your own account, nor toggle-disable yourself via the toggle
  route (self is skipped).

## Source-IP allowlist

`app/security/ipfilter.py` + `app/security/deps.py`:

- `client_ip()` returns the socket peer unless the peer is a **trusted proxy**
  (`VCM_TRUSTED_PROXIES`), in which case it reads the first configured real-IP
  header (`VCM_REAL_IP_HEADERS`). This prevents header spoofing from untrusted
  peers.
- `enforce_ip()` is a dependency on the login/auth routes and (transitively via
  `current_user`) on every authenticated route. A blocked IP gets `403 Source IP
  … not allowed`.
- `ip_allowed()`: if enforcement is off, always allow; with an empty allowlist,
  allow **loopback only** (fail-safe); otherwise match against enabled
  `ip_allowlist` CIDRs.

Admins manage entries under **Admin → Source-IP allowlist**
(`POST /admin/ip`, `POST /admin/ip/{id}/delete`); CIDRs are validated with
`ipaddress.ip_network(strict=False)`.

## Sessions

Server-side (`app/security/sessions.py`): a random `token_urlsafe(32)` id, a TTL
from `VCM_SESSION_TTL_MINUTES`, an `mfa_ok` flag, the client IP, and the
remembered `next_url`. Expired sessions are deleted on read. A restore operation
clears the entire session table, forcing everyone to re-authenticate.

## Audit log & tamper-evident hash chain

Every meaningful action is recorded in `audit_log` (user, action, detail,
resolved client IP) via `audit()` in `app/security/deps.py`. Each row also carries
a **SHA-256 hash chain** (`app/security/audit_chain.py`): `entry_hash =
sha256(prev_hash + canonical(ts, username, action, detail, ip))`, where
`prev_hash` links to the previous row's `entry_hash` (the first row seeds from a
zero genesis). Editing, deleting, or reordering any existing entry breaks the
chain and is pinpointed to the first bad row.

Admins verify the chain from **Admin → Audit log**, which shows an overall
**valid/broken** summary plus a per-line badge (each row's `entry_hash` is
recomputed and its `prev_hash` link checked independently). The nullable hash
columns are added by the additive startup schema sync and a **backfill** populates
historical rows so the chain is continuous. The same check is exposed to
automation at `GET /api/audit/verify` (admin scope) — see
[`api.md`](api.md#get-apiauditverify).

> **Caveat.** The chain detects casual tampering but does **not** stop an attacker
> with full DB write access, who could recompute the whole chain. Stronger
> integrity requires anchoring the head hash to an external append-only store
> (tracked as a follow-up).
</content>
