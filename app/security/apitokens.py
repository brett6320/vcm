"""API token issuance, hashing, and bearer authentication.

Design / security notes
------------------------
* Tokens are cryptographically random (`secrets.token_urlsafe(32)`, ~256 bits of
  entropy) prefixed with ``vcm_`` for recognisability.
* Only the SHA-256 hex digest is stored — never the plaintext. Because the secret
  is high-entropy, a fast one-way hash is sufficient; a slow KDF (argon2, used for
  low-entropy passwords) is unnecessary here, and constant-time lookup by digest
  keeps auth cheap.
* Bearer auth deliberately bypasses session cookies and MFA (the token *is* the
  credential) but still enforces the source-IP allowlist via ``enforce_ip`` — a
  token is a credential, not a network-ACL bypass.
* Auth failures raise ``HTTPException`` (JSON 401/403), never the browser
  ``AuthRedirect`` to /login.
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import ApiToken, Role, TokenScope, User, ensure_aware, utcnow
from .deps import enforce_ip

TOKEN_PREFIX = "vcm_"

# Privilege ordering — a token satisfies a requirement if its rank is >= the need.
_SCOPE_RANK = {TokenScope.read: 0, TokenScope.write: 1, TokenScope.admin: 2}

# The highest scope a user may mint, capped by their UI role.
_MAX_SCOPE_FOR_ROLE = {Role.operator: TokenScope.write, Role.admin: TokenScope.admin}

_UNAUTH_HEADERS = {"WWW-Authenticate": "Bearer"}


def generate_token() -> str:
    """A fresh plaintext secret. Shown to the user once; only its hash is stored."""
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def token_prefix(token: str) -> str:
    """Non-secret identifier for display (scheme + a few leading chars)."""
    return token[:12]


def scope_satisfies(have: TokenScope, need: TokenScope) -> bool:
    return _SCOPE_RANK[have] >= _SCOPE_RANK[need]


def max_scope_for(user: User) -> TokenScope:
    return _MAX_SCOPE_FOR_ROLE.get(user.role, TokenScope.read)


def allowed_scopes_for(user: User) -> list[TokenScope]:
    cap = _SCOPE_RANK[max_scope_for(user)]
    return [s for s in TokenScope if _SCOPE_RANK[s] <= cap]


def _bearer_token(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    scheme, _, param = auth.partition(" ")
    if scheme.lower() != "bearer" or not param.strip():
        return None
    return param.strip()


def api_principal(request: Request, db: Session = Depends(get_db),
                  _ip: str = Depends(enforce_ip)) -> ApiToken:
    """Authenticate an ``Authorization: Bearer <token>`` request.

    Enforces the IP allowlist (via ``enforce_ip``), rejects missing/invalid/
    revoked/expired tokens and inactive owners with a JSON 401, records
    ``last_used_at``, and returns the authenticated ``ApiToken`` (with ``.user``).
    """
    token = _bearer_token(request)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            detail="Missing or malformed bearer token",
                            headers=_UNAUTH_HEADERS)
    row = db.execute(
        select(ApiToken).where(ApiToken.token_hash == hash_token(token))
    ).scalar_one_or_none()
    if row is None or row.revoked:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid or revoked token", headers=_UNAUTH_HEADERS)
    if row.expires_at is not None and ensure_aware(row.expires_at) < utcnow():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            detail="Token has expired", headers=_UNAUTH_HEADERS)
    user = db.get(User, row.user_id)
    if user is None or user.disabled:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            detail="Token owner is inactive", headers=_UNAUTH_HEADERS)
    row.last_used_at = utcnow()  # persisted by get_db's commit
    request.state.user = user
    request.state.api_token = row
    # Record every authenticated API call, attributed to the user + token.
    from .deps import audit
    audit(db, request, "api.call",
          f"token={row.prefix} {request.method} {request.url.path}", user=user)
    return row


def require_scope(scope: TokenScope) -> Callable[..., ApiToken]:
    """Dependency factory: require the presented token to carry at least ``scope``."""

    def _dep(token: ApiToken = Depends(api_principal)) -> ApiToken:
        if not scope_satisfies(token.scope, scope):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=(f"Token scope '{token.scope.value}' is insufficient; "
                        f"'{scope.value}' scope required"))
        return token

    return _dep
