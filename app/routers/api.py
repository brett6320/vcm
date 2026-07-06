"""JSON REST surface under /api/, authenticated with API bearer tokens.

Read is the priority; scope is enforced per-endpoint (read < write < admin).
Never exposes CA/leaf private keys. Auth failures are JSON 401/403 (see the
StarletteHTTPException handler in app.main, which returns JSON for /api paths).
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import (
    ApiToken, AuditLog, Certificate, Site, TokenScope, VpnConnection,
)
from ..pki import ca as ca_ops
from ..security import apitokens
from ..security.deps import audit
from ..srx.model import VpnProfile, all_warnings

router = APIRouter(prefix="/api", tags=["api"])

# Scope-gated dependencies.
_read = Depends(apitokens.require_scope(TokenScope.read))
_write = Depends(apitokens.require_scope(TokenScope.write))
_admin = Depends(apitokens.require_scope(TokenScope.admin))


def _iso(dt) -> str | None:
    return dt.isoformat() if dt else None


def _token_public(t: ApiToken) -> dict:
    return {"id": t.id, "name": t.name, "prefix": t.prefix, "scope": t.scope.value,
            "status": t.status, "created_at": _iso(t.created_at),
            "last_used_at": _iso(t.last_used_at), "expires_at": _iso(t.expires_at),
            "revoked": t.revoked}


def _conn_public(c: VpnConnection) -> dict:
    profile = VpnProfile.from_dict(json.loads(c.params_json))
    return {"id": c.id, "name": c.name, "source": c.source,
            "needs_review": c.needs_review, "review_note": c.review_note,
            "peer_connection_id": c.peer_connection_id,
            "params": profile.to_dict(),
            "warnings": all_warnings(profile),
            "generated_config": c.generated_config}


def _cert_public(c: Certificate) -> dict:
    return {"id": c.id, "serial": c.serial, "subject_dn": c.subject_dn, "san": c.san,
            "status": c.status.value, "managed": c.managed, "source": c.source,
            "ca_id": c.ca_id, "site_id": c.site_id,
            "expiry_status": c.expiry_status, "days_until_expiry": c.days_until_expiry,
            "is_superseded": c.is_superseded,
            "not_before": _iso(c.not_before), "not_after": _iso(c.not_after)}


@router.get("/whoami")
def whoami(token: ApiToken = _read):
    """Identify the calling token and its owner."""
    return {"user": token.user.username, "role": token.user.role.value,
            "token": _token_public(token)}


@router.get("/sites")
def list_sites(db: Session = Depends(get_db), token: ApiToken = _read):
    rows = db.execute(select(Site).order_by(Site.id)).scalars().all()
    return {"sites": [
        {"id": s.id, "name": s.name, "vendor": s.vendor.value, "model": s.model,
         "source": s.source, "connection_count": len(s.connections),
         "created_at": _iso(s.created_at), "updated_at": _iso(s.updated_at)}
        for s in rows]}


@router.get("/sites/{site_id}")
def site_detail(site_id: int, db: Session = Depends(get_db), token: ApiToken = _read):
    """A site's connections, generated config, and per-connection warnings."""
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(404, "Site not found")
    return {"id": site.id, "name": site.name, "vendor": site.vendor.value,
            "model": site.model, "source": site.source,
            "connections": [_conn_public(c) for c in site.connections]}


@router.get("/certificates")
def list_certificates(db: Session = Depends(get_db), token: ApiToken = _read):
    """All tracked certificates with expiry status. Never includes private keys."""
    rows = db.execute(select(Certificate).order_by(Certificate.id.desc())).scalars().all()
    return {"certificates": [_cert_public(c) for c in rows]}


@router.get("/pki/tree")
def pki_tree(include_pem: bool = False, db: Session = Depends(get_db),
             token: ApiToken = _read):
    """The full PKI hierarchy (public data only — never CA private keys)."""
    return {"hierarchy": ca_ops.build_hierarchy(db, include_pem=include_pem)}


@router.get("/audit")
def list_audit(limit: int = 100, db: Session = Depends(get_db), token: ApiToken = _admin):
    """Recent audit-log entries — admin-scoped (privileged operational data)."""
    limit = max(1, min(limit, 500))
    rows = db.execute(
        select(AuditLog).order_by(AuditLog.ts.desc()).limit(limit)).scalars().all()
    return {"entries": [
        {"id": r.id, "ts": _iso(r.ts), "username": r.username, "action": r.action,
         "detail": r.detail, "ip": r.ip} for r in rows]}


@router.post("/tokens/{token_id}/revoke")
def revoke_own_token(token_id: int, request: Request, db: Session = Depends(get_db),
                     token: ApiToken = _write):
    """Revoke one of the caller's own API tokens (write scope). Self-service so
    automation can rotate its credentials without a browser session."""
    target = db.get(ApiToken, token_id)
    if not target or target.user_id != token.user_id:
        raise HTTPException(404, "Token not found")
    if target.revoked:
        return {"revoked": True, "token": _token_public(target)}
    target.revoked = True
    audit(db, request, "apitoken.revoke", f"api:{target.name} ({target.prefix})",
          user=token.user)
    return {"revoked": True, "token": _token_public(target)}
