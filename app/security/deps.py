"""FastAPI dependencies: current user, MFA gate, role gate, audit helper."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import AuditLog, IPAllowEntry, Role, User
from . import ipfilter, sessions


class AuthRedirect(Exception):
    def __init__(self, location: str):
        self.location = location


def audit(db: Session, request: Request, action: str, detail: str | None = None,
          user: User | None = None) -> None:
    db.add(AuditLog(
        user_id=user.id if user else None,
        username=user.username if user else None,
        action=action,
        detail=detail,
        ip=ipfilter.client_ip(request),
    ))


def _allow_cidrs(db: Session) -> list[str]:
    rows = db.execute(select(IPAllowEntry).where(IPAllowEntry.enabled.is_(True))).scalars()
    return [r.cidr for r in rows]


def enforce_ip(request: Request, db: Session = Depends(get_db)) -> str:
    ip = ipfilter.client_ip(request)
    if not ipfilter.ip_allowed(ip, _allow_cidrs(db)):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=f"Source IP {ip} not allowed")
    return ip


def _session_and_user(request: Request, db: Session):
    sid = request.cookies.get(get_settings().session_cookie)
    sess = sessions.get_session(db, sid)
    if not sess:
        return None, None
    user = db.get(User, sess.user_id)
    if not user or user.disabled:
        return None, None
    return sess, user


def current_user(request: Request, db: Session = Depends(get_db),
                 _ip: str = Depends(enforce_ip)) -> User:
    """Require a fully authenticated (MFA-passed) session. Redirects to login/UI."""
    sess, user = _session_and_user(request, db)
    if not user:
        raise AuthRedirect("/login" + _next_query(request))
    if user.must_change_password:
        # Force a password change before anything else, including MFA enrollment.
        raise AuthRedirect("/account/first-password")
    if user.has_mfa and not sess.mfa_ok:
        raise AuthRedirect("/mfa")
    if not user.has_mfa and not get_settings().is_dev:
        # Force enrollment before any privileged action (prod only).
        raise AuthRedirect("/mfa/enroll")
    request.state.user = user
    request.state.session = sess
    return user


def safe_next(url: str | None) -> str | None:
    """Only allow same-site absolute paths (avoid open redirects)."""
    if not url or not url.startswith("/") or url.startswith("//") or "://" in url:
        return None
    return url


def _next_query(request: Request) -> str:
    import urllib.parse

    # Only remember safe GET targets for the redirect-back.
    if request.method != "GET":
        return ""
    target = request.url.path
    if request.url.query:
        target += "?" + request.url.query
    if not safe_next(target) or target in ("/", "/login"):
        return ""
    return "?next=" + urllib.parse.quote(target, safe="")


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != Role.admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Admin privilege required")
    return user
