from __future__ import annotations

import secrets
from datetime import timedelta

from sqlalchemy import delete
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import UserSession, User, utcnow


def create_session(db: Session, user: User, ip: str | None, mfa_ok: bool) -> UserSession:
    ttl = get_settings().session_ttl_minutes
    sess = UserSession(
        id=secrets.token_urlsafe(32),
        user_id=user.id,
        ip=ip,
        mfa_ok=mfa_ok,
        expires_at=utcnow() + timedelta(minutes=ttl),
    )
    db.add(sess)
    db.flush()
    return sess


def get_session(db: Session, sid: str | None) -> UserSession | None:
    if not sid:
        return None
    sess = db.get(UserSession, sid)
    if not sess:
        return None
    if sess.expires_at <= utcnow():
        db.delete(sess)
        return None
    return sess


def mark_mfa_ok(db: Session, sess: UserSession) -> None:
    sess.mfa_ok = True
    db.add(sess)


def destroy_session(db: Session, sid: str | None) -> None:
    if sid:
        db.execute(delete(UserSession).where(UserSession.id == sid))
