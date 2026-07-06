from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import ApiToken, TokenScope, User, UserSession, WebAuthnCredential, utcnow
from ..security import apitokens, mfa
from ..security.deps import audit, current_user
from ..security.passwords import hash_password, verify_password
from ..templates_env import render

router = APIRouter(prefix="/profile", tags=["profile"])


@router.get("")
def profile_home(request: Request, db: Session = Depends(get_db),
                 user: User = Depends(current_user)):
    return _render(request, db, user)


@router.post("/contact")
def update_contact(request: Request, first_name: str = Form(""), last_name: str = Form(""),
                   email: str = Form(""), phone: str = Form(""),
                   db: Session = Depends(get_db), user: User = Depends(current_user)):
    user.first_name = first_name or None
    user.last_name = last_name or None
    user.email = email or None
    user.phone = phone or None
    audit(db, request, "profile.contact_update", user=user)
    return _ok(request, db, user, "Contact details updated")


@router.post("/password")
def change_password(request: Request, current: str = Form(...), new: str = Form(...),
                    confirm: str = Form(...), db: Session = Depends(get_db),
                    user: User = Depends(current_user)):
    if not verify_password(user.password_hash, current):
        return _err(request, db, user, "Current password is incorrect")
    if new != confirm:
        return _err(request, db, user, "New passwords do not match")
    if len(new) < 8:
        return _err(request, db, user, "New password must be at least 8 characters")
    user.password_hash = hash_password(new)
    audit(db, request, "profile.password_change", user=user)
    return _ok(request, db, user, "Password updated")


@router.post("/passkey/{cred_id}/rename")
def rename_passkey(cred_id: int, request: Request, name: str = Form(...),
                   db: Session = Depends(get_db), user: User = Depends(current_user)):
    cred = db.get(WebAuthnCredential, cred_id)
    if not cred or cred.user_id != user.id:
        raise HTTPException(404, "Not found")
    cred.name = name[:64]
    audit(db, request, "profile.passkey_rename", name, user=user)
    return RedirectResponse("/profile", status_code=303)


@router.post("/passkey/{cred_id}/delete")
def delete_passkey(cred_id: int, request: Request, db: Session = Depends(get_db),
                   user: User = Depends(current_user)):
    cred = db.get(WebAuthnCredential, cred_id)
    if not cred or cred.user_id != user.id:
        raise HTTPException(404, "Not found")
    # Don't let a user strip their last remaining MFA factor.
    if not user.totp_confirmed and len(user.credentials) <= 1:
        return _err(request, db, user, "Cannot remove your only MFA factor")
    db.delete(cred)
    audit(db, request, "profile.passkey_delete", cred.name, user=user)
    return RedirectResponse("/profile", status_code=303)


@router.post("/totp/reset")
def reset_totp(request: Request, db: Session = Depends(get_db),
               user: User = Depends(current_user)):
    if not user.credentials:
        return _err(request, db, user, "Add a passkey before removing TOTP")
    user.totp_secret_enc = None
    user.totp_confirmed = False
    audit(db, request, "profile.totp_reset", user=user)
    return RedirectResponse("/profile", status_code=303)


@router.post("/sessions/revoke-others")
def revoke_others(request: Request, db: Session = Depends(get_db),
                  user: User = Depends(current_user)):
    keep = request.state.session.id
    for s in db.execute(select(UserSession).where(UserSession.user_id == user.id)).scalars():
        if s.id != keep:
            db.delete(s)
    audit(db, request, "profile.revoke_sessions", user=user)
    return RedirectResponse("/profile", status_code=303)


@router.post("/tokens/create")
def create_token(request: Request, name: str = Form(...), scope: str = Form("read"),
                 expires_days: str = Form(""),
                 db: Session = Depends(get_db), user: User = Depends(current_user)):
    label = name.strip()[:64]
    if not label:
        return _err(request, db, user, "Give the token a name")
    try:
        wanted = TokenScope(scope)
    except ValueError:
        return _err(request, db, user, "Unknown scope")
    if wanted not in apitokens.allowed_scopes_for(user):
        return _err(request, db, user,
                    f"Your role cannot mint a '{wanted.value}' token")
    expires_at = None
    if expires_days.strip():
        try:
            days = int(expires_days)
        except ValueError:
            return _err(request, db, user, "Expiry must be a number of days")
        if days > 0:
            expires_at = utcnow() + timedelta(days=days)

    plaintext = apitokens.generate_token()
    tok = ApiToken(user_id=user.id, name=label, scope=wanted,
                   token_hash=apitokens.hash_token(plaintext),
                   prefix=apitokens.token_prefix(plaintext), expires_at=expires_at)
    db.add(tok)
    # Never log the plaintext — only the non-secret prefix/label.
    audit(db, request, "apitoken.create", f"{label} ({wanted.value}, {tok.prefix})", user=user)
    return _render(request, db, user, new_token=plaintext,
                   notice=f"Token '{label}' created — copy it now; it won't be shown again.")


@router.post("/tokens/{token_id}/revoke")
def revoke_token(token_id: int, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(current_user)):
    tok = db.get(ApiToken, token_id)
    if not tok or tok.user_id != user.id:
        raise HTTPException(404, "Not found")
    if not tok.revoked:
        tok.revoked = True
        audit(db, request, "apitoken.revoke", f"{tok.name} ({tok.prefix})", user=user)
    return RedirectResponse("/profile", status_code=303)


def _render(request, db, user, **extra):
    sessions = db.execute(
        select(UserSession).where(UserSession.user_id == user.id)
        .order_by(UserSession.created_at.desc())
    ).scalars().all()
    tokens = db.execute(
        select(ApiToken).where(ApiToken.user_id == user.id)
        .order_by(ApiToken.id.desc())
    ).scalars().all()
    return render(request, "profile.html", passkeys=user.credentials, sessions=sessions,
                  current_sid=request.state.session.id, api_tokens=tokens,
                  token_scopes=apitokens.allowed_scopes_for(user), **extra)


def _err(request, db, user, msg):
    return _render(request, db, user, error=msg)


def _ok(request, db, user, msg):
    return _render(request, db, user, notice=msg)
