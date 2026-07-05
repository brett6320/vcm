from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import User, WebAuthnChallenge, WebAuthnCredential
from ..security import mfa, sessions
from ..security.deps import audit, current_user, enforce_ip
from ..security.passwords import verify_password
from ..templates_env import render

router = APIRouter(tags=["auth"])
s = get_settings()


def _set_cookie(resp, sid: str):
    resp.set_cookie(s.session_cookie, sid, httponly=True, samesite="lax",
                    secure=s.cookie_secure, max_age=s.session_ttl_minutes * 60)


# ------------------------------------------------------------------ login --- #
@router.get("/login")
def login_form(request: Request, _ip: str = Depends(enforce_ip)):
    return render(request, "login.html")


@router.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...),
          db: Session = Depends(get_db), ip: str = Depends(enforce_ip)):
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if not user or user.disabled or not verify_password(user.password_hash, password):
        audit(db, request, "login.fail", f"user={username}")
        return render(request, "login.html", error="Invalid credentials")
    sess = sessions.create_session(db, user, ip, mfa_ok=not user.has_mfa)
    audit(db, request, "login.password_ok", f"user={username}", user=user)
    if user.must_change_password:
        target = "/account/first-password"  # forced change before MFA
    elif user.has_mfa:
        target = "/mfa"
    elif s.is_dev:
        target = "/"  # dev mode: skip forced enrollment
    else:
        target = "/mfa/enroll"
    resp = RedirectResponse(target, status_code=303)
    _set_cookie(resp, sess.id)
    return resp


@router.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    sessions.destroy_session(db, request.cookies.get(s.session_cookie))
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(s.session_cookie)
    return resp


# ---------------------------------------------- forced first-login change --- #
@router.get("/account/first-password")
def first_password_form(request: Request, db: Session = Depends(get_db),
                        _ip: str = Depends(enforce_ip)):
    sess, user = _partial_session(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not user.must_change_password:
        return RedirectResponse("/", status_code=303)
    return render(request, "first_password.html")


@router.post("/account/first-password")
def first_password_submit(request: Request, current: str = Form(...), new: str = Form(...),
                          confirm: str = Form(...), db: Session = Depends(get_db),
                          ip: str = Depends(enforce_ip)):
    from ..security.passwords import hash_password

    sess, user = _partial_session(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    err = None
    if not verify_password(user.password_hash, current):
        err = "Current password is incorrect"
    elif new != confirm:
        err = "New passwords do not match"
    elif len(new) < 8:
        err = "New password must be at least 8 characters"
    elif verify_password(user.password_hash, new):
        err = "New password must differ from the current one"
    if err:
        return render(request, "first_password.html", error=err)
    user.password_hash = hash_password(new)
    user.must_change_password = False
    audit(db, request, "account.first_password_set", user=user)
    # Continue to MFA enrollment (or app in dev).
    return RedirectResponse("/", status_code=303)


# --------------------------------------------------------------- MFA gate --- #
def _partial_session(request: Request, db: Session):
    sess = sessions.get_session(db, request.cookies.get(s.session_cookie))
    if not sess:
        return None, None
    return sess, db.get(User, sess.user_id)


@router.get("/mfa")
def mfa_gate(request: Request, db: Session = Depends(get_db), _ip: str = Depends(enforce_ip)):
    sess, user = _partial_session(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if sess.mfa_ok:
        return RedirectResponse("/", status_code=303)
    return render(request, "mfa.html", has_totp=user.totp_confirmed,
                  has_passkey=bool(user.credentials))


@router.post("/mfa/totp")
def mfa_totp(request: Request, code: str = Form(...), db: Session = Depends(get_db),
             ip: str = Depends(enforce_ip)):
    sess, user = _partial_session(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    secret = mfa.decrypt_totp_secret(user)
    if not secret or not mfa.verify_totp(secret, code):
        audit(db, request, "mfa.totp_fail", user=user)
        return render(request, "mfa.html", error="Invalid code", has_totp=True,
                      has_passkey=bool(user.credentials))
    sessions.mark_mfa_ok(db, sess)
    audit(db, request, "mfa.totp_ok", user=user)
    return RedirectResponse("/", status_code=303)


# ---------------------------------------------------- WebAuthn (passkey) --- #
@router.post("/mfa/passkey/options")
def passkey_auth_options(request: Request, db: Session = Depends(get_db),
                         _ip: str = Depends(enforce_ip)):
    sess, user = _partial_session(request, db)
    if not user:
        return JSONResponse({"error": "no session"}, status_code=401)
    cred_ids = [c.credential_id for c in user.credentials]
    opts = mfa.authentication_options(cred_ids)
    db.add(WebAuthnChallenge(user_id=user.id, kind="auth", challenge=opts.challenge))
    return JSONResponse(json.loads(mfa.options_to_json(opts)))


@router.post("/mfa/passkey/verify")
async def passkey_auth_verify(request: Request, db: Session = Depends(get_db),
                              _ip: str = Depends(enforce_ip)):
    sess, user = _partial_session(request, db)
    if not user:
        return JSONResponse({"error": "no session"}, status_code=401)
    body = await request.json()
    raw_id = mfa.base64url_to_bytes(body["rawId"])
    cred = db.execute(
        select(WebAuthnCredential).where(WebAuthnCredential.credential_id == raw_id)
    ).scalar_one_or_none()
    if not cred or cred.user_id != user.id:
        return JSONResponse({"error": "unknown credential"}, status_code=400)
    chal = db.execute(
        select(WebAuthnChallenge).where(WebAuthnChallenge.user_id == user.id,
                                        WebAuthnChallenge.kind == "auth")
        .order_by(WebAuthnChallenge.id.desc())
    ).scalars().first()
    if not chal:
        return JSONResponse({"error": "no challenge"}, status_code=400)
    try:
        res = mfa.verify_authentication(body, chal.challenge, cred.public_key, cred.sign_count)
    except Exception as e:  # noqa: BLE001
        audit(db, request, "mfa.passkey_fail", str(e), user=user)
        return JSONResponse({"error": "verification failed"}, status_code=400)
    cred.sign_count = res.new_sign_count
    db.delete(chal)
    sessions.mark_mfa_ok(db, sess)
    audit(db, request, "mfa.passkey_ok", user=user)
    return JSONResponse({"ok": True})


# ------------------------------------------------------- MFA enrollment --- #
@router.get("/mfa/enroll")
def enroll_form(request: Request, db: Session = Depends(get_db), _ip: str = Depends(enforce_ip)):
    sess, user = _partial_session(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    secret = mfa.decrypt_totp_secret(user)
    if not secret:
        secret = mfa.new_totp_secret()
        user.totp_secret_enc = mfa.encrypt_totp_secret(secret)
        db.add(user)
        db.flush()
    uri = mfa.totp_uri(user.username, secret)
    return render(request, "enroll.html", qr=mfa.totp_qr_data_uri(uri), secret=secret,
                  has_passkey=bool(user.credentials), totp_confirmed=user.totp_confirmed)


@router.post("/mfa/enroll/totp")
def enroll_totp_confirm(request: Request, code: str = Form(...), db: Session = Depends(get_db),
                        ip: str = Depends(enforce_ip)):
    sess, user = _partial_session(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    secret = mfa.decrypt_totp_secret(user)
    if not secret or not mfa.verify_totp(secret, code):
        uri = mfa.totp_uri(user.username, secret) if secret else ""
        return render(request, "enroll.html", error="Code did not verify",
                      qr=mfa.totp_qr_data_uri(uri) if uri else "", secret=secret or "",
                      has_passkey=bool(user.credentials), totp_confirmed=False)
    user.totp_confirmed = True
    sessions.mark_mfa_ok(db, sess)
    audit(db, request, "mfa.totp_enrolled", user=user)
    return RedirectResponse("/", status_code=303)


@router.post("/mfa/enroll/passkey/options")
def enroll_passkey_options(request: Request, db: Session = Depends(get_db),
                           _ip: str = Depends(enforce_ip)):
    sess, user = _partial_session(request, db)
    if not user:
        return JSONResponse({"error": "no session"}, status_code=401)
    opts = mfa.registration_options(user, [c.credential_id for c in user.credentials])
    db.add(WebAuthnChallenge(user_id=user.id, kind="register", challenge=opts.challenge))
    return JSONResponse(json.loads(mfa.options_to_json(opts)))


@router.post("/mfa/enroll/passkey/verify")
async def enroll_passkey_verify(request: Request, db: Session = Depends(get_db),
                                _ip: str = Depends(enforce_ip)):
    sess, user = _partial_session(request, db)
    if not user:
        return JSONResponse({"error": "no session"}, status_code=401)
    body = await request.json()
    chal = db.execute(
        select(WebAuthnChallenge).where(WebAuthnChallenge.user_id == user.id,
                                        WebAuthnChallenge.kind == "register")
        .order_by(WebAuthnChallenge.id.desc())
    ).scalars().first()
    if not chal:
        return JSONResponse({"error": "no challenge"}, status_code=400)
    try:
        res = mfa.verify_registration(body, chal.challenge)
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"error": f"registration failed: {e}"}, status_code=400)
    db.add(WebAuthnCredential(
        user_id=user.id, name=(body.get("name") or "passkey")[:64],
        credential_id=res.credential_id, public_key=res.credential_public_key,
        sign_count=res.sign_count,
    ))
    db.delete(chal)
    sessions.mark_mfa_ok(db, sess)
    audit(db, request, "mfa.passkey_enrolled", user=user)
    return JSONResponse({"ok": True})
