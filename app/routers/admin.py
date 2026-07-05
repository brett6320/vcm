from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AuditLog, IPAllowEntry, Role, User
from ..security.deps import audit, require_admin
from ..security.passwords import hash_password
from .. import notify as notify_mod
from ..srx import defaults as defaults_svc
from ..srx import proposals as proposals_mod
from ..srx.proposals import catalog
from ..templates_env import render

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("")
def admin_home(request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    users = db.execute(select(User).order_by(User.id)).scalars().all()
    ips = db.execute(select(IPAllowEntry).order_by(IPAllowEntry.id)).scalars().all()
    return render(request, "admin.html", users=users, ips=ips, roles=list(Role),
                  email_enabled=notify_mod.email_enabled(), sms_enabled=notify_mod.sms_enabled())


@router.post("/users")
def create_user(request: Request, username: str = Form(...), password: str = Form(...),
                role: str = Form("operator"), first_name: str = Form(""),
                last_name: str = Form(""), email: str = Form(""), phone: str = Form(""),
                notify: str = Form(""), db: Session = Depends(get_db),
                user: User = Depends(require_admin)):
    if db.execute(select(User).where(User.username == username)).scalar_one_or_none():
        return RedirectResponse("/admin", status_code=303)
    u = User(username=username, password_hash=hash_password(password), role=Role(role),
             first_name=first_name or None, last_name=last_name or None,
             email=email or None, phone=phone or None, must_change_password=True)
    db.add(u)
    audit(db, request, "admin.user_create", f"{username}/{role}", user=user)
    # Optionally notify the new user of their temporary credentials.
    if notify and email:
        ok, detail = notify_mod.send_email(
            email, "Your VCM account",
            f"An account '{username}' was created for you.\n\n"
            f"Temporary password: {password}\n\n"
            "You will be required to change it at first login.")
        audit(db, request, "admin.user_notify", f"{email}: {detail}", user=user)
    return RedirectResponse("/admin", status_code=303)


@router.post("/users/{uid}/toggle")
def toggle_user(uid: int, request: Request, db: Session = Depends(get_db),
                user: User = Depends(require_admin)):
    u = db.get(User, uid)
    if u and u.id != user.id:
        u.disabled = not u.disabled
        audit(db, request, "admin.user_toggle", f"{u.username}={u.disabled}", user=user)
    return RedirectResponse("/admin", status_code=303)


@router.post("/users/{uid}/reset-mfa")
def reset_mfa(uid: int, request: Request, db: Session = Depends(get_db),
              user: User = Depends(require_admin)):
    u = db.get(User, uid)
    if u:
        u.totp_secret_enc = None
        u.totp_confirmed = False
        for c in list(u.credentials):
            db.delete(c)
        audit(db, request, "admin.user_reset_mfa", u.username, user=user)
    return RedirectResponse(_back(uid), status_code=303)


def _back(uid: int) -> str:
    return f"/admin/users/{uid}"


def _admin_count(db: Session) -> int:
    return db.execute(
        select(func.count()).select_from(User).where(User.role == Role.admin,
                                                      User.disabled.is_(False))
    ).scalar_one()


@router.get("/users/{uid}")
def user_detail(uid: int, request: Request, db: Session = Depends(get_db),
                user: User = Depends(require_admin)):
    u = db.get(User, uid)
    if not u:
        raise HTTPException(404, "Not found")
    return render(request, "user.html", u=u, roles=list(Role), is_self=(u.id == user.id))


@router.post("/users/{uid}/role")
def set_role(uid: int, request: Request, role: str = Form(...), db: Session = Depends(get_db),
             user: User = Depends(require_admin)):
    u = db.get(User, uid)
    if not u:
        raise HTTPException(404, "Not found")
    # Don't allow removing the last active admin (including demoting yourself).
    if u.role == Role.admin and Role(role) != Role.admin and _admin_count(db) <= 1:
        return render(request, "user.html", u=u, roles=list(Role), is_self=(u.id == user.id),
                      error="Cannot demote the last remaining admin")
    u.role = Role(role)
    audit(db, request, "admin.user_role", f"{u.username}={role}", user=user)
    return RedirectResponse(_back(uid), status_code=303)


@router.post("/users/{uid}/password")
def admin_set_password(uid: int, request: Request, password: str = Form(...),
                       db: Session = Depends(get_db), user: User = Depends(require_admin)):
    u = db.get(User, uid)
    if not u:
        raise HTTPException(404, "Not found")
    if len(password) < 8:
        return render(request, "user.html", u=u, roles=list(Role), is_self=(u.id == user.id),
                      error="Password must be at least 8 characters")
    u.password_hash = hash_password(password)
    audit(db, request, "admin.user_password_reset", u.username, user=user)
    return render(request, "user.html", u=u, roles=list(Role), is_self=(u.id == user.id),
                  notice="Password reset")


@router.post("/users/{uid}/delete")
def delete_user(uid: int, request: Request, db: Session = Depends(get_db),
                user: User = Depends(require_admin)):
    u = db.get(User, uid)
    if not u:
        raise HTTPException(404, "Not found")
    if u.id == user.id:
        raise HTTPException(400, "You cannot delete your own account")
    if u.role == Role.admin and _admin_count(db) <= 1:
        raise HTTPException(400, "Cannot delete the last remaining admin")
    name = u.username
    db.delete(u)
    audit(db, request, "admin.user_delete", name, user=user)
    return RedirectResponse("/admin", status_code=303)


# ------------------------------------------------------------ IP allowlist --- #
@router.post("/ip")
def add_ip(request: Request, cidr: str = Form(...), description: str = Form(""),
           db: Session = Depends(get_db), user: User = Depends(require_admin)):
    import ipaddress

    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return RedirectResponse("/admin", status_code=303)
    db.add(IPAllowEntry(cidr=cidr, description=description))
    audit(db, request, "admin.ip_add", cidr, user=user)
    return RedirectResponse("/admin", status_code=303)


@router.post("/ip/{eid}/delete")
def del_ip(eid: int, request: Request, db: Session = Depends(get_db),
           user: User = Depends(require_admin)):
    e = db.get(IPAllowEntry, eid)
    if e:
        db.delete(e)
        audit(db, request, "admin.ip_del", e.cidr, user=user)
    return RedirectResponse("/admin", status_code=303)


# --------------------------------------------------------------- defaults --- #
@router.get("/defaults")
def defaults_form(request: Request, db: Session = Depends(get_db),
                  user: User = Depends(require_admin)):
    return render(request, "defaults.html", defaults=defaults_svc.get_defaults(db),
                  catalog=catalog(), opts=proposals_mod.options())


@router.post("/defaults")
def save_defaults(request: Request,
                  p1_enc: str = Form(...), p1_integ: str = Form(...), p1_dh: str = Form(...),
                  p1_ver: str = Form(...), p1_life: int = Form(28800), p1_auth: str = Form(...),
                  p2_enc: str = Form(...), p2_integ: str = Form(...), p2_pfs: str = Form(...),
                  p2_life: int = Form(3600),
                  db: Session = Depends(get_db), user: User = Depends(require_admin)):
    phase1 = {"ike_version": p1_ver, "encryption": p1_enc, "integrity": p1_integ,
              "dh_group": p1_dh, "lifetime_seconds": p1_life, "auth_method": p1_auth,
              "dpd_seconds": 10}
    phase2 = {"encryption": p2_enc, "integrity": p2_integ, "pfs_group": p2_pfs,
              "lifetime_seconds": p2_life, "protocol": "esp"}
    defaults_svc.set_defaults(db, phase1, phase2)
    audit(db, request, "admin.defaults_save", user=user)
    return RedirectResponse("/admin/defaults", status_code=303)


# ------------------------------------------------------------------ audit --- #
@router.get("/audit")
def audit_log(request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    rows = db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(200)).scalars().all()
    return render(request, "audit.html", rows=rows)
