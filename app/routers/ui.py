from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import (
    CertAuthority, CertStatus, Certificate, Site, User, VpnConnection, classify_expiry,
)
from ..security.deps import current_user
from ..templates_env import render

router = APIRouter(tags=["ui"])


@router.get("/")
def dashboard(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    stats = {
        "cas": db.scalar(select(func.count()).select_from(CertAuthority)),
        "certs": db.scalar(select(func.count()).select_from(Certificate)),
        "sites": db.scalar(select(func.count()).select_from(Site)),
        "connections": db.scalar(select(func.count()).select_from(VpnConnection)),
    }
    # Expiry tracking across ALL certs (managed + observed), excluding revoked
    # and superseded ones, since those need no renewal attention.
    tracked = db.execute(
        select(Certificate).where(Certificate.replaced_by_id.is_(None),
                                  Certificate.status != CertStatus.revoked)
    ).scalars().all()
    buckets = {"expired": 0, "critical": 0, "warning": 0, "ok": 0}
    expiring = []
    for c in tracked:
        sev = classify_expiry(c.not_after)
        buckets[sev] += 1
        if sev != "ok":
            expiring.append(c)
    stats.update(expiry_expired=buckets["expired"], expiry_critical=buckets["critical"],
                 expiry_warning=buckets["warning"])
    expiring.sort(key=lambda c: c.not_after)  # soonest first
    expiring = expiring[:8]
    recent_sites = db.execute(select(Site).order_by(Site.id.desc()).limit(5)).scalars().all()
    return render(request, "dashboard.html", stats=stats, recent_sites=recent_sites,
                  expiring=expiring)
