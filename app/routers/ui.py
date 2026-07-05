from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import CertAuthority, Certificate, Site, User
from ..security.deps import current_user
from ..templates_env import render

router = APIRouter(tags=["ui"])


@router.get("/")
def dashboard(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    stats = {
        "cas": db.scalar(select(func.count()).select_from(CertAuthority)),
        "certs": db.scalar(select(func.count()).select_from(Certificate)),
        "sites": db.scalar(select(func.count()).select_from(Site)),
    }
    recent_sites = db.execute(select(Site).order_by(Site.id.desc()).limit(5)).scalars().all()
    return render(request, "dashboard.html", stats=stats, recent_sites=recent_sites)
