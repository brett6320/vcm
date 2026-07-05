from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import get_settings
from .db import init_db, SessionLocal
from .models import Role, User
from .security.deps import AuthRedirect
from .security.passwords import hash_password
from .routers import admin, auth, pki, profile, sites, ui
from .templates_env import render

# Path prefixes that speak JSON (fetch/XHR clients) — errors stay JSON there.
_JSON_PREFIXES = ("/mfa/passkey", "/mfa/enroll/passkey", "/healthz")


def _wants_json(request: Request) -> bool:
    if request.url.path.startswith(_JSON_PREFIXES):
        return True
    accept = request.headers.get("accept", "")
    # Browsers send "text/html"; fetch() defaults to "*/*".
    return "application/json" in accept or "text/html" not in accept

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    _bootstrap_admin()
    _seed_allowlist()
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)

_static = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=_static), name="static")

app.include_router(ui.router)
app.include_router(auth.router)
app.include_router(pki.router)
app.include_router(sites.router)
app.include_router(profile.router)
app.include_router(admin.router)


@app.exception_handler(AuthRedirect)
async def _auth_redirect(request: Request, exc: AuthRedirect):
    return RedirectResponse(exc.location, status_code=303)


_STATUS_TEXT = {403: "Forbidden", 404: "Not found", 405: "Method not allowed",
                500: "Internal server error"}


@app.exception_handler(StarletteHTTPException)
async def _http_exc(request: Request, exc: StarletteHTTPException):
    if _wants_json(request):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    detail = exc.detail if isinstance(exc.detail, str) else _STATUS_TEXT.get(
        exc.status_code, "Error")
    resp = render(request, "error.html", status=exc.status_code, detail=detail)
    resp.status_code = exc.status_code
    return resp


def _bootstrap_admin() -> None:
    """Create an initial admin from env on first run (VCM_BOOTSTRAP_ADMIN=user:pass)."""
    import os

    spec = os.environ.get("VCM_BOOTSTRAP_ADMIN")
    if not spec or ":" not in spec:
        return
    username, password = spec.split(":", 1)
    with SessionLocal() as db:
        exists = db.query(User).filter(User.username == username).first()
        if exists:
            return
        db.add(User(username=username, password_hash=hash_password(password), role=Role.admin))
        db.commit()


def _seed_allowlist() -> None:
    """Seed VCM_INITIAL_ALLOW CIDRs when the allowlist is empty (first run only)."""
    cidrs = settings.initial_allow_list
    if not cidrs:
        return
    from .models import IPAllowEntry

    with SessionLocal() as db:
        if db.query(IPAllowEntry).first():
            return  # already configured; don't re-seed
        for cidr in cidrs:
            db.add(IPAllowEntry(cidr=cidr, description="seeded from VCM_INITIAL_ALLOW"))
        db.commit()


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
