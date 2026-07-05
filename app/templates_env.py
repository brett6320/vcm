from __future__ import annotations

from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

from .config import get_settings

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def render(request: Request, name: str, **ctx):
    base = {"app_name": get_settings().app_name,
            "user": getattr(request.state, "user", None)}
    base.update(ctx)
    return templates.TemplateResponse(request, name, base)
