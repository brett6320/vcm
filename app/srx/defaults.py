"""App-wide default VPN parameters, editable in the UI and applied to new sites."""
from __future__ import annotations

import json
from dataclasses import asdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Defaults
from .model import Phase1, Phase2

_KEY = "vpn_defaults"

_FALLBACK = {"phase1": asdict(Phase1()), "phase2": asdict(Phase2())}


def get_defaults(db: Session) -> dict:
    row = db.execute(select(Defaults).where(Defaults.key == _KEY)).scalar_one_or_none()
    if not row:
        return json.loads(json.dumps(_FALLBACK))
    data = json.loads(row.value_json)
    # merge over fallback so new fields are always present
    merged = json.loads(json.dumps(_FALLBACK))
    merged["phase1"].update(data.get("phase1", {}))
    merged["phase2"].update(data.get("phase2", {}))
    return merged


def set_defaults(db: Session, phase1: dict, phase2: dict) -> None:
    row = db.execute(select(Defaults).where(Defaults.key == _KEY)).scalar_one_or_none()
    payload = json.dumps({"phase1": phase1, "phase2": phase2})
    if row:
        row.value_json = payload
    else:
        db.add(Defaults(key=_KEY, value_json=payload))


def apply_defaults(db: Session, p1: Phase1 | None = None, p2: Phase2 | None = None):
    d = get_defaults(db)
    return Phase1(**d["phase1"]), Phase2(**d["phase2"])
