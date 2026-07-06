"""Encrypted, versioned backup/restore of application state.

A backup is a JSON dump of all data tables (except ephemeral/self tables),
encrypted with AES-256-GCM using the app KEK — so a backup is only restorable on
an instance holding the same VCM_KEK_B64. Backups are versioned and never
overwrite each other; restore takes a safety snapshot first.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .db import Base
from .models import Backup, utcnow
from .security import crypto

# Not included in a snapshot: self, ephemeral auth state.
_EXCLUDE_DUMP = {"backups", "sessions", "webauthn_challenges"}
# Wiped on restore (everything except the backup history itself).
_KEEP_ON_RESTORE = {"backups"}


def _enc(v):
    if isinstance(v, bytes):
        return {"__b64__": base64.b64encode(v).decode()}
    if isinstance(v, datetime):
        return {"__dt__": v.isoformat()}
    return v


def _dec(v):
    if isinstance(v, dict):
        if "__b64__" in v:
            return base64.b64decode(v["__b64__"])
        if "__dt__" in v:
            return datetime.fromisoformat(v["__dt__"])
    return v


def dump_state(db: Session) -> dict:
    out: dict[str, list] = {}
    for table in Base.metadata.sorted_tables:
        if table.name in _EXCLUDE_DUMP:
            continue
        rows = db.execute(table.select()).mappings().all()
        out[table.name] = [{k: _enc(v) for k, v in dict(r).items()} for r in rows]
    return out


def create_backup(db: Session, note: str = "", by: str | None = None) -> Backup:
    raw = json.dumps(dump_state(db)).encode()
    version = (db.execute(select(func.max(Backup.version))).scalar() or 0) + 1
    b = Backup(version=version, note=note or None, created_by=by, size=len(raw),
               sha256=hashlib.sha256(raw).hexdigest(), payload=crypto.encrypt(raw))
    db.add(b)
    db.flush()
    return b


def decode_payload(payload: bytes) -> tuple[dict, str]:
    """Decrypt + parse a backup payload. Returns (state, sha256_of_plaintext)."""
    raw = crypto.decrypt(payload)
    return json.loads(raw.decode()), hashlib.sha256(raw).hexdigest()


def restore_state(db: Session, data: dict) -> None:
    """Replace all data tables with the snapshot. Wipes in reverse-FK order, then
    re-inserts in FK order. `backups` is preserved; sessions are cleared (forcing
    re-auth). Runs in the caller's transaction."""
    for table in reversed(Base.metadata.sorted_tables):
        if table.name in _KEEP_ON_RESTORE:
            continue
        db.execute(table.delete())
    for table in Base.metadata.sorted_tables:
        if table.name in _KEEP_ON_RESTORE:
            continue
        rows = data.get(table.name)
        if not rows:
            continue
        recs = [{k: _dec(v) for k, v in row.items()} for row in rows]
        db.execute(table.insert(), recs)


def restore_backup(db: Session, backup: Backup, by: str | None = None) -> None:
    """Safety-snapshot the current state, then restore the given backup."""
    create_backup(db, note=f"auto safety before restore of v{backup.version}", by=by)
    state, sha = decode_payload(backup.payload)
    if sha != backup.sha256:
        raise ValueError("Backup integrity check failed (sha256 mismatch)")
    restore_state(db, state)


def restore_from_bytes(db: Session, payload: bytes, by: str | None = None) -> dict:
    """Restore from an uploaded encrypted payload (safety snapshot first)."""
    state, _sha = decode_payload(payload)  # raises if KEK/format wrong
    create_backup(db, note="auto safety before uploaded restore", by=by)
    restore_state(db, state)
    return state
