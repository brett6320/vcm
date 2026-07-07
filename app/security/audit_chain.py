"""Tamper-evident audit log via a SHA-256 hash chain.

Each ``AuditLog`` row carries ``prev_hash`` (the chain head at insert time) and
``entry_hash = sha256(prev_hash + canonical(row))`` over the immutable fields
(timestamp/username/action/detail/ip). Walking the chain in id order lets us
detect edits, deletions, and reordering of existing entries: any change makes a
row's stored ``entry_hash`` (or the next row's ``prev_hash`` link) no longer
recompute, pinpointing the first broken link.

Caveat: this detects casual tampering, deletions, and reordering, but an
attacker with full DB write access could recompute the whole chain. Stronger
integrity requires periodically anchoring the head hash to an external
append-only store — tracked as a follow-up, out of scope here.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AuditLog, ensure_aware

# Genesis seed for the first entry's prev_hash (64 hex chars, like a sha256).
GENESIS_HASH = "0" * 64


def _norm_ts(ts: datetime | None) -> str | None:
    """Stable UTC ISO string. SQLite drops tzinfo on read, so coerce naive->UTC
    to keep insert-time and verify-time serialization identical."""
    if ts is None:
        return None
    return ensure_aware(ts).astimezone(timezone.utc).isoformat()


def canonical(ts, username, action, detail, ip) -> str:
    """Stable serialization of the immutable fields."""
    return json.dumps(
        {"ts": _norm_ts(ts), "username": username, "action": action,
         "detail": detail, "ip": ip},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )


def entry_hash(prev_hash: str | None, ts, username, action, detail, ip) -> str:
    data = (prev_hash or GENESIS_HASH) + canonical(ts, username, action, detail, ip)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def row_hash(prev_hash: str | None, row: AuditLog) -> str:
    return entry_hash(prev_hash, row.ts, row.username, row.action, row.detail, row.ip)


def chain_head(db: Session) -> str:
    """entry_hash of the most recent row (becomes the next row's prev_hash),
    or the genesis seed if the log is empty."""
    head = db.execute(
        select(AuditLog.entry_hash).order_by(AuditLog.id.desc()).limit(1)).scalar()
    return head or GENESIS_HASH


def backfill(db: Session) -> int:
    """Walk existing rows in id order and populate any missing chain fields so
    the chain is continuous from the first historical entry. Returns the number
    of rows updated. Rows that already carry hashes are left untouched (their
    entry_hash still advances the chain)."""
    rows = db.execute(select(AuditLog).order_by(AuditLog.id.asc())).scalars().all()
    prev = GENESIS_HASH
    changed = 0
    for r in rows:
        if r.prev_hash is None or r.entry_hash is None:
            r.prev_hash = prev
            r.entry_hash = row_hash(prev, r)
            changed += 1
        prev = r.entry_hash
    if changed:
        db.commit()
    return changed


def verify(db: Session) -> dict:
    """Re-walk the chain. Returns a dict describing integrity:
    ``ok`` True with ``checked`` count, or ``ok`` False pinpointing the first
    broken row (``broken_id``, ``broken_index``, ``reason``)."""
    rows = db.execute(select(AuditLog).order_by(AuditLog.id.asc())).scalars().all()
    prev = GENESIS_HASH
    for i, r in enumerate(rows):
        if r.prev_hash != prev:
            return {"ok": False, "total": len(rows), "checked": i,
                    "broken_id": r.id, "broken_index": i,
                    "reason": "prev_hash link broken (deleted/reordered entry)"}
        expected = row_hash(prev, r)
        if r.entry_hash != expected:
            return {"ok": False, "total": len(rows), "checked": i,
                    "broken_id": r.id, "broken_index": i,
                    "reason": "entry_hash mismatch (modified entry)"}
        prev = r.entry_hash
    return {"ok": True, "total": len(rows), "checked": len(rows),
            "broken_id": None, "broken_index": None, "reason": None}
