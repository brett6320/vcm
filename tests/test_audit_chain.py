"""Tests for the tamper-evident audit-log hash chain (issue #76)."""
import base64
import os
import types

os.environ.setdefault("VCM_SECRET_KEY", "test-secret")
os.environ.setdefault("VCM_KEK_B64", base64.b64encode(os.urandom(32)).decode())
os.environ.setdefault("VCM_DATABASE_URL", "sqlite:///:memory:")

import pytest  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.db import SessionLocal, init_db, _backfill_audit_chain, engine  # noqa: E402
from app.models import AuditLog  # noqa: E402
from app.security import audit_chain  # noqa: E402
from app.security.deps import audit  # noqa: E402


def _fake_request(ip="203.0.113.9"):
    return types.SimpleNamespace(client=types.SimpleNamespace(host=ip), headers={})


@pytest.fixture()
def db():
    init_db()
    s = SessionLocal()
    # Start each test from an empty log for isolation.
    s.query(AuditLog).delete()
    s.commit()
    try:
        yield s
    finally:
        s.close()


def _write(db, action, detail=None):
    audit(db, _fake_request(), action, detail)
    db.commit()


def test_new_writes_are_chained(db):
    _write(db, "test.one")
    _write(db, "test.two")
    _write(db, "test.three")
    rows = db.execute(select(AuditLog).order_by(AuditLog.id)).scalars().all()
    assert len(rows) == 3
    # Every row has both hash fields populated.
    assert all(r.prev_hash and r.entry_hash for r in rows)
    # Genesis seed on the first entry, then each prev_hash links the prior entry.
    assert rows[0].prev_hash == audit_chain.GENESIS_HASH
    assert rows[1].prev_hash == rows[0].entry_hash
    assert rows[2].prev_hash == rows[1].entry_hash
    # entry_hash matches the recomputed value.
    for r, prev in zip(rows, [audit_chain.GENESIS_HASH,
                              rows[0].entry_hash, rows[1].entry_hash]):
        assert r.entry_hash == audit_chain.row_hash(prev, r)


def test_verify_passes_on_untouched_log(db):
    for i in range(5):
        _write(db, f"test.{i}")
    result = audit_chain.verify(db)
    assert result["ok"] is True
    assert result["checked"] == 5
    assert result["broken_id"] is None


def test_verify_passes_on_empty_log(db):
    assert audit_chain.verify(db)["ok"] is True


def test_modification_is_detected(db):
    for i in range(5):
        _write(db, f"test.{i}")
    rows = db.execute(select(AuditLog).order_by(AuditLog.id)).scalars().all()
    victim = rows[2]
    victim.detail = "tampered!"
    db.commit()
    result = audit_chain.verify(db)
    assert result["ok"] is False
    assert result["broken_id"] == victim.id
    assert "modified" in result["reason"]


def test_deletion_is_detected(db):
    for i in range(5):
        _write(db, f"test.{i}")
    rows = db.execute(select(AuditLog).order_by(AuditLog.id)).scalars().all()
    # Delete a middle row; the following row's prev_hash link no longer matches.
    following_id = rows[3].id
    db.delete(rows[2])
    db.commit()
    result = audit_chain.verify(db)
    assert result["ok"] is False
    assert result["broken_id"] == following_id
    assert "deleted" in result["reason"] or "reorder" in result["reason"]


def test_reorder_is_detected(db):
    for i in range(5):
        _write(db, f"test.{i}")
    rows = db.execute(select(AuditLog).order_by(AuditLog.id)).scalars().all()
    # Swap the immutable content of two rows (reordering their meaning) while
    # leaving stored hashes in place -> recomputed entry_hash no longer matches.
    a, b = rows[1], rows[3]
    a.action, b.action = b.action, a.action
    a.detail, b.detail = b.detail, a.detail
    db.commit()
    result = audit_chain.verify(db)
    assert result["ok"] is False
    # First break is at the earlier of the two swapped rows.
    assert result["broken_id"] == a.id


def test_backfill_populates_missing_hashes(db):
    # Simulate historical rows written before the chain existed (no hashes).
    for i in range(4):
        db.add(AuditLog(action=f"legacy.{i}", detail=str(i)))
    db.commit()
    rows = db.execute(select(AuditLog)).scalars().all()
    assert all(r.entry_hash is None for r in rows)

    changed = audit_chain.backfill(db)
    assert changed == 4
    assert audit_chain.verify(db)["ok"] is True

    # Re-running backfill is a no-op (idempotent).
    assert audit_chain.backfill(db) == 0

    # New writes continue the backfilled chain.
    _write(db, "test.after")
    assert audit_chain.verify(db)["ok"] is True


def test_startup_backfill_hook(db):
    for i in range(3):
        db.add(AuditLog(action=f"legacy.{i}"))
    db.commit()
    _backfill_audit_chain(engine)
    db.expire_all()
    assert audit_chain.verify(db)["ok"] is True
