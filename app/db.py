from __future__ import annotations

import logging
from collections.abc import Iterator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .config import get_settings

log = logging.getLogger("vcm.db")

settings = get_settings()

_connect_args = {}
_engine_kwargs = {}
if settings.database_url.startswith("sqlite"):
    _connect_args = {"check_same_thread": False}
    # In-memory SQLite is per-connection; share one connection across threads so
    # the schema is visible to worker-thread requests (and tests).
    if ":memory:" in settings.database_url:
        _engine_kwargs["poolclass"] = StaticPool

engine = create_engine(settings.database_url, connect_args=_connect_args,
                       future=True, **_engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    pass


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    from . import models  # noqa: F401  (register mappers)

    Base.metadata.create_all(bind=engine)
    add_missing_columns(engine)
    _relax_ca_name_uniqueness(engine)
    _relax_nullable_columns(engine)
    _backfill_cert_fingerprints(engine)


def _relax_nullable_columns(eng) -> None:
    """Additive sync adds columns but never relaxes NOT NULL on existing ones.
    Some columns became nullable after their table already existed (e.g.
    certificates.ca_id — observed leaf certs have no issuing CA). Drop NOT NULL
    where the current model says the column is nullable (Postgres; DROP NOT NULL
    is idempotent). SQLite can't ALTER, but create_all makes it nullable there."""
    if eng.dialect.name != "postgresql":
        return
    for table in ("certificates",):
        insp = inspect(eng)
        if not insp.has_table(table):
            continue
        model_tbl = Base.metadata.tables.get(table)
        db_cols = {c["name"]: c for c in insp.get_columns(table)}
        for col in (model_tbl.columns if model_tbl is not None else []):
            info = db_cols.get(col.name)
            if col.nullable and info is not None and info.get("nullable") is False:
                try:
                    with eng.begin() as conn:
                        conn.execute(text(
                            f"ALTER TABLE {table} ALTER COLUMN {col.name} DROP NOT NULL"))
                    log.warning("schema sync: relaxed NOT NULL on %s.%s", table, col.name)
                except Exception as e:  # noqa: BLE001
                    log.error("schema sync: could not relax %s.%s: %s", table, col.name, e)


def _relax_ca_name_uniqueness(eng) -> None:
    """CA identity moved from name to certificate fingerprint. Drop the legacy
    unique constraint on cert_authorities.name if a prior schema created it
    (Postgres). SQLite can't drop it, but create_all never adds it now."""
    if eng.dialect.name != "postgresql":
        return
    try:
        with eng.begin() as conn:
            conn.execute(text(
                "ALTER TABLE cert_authorities DROP CONSTRAINT IF EXISTS "
                "cert_authorities_name_key"))
    except Exception as e:  # noqa: BLE001
        log.error("schema sync: could not drop cert_authorities_name_key: %s", e)


def _backfill_cert_fingerprints(eng) -> None:
    """Populate the new fingerprint columns for rows imported before it existed."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    def _fp(pem: str) -> str | None:
        try:
            return x509.load_pem_x509_certificate(pem.encode()).fingerprint(
                hashes.SHA256()).hex()
        except Exception:  # noqa: BLE001
            return None

    insp = inspect(eng)
    for table in ("cert_authorities", "certificates"):
        if not insp.has_table(table):
            continue
        cols = {c["name"] for c in insp.get_columns(table)}
        if "fingerprint" not in cols or "cert_pem" not in cols:
            continue
        try:
            with eng.begin() as conn:
                rows = conn.execute(text(
                    f"SELECT id, cert_pem FROM {table} WHERE fingerprint IS NULL "
                    "AND cert_pem IS NOT NULL AND cert_pem <> ''")).fetchall()
                for rid, pem in rows:
                    fp = _fp(pem)
                    if fp:
                        conn.execute(
                            text(f"UPDATE {table} SET fingerprint = :fp WHERE id = :id"),
                            {"fp": fp, "id": rid})
        except Exception as e:  # noqa: BLE001
            log.error("schema sync: fingerprint backfill on %s failed: %s", table, e)


def add_missing_columns(eng) -> None:
    """Lightweight, additive schema sync: for every mapped table that already
    exists, ADD COLUMN for any model column the DB is missing. This lets new
    releases add nullable/defaulted columns without a separate migration step.
    It never drops or alters existing columns/types.
    """
    insp = inspect(eng)
    dialect = eng.dialect
    for table in Base.metadata.sorted_tables:
        if not insp.has_table(table.name):
            continue
        existing = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in existing:
                continue
            ddl = _add_column_ddl(table.name, col, dialect)
            try:
                with eng.begin() as conn:
                    conn.execute(text(ddl))
                log.warning("schema sync: added column %s.%s", table.name, col.name)
            except Exception as e:  # noqa: BLE001
                log.error("schema sync: could not add %s.%s: %s", table.name, col.name, e)


def _add_column_ddl(table_name: str, col, dialect) -> str:
    coltype = col.type.compile(dialect=dialect)
    parts = [f"ALTER TABLE {table_name} ADD COLUMN {col.name} {coltype}"]
    default_sql = _scalar_default_sql(col)
    if default_sql is not None:
        parts.append(f"DEFAULT {default_sql}")
        if not col.nullable:
            parts.append("NOT NULL")
    # If no default and NOT NULL, add as nullable to avoid failing on existing
    # rows; the app supplies values for new rows.
    return " ".join(parts)


def _scalar_default_sql(col) -> str | None:
    default = col.default
    if default is None or not getattr(default, "is_scalar", False):
        return None
    val = default.arg
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return str(val)
    if isinstance(val, str):
        return "'" + val.replace("'", "''") + "'"
    return None
