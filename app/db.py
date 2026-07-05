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
