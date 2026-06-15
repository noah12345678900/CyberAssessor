"""SQLite engine + session helpers.

Schema lifecycle lives in ``migrations`` (Alembic). This module owns
exactly two things:

* ``_make_engine`` — the WAL/busy_timeout configuration that every
  connection in the app must share. Replicated in env.py *only* via
  the connection handoff (alembic uses our engine when called in-process).
* ``init_db`` — the boot-time bring-up entry point: empty DB → run
  every migration; alembic-managed DB → run any new revisions; legacy
  pre-Alembic DB → refuse with a clear cutover message.

Everything additive used to live here as the 130-entry
``_ADDITIVE_COLUMNS`` list and four post-create helpers
(``_apply_additive_migrations``, ``_relax_systemcontext_…``,
``_drop_obsolete_baselineobjective_in_scope``,
``_migrate_stale_ref_abstains_to_rewrite_requested``,
``_seed_initial_sweep_weights``). All of that is now versioned in
``alembic/versions/`` — 0001 is the initial schema snapshot, 0002 is
the SweepWeights seed. Data backfills the previous helpers performed
on every boot are now no-ops under the wipe-and-reseed cutover (the
rows they touched don't exist on a fresh DB).
"""

from __future__ import annotations

from collections.abc import Generator, Iterable, Iterator
from contextlib import contextmanager
from typing import TypeVar

from sqlalchemy import event, inspect
from sqlmodel import Session, SQLModel, create_engine  # noqa: F401 -- SQLModel re-exported for callers

from . import config as cfg
from . import models  # noqa: F401  -- ensure tables are registered

_T = TypeVar("_T")

# SQLite's compiled-in host-parameter ceiling. Modern builds (>=3.32, which is
# everything we ship and everything on a current Windows Server) cap at 32766;
# legacy builds capped at 999. A ``WHERE col IN (:p1, :p2, ...)`` binds ONE
# host parameter per id, so an un-chunked ``col.in_(ids)`` over a 50k-evidence
# workbook raises "too many SQL variables" and the whole query aborts. Every
# call site that builds an IN-clause from a caller-supplied id collection must
# route through :func:`chunked` and union the per-batch results.
SQLITE_MAX_VARIABLES = 32766

# Conservative batch size for IN-clause chunking. Well under the 32766 ceiling
# (and under the legacy 999 cap, so the same code is safe on an ancient SQLite)
# with headroom for the OTHER bound parameters a query may carry alongside the
# IN list (workbook_id, status filters, ORDER/LIMIT params, etc.).
IN_CLAUSE_CHUNK = 900


def chunked(seq: Iterable[_T], size: int = IN_CLAUSE_CHUNK) -> Iterator[list[_T]]:
    """Yield ``seq`` in lists of at most ``size`` items.

    The canonical way to feed a large id collection into a SQLite ``IN`` clause
    without tripping :data:`SQLITE_MAX_VARIABLES`. Callers run their query once
    per yielded batch and concatenate the rows. Accepts any iterable (lists,
    sets, generators); a ``size < 1`` is clamped to 1 so a bad caller can't
    spin an empty-batch loop.
    """
    if size < 1:
        size = 1
    batch: list[_T] = []
    for item in seq:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def _make_engine():
    url = f"sqlite:///{cfg.db_path()}"
    # ``timeout`` is the sqlite3.connect busy-wait in seconds. The default 5s
    # was not enough during journal recovery on a crashed prior startup —
    # PRAGMA reads in the migration would surface "database is locked" while
    # the journal was still being applied, leaving an even larger journal
    # behind on exit and recursing the failure. 60s is well over any real
    # recovery time and adds no latency in the steady state.
    eng = create_engine(
        url,
        echo=False,
        connect_args={"check_same_thread": False, "timeout": 60},
    )

    # WAL mode is critical for our workload: a background ingest / sweep job
    # holds the writer across many per-file commits, and in default DELETE
    # journal mode that starves any concurrent writer (e.g. the user clicking
    # "Clear Evidence" in the UI) — the second writer waits out the full 60s
    # busy_timeout and then errors with "database is locked". WAL lets readers
    # and writers coexist, and writer-vs-writer contention windows shrink to
    # the length of a single commit instead of the whole session.
    #
    # synchronous=NORMAL is the standard WAL companion — safe with WAL's
    # crash-recovery model, and an order-of-magnitude faster than FULL on the
    # per-file commits the ingest path does.
    #
    # PRAGMA busy_timeout mirrors the connect-string ``timeout=60`` so it
    # applies inside transactions too (sqlite3's ``timeout`` only covers
    # connection setup on some platforms).
    @event.listens_for(eng, "connect")
    def _set_sqlite_pragma(dbapi_conn, _conn_record):
        cursor = dbapi_conn.cursor()
        try:
            # busy_timeout first — it has to be in place before the WAL
            # switch tries to take its exclusive lock, otherwise an orphan
            # holding the writer (we've had unkillable Access-Denied python
            # processes from prior crashes) errors instantly.
            cursor.execute("PRAGMA busy_timeout=60000")
            # WAL is persistent on the DB file, so it only needs to take
            # once. On retries, the PRAGMA is a cheap no-op confirmation.
            # Wrap defensively — if an orphan really won't release the
            # exclusive lock, fall back to DELETE journal mode so startup
            # still succeeds. The clear-evidence freeze comes back in that
            # case, but at least the app boots.
            try:
                cursor.execute("PRAGMA journal_mode=WAL")
            except Exception:  # noqa: BLE001 - orphan-lock fallback
                pass
            cursor.execute("PRAGMA synchronous=NORMAL")
            # FK enforcement is per-connection and OFF by default in SQLite,
            # so every ``ondelete`` clause in the models is inert without
            # this. Needed for the evidence→BoundaryTokenSource cascade
            # (deleting evidence must drop its sweep tokens); set on each
            # connect since the pool hands out fresh connections.
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    return eng


engine = _make_engine()


def init_db() -> None:
    """Bring the user's database to the current schema head.

    Three branches, in order:

    1. **Empty DB file** (no tables at all) → run every Alembic revision
       from scratch. The sidecar's first-ever boot path; also the path
       a developer takes after deleting ``~/.cybersecurity-assessor/
       assessor.sqlite`` to start clean.
    2. **Alembic-managed DB** (``alembic_version`` table present) →
       ``upgrade head``. No-op when already at head; otherwise applies
       any revisions added since the last boot.
    3. **Legacy pre-Alembic DB** (tables exist but no ``alembic_version``)
       → raise. This is the v0.x → Alembic cutover; per the
       wipe-and-reseed plan the user is expected to delete their dev DB
       once. The error message tells them so.

    The function is idempotent at head and safe to call from FastAPI's
    lifespan on every cold start.
    """
    from .migrations import has_alembic_version_table, upgrade_to_head

    table_names = inspect(engine).get_table_names()

    if not table_names:
        # Branch 1 — fresh DB. ``upgrade head`` creates the schema and
        # the ``alembic_version`` row in one go.
        upgrade_to_head(engine)
        return

    if has_alembic_version_table(engine):
        # Branch 2 — already adopted. No-op when at head, otherwise
        # applies pending revisions (this is how future schema changes
        # ship to existing installs).
        upgrade_to_head(engine)
        return

    # Branch 3 — legacy DB. Refuse rather than silently drift.
    db_file = cfg.db_path()
    raise RuntimeError(
        f"Database at {db_file} predates the Alembic cutover and cannot "
        "be auto-upgraded. The v0.x line moved schema management to "
        "Alembic; existing dev databases must be rebuilt once to adopt "
        f"it. Please delete {db_file} and relaunch the app — your "
        "workbook can be re-opened from the original .xlsx file. "
        "This message will not appear again after the rebuild."
    )


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    s = Session(engine)
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def get_session() -> Generator[Session, None, None]:
    """FastAPI dependency."""
    with session_scope() as s:
        yield s
