"""Alembic wrapper — the only module the rest of the app should import.

Two callers exist:

1. **Sidecar boot** (``db.init_db()``) — needs ``upgrade_to_head(engine)`` and
   ``current_revision(engine)`` to decide between fresh-DB and upgrade paths.
   Runs inside an already-bound SQLAlchemy engine; must not open a second
   connection (would race the WAL pragma setup in ``db._make_engine``).

2. **Operator CLI** (``cybersec-migrate upgrade`` / ``stamp`` / ``current``)
   — for the rare case Noah needs to step a dev DB forward without launching
   the app. Mirrors the most common ``alembic`` subcommands with one less
   typing layer and no need to ``cd`` into ``backend/``.

The Alembic ``Config`` is built **programmatically** here — we don't read
backend/alembic.ini from disk. That file still exists for devs who want to
run the shell ``alembic`` command directly from backend/, but the
in-process path can't depend on it (a wheel install drops the package into
site-packages; a PyInstaller bundle has no on-disk layout at all). The
script_location points at the ``cybersecurity_assessor.alembic`` package
resource, which importlib.resources resolves on every platform.
"""

from __future__ import annotations

import argparse
import logging
from importlib import resources
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)


def _resolve_script_location() -> str:
    """Return an absolute filesystem path to cybersecurity_assessor/alembic/.

    importlib.resources is the portable way to find package data — works in
    a source checkout, in an installed wheel, and (with the right
    ``--add-data`` flag) in a PyInstaller-onefile bundle.
    """
    try:
        # ``files()`` returns a Traversable; ``as_file`` materializes it to
        # an OS path. For a normal package on disk that's a no-op; for a
        # zipped/frozen package it extracts to a temp dir.
        traversable = resources.files("cybersecurity_assessor").joinpath("alembic")
        with resources.as_file(traversable) as path:
            resolved = Path(path)
            if not resolved.exists():
                raise FileNotFoundError(resolved)
            return str(resolved)
    except (ModuleNotFoundError, FileNotFoundError) as exc:
        raise RuntimeError(
            "cybersecurity_assessor.alembic resource directory not found — "
            "did the package install drop the alembic/ subtree?"
        ) from exc


def _alembic_config(connection=None) -> Config:
    """Build an Alembic Config in memory, optionally attaching a connection.

    No alembic.ini is consulted — every setting is injected via main options
    so the same code works for source / wheel / PyInstaller invocations.

    When ``connection`` is provided, env.py reuses it instead of opening
    a fresh one (see env.run_migrations_online's config.attributes lookup).
    """
    cfg = Config()
    cfg.set_main_option("script_location", _resolve_script_location())
    # Empty URL — env.py reads cfg.db_path() at runtime, which is the right
    # answer whether we're talking to ~/.cybersecurity-assessor/assessor.sqlite
    # or a test override.
    cfg.set_main_option("sqlalchemy.url", "")
    if connection is not None:
        cfg.attributes["connection"] = connection
    return cfg


def current_revision(engine: Engine) -> str | None:
    """Return the alembic_version row (or None for a virgin DB)."""
    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn)
        return ctx.get_current_revision()


def has_alembic_version_table(engine: Engine) -> bool:
    """True if the DB has been brought under Alembic management at all.

    Used by ``db.init_db`` to distinguish a fresh DB (no tables, no
    alembic_version) from a legacy pre-Alembic DB (tables exist but no
    alembic_version row). The legacy case is the v0.x → Alembic cutover
    and is treated as a hard error per the wipe-and-reseed plan.
    """
    from sqlalchemy import inspect

    return "alembic_version" in inspect(engine).get_table_names()


def upgrade_to_head(engine: Engine) -> None:
    """Bring the DB at ``engine`` up to head.

    Reuses ``engine``'s connection so the WAL/busy_timeout pragmas already
    applied by ``db._make_engine`` stay in effect for the migration's
    transactions. No-op when already at head.
    """
    with engine.begin() as connection:
        cfg = _alembic_config(connection=connection)
        command.upgrade(cfg, "head")


def stamp_head(engine: Engine) -> None:
    """Mark the DB as being at head without running any migrations.

    Reserved for tests / fixtures that build the schema via
    ``SQLModel.metadata.create_all`` and then need alembic_version populated
    so subsequent ``upgrade_to_head`` calls are no-ops.
    """
    with engine.begin() as connection:
        cfg = _alembic_config(connection=connection)
        command.stamp(cfg, "head")


def revision(
    engine: Engine,
    message: str,
    *,
    autogenerate: bool = True,
) -> None:
    """Generate a new revision file. Dev-only — not invoked by the sidecar."""
    with engine.begin() as connection:
        cfg = _alembic_config(connection=connection)
        command.revision(cfg, message=message, autogenerate=autogenerate)


# ----------------------------------------------------------------------
# CLI — `cybersec-migrate <subcommand>` is wired in pyproject.toml.
# Kept argparse-only (no Typer) to avoid pulling Typer's dependencies
# into the cold path; this is a single-purpose ops tool.
# ----------------------------------------------------------------------


def cli() -> None:
    parser = argparse.ArgumentParser(
        prog="cybersec-migrate",
        description="Apply or inspect Alembic migrations against the user's "
        "~/.cybersecurity-assessor/assessor.sqlite database.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("upgrade", help="alembic upgrade head")
    sub.add_parser("current", help="print current revision (or 'none')")
    sub.add_parser(
        "stamp",
        help="mark DB as being at head without running migrations "
        "(advanced — only use to adopt a hand-built schema)",
    )
    rev = sub.add_parser("revision", help="generate a new --autogenerate revision")
    rev.add_argument("message", help="short slug for the migration filename")

    args = parser.parse_args()

    # Import here so the CLI startup cost stays cheap when the user runs
    # `cybersec-migrate --help`.
    from .db import engine

    if args.cmd == "upgrade":
        upgrade_to_head(engine)
        print(f"Upgraded to {current_revision(engine) or '<none>'}")
    elif args.cmd == "current":
        rev = current_revision(engine)
        print(rev if rev is not None else "none")
    elif args.cmd == "stamp":
        stamp_head(engine)
        print(f"Stamped at {current_revision(engine)}")
    elif args.cmd == "revision":
        revision(engine, args.message)
    else:  # pragma: no cover - argparse guards
        parser.error(f"unknown command {args.cmd!r}")


if __name__ == "__main__":  # pragma: no cover
    cli()
