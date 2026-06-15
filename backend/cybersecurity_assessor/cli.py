"""Operator CLI for the cybersecurity assessor sidecar.

Exposed via the ``cybersec`` console-script entry point declared in
``pyproject.toml`` (``[project.scripts]``). The CLI is intentionally
small — the FastAPI sidecar is the primary surface — and exists only
for operator-initiated maintenance that doesn't belong in a route
handler (cache wipes, etc.).

Commands are grouped by Typer sub-app so future additions don't
clutter the top-level help. The ``cache`` group owns the decision-
cache escape hatch documented in
``engine/decision_cache.py:clear_all``.
"""

from __future__ import annotations

import typer

from .db import init_db, session_scope
from .engine import decision_cache

app = typer.Typer(
    name="cybersec",
    help="Cybersecurity Assessor operator CLI.",
    no_args_is_help=True,
    add_completion=False,
)

cache_app = typer.Typer(
    name="cache",
    help="Decision-cache maintenance.",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(cache_app, name="cache")


@cache_app.command("clear")
def cache_clear(
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip the confirmation prompt.",
    ),
) -> None:
    """Wipe every DecisionCache row.

    Use this when a reviewer has corrected evidence outside the ingest
    path (manual fix-ups, out-of-band POAM updates) and wants to force
    re-evaluation of an entire workbook without bumping ``KERNEL_VERSION``.

    Bumping ``KERNEL_VERSION`` is the normal invalidation lever — it
    automatically misses every entry on the next run. This command
    exists for the narrower case where the kernel logic is unchanged
    but the underlying evidence shifted in a way the fingerprint
    can't detect.
    """
    if not yes:
        typer.confirm(
            "Wipe ALL cached decisions? Next assessment run will re-burn "
            "LLM calls for every row.",
            abort=True,
        )

    # init_db is idempotent — safe to run before the wipe so the
    # decision_cache table exists even on a fresh install.
    init_db()
    with session_scope() as session:
        deleted = decision_cache.clear_all(session)

    typer.echo(f"Cleared {deleted} cache row(s).")


if __name__ == "__main__":
    app()
