"""Persistent per-workbook write target.

Why this module exists
----------------------
The Apply-to-workbook flow used to open the user's original CCIS .xlsx in
xlwings and save N/O/P/Q directly into it. The :func:`safe_write` harness
in ``ccis_writer.py`` makes a ``.bak-<ts>`` snapshot first and rolls back
on verify failure, so a *crash mid-write* is recoverable -- but a
*successful write of bad data* (e.g. the LLM proposed a wrong status, the
tester clicked Apply, and we only notice later) is not. The original gets
mutated; the only way back is digging through timestamped backups.

This module breaks that coupling. On the first Apply for a given workbook
we copy ``Foo.xlsx`` → ``Foo_CYBERASSESSOR_<timestamp>.xlsx`` into
``~/Downloads/CyberAssessor/<wb_id>/`` and remember the path on the
``Workbook`` row. The original is opened only for reads (catalog reader,
validator) and never written.

Location choice
---------------
Working copies live under ``~/Downloads/CyberAssessor/<wb_id>/`` so the
assessor finds them in the same place they look for any other desktop-app
output. The local Downloads folder is not OneDrive-synced on this
workstation, so the original concern about racing the sync engine
doesn't apply here. The ``CyberAssessor/`` subfolder keeps the program's
outputs grouped together instead of scattering them across the Downloads
root; the per-workbook-id subdirectory below that prevents collisions
when two different originals share a stem (e.g. two ``RAR.xlsx``
workbooks from different programs both opened in the same install).

Naming choice
-------------
``<stem>_CYBERASSESSOR_<YYYYMMDDTHHMMSS><suffix>`` — every Apply lands in
a NEW file. Rationale:

- Excel takes an exclusive OS lock on a workbook it has open, so a stable
  working-copy name (the earlier ``_edited.xlsx`` scheme) would hard-fail
  the moment the assessor double-clicked the working copy to inspect it
  mid-session. The timestamp ensures the write target never collides with
  whatever the user happens to have open.
- Each Apply copies forward from the previous working copy so cumulative
  state is preserved — yesterday's writes to N7 are still there when
  today's Apply writes N8.
- The ``_CYBERASSESSOR_`` infix makes the program's output
  unambiguous in Explorer when the user inspects the working_copies
  directory and reads cleanly when surfaced in UI labels.

Lazy semantics
--------------
We do not create the working copy when the workbook is opened -- only on
the first Apply. Opening is read-only metadata extraction; many opened
workbooks never see a writeback (the user is browsing, comparing, etc.)
and creating phantom ``_CYBERASSESSOR_*.xlsx`` files on every open would
clutter the program directory.
"""

from __future__ import annotations

import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path

from sqlmodel import Session

from ..config import working_copies_dir
from ..models import Workbook

_log = logging.getLogger(__name__)

# Surface as a module-level constant so callers (e.g. UI labels, tests)
# can reference it without hard-coding the string.
WORKING_SUFFIX = "_CYBERASSESSOR"


def _timestamp() -> str:
    """UTC ``YYYYMMDDTHHMMSS`` stamp — collision-safe at one-second
    granularity, monotonic so the latest file sorts last in Explorer."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")


def _assert_parent_is_directory(parent: Path) -> None:
    """Refuse to proceed if ``parent`` exists but isn't a directory.

    ``Path.mkdir(exist_ok=True)`` silently succeeds when the target is a
    directory but raises ``FileExistsError`` when a regular file happens
    to occupy the same path — and the raw FileExistsError gives the user
    no clue what to do about it. This shouldn't ever happen organically
    (we own the ``<wb_id>`` subdirectory), but a user who pastes a stray
    file into ``~/Downloads/CyberAssessor/`` named e.g. ``7`` would land
    here. Surface a clear, actionable error instead of leaking the COM
    layer's FileExistsError up through the Apply route.
    """
    if parent.exists() and not parent.is_dir():
        raise RuntimeError(
            f"Working-copy slot {parent} exists as a file, not a directory. "
            "Remove or rename it so the assessor can create the per-workbook "
            "directory in its place."
        )


def _quarantine_foreign_working_copies(parent: Path, expected_stem: str) -> None:
    """Sequester pre-existing working copies whose stem doesn't match.

    Scenario: the SQLite DB was wiped (manual delete, schema rebuild,
    fresh machine restore) but the ``~/Downloads/CyberAssessor/<wb_id>/``
    tree was left in place. The new ``Workbook`` row gets the same
    ``wb_id`` (auto-increment starts at 1), so on the first Apply we
    would happily copy-forward state from a *different* prior workbook's
    file that happens to live in the same numbered slot — silent data
    corruption masquerading as a clean run.

    Detection: any file in ``parent`` whose stem doesn't begin with
    ``<expected_stem>_CYBERASSESSOR_`` is from a previous tenant of this
    slot. We move those files into ``parent / _orphans_<ts>/`` rather
    than deleting them (the user might want them; they're the only
    record of the prior workbook's assessment edits) and log a WARNING
    so the operator can see what happened.

    Called only when ``wb.working_path is None`` — the fresh-row case
    where a stale neighbour is the smoking gun for a DB reset. On
    subsequent Apply calls we already know which working copy is ours
    (via ``wb.working_path``) and don't need to scrub the directory.
    """
    if not parent.exists():
        return
    # Mirror derive_working_path's guard: iterdir() on a regular file
    # raises NotADirectoryError, which would mask the clear RuntimeError
    # that the directory-shape guard is here to surface. Run the same
    # check first so the user sees the actionable message.
    _assert_parent_is_directory(parent)
    expected_prefix = f"{expected_stem}{WORKING_SUFFIX}_"
    orphans = [
        p
        for p in parent.iterdir()
        if p.is_file() and not p.name.startswith(expected_prefix)
    ]
    if not orphans:
        return
    quarantine = parent / f"_orphans_{_timestamp()}"
    quarantine.mkdir(parents=True, exist_ok=True)
    for orphan in orphans:
        try:
            shutil.move(str(orphan), str(quarantine / orphan.name))
        except OSError as e:
            # If a quarantine move fails (e.g. the orphan is locked open
            # in Excel), leave it where it is. The expected-prefix guard
            # on subsequent reads still keeps us from picking it up by
            # accident; we just can't tidy it.
            _log.warning(
                "Could not quarantine orphan working copy %s: %s", orphan, e
            )
    _log.warning(
        "Quarantined %d orphan working-copy file(s) from %s into %s — "
        "likely from a prior workbook that occupied this id slot before "
        "a DB reset. Inspect %s if you need to recover prior assessment edits.",
        len(orphans),
        parent,
        quarantine,
        quarantine,
    )


def derive_working_path(original: Path, wb_id: int) -> Path:
    """Compute a fresh working-copy path inside the program dir.

    ``Foo.xlsx`` → ``~/Downloads/CyberAssessor/<wb_id>/Foo_CYBERASSESSOR_<ts>.xlsx``
    with the original suffix preserved (so ``.xlsm`` macro-enabled
    workbooks stay macro-enabled). The ``<wb_id>`` subdirectory keeps
    different workbooks with the same stem from colliding.

    A new timestamp is computed on every call — callers that need a
    stable path across one Apply operation must hold onto the result.
    """
    parent = working_copies_dir() / str(wb_id)
    _assert_parent_is_directory(parent)
    parent.mkdir(parents=True, exist_ok=True)
    return parent / f"{original.stem}{WORKING_SUFFIX}_{_timestamp()}{original.suffix}"


def get_or_create_working_copy(wb: Workbook, session: Session) -> Path:
    """Return a path that is safe to write to for THIS Apply call.

    Every invocation produces a fresh timestamped file so the write
    target can never collide with a working copy the user has opened in
    Excel (the lock that previously caused WinError 32 saves to fail).
    State is copied forward from the prior working copy so cumulative
    edits are preserved.

    Behaviour matrix:

    - ``wb.working_path`` unset           -> derive fresh timestamped
      path, copy original to it, persist on the row, return.
    - ``wb.working_path`` set and present -> derive fresh timestamped
      path, copy the existing working copy to it (preserves cumulative
      writes), persist new path on the row, return. Old working copies
      are LEFT IN PLACE as an audit trail of prior Apply calls.
    - ``wb.working_path`` set but missing -> the user deleted the
      working copy out-of-band. Derive a fresh timestamped path, copy
      from the original, persist the new path.
    - Original missing                    -> raise ``FileNotFoundError``.
      We deliberately do NOT silently re-anchor to a new location: the
      user almost certainly moved the file and the right answer is to
      surface a 410 so they can re-open from the correct path.

    The DB row is updated in-place via the same session the caller is
    using; this function commits its own change so the new path survives
    a crash before the next write attempt.
    """
    original = Path(wb.path)
    if not original.exists():
        raise FileNotFoundError(f"Original workbook missing: {original}")

    if wb.id is None:
        # Defensive: every persisted Workbook row has an id; this branch
        # exists so a future refactor that calls us with a transient
        # instance gets a loud failure instead of a silent miscompute.
        raise ValueError("Workbook must be persisted (id is None) before deriving a working copy path")

    # Source for the copy-forward: the previous working copy if it still
    # exists, otherwise the original. Using the previous working copy
    # preserves any edits the assessor has already made; falling back to
    # the original handles the "user wiped working_copies/" case.
    prior = Path(wb.working_path) if wb.working_path else None
    source = prior if (prior is not None and prior.exists()) else original

    # First-Apply guard: if the DB row has no working_path yet but the
    # numbered slot directory already has files in it, those files are
    # from a previous tenant of the same wb_id (DB reset scenario).
    # Quarantine them so we never silently copy-forward someone else's
    # workbook state into this one. Subsequent Apply calls — when
    # working_path is set — skip this scan; by then we know which file
    # is ours and the prefix mismatch can't bite.
    if wb.working_path is None:
        _quarantine_foreign_working_copies(
            working_copies_dir() / str(wb.id), original.stem
        )

    target = derive_working_path(original, wb.id)
    # The fresh timestamp makes collisions vanishingly unlikely, but
    # guard against a same-second double-call (e.g. two parallel Apply
    # requests from the UI) by spinning until we land on an unused name.
    while target.exists():
        target = derive_working_path(original, wb.id)

    # copy2 preserves mtime/permissions so the freshly-cloned working
    # copy looks "as of" the source in Explorer until the first write
    # touches it.
    shutil.copy2(source, target)

    wb.working_path = str(target)
    session.add(wb)
    session.commit()
    session.refresh(wb)

    return target
