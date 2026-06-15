"""Manual-override epoch — decision-cache invalidation on human edits.

Companion to :mod:`engine.invalidation`. Where that module flags stale
:class:`Assessment` rows when the *evidence picture* changes, this module
handles the orthogonal case: a reviewer manually edits a verdict via
``POST /api/assessments`` while the underlying content (row + evidence +
CRM) is unchanged.

The :class:`DecisionCache` fingerprint is content-addressed, so an
unchanged objective recomputes the same fingerprint on the next
``/assess`` and replays the stale pre-override Decision — silently
reverting the human's correction. The :class:`OverrideEpoch` counter
breaks that tie: each manual override bumps the epoch for the
``(workbook_id, objective_id)`` pair, the epoch participates in the
fingerprint, and the next re-run misses the cache and re-assesses fresh.

Two invariants (mirroring ``invalidation.py``):

1. The epoch defaults to 0. An objective that has never been overridden
   computes exactly the legacy fingerprint, so cache sharing across
   workbooks for never-touched content is preserved.

2. The caller owns the transaction. ``bump_override_epoch`` stages the
   INSERT/UPDATE; the route commits after its own work.
"""

from __future__ import annotations

from sqlmodel import Session

from ..models import OverrideEpoch, _utcnow


def get_override_epoch(
    session: Session, workbook_id: int | None, objective_id: int | None
) -> int:
    """Return the current override epoch for an objective, or 0 if none.

    A return of ``0`` is the common case — most objectives are never
    manually overridden — and yields the legacy content-only fingerprint.
    """
    if workbook_id is None or objective_id is None:
        return 0
    row = session.get(OverrideEpoch, (int(workbook_id), int(objective_id)))
    if row is None:
        return 0
    return int(row.epoch)


def bump_override_epoch(
    session: Session, workbook_id: int | None, objective_id: int | None
) -> int:
    """Increment (or create) the override epoch for an objective.

    Stages the change on the session; the caller commits. Returns the new
    epoch value. A missing ``workbook_id``/``objective_id`` is a no-op that
    returns 0 — the manual-override route may run before either is known,
    and a content fingerprint with epoch 0 is the safe default.
    """
    if workbook_id is None or objective_id is None:
        return 0
    wid, oid = int(workbook_id), int(objective_id)
    row = session.get(OverrideEpoch, (wid, oid))
    if row is None:
        row = OverrideEpoch(workbook_id=wid, objective_id=oid, epoch=1)
        session.add(row)
        return 1
    row.epoch = int(row.epoch) + 1
    row.updated_at = _utcnow()
    session.add(row)
    return row.epoch
