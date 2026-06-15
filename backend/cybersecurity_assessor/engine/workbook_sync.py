"""Workbook sync diff engine.

Glues the read-only ``reread_workbook`` parser in
``excel.ccis_reader`` to the append-only ``WorkbookSyncEvent`` audit log.
Each row-level change reported by the keyed diff (added / removed /
moved / edited) is persisted as one event so the UI can later show
"what changed since you last looked" without recomputing the diff.

The function commits in a single transaction. Any failure during event
construction or write rolls the session back and re-raises — partial
syncs would leave the audit log in an inconsistent state relative to
the snapshot sidecar, which is also rewritten by ``reread_workbook``.

For ``edited`` events both ``old_value_json`` and ``new_value_json``
hold the full snapshot dict (the same shape ``_row_to_snapshot_dict``
emits), not just the changed columns — downstream UIs need to diff
arbitrary subsets without re-parsing the workbook.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlmodel import Session

from ..excel.ccis_reader import (
    RereadResult,
    _load_snapshot,
    _row_to_snapshot_dict,
    _snapshot_path,
    reread_workbook,
)
from ..models import WorkbookSyncEvent

_SOURCE_REREAD = "reread"


@dataclass
class SyncSummary:
    """Result of one :func:`sync_workbook` call.

    ``events`` are the rows as they were written to the DB (with ``id``
    populated after refresh) so the caller can hand them straight to a
    UI without re-querying.
    """

    added_count: int = 0
    removed_count: int = 0
    moved_count: int = 0
    edited_count: int = 0
    had_prior_snapshot: bool = False
    events: list[WorkbookSyncEvent] = field(default_factory=list)


def _dumps(payload: Any) -> str:
    """JSON-encode a snapshot dict with stable key order."""
    return json.dumps(payload, sort_keys=True, default=str)


def _key_parts(entry: dict[str, Any]) -> tuple[str, str | None]:
    """Pull (control_id, cci_id) from a diff entry's ``key`` list."""
    key = entry.get("key") or []
    control_id = str(key[0]) if len(key) >= 1 else ""
    cci_id = str(key[1]) if len(key) >= 2 and key[1] is not None else None
    return control_id, cci_id


def _current_snapshot_for(
    result: RereadResult, control_id: str, cci_id: str | None
) -> dict[str, Any] | None:
    """Find the current snapshot dict for a (control_id, cci_id) key.

    Used for ``moved`` / ``edited`` events where the diff entry only
    carries the key + change metadata, not the full row.
    """
    for row in result.index.rows:
        if row.control_id == control_id and row.cci_id == cci_id:
            return _row_to_snapshot_dict(row)
    return None


def sync_workbook(
    session: Session, workbook_id: int, workbook_path: Path
) -> SyncSummary:
    """Re-read ``workbook_path`` and persist one event per diff entry.

    Calls :func:`reread_workbook` exactly once with ``update_snapshot=True``
    so the sidecar baseline rolls forward to match the events written
    here — re-running ``sync_workbook`` on an unchanged file produces
    zero events.

    All events for a single call share the same ``occurred_at``
    timestamp (UTC) so downstream UIs can group them into a single
    "sync run". On any exception, the session is rolled back and the
    error re-raised — note this does NOT undo the snapshot sidecar
    write (that's owned by ``reread_workbook``).
    """
    # Read the prior snapshot BEFORE re-reading the workbook, because
    # reread_workbook(update_snapshot=True) overwrites the sidecar with
    # the current parse. We need the prior dicts to populate
    # ``old_value_json`` for edited/moved events.
    prior_snapshot = _load_snapshot(_snapshot_path(Path(workbook_path))) or {}

    result = reread_workbook(workbook_path, update_snapshot=True)
    diff = result.diff

    now = datetime.now(timezone.utc)
    events: list[WorkbookSyncEvent] = []

    try:
        for entry in diff.added:
            control_id, cci_id = _key_parts(entry)
            events.append(
                WorkbookSyncEvent(
                    workbook_id=workbook_id,
                    control_id=control_id,
                    cci_id=cci_id,
                    occurred_at=now,
                    event_type="added",
                    old_value_json=None,
                    new_value_json=_dumps(entry.get("row", {})),
                    source=_SOURCE_REREAD,
                )
            )

        for entry in diff.removed:
            control_id, cci_id = _key_parts(entry)
            events.append(
                WorkbookSyncEvent(
                    workbook_id=workbook_id,
                    control_id=control_id,
                    cci_id=cci_id,
                    occurred_at=now,
                    event_type="removed",
                    old_value_json=_dumps(entry.get("row", {})),
                    new_value_json=None,
                    source=_SOURCE_REREAD,
                )
            )

        for entry in diff.moved:
            control_id, cci_id = _key_parts(entry)
            current = _current_snapshot_for(result, control_id, cci_id) or {}
            old_snapshot = prior_snapshot.get((control_id, cci_id)) or {}
            events.append(
                WorkbookSyncEvent(
                    workbook_id=workbook_id,
                    control_id=control_id,
                    cci_id=cci_id,
                    occurred_at=now,
                    event_type="moved",
                    old_value_json=_dumps(old_snapshot),
                    new_value_json=_dumps(current),
                    source=_SOURCE_REREAD,
                )
            )

        for entry in diff.edited:
            control_id, cci_id = _key_parts(entry)
            current = _current_snapshot_for(result, control_id, cci_id) or {}
            old_snapshot = prior_snapshot.get((control_id, cci_id)) or {}
            events.append(
                WorkbookSyncEvent(
                    workbook_id=workbook_id,
                    control_id=control_id,
                    cci_id=cci_id,
                    occurred_at=now,
                    event_type="edited",
                    old_value_json=_dumps(old_snapshot),
                    new_value_json=_dumps(current),
                    source=_SOURCE_REREAD,
                )
            )

        for event in events:
            session.add(event)
        session.commit()
        for event in events:
            session.refresh(event)
    except Exception:
        session.rollback()
        raise

    return SyncSummary(
        added_count=len(diff.added),
        removed_count=len(diff.removed),
        moved_count=len(diff.moved),
        edited_count=len(diff.edited),
        had_prior_snapshot=result.had_prior_snapshot,
        events=events,
    )
