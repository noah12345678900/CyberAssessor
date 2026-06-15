"""In-memory progress tracker for /assess-batch.

Why this exists
---------------
``assess_objectives_batch`` is a single blocking POST that runs every
in-scope CCI through the 3-round LLM pipeline before returning. On
realistic workbooks (hundreds of CCIs, Opus 4.7/4.8 selected) the call
takes several minutes; the UI shows only an indeterminate spinner. The
user can't tell if the run is stuck, halfway done, or about to finish.

This module is the smallest thing that fixes that. A process-wide
``dict[int, _Progress]`` keyed by ``workbook_id`` records the per-batch
counters (total / completed / errored / started_at / last_objective).
The fan-out worker in ``controls.py`` bumps ``completed`` after every
``Assessor.assess`` call; a thin GET endpoint exposes the snapshot so
the UI can poll it on a short interval while the mutation is in flight.

Why in-memory (not DB)
----------------------
The progress record is interesting only for the lifetime of one
``/assess-batch`` call — once the POST returns, the response payload
carries the full result and the per-batch counters are obsolete.
Persisting them to SQLite would buy nothing and add write contention
to the same session the batch is already pumping decisions through.
The Python sidecar is a single process per user, so a module-level
dict + threading.Lock is all the synchronization the parallel
ThreadPoolExecutor workers need.

Scope per ``workbook_id``
-------------------------
Only one assess-batch can be in flight per workbook at a time (the UI
disables the trigger while ``assessBatch.isPending``). Keying by
workbook_id keeps the surface trivial — no batch IDs, no UUIDs, no
client-side correlation logic — and matches how the UI thinks about
runs ("show me progress for THIS workbook").

If two workbooks run concurrently in the future, they get independent
slots in the dict. Two batches against the *same* workbook would clobber
each other's counters; the UI's button-disable contract makes this an
"impossible by construction" condition rather than something this
module needs to defend against.
"""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass, field


@dataclass
class _Progress:
    """One in-flight batch's running state.

    All fields are owned by ``_LOCK`` -- readers and writers must hold it
    even for a snapshot read, because ``completed`` and ``last_objective``
    are written from the ThreadPoolExecutor workers without further
    coordination.
    """

    workbook_id: int
    total: int
    """Number of CCIs the batch will attempt. Set once at the start of
    Phase 2 and never changes."""
    completed: int = 0
    """CCIs that finished one way or another -- accepted, unresolved, or
    raised. Incremented by the worker callback regardless of outcome so
    the bar reaches 100% even when individual CCIs error out."""
    errored: int = 0
    """Subset of ``completed`` where the worker caught an exception.
    Surfaced so the UI can color the bar amber when failures accumulate
    before the final response lands."""
    started_at: float = field(default_factory=time.time)
    """``time.time()`` epoch -- used by the UI to render elapsed time and
    estimate ETA from the current rate."""
    last_objective: str | None = None
    """The most recent CCI id the worker reported. Lets the UI surface a
    'currently assessing CCI-001234' line so the user knows something is
    actively happening even when the count moves slowly."""


_LOCK = threading.Lock()
_ACTIVE: dict[int, _Progress] = {}


def start(workbook_id: int, total: int) -> None:
    """Register a new batch. Replaces any stale slot from a prior crash.

    Called by ``assess_objectives_batch`` immediately before the
    ThreadPoolExecutor.map fan-out, with the post-Phase-1 ``work_items``
    length as ``total``. Replacing rather than refusing on collision is
    deliberate: the UI's button-disable contract makes a real collision
    impossible; a stale slot only exists if a previous batch crashed
    before ``finish`` ran, and the right answer there is "trust the new
    batch's intent" rather than wedging on phantom state.
    """
    with _LOCK:
        _ACTIVE[workbook_id] = _Progress(workbook_id=workbook_id, total=total)


def record_done(workbook_id: int, objective_id: str | None, errored: bool) -> None:
    """Worker-side hook: one CCI finished, bump the counter.

    Tolerates a missing slot silently -- if the batch was never
    registered (defensive: future caller that forgets to call start)
    the worker still completes its DB / decision work without raising.
    Logging here would just spam the sidecar log; the
    /assess-batch/progress endpoint will simply report "no active batch"
    and the UI will hide its bar.
    """
    with _LOCK:
        p = _ACTIVE.get(workbook_id)
        if p is None:
            return
        p.completed += 1
        if errored:
            p.errored += 1
        if objective_id:
            p.last_objective = objective_id


def finish(workbook_id: int) -> None:
    """Clear the slot when the batch returns (success OR exception).

    Called from the ``finally:`` block in ``assess_objectives_batch`` so
    a mid-batch crash doesn't leave a dangling row that the next UI
    poll would interpret as "still running".
    """
    with _LOCK:
        _ACTIVE.pop(workbook_id, None)


def snapshot(workbook_id: int) -> dict | None:
    """Return a JSON-safe copy of the slot or None if no batch is active.

    The dict shape mirrors ``_Progress`` field names so the UI's
    TypeScript surface can ``as``-cast it directly.
    """
    with _LOCK:
        p = _ACTIVE.get(workbook_id)
        if p is None:
            return None
        return asdict(p)
