"""In-memory ingest-job registry — fire-and-poll wrapper around ingest_source.

The synchronous ``POST /api/evidence/ingest`` blocked the FastAPI request
thread for the duration of a full source walk. On a SharePoint pull of
the demo set that's minutes, during which the UI spinner is the only
feedback the user gets. This module turns the call into a fire-and-poll
pattern: the route spawns a daemon thread, returns a ``job_id`` instantly,
and the UI polls a status endpoint to render a live counter.

The registry is process-local and **not** persisted — it's a UI affordance,
not a durable queue. A sidecar restart wipes in-flight jobs (their
already-committed Evidence rows survive in SQLite). Only one ingest job
can be active at a time; the route rejects concurrent starts so the
batch-commit cadence in :func:`ingest_source` doesn't trip over itself.

Pattern intentionally mirrors the MSAL device-code flow in
``routes/sharepoint.py`` — threading.Thread + lock-guarded dict — so
there's one in-process concurrency story across the sidecar, not two.

Concurrency note — single-file ingest
--------------------------------------
``ingest.ingest_single_local_file`` is a synchronous helper used by the
boundary-doc upload route. It calls ``ingest_source`` directly and therefore
bypasses the daemon-thread + JobRegistry mutex that batch ingest uses. Two
concurrent boundary-doc uploads (or a batch job and a boundary-doc upload
running simultaneously) would then race on the same SQLite write path.

SQLite WAL + busy_timeout=60s (see db.py) make writer–writer contention safe
in theory, but the batch-commit cadence in ``ingest_source`` means the window
of contention is measured in seconds, not microseconds. To eliminate the race
entirely, single-file ingest now also goes through the registry mutex via
:meth:`JobRegistry.claim_single_file`. The claim is synchronous (no thread),
so the route's caller blocks until the registry is free — matching the
existing 409-on-busy semantics while keeping a single in-process concurrency
story.
"""

from __future__ import annotations

import contextlib
import logging
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Generator, Literal

from ..db import session_scope
from .ingest import IngestSummary, ingest_source
from .sources import Source

log = logging.getLogger(__name__)

JobStatus = Literal["running", "done", "error"]


def _estimate_total(source: Source) -> int | None:
    """Best-effort, duck-typed pre-count of files a source will yield.

    The ``Source`` protocol is iterator-only (``uri`` + ``iter_files``); its
    docstring sanctions optional metadata via ``getattr`` rather than widening
    the protocol. A source that can count cheaply (``LocalFolderSource`` reuses
    its rglob filter) exposes ``estimated_total()``; streaming sources omit it
    so we never trigger a second network walk. Any failure degrades silently to
    ``None`` → the UI renders an indeterminate bar exactly as before.
    """
    counter = getattr(source, "estimated_total", None)
    if not callable(counter):
        return None
    try:
        total = counter()
    except Exception:  # pragma: no cover - estimate is purely advisory
        log.debug("estimated_total() failed for %r", source, exc_info=True)
        return None
    if isinstance(total, int) and total >= 0:
        return total
    return None


@dataclass
class IngestJob:
    """One ingest run's worth of state — what the polling endpoint returns."""

    job_id: str
    source_uri: str
    status: JobStatus = "running"
    started_at: str = ""
    finished_at: str | None = None
    # v0.3-ready: the workbook (and therefore framework) the user had open
    # when the ingest fired. Persisted so the UI's progress strip can
    # remind the assessor which catalog lens auto-tags will land under.
    workbook_id: int | None = None
    # Best-effort file count known up front, so the UI can render a real
    # progress bar + ETA instead of an indeterminate sweep. Populated only
    # when the source can cheaply pre-count (LocalFolderSource reuses its
    # rglob filter); streaming sources (SharePoint) leave this ``None`` to
    # avoid a second network walk, and the UI falls back to indeterminate.
    estimated_total: int | None = None
    # Live counters mirrored from IngestSummary so the UI doesn't need to
    # reach into a nested ``summary`` blob while the job is still running.
    scanned: int = 0
    ingested: int = 0
    skipped_existing: int = 0
    skipped_unsupported: int = 0
    tags_created: int = 0
    findings_created: int = 0
    error_count: int = 0
    # Full summary dict, populated on completion (status != "running").
    summary: dict | None = None
    # Fatal error (thread crashed). Per-file errors live in summary["errors"].
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class JobRegistry:
    """Thread-safe registry of in-process ingest jobs.

    Single instance, module-level singleton (see ``registry`` below). The
    lock is held only across dict mutations / reads — never across the
    ingest work itself — so the polling endpoint never blocks behind a
    slow file extraction.
    """

    def __init__(self) -> None:
        self._jobs: dict[str, IngestJob] = {}
        self._lock = threading.Lock()
        self._active_job_id: str | None = None

    # -- lifecycle -----------------------------------------------------

    def start_ingest_job(
        self, source: Source, *, workbook_id: int | None = None
    ) -> str:
        """Spawn a daemon thread to walk ``source``; return the job id.

        Refuses to start a second job while one is already running — the
        in-memory counters and the per-thread Session would race otherwise.
        Callers should surface the rejection to the UI so the user can
        either wait or (eventually) cancel the in-flight job.

        ``workbook_id`` (v0.3-ready) ties the run to the catalog lens that
        was active in the UI when the user kicked it off. Threaded straight
        through to :func:`ingest_source` so auto-tags get stamped with the
        matching ``EvidenceTag.framework_id``. ``None`` is the framework-
        agnostic default — historical behavior preserved for legacy callers.
        """
        with self._lock:
            if self._active_job_id is not None:
                active = self._jobs.get(self._active_job_id)
                if active and active.status == "running":
                    raise RuntimeError(
                        f"An ingest job is already running ({self._active_job_id})."
                    )

            job_id = uuid.uuid4().hex
            job = IngestJob(
                job_id=job_id,
                source_uri=getattr(source, "uri", "") or "",
                started_at=datetime.now(timezone.utc).isoformat(),
                workbook_id=workbook_id,
                estimated_total=_estimate_total(source),
            )
            self._jobs[job_id] = job
            self._active_job_id = job_id

        # Spawn outside the lock — Thread.start() returns immediately, but
        # holding the lock through it would still serialise unnecessarily.
        thread = threading.Thread(
            target=self._run_job,
            args=(job_id, source, workbook_id),
            name=f"ingest-{job_id[:8]}",
            daemon=True,
        )
        thread.start()
        return job_id

    def _run_job(
        self, job_id: str, source: Source, workbook_id: int | None = None
    ) -> None:
        """Background-thread entry point. Owns its own Session.

        FastAPI's ``get_session`` dependency is request-scoped and would
        die with the originating HTTP response — we open a fresh Session
        via ``session_scope`` so the thread has its own transaction.

        Acquires ``_INGEST_LOCK`` for the duration of the walk so that a
        concurrent ``claim_single_file`` call is rejected (409) while a
        batch job runs. The lock is blocking here (no timeout) because the
        registry already refuses to start a second batch job via the
        ``_active_job_id`` guard in ``start_ingest_job``; the lock wait will
        only block if a single-file claim beat us, which is bounded by one
        file's extraction time — well under the SQLite busy_timeout (60s).
        """

        def _on_progress(summary: IngestSummary) -> None:
            with self._lock:
                job = self._jobs.get(job_id)
                if job is None:
                    return
                job.scanned = summary.scanned
                job.ingested = summary.ingested
                job.skipped_existing = summary.skipped_existing
                job.skipped_unsupported = summary.skipped_unsupported
                job.tags_created = summary.tags_created
                job.findings_created = summary.findings_created
                job.error_count = len(summary.errors)

        # Acquire the shared writer lock before any SQLite writes. Blocking
        # is safe here: the only holder would be a single-file claim, which
        # is bounded in time. The lock is released in the finally block.
        _INGEST_LOCK.acquire()
        try:
            with session_scope() as session:
                summary = ingest_source(
                    session,
                    source,
                    progress_callback=_on_progress,
                    workbook_id=workbook_id,
                )
            with self._lock:
                job = self._jobs.get(job_id)
                if job is not None:
                    job.status = "done"
                    job.finished_at = datetime.now(timezone.utc).isoformat()
                    job.summary = summary.as_dict()
                    # Mirror final counters in case the last _on_progress
                    # was swallowed (it shouldn't be, but belt + braces).
                    job.scanned = summary.scanned
                    job.ingested = summary.ingested
                    job.skipped_existing = summary.skipped_existing
                    job.skipped_unsupported = summary.skipped_unsupported
                    job.tags_created = summary.tags_created
                    job.findings_created = summary.findings_created
                    job.error_count = len(summary.errors)
        except Exception as exc:  # pragma: no cover - unexpected fatal
            log.exception("ingest job %s crashed", job_id)
            with self._lock:
                job = self._jobs.get(job_id)
                if job is not None:
                    job.status = "error"
                    job.finished_at = datetime.now(timezone.utc).isoformat()
                    job.error = f"{type(exc).__name__}: {exc}"
        finally:
            _INGEST_LOCK.release()
            with self._lock:
                if self._active_job_id == job_id:
                    self._active_job_id = None

    # -- read accessors ------------------------------------------------

    def get_job(self, job_id: str) -> IngestJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def get_active_job(self) -> IngestJob | None:
        """The currently-running job, if any. Returns None when idle.

        The UI calls this on page load so a tab refresh in the middle of
        an ingest reattaches the progress strip without losing context.
        """
        with self._lock:
            active_id = self._active_job_id
            if active_id is None:
                return None
            job = self._jobs.get(active_id)
            if job is None or job.status != "running":
                return None
            return job

    @contextlib.contextmanager
    def claim_single_file(self) -> Generator[None, None, None]:
        """Serialise synchronous single-file ingest through the same mutex.

        Usage (in the boundary-doc upload route)::

            with registry.claim_single_file():
                ev = ingest_single_local_file(session, path, workbook_id=wid)

        Raises RuntimeError (→ 409) if a batch job is already running or if
        another single-file ingest is in progress, matching the existing
        semantics of :meth:`start_ingest_job`.

        Implementation: acquires ``_INGEST_LOCK`` non-blocking so the route
        layer can surface a 409 immediately instead of waiting. Also sets
        ``_active_job_id`` to a synthetic sentinel so :meth:`get_active_job`
        correctly reports the registry as busy during the single-file window.
        """
        # Fast-path: refuse if a batch job claims the registry.
        with self._lock:
            if self._active_job_id is not None:
                active = self._jobs.get(self._active_job_id)
                if active and active.status == "running":
                    raise RuntimeError(
                        f"An ingest job is already running ({self._active_job_id})."
                    )

        # Try to acquire the shared writer lock non-blocking. If another
        # single-file ingest (or a batch job that already grabbed the lock)
        # is in progress, raise 409-equivalent immediately.
        acquired = _INGEST_LOCK.acquire(blocking=False)
        if not acquired:
            raise RuntimeError(
                "Another ingest operation is in progress — please retry shortly."
            )

        sentinel_id = f"__single_file_{uuid.uuid4().hex}"
        with self._lock:
            self._active_job_id = sentinel_id
        try:
            yield
        finally:
            with self._lock:
                if self._active_job_id == sentinel_id:
                    self._active_job_id = None
            _INGEST_LOCK.release()


# ---------------------------------------------------------------------------
# Shared ingest serialisation lock
#
# ``ingest_single_local_file`` (called synchronously from the boundary-doc
# upload route) bypasses the JobRegistry daemon thread entirely, so it
# cannot hold the registry's internal ``_lock`` (that lock is private and
# not reentrant). Instead we expose this module-level threading.Lock so that
# BOTH paths can share a single serialisation point:
#
#   * Batch ingest (JobRegistry._run_job) acquires ``_INGEST_LOCK`` for the
#     full duration of the walk.
#   * Single-file ingest (ingest_single_local_file, via the
#     ``claim_single_file`` context manager) acquires it for the duration of
#     one file's ingest.
#
# SQLite WAL + busy_timeout=60s (db.py) would handle the resulting writer–
# writer contention, but the contention window with 50-file batches is up to
# seconds, not microseconds. The lock eliminates that window entirely and
# avoids a busy_timeout retry storm for concurrent boundary-doc uploads.
#
# Non-blocking: ``claim_single_file`` raises RuntimeError (→ 409) if it
# cannot acquire immediately, matching the batch-job rejection semantics.
# ``_run_job`` blocks up to the SQLite busy_timeout (60s) if the single-file
# path holds the lock — that window is bounded by one file's extraction time,
# well under the busy_timeout. Inversion of wait direction is acceptable
# because batch jobs start less frequently than boundary-doc uploads.
# ---------------------------------------------------------------------------
_INGEST_LOCK: threading.Lock = threading.Lock()

# Module-level singleton — the route imports this directly.
registry = JobRegistry()
