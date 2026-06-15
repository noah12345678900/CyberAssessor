"""Per-workbook autostart scheduler.

A single background thread ticks every ``automation_tick_seconds`` and
fires any enabled :class:`~cybersecurity_assessor.models.AutomationSchedule`
rows whose ``next_run_at <= now``.

Concurrency contract
---------------------
The ingest path uses a single daemon thread protected by ``_INGEST_LOCK``
(in ``evidence/jobs.py``).  The scheduler NEVER blocks on that lock; if
the registry is busy it defers the schedule by one tick interval and moves
on.  This guarantees the scheduler loop is never stalled by a long-running
ingest.

Assessment chain
-----------------
When ``run_assessment=True`` and the ingest succeeded, the scheduler posts
to ``POST /api/controls/assess-batch`` via ``httpx`` on loopback so we reuse
the existing route logic (and its session management, batch progress tracker,
etc.) without duplicating it here.  The sidecar's listening address is
injected at startup via :func:`configure`.

Never-raises guarantee
-----------------------
Each schedule row is wrapped in its own try/except so one broken schedule
cannot kill the tick loop.  Mirrors the pattern in ``supersession_tracker``.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_tick_thread: threading.Thread | None = None
_stop_event: threading.Event = threading.Event()

# Set by configure() at lifespan startup so the assess chain knows the port.
_base_url: str = "http://127.0.0.1:8000"


def configure(base_url: str) -> None:
    """Inject the sidecar's bound base URL before the tick loop starts."""
    global _base_url
    _base_url = base_url.rstrip("/")


# ---------------------------------------------------------------------------
# Source construction helpers
# ---------------------------------------------------------------------------


def _build_source(source_type: str, source_ref: str | None):  # type: ignore[return]
    """Construct a :class:`~evidence.sources.Source` from scheduler row fields.

    Returns ``None`` and logs a warning for unknown/unconfigured types so the
    tick loop can mark the row as an error without crashing.
    """
    from pathlib import Path

    from .sources import (
        AzureBlobSource,
        LocalFolderSource,
        S3Source,
        SharePointSource,
    )
    from ..config import load_config

    st = source_type.lower()

    if st == "local":
        root = Path(source_ref) if source_ref else None
        if root is None or not root.exists() or not root.is_dir():
            log.warning(
                "scheduler: local source_ref %r is not a valid directory — skipping",
                source_ref,
            )
            return None
        return LocalFolderSource(root, recursive=True)

    if st == "sharepoint":
        cfg = load_config()
        site_url = source_ref or cfg.sharepoint_site_url
        if not site_url:
            log.warning(
                "scheduler: sharepoint source_ref and sharepoint_site_url are both "
                "unset — skipping"
            )
            return None
        return SharePointSource(
            site_url,
            cfg.sharepoint_library or "",
            cfg.sharepoint_folder_path or "",
        )

    if st == "s3":
        # source_ref expected as "bucket/prefix" or just "bucket"
        if not source_ref:
            log.warning("scheduler: s3 source requires source_ref='bucket[/prefix]'")
            return None
        parts = source_ref.split("/", 1)
        bucket, prefix = parts[0], parts[1] if len(parts) > 1 else ""
        return S3Source(bucket, prefix)

    if st in ("azblob", "azure"):
        # source_ref expected as "account/container[/prefix]"
        if not source_ref:
            log.warning(
                "scheduler: azblob source requires source_ref='account/container[/prefix]'"
            )
            return None
        parts = source_ref.split("/", 2)
        if len(parts) < 2:
            log.warning("scheduler: azblob source_ref must be 'account/container[/prefix]'")
            return None
        account, container = parts[0], parts[1]
        prefix = parts[2] if len(parts) > 2 else ""
        return AzureBlobSource(account, container, prefix)

    if st == "gitlab":
        cfg = load_config()
        if not cfg.enable_gitlab:
            log.warning("scheduler: gitlab connector disabled (enable_gitlab=False) — skipping")
            return None
        server_url = source_ref or cfg.gitlab_server_url
        project_paths = [p for p in cfg.gitlab_project_paths if p and p.strip()]
        if not server_url or not project_paths:
            log.warning(
                "scheduler: gitlab not configured (need gitlab_server_url + "
                "gitlab_project_paths) — skipping"
            )
            return None
        from .sources import GitLabSource

        try:
            return GitLabSource(
                server_url=server_url,
                project_paths=project_paths,
                ref=(cfg.gitlab_ref or "HEAD"),
                include_globs=tuple(cfg.gitlab_include_globs) or None,
            )
        except Exception:
            log.exception("scheduler: failed to build GitLabSource — skipping")
            return None

    if st == "splunk":
        from ..config import get_splunk_token

        cfg = load_config()
        if not cfg.enable_splunk:
            log.warning("scheduler: splunk connector disabled (enable_splunk=False) — skipping")
            return None
        host = (cfg.splunk_host or "").strip()
        token = get_splunk_token()
        saved = [s.strip() for s in cfg.splunk_saved_searches if s and s.strip()]
        if not host or not token or not saved:
            log.warning(
                "scheduler: splunk not configured (need host, stored token, and at "
                "least one saved search) — skipping"
            )
            return None
        from .sources import SplunkSource

        try:
            return SplunkSource(
                host=host,
                token=token,
                saved_searches=saved,
                port=int(cfg.splunk_port),
                scheme=cfg.splunk_scheme,
                app=cfg.splunk_app,
                owner=cfg.splunk_owner,
                verify=bool(cfg.splunk_verify_tls),
            )
        except Exception:
            log.exception("scheduler: failed to build SplunkSource — skipping")
            return None

    if st == "tenable":
        from ..config import get_tenable_access_key, get_tenable_secret_key

        cfg = load_config()
        if not cfg.enable_tenable:
            log.warning("scheduler: tenable connector disabled (enable_tenable=False) — skipping")
            return None
        flavor = (cfg.tenable_flavor or "").strip().lower()
        if flavor not in ("sc", "io"):
            log.warning("scheduler: tenable flavor not set ('sc' or 'io') — skipping")
            return None
        access = get_tenable_access_key()
        secret = get_tenable_secret_key()
        if not access or not secret:
            log.warning("scheduler: tenable keyset not stored — skipping")
            return None
        host = None if flavor == "io" else ((cfg.tenable_host or "").strip().rstrip("/") or None)
        if flavor == "sc" and not host:
            log.warning("scheduler: tenable.sc requires tenable_host — skipping")
            return None
        from .sources import TenableSource

        try:
            # feature_enabled must be True or iter_files() yields nothing.
            return TenableSource(
                flavor=flavor,  # type: ignore[arg-type]
                access_key=access,
                secret_key=secret,
                host=host,
                feature_enabled=True,
            )
        except Exception:
            log.exception("scheduler: failed to build TenableSource — skipping")
            return None

    if st in ("servicenow_grc", "snow_grc", "servicenow"):
        cfg = load_config()
        if not cfg.enable_snow_grc:
            log.warning(
                "scheduler: servicenow_grc connector disabled (enable_snow_grc=False) — skipping"
            )
            return None
        instance_url = (cfg.servicenow_grc_instance_url or "").strip()
        username = (cfg.servicenow_grc_username or "").strip()
        auth = (cfg.servicenow_grc_auth_method or "").strip().lower()
        if not instance_url or not username or auth not in ("oauth", "basic"):
            log.warning(
                "scheduler: servicenow_grc not configured (need instance_url, username, "
                "auth_method 'oauth'|'basic') — skipping"
            )
            return None
        from .sources.servicenow_grc import (
            DEFAULT_TABLES,
            SnowGrcConfig,
            TableSpec,
            build_source_from_config,
        )

        tables = [t.strip() for t in cfg.servicenow_grc_allowed_tables if t and t.strip()] or list(
            DEFAULT_TABLES
        )
        try:
            snow_cfg = SnowGrcConfig(
                instance_url=instance_url,
                auth_mode=auth,
                oauth_client_id=username if auth == "oauth" else None,
                basic_username=username if auth == "basic" else None,
                tables=tuple(TableSpec(name=n) for n in tables),
            )
            return build_source_from_config(snow_cfg)
        except Exception:
            log.exception("scheduler: failed to build ServiceNowGrcSource — skipping")
            return None

    if st == "archer":
        # Archer ingest needs per-application query IDs that aren't carried in
        # plain AppConfig, so it can't be driven from a schedule row alone.
        log.warning(
            "scheduler: archer is not supported for scheduled pulls (requires "
            "per-application query IDs) — skipping"
        )
        return None

    log.warning("scheduler: unknown source_type %r — skipping", source_type)
    return None


def _build_all_sources(source_ref: str | None) -> list[tuple[str, object]]:
    """Build every configured + enabled source for a ``source_type='all'`` row.

    Tries each connector the scheduler can construct from config and keeps the
    ones that build successfully. ``local`` consumes ``source_ref`` as its root;
    the connector types read their own config/secrets and ignore ``source_ref``.
    Unconfigured / disabled connectors are silently skipped (``_build_source``
    logs the reason), so the returned list is exactly what will be ingested.
    """
    out: list[tuple[str, object]] = []
    for st in ("local", "sharepoint", "gitlab", "splunk", "tenable", "servicenow_grc"):
        ref = source_ref if st == "local" else None
        src = _build_source(st, ref)
        if src is not None:
            out.append((st, src))
    return out


# ---------------------------------------------------------------------------
# Per-schedule fire logic
# ---------------------------------------------------------------------------


def _run_ingest_source(
    label: str,
    source: object,
    workbook_id: int,
    tick_seconds: int,
) -> tuple[str, str]:
    """Start one ingest job for ``source`` and poll it to completion.

    Returns ``(status, detail)`` where status is ``"ok"`` or ``"error"``. The
    detail string is a compact per-source summary suitable for concatenation
    into a schedule's ``last_detail``. Never raises — registry contention and
    timeouts are reported through the return value so an ``all`` fan-out keeps
    running the remaining sources.
    """
    from .jobs import registry as ingest_jobs

    try:
        job_id = ingest_jobs.start_ingest_job(source, workbook_id=workbook_id)
    except RuntimeError as exc:
        return "error", f"{label}: registry busy ({exc})"
    except Exception as exc:  # noqa: BLE001 — never let one source kill the run
        log.exception("scheduler: %s ingest failed to start", label)
        return "error", f"{label}: start failed ({exc})"

    log.info("scheduler: %s started ingest job %s (workbook=%d)", label, job_id, workbook_id)

    deadline = time.monotonic() + 7200
    poll_interval = 5  # seconds
    while time.monotonic() < deadline:
        time.sleep(poll_interval)
        job = ingest_jobs.get_job(job_id)
        if job is None or job.status != "running":
            break

    job = ingest_jobs.get_job(job_id)
    if job is None or job.status == "running":
        return "error", f"{label}: ingest did not finish within 2 hours"

    if job.status == "error":
        err = job.error or "ingest job reported error"
        log.warning("scheduler: %s ingest failed: %s", label, err)
        return "error", f"{label}: {err}"

    summary = job.summary or {}
    detail = (
        f"{label}: ingested={summary.get('ingested', 0)} "
        f"skipped={summary.get('skipped_existing', 0)} "
        f"tags={summary.get('tags_created', 0)} "
        f"errors={len(summary.get('errors', []))}"
    )
    log.info("scheduler: %s ingest done — %s", label, detail)
    return "ok", detail


def _run_assess_chain(workbook_id: int) -> str:
    """Trigger the assess-batch route on loopback. Returns a detail fragment.

    Never raises — any failure is folded into the returned string so the
    schedule still records an overall result.
    """
    try:
        import httpx

        resp = httpx.post(
            f"{_base_url}/api/controls/assess-batch",
            json={"workbook_id": workbook_id, "skip_existing": False, "persist": True},
            timeout=7200.0,
        )
        if resp.status_code == 200:
            accepted = resp.json().get("accepted", 0)
            log.info("scheduler: assess chain done (workbook=%d) — accepted=%d", workbook_id, accepted)
            return f"assess accepted={accepted}"
        log.warning("scheduler: assess chain returned %d (workbook=%d)", resp.status_code, workbook_id)
        return f"assess chain HTTP {resp.status_code}"
    except Exception as exc:  # noqa: BLE001
        log.exception("scheduler: assess chain raised (workbook=%d)", workbook_id)
        return f"assess chain error: {exc}"


def _fire_schedule(schedule_id: int, tick_seconds: int) -> None:
    """Run one schedule row: ingest → optional assess chain.

    Uses its own ``session_scope`` so the caller's session is not held across
    the potentially long ingest wait.  All exceptions are caught so a broken
    schedule cannot kill the tick loop.
    """
    from ..db import session_scope
    from ..models import AutomationSchedule, _utcnow
    from .jobs import registry as ingest_jobs

    def _utcnow_aware() -> datetime:
        return datetime.now(timezone.utc)

    def _patch(status: str, detail: str, now: datetime, interval_minutes: int) -> None:
        """Write last_status / last_detail / next_run_at back to the row."""
        with session_scope() as s:
            row = s.get(AutomationSchedule, schedule_id)
            if row is None:
                return
            row.last_run_at = now
            row.last_status = status
            row.last_detail = detail
            row.next_run_at = now + timedelta(minutes=interval_minutes)
            from ..models import _utcnow as _un
            row.updated_at = _un()
            s.add(row)
            # session_scope commits on exit

    # --- load the row ---
    try:
        with session_scope() as s:
            row = s.get(AutomationSchedule, schedule_id)
            if row is None:
                return
            workbook_id = row.workbook_id
            source_type = row.source_type
            source_ref = row.source_ref
            interval_minutes = row.interval_minutes
            run_assessment = row.run_assessment
    except Exception:
        log.exception("scheduler: failed to load schedule %d", schedule_id)
        return

    now = _utcnow_aware()

    # --- check registry availability (non-blocking) ---
    active = ingest_jobs.get_active_job()
    if active is not None:
        # Defer: push next_run_at out by one tick interval (not the full
        # schedule interval) so we retry shortly without hammering.
        backoff = max(tick_seconds, 60)
        with session_scope() as s:
            row = s.get(AutomationSchedule, schedule_id)
            if row is None:
                return
            row.next_run_at = now + timedelta(seconds=backoff)
            from ..models import _utcnow as _un
            row.updated_at = _un()
            s.add(row)
        log.info(
            "scheduler: schedule %d deferred (ingest busy); next_run in %ds",
            schedule_id,
            backoff,
        )
        return

    # --- build source(s) and run ingest(s) ---
    # The registry is single-job, so an "all" fan-out runs each connector
    # serially (each ingest is polled to completion before the next starts).
    if source_type.lower() == "all":
        built = _build_all_sources(source_ref)
        if not built:
            _patch(
                "error",
                "source_type='all' built no sources — no connectors are "
                "enabled/configured (see logs for per-connector reasons)",
                now,
                interval_minutes,
            )
            return

        fragments: list[str] = []
        any_ok = False
        for label, source in built:
            status, detail = _run_ingest_source(label, source, workbook_id, tick_seconds)
            fragments.append(detail)
            if status == "ok":
                any_ok = True

        # Run the assess chain once after all ingests, if any succeeded.
        if run_assessment and any_ok:
            fragments.append(_run_assess_chain(workbook_id))

        overall = "ok" if any_ok else "error"
        _patch(overall, " | ".join(fragments), now, interval_minutes)
        return

    # --- single source ---
    source = _build_source(source_type, source_ref)
    if source is None:
        _patch(
            "error",
            f"Could not build source for type={source_type!r} ref={source_ref!r}",
            now,
            interval_minutes,
        )
        return

    status, detail = _run_ingest_source(source_type, source, workbook_id, tick_seconds)
    if status != "ok":
        _patch("error", detail, now, interval_minutes)
        return

    # --- optional assessment chain ---
    if run_assessment:
        detail += "; " + _run_assess_chain(workbook_id)

    _patch("ok", detail, now, interval_minutes)


# ---------------------------------------------------------------------------
# Tick loop
# ---------------------------------------------------------------------------


def _tick_loop(tick_seconds: int) -> None:
    """Background thread: wake every ``tick_seconds``, fire due schedules."""
    from ..config import load_config
    from ..db import session_scope
    from ..models import AutomationSchedule

    log.info("scheduler: tick loop started (interval=%ds)", tick_seconds)

    while not _stop_event.is_set():
        # Re-read config each tick so a live config change (automation_enabled
        # flipped to False) is honoured without a sidecar restart.
        try:
            cfg = load_config()
            if not cfg.automation_enabled:
                _stop_event.wait(tick_seconds)
                continue
        except Exception:
            log.exception("scheduler: failed to load config; sleeping")
            _stop_event.wait(tick_seconds)
            continue

        now = datetime.now(timezone.utc)
        due_ids: list[int] = []
        try:
            from sqlmodel import select as _select

            with session_scope() as s:
                rows = s.exec(
                    _select(AutomationSchedule)
                    .where(AutomationSchedule.enabled == True)  # noqa: E712
                    .where(AutomationSchedule.next_run_at <= now)
                    .order_by(AutomationSchedule.next_run_at)
                ).all()
                due_ids = [r.id for r in rows if r.id is not None]
        except Exception:
            log.exception("scheduler: error querying due schedules")
            _stop_event.wait(tick_seconds)
            continue

        for sid in due_ids:
            if _stop_event.is_set():
                break
            try:
                _fire_schedule(sid, tick_seconds)
            except Exception:
                # Never-raises: one bad schedule must not kill the loop.
                log.exception("scheduler: uncaught exception firing schedule %d", sid)

        _stop_event.wait(tick_seconds)

    log.info("scheduler: tick loop stopped")


# ---------------------------------------------------------------------------
# Public API (called by server.py lifespan)
# ---------------------------------------------------------------------------


def start_scheduler(tick_seconds: int = 60) -> None:
    """Start the background tick thread.  No-op if already running."""
    global _tick_thread, _stop_event

    if _tick_thread is not None and _tick_thread.is_alive():
        log.debug("scheduler: already running — ignoring start_scheduler() call")
        return

    _stop_event = threading.Event()
    _tick_thread = threading.Thread(
        target=_tick_loop,
        args=(tick_seconds,),
        name="automation-scheduler",
        daemon=True,
    )
    _tick_thread.start()


def stop_scheduler() -> None:
    """Signal the tick thread to stop and wait up to 5 s for it to exit."""
    global _tick_thread

    if _tick_thread is None or not _tick_thread.is_alive():
        return

    _stop_event.set()
    _tick_thread.join(timeout=5)
    _tick_thread = None
    log.info("scheduler: stopped")
