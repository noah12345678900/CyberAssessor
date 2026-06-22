"""FastAPI sidecar entry point.

Electron spawns this process and reads the bound port from stdout (line
prefixed with ``CCIS_PORT=``). All endpoints bind to 127.0.0.1 only.
"""

from __future__ import annotations

# MUST run before anthropic / httpx are imported so the patched ssl
# context is in effect when those clients build their default transport.
from . import tls as _tls

_tls.install()

import argparse  # noqa: E402
import asyncio  # noqa: E402
import logging  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
from collections.abc import AsyncIterator  # noqa: E402
from contextlib import asynccontextmanager  # noqa: E402
from logging.handlers import RotatingFileHandler  # noqa: E402

import uvicorn  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402

from . import __version__  # noqa: E402
from .config import config_dir, load_config  # noqa: E402
from .db import init_db, session_scope  # noqa: E402
from .evidence.scheduler import configure as _scheduler_configure  # noqa: E402
from .evidence.scheduler import start_scheduler, stop_scheduler  # noqa: E402
from .evidence.scope_backfill import run_scope_backfill  # noqa: E402
from .routes import (  # noqa: E402
    archer,
    automation,
    baselines,
    boundary_sweep,
    calibration,
    catalog,
    confluence,
    controls,
    emass,
    evidence,
    gitlab,
    jira,
    metrics,
    poams,
    reports,
    runs,
    scope,
    servicenow_grc,
    settings,
    sharepoint,
    splunk,
    stig,
    supersession,
    system_context,
    tenable,
    workbooks,
)


def _install_file_logging() -> None:
    """Mirror sidecar logs to ~/.cybersecurity-assessor/sidecar.log.

    Electron launches this process detached, so stderr/stdout never reach
    the user. Without a file sink, every exception inside a route handler
    vanishes — the user just sees ERR_FAILED in DevTools. RotatingFileHandler
    keeps the file from growing unbounded (10MB x 3 = 40MB ceiling). Called
    once at import time so the handler is in place before any route serves
    a request.
    """
    log_path = config_dir() / "sidecar.log"
    handler = RotatingFileHandler(
        log_path, maxBytes=10 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    root = logging.getLogger()
    # Don't double-attach if the module is re-imported (uvicorn --reload).
    if not any(
        isinstance(h, RotatingFileHandler)
        and getattr(h, "baseFilename", None) == str(log_path)
        for h in root.handlers
    ):
        root.addHandler(handler)
    # INFO captures the assess-batch per-CCI failure log + any
    # logger.exception() call site without flooding the file.
    if root.level > logging.INFO or root.level == logging.NOTSET:
        root.setLevel(logging.INFO)


_install_file_logging()


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    # Lifespan replaces the deprecated @app.on_event("startup") hook.
    # init_db() runs additive ALTER TABLE migrations for columns added
    # after the initial schema (see db._ADDITIVE_COLUMNS) — must run
    # before any route serves a query.
    init_db()
    # One-shot scope-table backfill from legacy Evidence.host_inventory
    # JSON + is_boundary_doc flag. Idempotent — short-circuits if any
    # EvidenceAsset/EvidenceBoundary row already exists. Logs only on
    # actual work done; startup stays silent on already-migrated DBs.
    try:
        with session_scope() as s:
            summary = run_scope_backfill(s)
        if summary.assets_created or summary.boundary_segments_created:
            logging.getLogger(__name__).info(
                "scope_backfill: assets=%d boundaries=%d "
                "ev_asset_links=%d ev_boundary_links=%d",
                summary.assets_created,
                summary.boundary_segments_created,
                summary.asset_links_created,
                summary.boundary_links_created,
            )
    except Exception:  # pragma: no cover - startup must never wedge
        # A broken backfill must not prevent the sidecar from coming up.
        # The legacy fallback in asset_crosscheck still serves the data;
        # the worst case is the new filter chips render empty until the
        # underlying issue is fixed.
        logging.getLogger(__name__).exception("scope_backfill failed; continuing startup")

    # Start the automation scheduler if the master switch is on.
    # The base URL is loopback — port is irrelevant here because the
    # assess-chain call happens on the already-listening server; we leave
    # port=8000 as a placeholder and the `_serve_with_handshake` path
    # overrides it via configure() after binding.  On --reload the port
    # is pinned explicitly so this is always correct.
    _cfg = load_config()
    if _cfg.automation_enabled:
        # Port is not yet known at this exact moment (uvicorn binds after
        # lifespan yields), but configure() is called again from
        # _serve_with_handshake once the actual port is known.  The
        # default 127.0.0.1:8000 serves --reload runs that pin a port.
        _scheduler_configure("http://127.0.0.1:8000")
        start_scheduler(tick_seconds=_cfg.automation_tick_seconds)
        logging.getLogger(__name__).info(
            "automation scheduler started (tick=%ds)", _cfg.automation_tick_seconds
        )

    yield

    # Graceful shutdown.
    stop_scheduler()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Cybersecurity Assessor sidecar",
        version=__version__,
        description="Local-only FastAPI sidecar for the Electron UI.",
        lifespan=_lifespan,
    )

    # Vite dev server runs on a different port; allow it
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "app://-",  # electron production
        ],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
        # Pagination total — JS can only read this cross-origin if it's
        # explicitly exposed (allow_headers governs the REQUEST side, not
        # the response side). The Evidence list returns the pre-limit count
        # here so the UI can render "page N of M".
        expose_headers=["X-Total-Count"],
    )

    @app.get("/healthz", tags=["meta"])
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    app.include_router(automation.router)
    app.include_router(catalog.router)
    app.include_router(workbooks.router)
    app.include_router(baselines.router)
    app.include_router(controls.router)
    app.include_router(evidence.router)
    app.include_router(scope.router)
    app.include_router(stig.router)
    app.include_router(runs.router)
    app.include_router(reports.router)
    app.include_router(settings.router)
    app.include_router(confluence.router)
    app.include_router(emass.router)
    app.include_router(poams.router)
    app.include_router(sharepoint.router)
    app.include_router(tenable.router)
    app.include_router(servicenow_grc.router)
    app.include_router(archer.router)
    app.include_router(splunk.router)
    app.include_router(boundary_sweep.router)
    app.include_router(gitlab.router)
    app.include_router(jira.router)
    app.include_router(system_context.router)
    app.include_router(metrics.router)
    app.include_router(supersession.router)
    app.include_router(calibration.router)

    return app


app = create_app()


# Seconds between parent-liveness polls. Short enough that an orphaned
# sidecar dies within a couple seconds of its Electron parent, long enough
# that the poll loop is free (one syscall per tick).
_PARENT_POLL_SECONDS = 2.0


def _pid_alive(pid: int) -> bool:
    """Return True while process ``pid`` is still running.

    On Windows we cannot rely on ``os.kill(pid, 0)`` — it raises on
    access-denied for processes we don't own, which would read as "alive"
    even after death. Instead open a SYNCHRONIZE handle and ask the kernel
    whether the process object is signaled: WAIT_OBJECT_0 (0) means it has
    exited, WAIT_TIMEOUT (0x102) means it's still live. If OpenProcess
    fails the PID is gone (or recycled to something we can't see) — treat
    as dead so the watchdog errs toward self-termination, never toward a
    lingering orphan.
    """
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes

        SYNCHRONIZE = 0x00100000
        WAIT_OBJECT_0 = 0x0
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(SYNCHRONIZE, False, pid)
        if not handle:
            return False
        try:
            return kernel32.WaitForSingleObject(handle, 0) != WAIT_OBJECT_0
        finally:
            kernel32.CloseHandle(handle)
    else:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True


def _start_parent_watchdog() -> None:
    """Self-terminate when the spawning Electron process disappears.

    Electron passes its own PID via ``CCIS_PARENT_PID``. EDR on locked-down
    federal endpoints protects python.exe from cross-process termination —
    even the direct parent gets Access Denied on taskkill /F — so the app
    cannot reliably reap us from the outside. A process exiting *itself* is
    not a cross-process kill, so EDR never intervenes. This daemon thread
    polls the parent and calls ``os._exit(0)`` the moment it's gone,
    covering both a graceful Quit and an Electron crash. No-op when the env
    var is absent (e.g. standalone ``--reload`` dev runs).
    """
    raw = os.environ.get("CCIS_PARENT_PID")
    if not raw:
        return
    try:
        parent_pid = int(raw)
    except ValueError:
        return
    if parent_pid <= 0:
        return

    log = logging.getLogger(__name__)

    def _watch() -> None:
        while True:
            if not _pid_alive(parent_pid):
                log.info(
                    "parent process %d gone; sidecar self-terminating", parent_pid
                )
                os._exit(0)
            time.sleep(_PARENT_POLL_SECONDS)

    threading.Thread(target=_watch, name="parent-watchdog", daemon=True).start()
    logging.getLogger(__name__).info(
        "parent watchdog armed (parent_pid=%d, poll=%.1fs)",
        parent_pid,
        _PARENT_POLL_SECONDS,
    )


async def _serve_with_handshake(host: str, port: int) -> None:
    """Race-free port handshake: let uvicorn bind, then announce.

    The old implementation pre-bound a socket with SO_REUSEADDR off, read
    the assigned port, closed the socket, and trusted uvicorn to re-bind
    to the same port before any other process grabbed it. That window is
    typically microseconds — fine on a quiet developer laptop. On a
    locked-down federal endpoint with EDR/AV agents that constantly probe
    127.0.0.1 sockets, the window is wide enough to lose the port and
    crash startup with EADDRINUSE.

    Instead, hand port=0 straight to ``uvicorn.Server`` so uvicorn itself
    does the bind under the asyncio loop. Once ``server.started`` flips
    true, the listener sockets are live and we can read the OS-assigned
    port from ``server.servers[0].sockets[0]`` and only then print the
    handshake banner.
    """
    config = uvicorn.Config(
        "cybersecurity_assessor.server:app",
        host=host,
        port=port,
        log_level="info",
    )
    server = uvicorn.Server(config)
    serve_task = asyncio.create_task(server.serve())

    # Tight poll while uvicorn brings listeners up. ``started`` flips
    # inside ``Server.serve()`` after socket creation; until then
    # ``server.servers`` is empty. If serve() exits before flipping
    # (e.g. ALREADY-bound error on an explicit --port), surface that as
    # the original exception rather than hanging.
    while not server.started:
        if serve_task.done():
            await serve_task
            return
        await asyncio.sleep(0.05)

    actual_port = server.servers[0].sockets[0].getsockname()[1]
    # Electron handshake: first stdout line matching CCIS_PORT=<n> is what
    # ui/electron/main.ts parses with SIDECAR_PORT_RE.
    print(f"CCIS_PORT={actual_port}", flush=True)
    sys.stdout.flush()

    await serve_task


def run() -> None:
    parser = argparse.ArgumentParser(prog="cybersec-server")
    parser.add_argument("--port", type=int, default=0, help="0 = auto-assign")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    # Arm the self-termination watchdog before we bind anything. Covers both
    # the production handshake path and the --reload path; no-op when the
    # sidecar was launched without CCIS_PARENT_PID.
    _start_parent_watchdog()

    if args.reload:
        # --reload uses uvicorn's watchfiles import-string model, which
        # spawns a supervisor process and can't share state with our
        # ``Server`` instance. The race-free handshake path is therefore
        # production-only; dev users who want --reload must pin --port
        # explicitly so we have a concrete number to announce.
        if args.port == 0:
            parser.error("--reload requires --port to be specified explicitly")
        print(f"CCIS_PORT={args.port}", flush=True)
        sys.stdout.flush()
        uvicorn.run(
            "cybersecurity_assessor.server:app",
            host=args.host,
            port=args.port,
            reload=True,
            log_level="info",
        )
        return

    asyncio.run(_serve_with_handshake(args.host, args.port))


if __name__ == "__main__":
    run()
