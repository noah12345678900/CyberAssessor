"""Regression gate for the PyInstaller-bundled sidecar.

Spawns ``backend/dist/cybersec-server/cybersec-server.exe`` directly,
waits for the ``CCIS_PORT=<n>`` handshake, then HTTPs ``/healthz`` on
the captured port. This is the test version of
``backend/scripts/smoke_test_sidecar.py`` (which the build pipeline
runs as a post-build gate) — same shape, wired into pytest so a CI
worker that publishes packaged builds can keep the test suite as the
single source of truth.

The test SKIPS when the bundled exe is absent. That keeps the dev path
green (no one wants to rebuild a 245 MB onedir tree before every
``pytest`` run), while still failing loudly on CI / release builds where
build-sidecar.ps1 has already produced it.

Why a real spawn rather than mocking out subprocess:
  Onefile vs onedir, missing hidden imports, dropped data files —
  every regression we worry about manifests at process start, not in
  Python-level call paths. Mocking would test the test, not the bundle.

The 15s handshake budget mirrors ``ui/electron/main.ts``
SIDECAR_PORT_RE timeout — if the bundle slips past that here, it would
have stranded the user with a "Backend failed to start" dialog in
production.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

# Match the handshake regex in ui/electron/main.ts and
# backend/scripts/smoke_test_sidecar.py — three copies of the same
# pattern is intentional: each side has to recognize the banner
# independently, so they must agree on its shape.
PORT_RE = re.compile(rb"^CCIS_PORT=(\d+)\s*$", re.MULTILINE)

HANDSHAKE_BUDGET_SECONDS = 15.0


def _bundled_exe_path() -> Path:
    # backend/tests/test_packaged_sidecar.py -> backend/dist/cybersec-server/cybersec-server.exe
    return (
        Path(__file__).resolve().parent.parent
        / "dist"
        / "cybersec-server"
        / "cybersec-server.exe"
    )


def _drain_until_port(stream, sink: list[bytes], event: threading.Event) -> None:
    for raw in iter(stream.readline, b""):
        sink.append(raw)
        if PORT_RE.search(raw):
            event.set()
    stream.close()


@pytest.mark.integration
def test_packaged_sidecar_handshake_and_healthz() -> None:
    exe = _bundled_exe_path()
    if not exe.exists():
        pytest.skip(
            f"Bundled sidecar not present at {exe}. "
            "Run `pwsh backend/scripts/build-sidecar.ps1` to produce it."
        )

    t0 = time.monotonic()
    proc = subprocess.Popen(
        [str(exe), "--host", "127.0.0.1", "--port", "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
        cwd=exe.parent,
    )

    captured: list[bytes] = []
    port_seen = threading.Event()
    reader = threading.Thread(
        target=_drain_until_port,
        args=(proc.stdout, captured, port_seen),
        daemon=True,
    )
    reader.start()

    try:
        assert port_seen.wait(timeout=HANDSHAKE_BUDGET_SECONDS), (
            f"Sidecar did not print CCIS_PORT= within {HANDSHAKE_BUDGET_SECONDS}s. "
            f"Captured stdout:\n{b''.join(captured).decode('utf-8', 'replace')}"
        )
        elapsed = time.monotonic() - t0
        match = PORT_RE.search(b"".join(captured))
        assert match is not None  # event only fires when PORT_RE matches
        port = int(match.group(1))

        # Soft assertion logged for visibility — if cold start drifts back
        # toward the onefile range, the Electron-side handshake timer is
        # what will start failing first. Capture the trend before that.
        print(
            f"[test_packaged_sidecar] handshake {elapsed:.2f}s "
            f"(budget {HANDSHAKE_BUDGET_SECONDS}s) on port {port}",
            file=sys.stderr,
        )

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request("GET", "/healthz")
            resp = conn.getresponse()
            body = resp.read().decode("utf-8")
        finally:
            conn.close()

        assert resp.status == 200, f"/healthz returned {resp.status}: {body}"
        payload = json.loads(body)
        assert payload.get("status") == "ok", f"/healthz payload: {payload}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
