"""Smoke-test the PyInstaller-bundled sidecar.

Spawns ``dist/cybersec-server/cybersec-server.exe`` (path overridable
via argv), reads stdout until the ``CCIS_PORT=<n>`` handshake banner
appears, times that, then HTTPs ``/healthz`` on the captured port and
exits 0 on success / nonzero on any failure.

Used by ``backend/scripts/build-sidecar.ps1`` as the post-build gate
and (eventually) by ``tests/test_packaged_sidecar.py`` as a regression
guard. Standalone so it can run with nothing but stdlib + pre-built
exe — no need for the dev venv to be activated on the CI worker.

Exits with diagnostic info on stderr so the build pipeline can show
the failure mode without re-running.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

# Matches the handshake line printed by server.py::_serve_with_handshake.
# Same regex shape as ui/electron/main.ts SIDECAR_PORT_RE — keep them in sync.
PORT_RE = re.compile(rb"^CCIS_PORT=(\d+)\s*$", re.MULTILINE)

# Onedir cold start should land well under the Electron 15s handshake budget
# (ui/electron/main.ts). Onefile blows past it; this gate is what tells us
# onedir actually fixed the problem.
HANDSHAKE_BUDGET_SECONDS = 15.0


def _stream_collector(stream, sink: list[bytes], event: threading.Event) -> None:
    """Drain a pipe into ``sink`` and flip ``event`` when ``CCIS_PORT=`` lands."""
    for raw in iter(stream.readline, b""):
        sink.append(raw)
        if PORT_RE.search(raw):
            event.set()
    stream.close()


def run_smoke(exe_path: Path) -> int:
    if not exe_path.exists():
        print(f"smoke: exe not found: {exe_path}", file=sys.stderr)
        return 2

    print(f"smoke: spawning {exe_path}", file=sys.stderr)
    t0 = time.monotonic()
    proc = subprocess.Popen(
        [str(exe_path), "--host", "127.0.0.1", "--port", "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
        cwd=exe_path.parent,
    )

    captured: list[bytes] = []
    port_seen = threading.Event()
    reader = threading.Thread(
        target=_stream_collector, args=(proc.stdout, captured, port_seen), daemon=True
    )
    reader.start()

    if not port_seen.wait(timeout=HANDSHAKE_BUDGET_SECONDS):
        elapsed = time.monotonic() - t0
        print(
            f"smoke: TIMEOUT — no CCIS_PORT= in {elapsed:.2f}s (budget {HANDSHAKE_BUDGET_SECONDS}s)",
            file=sys.stderr,
        )
        print(b"".join(captured).decode("utf-8", "replace"), file=sys.stderr)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        return 3

    elapsed = time.monotonic() - t0
    match = PORT_RE.search(b"".join(captured))
    assert match  # event only fires when PORT_RE matches
    port = int(match.group(1))
    print(f"smoke: CCIS_PORT={port} in {elapsed:.2f}s", file=sys.stderr)

    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/healthz")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        conn.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    if resp.status != 200:
        print(f"smoke: /healthz returned {resp.status}: {body}", file=sys.stderr)
        return 4

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        print(f"smoke: /healthz body is not JSON: {body!r}", file=sys.stderr)
        return 5

    if payload.get("status") != "ok":
        print(f"smoke: /healthz status != ok: {payload}", file=sys.stderr)
        return 6

    print(f"smoke: PASS — handshake {elapsed:.2f}s, /healthz={payload}", file=sys.stderr)

    # OCR packaging gate. /healthz can't catch a mispackaged Tesseract because
    # the OCR path is lazy-imported and only runs on image evidence. A flattened
    # tessdata dir or a missing tesseract.exe would ship green otherwise. Assert
    # the bundled binary exists at the path _ocr.py resolves AND that it runs
    # against its bundled language data (rc 0 with TESSDATA_PREFIX=.../tessdata).
    ocr_rc = _check_bundled_ocr(exe_path.parent)
    if ocr_rc != 0:
        return ocr_rc

    print("smoke: PASS — bundled Tesseract OCR reachable", file=sys.stderr)
    return 0


def _check_bundled_ocr(dist_dir: Path) -> int:
    """Verify the bundled Tesseract is present and runs with its tessdata.

    Mirrors extractors/_ocr.py: binary at ``_internal/tesseract/tesseract.exe``,
    language data at ``_internal/tesseract/tessdata/``. Runs ``tesseract
    --list-langs`` with ``TESSDATA_PREFIX`` set the way _ocr.py sets it; rc 0
    proves the data file is readable at that prefix (the exact failure a
    flattened/backslashed dest path would cause). Stdlib only.
    """
    tess_dir = dist_dir / "_internal" / "tesseract"
    exe = tess_dir / "tesseract.exe"
    eng = tess_dir / "tessdata" / "eng.traineddata"
    if not exe.exists():
        print(f"smoke: OCR FAIL — bundled tesseract.exe missing: {exe}", file=sys.stderr)
        return 7
    if not eng.exists():
        print(
            f"smoke: OCR FAIL — bundled eng.traineddata missing: {eng} "
            "(tessdata likely flattened by a bad dest path)",
            file=sys.stderr,
        )
        return 8
    try:
        result = subprocess.run(
            [str(exe), "--list-langs"],
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "TESSDATA_PREFIX": str(tess_dir / "tessdata")},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"smoke: OCR FAIL — could not run tesseract: {exc}", file=sys.stderr)
        return 9
    if result.returncode != 0 or "eng" not in (result.stdout + result.stderr):
        print(
            f"smoke: OCR FAIL — tesseract --list-langs rc={result.returncode}; "
            f"stdout={result.stdout!r} stderr={result.stderr!r}",
            file=sys.stderr,
        )
        return 10
    return 0


def _default_exe_path() -> Path:
    # Resolves relative to this file so the script can be invoked from anywhere.
    return Path(__file__).resolve().parent.parent / "dist" / "cybersec-server" / "cybersec-server.exe"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "exe",
        nargs="?",
        type=Path,
        default=_default_exe_path(),
        help="Path to cybersec-server.exe (default: backend/dist/cybersec-server/cybersec-server.exe)",
    )
    args = parser.parse_args()
    sys.exit(run_smoke(args.exe))
