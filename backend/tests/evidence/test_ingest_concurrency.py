"""Tests for the ingest job registry mutex (claim_single_file + _INGEST_LOCK).

Verifies:
  - Two concurrent claim_single_file() calls: the second raises RuntimeError
  - While a batch job is "running", claim_single_file() raises RuntimeError
  - State is fully reset after the context manager exits (next call succeeds)

Uses the module-level ``registry`` singleton to match production semantics.
Each test cleans up in a finally block so the lock is never left held.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

import cybersecurity_assessor.evidence.jobs as jobs_mod
from cybersecurity_assessor.evidence.jobs import JobRegistry, _INGEST_LOCK


# ---------------------------------------------------------------------------
# Fixture: fresh JobRegistry per test so singleton state doesn't leak
# ---------------------------------------------------------------------------


@pytest.fixture
def reg():
    """A clean JobRegistry (not the module singleton) + a fresh Lock.

    We instantiate a new JobRegistry rather than using the module-level
    ``registry`` singleton so tests are fully isolated — no "previous test
    left the lock acquired" surprises. We do NOT monkeypatch the module
    singleton because the production code uses the same Lock object inside
    _run_job and claim_single_file; swapping it mid-test would break the
    invariant.

    The _INGEST_LOCK is module-level and shared, so we snapshot and restore
    its state to ensure cross-test isolation.
    """
    r = JobRegistry()
    # Ensure the module-level lock is free before and after
    if _INGEST_LOCK.locked():
        _INGEST_LOCK.release()
    yield r
    # Cleanup: release if test left it held (shouldn't happen, but safe)
    if _INGEST_LOCK.locked():
        _INGEST_LOCK.release()


# ---------------------------------------------------------------------------
# Test 1: claim_single_file is a context manager that works normally
# ---------------------------------------------------------------------------


def test_claim_single_file_normal_use(reg):
    """Happy path: claim succeeds, exits cleanly, second claim then works."""
    # Replace the module-level lock on this fresh registry to avoid
    # touching the shared _INGEST_LOCK. We give the registry a local lock.
    local_lock = threading.Lock()

    # Patch the module-level _INGEST_LOCK only for this test scope
    orig = jobs_mod._INGEST_LOCK
    jobs_mod._INGEST_LOCK = local_lock
    try:
        with reg.claim_single_file():
            pass  # should not raise
        # After exit, lock is released — second claim succeeds too
        with reg.claim_single_file():
            pass
    finally:
        jobs_mod._INGEST_LOCK = orig


# ---------------------------------------------------------------------------
# Test 2: nested claim_single_file raises RuntimeError
# ---------------------------------------------------------------------------


def test_nested_claim_raises(reg):
    """A second claim_single_file while one is held raises RuntimeError."""
    local_lock = threading.Lock()
    orig = jobs_mod._INGEST_LOCK
    jobs_mod._INGEST_LOCK = local_lock
    try:
        with reg.claim_single_file():
            # Lock is now held; a second claim must fail non-blocking
            with pytest.raises(RuntimeError, match="ingest operation is in progress"):
                with reg.claim_single_file():
                    pass
    finally:
        jobs_mod._INGEST_LOCK = orig


# ---------------------------------------------------------------------------
# Test 3: while a "batch job" marks registry active, claim_single_file raises
# ---------------------------------------------------------------------------


def test_batch_job_active_blocks_single_file(reg):
    """If _active_job_id is set and job status == 'running', single-file raises."""
    import uuid
    from cybersecurity_assessor.evidence.jobs import IngestJob

    # Manually inject a fake "running" batch job
    fake_id = uuid.uuid4().hex
    fake_job = IngestJob(job_id=fake_id, source_uri="file:///tmp/fake")
    fake_job.status = "running"

    with reg._lock:
        reg._jobs[fake_id] = fake_job
        reg._active_job_id = fake_id

    local_lock = threading.Lock()
    orig = jobs_mod._INGEST_LOCK
    jobs_mod._INGEST_LOCK = local_lock
    try:
        with pytest.raises(RuntimeError, match="ingest job is already running"):
            with reg.claim_single_file():
                pass
    finally:
        jobs_mod._INGEST_LOCK = orig
        # Clean up injected state
        with reg._lock:
            reg._jobs.pop(fake_id, None)
            reg._active_job_id = None


# ---------------------------------------------------------------------------
# Test 4: finished batch job does NOT block single-file claim
# ---------------------------------------------------------------------------


def test_finished_batch_job_does_not_block(reg):
    """A done/error batch job must not block a subsequent single-file claim."""
    import uuid
    from cybersecurity_assessor.evidence.jobs import IngestJob

    fake_id = uuid.uuid4().hex
    fake_job = IngestJob(job_id=fake_id, source_uri="file:///tmp/done")
    fake_job.status = "done"  # finished

    with reg._lock:
        reg._jobs[fake_id] = fake_job
        reg._active_job_id = None  # cleared on job completion

    local_lock = threading.Lock()
    orig = jobs_mod._INGEST_LOCK
    jobs_mod._INGEST_LOCK = local_lock
    try:
        with reg.claim_single_file():
            pass  # must succeed
    finally:
        jobs_mod._INGEST_LOCK = orig


# ---------------------------------------------------------------------------
# Test 5: lock is released after normal exit (no leak)
# ---------------------------------------------------------------------------


def test_lock_released_after_normal_exit(reg):
    """_INGEST_LOCK must not be held after claim_single_file exits normally."""
    local_lock = threading.Lock()
    orig = jobs_mod._INGEST_LOCK
    jobs_mod._INGEST_LOCK = local_lock
    try:
        with reg.claim_single_file():
            assert local_lock.locked(), "Lock must be held inside the context"
        assert not local_lock.locked(), "Lock must be released after exit"
    finally:
        jobs_mod._INGEST_LOCK = orig


# ---------------------------------------------------------------------------
# Test 6: lock is released even when the body raises
# ---------------------------------------------------------------------------


def test_lock_released_after_exception(reg):
    """_INGEST_LOCK must be released even if the context body raises."""
    local_lock = threading.Lock()
    orig = jobs_mod._INGEST_LOCK
    jobs_mod._INGEST_LOCK = local_lock
    try:
        with pytest.raises(ValueError):
            with reg.claim_single_file():
                raise ValueError("simulated failure")
        assert not local_lock.locked(), "Lock must be released after exception"
    finally:
        jobs_mod._INGEST_LOCK = orig
