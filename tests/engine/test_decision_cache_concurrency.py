"""Regression: concurrent bump_hit must not hold SQLite's write lock.

THE BUG (2026-06-20). A "perf" change dropped the per-call commit in
``decision_cache.bump_hit`` on the theory the staged hit-counter could ride the
next ``store`` commit. But each batch worker's cache Session has autoflush ON:
the worker's NEXT ``lookup`` (session.get) flushes the dirty UPDATE, acquiring
SQLite's single write lock — and with no commit the lock is HELD for the rest of
the batch. Eight workers each holding an uncommitted writer contend on that lock
→ ``OperationalError: database is locked`` after busy_timeout → the assess-batch
"dev error" (hit hard on re-assess-after-CRM-attach, which is almost all cache
hits). The fix restores the commit so the lock is acquired-AND-released per hit.

This test reproduces it deterministically: a REAL on-disk SQLite DB (separate
connection per worker — the in-memory StaticPool used by most tests shares one
connection and can't surface a cross-connection lock) with a SHORT busy_timeout,
seeded cached rows, and N threads each running the production lookup→bump_hit
pair in a loop. If bump_hit holds the lock (no commit), a sibling's flush trips
``database is locked`` quickly; with the commit it passes. Collected via
testpaths.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest
from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine, select

from cybersecurity_assessor import models  # noqa: F401 -- register tables
from cybersecurity_assessor.engine import decision_cache
from cybersecurity_assessor.models import DecisionCache


@pytest.fixture
def file_engine(tmp_path):
    """On-disk SQLite with a SHORT busy_timeout so a held-lock regression fails
    fast (in ~1s) instead of hanging on the production 60s timeout. WAL +
    busy_timeout mirror the production pragmas (db.py) minus the long wait.
    """
    db = tmp_path / "cache.db"
    engine = create_engine(
        f"sqlite:///{db}",
        connect_args={"check_same_thread": False, "timeout": 1},
    )

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_conn, _rec):  # pragma: no cover - trivial
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA busy_timeout=1000")
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()

    SQLModel.metadata.create_all(engine)
    # Seed N cached rows the workers will hit.
    with Session(engine) as s:
        for i in range(8):
            s.add(
                DecisionCache(
                    fingerprint=f"fp-{i}",
                    kernel_version="v1",
                    prompt_sha="sha",
                    decided_at=datetime.now(timezone.utc),
                    payload_json="{}",
                    hit_count=0,
                )
            )
        s.commit()
    yield engine
    engine.dispose()


def test_concurrent_bump_hit_does_not_deadlock(file_engine):
    """8 workers each run lookup→bump_hit in a loop on their own connection.

    Reproduces the batch-assess worker model: one private autoflush Session per
    thread, repeated cache hits. With bump_hit committing, the write lock is
    released each hit and all workers finish; without the commit, autoflush on
    the next lookup deadlocks on the held lock → database is locked.
    """
    errors: list[Exception] = []
    barrier = threading.Barrier(8)

    def worker(wid: int) -> None:
        # One private session per worker — exactly like _worker_cache_session.
        sess = Session(file_engine)
        try:
            barrier.wait(timeout=10)  # maximize lock overlap across workers
            for _ in range(10):
                for i in range(8):
                    cached = decision_cache.lookup(sess, f"fp-{i}")
                    if cached is not None:
                        decision_cache.bump_hit(sess, cached)
        except Exception as exc:  # noqa: BLE001 -- capture for the assertion
            errors.append(exc)
        finally:
            sess.close()

    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(worker, range(8)))

    assert not errors, (
        "concurrent bump_hit deadlocked on the SQLite write lock — bump_hit must "
        f"commit so the lock is released per hit. First error: {errors[0]!r}"
    )

    # Hit counts advanced (commits landed). Race may under-count, but every
    # row should have a non-zero count after 8×10×(its turn) increments.
    with Session(file_engine) as s:
        rows = s.exec(select(DecisionCache)).all()
        assert all(r.hit_count > 0 for r in rows)
