"""Tests for the manual-override epoch helper (fix #7).

The epoch is the tiebreaker that keeps a reviewer's manual verdict
correction from being silently reverted by the content-addressed decision
cache. ``get_override_epoch`` reads the per-(workbook, objective) counter
(0 when never overridden); ``bump_override_epoch`` increments it on each
manual override via ``POST /api/assessments``. The caller owns the
transaction — these helpers only stage the INSERT/UPDATE.

A scratch in-memory SQLite session is wired per-test. SQLite does not
enforce foreign keys unless ``PRAGMA foreign_keys=ON``, so the epoch rows
can be created without parent workbook/objective rows.
"""

from __future__ import annotations

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from cybersecurity_assessor.engine.override_epoch import (
    bump_override_epoch,
    get_override_epoch,
)
from cybersecurity_assessor.models import OverrideEpoch


@pytest.fixture
def session() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def test_get_epoch_defaults_to_zero(session):
    """Never-overridden objective → 0, the legacy-fingerprint default."""
    assert get_override_epoch(session, workbook_id=1, objective_id=10) == 0


def test_bump_creates_row_at_one(session):
    """First bump inserts a row with epoch 1 and returns it."""
    new = bump_override_epoch(session, workbook_id=1, objective_id=10)
    session.commit()

    assert new == 1
    assert get_override_epoch(session, 1, 10) == 1
    rows = session.exec(select(OverrideEpoch)).all()
    assert len(rows) == 1
    assert (rows[0].workbook_id, rows[0].objective_id, rows[0].epoch) == (1, 10, 1)


def test_bump_increments_existing(session):
    """Subsequent bumps increment the same row monotonically."""
    bump_override_epoch(session, 1, 10)
    bump_override_epoch(session, 1, 10)
    third = bump_override_epoch(session, 1, 10)
    session.commit()

    assert third == 3
    assert get_override_epoch(session, 1, 10) == 3
    # Still exactly one row for the pair — no duplicate inserts.
    assert len(session.exec(select(OverrideEpoch)).all()) == 1


def test_epoch_isolated_per_objective(session):
    """Each (workbook, objective) pair tracks its own epoch."""
    bump_override_epoch(session, 1, 10)
    bump_override_epoch(session, 1, 11)
    bump_override_epoch(session, 1, 11)
    bump_override_epoch(session, 2, 10)
    session.commit()

    assert get_override_epoch(session, 1, 10) == 1
    assert get_override_epoch(session, 1, 11) == 2
    assert get_override_epoch(session, 2, 10) == 1
    # Untouched pair stays at the default.
    assert get_override_epoch(session, 2, 11) == 0


@pytest.mark.parametrize(
    "wid,oid",
    [(None, 10), (1, None), (None, None)],
)
def test_missing_ids_are_noops(session, wid, oid):
    """The manual-override route may run before workbook/objective are
    known; a missing id is a safe no-op returning 0 (epoch-0 fingerprint
    is the correct default), and stages nothing."""
    assert bump_override_epoch(session, wid, oid) == 0
    assert get_override_epoch(session, wid, oid) == 0
    assert session.exec(select(OverrideEpoch)).all() == []


def test_bump_updates_timestamp(session):
    """An update bump refreshes ``updated_at`` (audit signal)."""
    bump_override_epoch(session, 1, 10)
    session.commit()
    first_ts = session.get(OverrideEpoch, (1, 10)).updated_at

    bump_override_epoch(session, 1, 10)
    session.commit()
    second_ts = session.get(OverrideEpoch, (1, 10)).updated_at

    assert second_ts >= first_ts
