"""Migration 0016 — dedup duplicate Assessments + enforce uniqueness.

Pins the two-part contract of
``alembic/versions/0016_assessment_unique_workbook_objective.py``:

1. On upgrade, pre-existing duplicate Assessment rows for the same
   (workbook_id, objective_id) are deduplicated — the "richest" row (most
   AssessmentImplementation children, newest id as tiebreaker) survives, the
   losers AND their orphan impl rows are deleted. This repairs the PE-3
   double-write the attach-time backfill produced before the constraint existed.
2. After upgrade, the ``uq_assessment_workbook_objective`` UNIQUE constraint is
   present and a duplicate INSERT raises IntegrityError.

The DB is built by running the real Alembic chain to 0015 (one row per
objective is still legal there), seeding a duplicate via raw SQL, then
upgrading through 0016.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import create_engine, inspect, text

_BACKEND = Path(__file__).resolve().parents[1]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402 — register tables
from cybersecurity_assessor.migrations import _alembic_config  # noqa: E402


def _engine_at_0015():
    tf = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    tf.close()
    eng = create_engine(f"sqlite:///{tf.name}")
    with eng.begin() as conn:
        command.upgrade(_alembic_config(connection=conn), "0015")
    return eng, tf.name


# Column set that satisfies every NOT NULL on the assessment table at rev 0015.
_A_COLS = (
    "id, workbook_id, objective_id, status, tester, date_tested, narrative_q, "
    "narrative_class, needs_review, created_at, rewrite_requested, "
    "dual_narrative_flagged"
)


def _ins_assessment(conn, *, aid: int, wb: int, obj: int, nq: str) -> None:
    conn.execute(
        text(
            f"INSERT INTO assessment ({_A_COLS}) VALUES "
            f"(:id,:wb,:obj,'COMPLIANT','t','2026-01-01',:nq,"
            f"'COMPLIANCE_AFFIRMING',0,'2026-01-01',0,0)"
        ),
        {"id": aid, "wb": wb, "obj": obj, "nq": nq},
    )


def _ins_impl(conn, *, iid: int, aid: int, scope: str) -> None:
    conn.execute(
        text(
            "INSERT INTO assessmentimplementation "
            "(id,assessment_id,scope_label,responsibility,status,narrative,created_at) "
            "VALUES (:iid,:aid,:scope,'inherited','COMPLIANT','x','2026-01-01')"
        ),
        {"iid": iid, "aid": aid, "scope": scope},
    )


def test_0016_dedups_keeping_richest_and_enforces_uniqueness():
    eng, path = _engine_at_0015()
    try:
        # Seed two rows for the same (workbook=5, objective=947). Row 1 has TWO
        # impl children (the correct multi-cloud row); row 2 has ZERO (the stale
        # single-cloud partial). Row 1 must survive.
        with eng.begin() as c:
            _ins_assessment(c, aid=1, wb=5, obj=947, nq="AWS GovCloud: a\nAzure Government: b")
            _ins_assessment(c, aid=2, wb=5, obj=947, nq="Azure only")
            _ins_impl(c, iid=1, aid=1, scope="AWS GovCloud")
            _ins_impl(c, iid=2, aid=1, scope="Azure Government")
            _ins_impl(c, iid=3, aid=2, scope="Azure Government")
            # A non-duplicate row on another objective — must be untouched.
            _ins_assessment(c, aid=3, wb=5, obj=948, nq="solo")

        with eng.begin() as conn:
            command.upgrade(_alembic_config(connection=conn), "head")

        with eng.connect() as c:
            survivors = c.execute(
                text("SELECT id FROM assessment WHERE workbook_id=5 AND objective_id=947")
            ).fetchall()
            assert [r[0] for r in survivors] == [1], (
                "richest row (id=1, 2 impls) must survive; stale id=2 deleted"
            )
            # Orphan impl of the deleted row is gone; survivor's two remain.
            impl_aids = [
                r[0]
                for r in c.execute(
                    text("SELECT assessment_id FROM assessmentimplementation")
                ).fetchall()
            ]
            assert sorted(impl_aids) == [1, 1], "orphan impl of deleted row must be removed"
            # Untouched non-duplicate row still present.
            assert c.execute(
                text("SELECT COUNT(*) FROM assessment WHERE objective_id=948")
            ).scalar() == 1

        # Constraint present + enforced.
        insp = inspect(eng)
        ucs = {uc["name"] for uc in insp.get_unique_constraints("assessment")}
        assert "uq_assessment_workbook_objective" in ucs

        with pytest.raises(Exception):
            with eng.begin() as c:
                _ins_assessment(c, aid=99, wb=5, obj=947, nq="dup")
    finally:
        eng.dispose()
        Path(path).unlink(missing_ok=True)


def test_0016_fresh_db_has_constraint_and_no_dup_allowed():
    """Fresh upgrade-to-head (no seeded dupes) still lands the constraint."""
    tf = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    tf.close()
    eng = create_engine(f"sqlite:///{tf.name}")
    try:
        with eng.begin() as conn:
            command.upgrade(_alembic_config(connection=conn), "head")
        insp = inspect(eng)
        ucs = {uc["name"] for uc in insp.get_unique_constraints("assessment")}
        assert "uq_assessment_workbook_objective" in ucs
    finally:
        eng.dispose()
        Path(tf.name).unlink(missing_ok=True)
