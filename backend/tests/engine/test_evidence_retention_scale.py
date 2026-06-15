"""Scale + stress tests for evidence_retention.enforce_retention.

Exercises:
  - within-budget: no eviction, returns 0
  - over-budget: oldest-first eviction, ledger rows written
  - safe-only refusal: load-bearing rows never evicted
  - cap<=0 disables enforcement
  - workbook isolation: only the over-cap workbook is trimmed
  - large-N bulk insert path (~30 100 rows, cap 30 000 — a 10k-person
    system's realistic artifact ceiling; sits just under SQLite's
    32 766 bound-parameter cap so chunked() batching is exercised)

Pattern matches test_evidence_bundle.py: in-memory StaticPool SQLite,
SQLModel.metadata.create_all, Session fixture, helpers that persist rows.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, func, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401 -- registers tables
from cybersecurity_assessor.evidence.evidence_retention import enforce_retention
from cybersecurity_assessor.models import (
    AutomationSchedule,
    Evidence,
    EvidenceKind,
    EvidenceRetentionEvent,
    EvidenceTag,
    Framework,
    Control,
    Objective,
    PoamEvidence,
    Poam,
    PoamStatus,
    Workbook,
    StigFinding,
    FindingStatus,
    AssessmentEvidenceShown,
    Assessment,
    ComplianceStatus,
    NarrativeClass,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    """In-memory SQLite, single shared connection per test."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def workbook(session) -> Workbook:
    wb = Workbook(path="/tmp/test_wb.xlsx", filename="test_wb.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb


@pytest.fixture
def workbook2(session) -> Workbook:
    wb = Workbook(path="/tmp/test_wb2.xlsx", filename="test_wb2.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _add_evidence(
    session: Session,
    *,
    workbook_id: int,
    path: str,
    sha: str | None = None,
    is_asset_list: bool = False,
    is_boundary_doc: bool = False,
) -> Evidence:
    ev = Evidence(
        path=path,
        sha256=sha or f"sha_{path}",
        kind=EvidenceKind.PDF,
        size_bytes=1024,
        workbook_id=workbook_id,
        is_asset_list=is_asset_list,
        is_boundary_doc=is_boundary_doc,
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    return ev


def _count_evidence(session: Session, workbook_id: int) -> int:
    return session.exec(
        select(func.count()).select_from(Evidence).where(
            Evidence.workbook_id == workbook_id
        )
    ).one()


def _count_ledger(session: Session, workbook_id: int) -> int:
    return session.exec(
        select(func.count()).select_from(EvidenceRetentionEvent).where(
            EvidenceRetentionEvent.workbook_id == workbook_id
        )
    ).one()


# ---------------------------------------------------------------------------
# Test 1 — within budget: no eviction
# ---------------------------------------------------------------------------


def test_within_budget_returns_zero(session, workbook):
    cap = 10
    for i in range(5):
        _add_evidence(session, workbook_id=workbook.id, path=f"/ev/{i}.pdf")
    result = enforce_retention(session, workbook.id, cap=cap)
    assert result == 0
    assert _count_evidence(session, workbook.id) == 5
    assert _count_ledger(session, workbook.id) == 0


# ---------------------------------------------------------------------------
# Test 2 — over budget: evict oldest N, ledger rows written
# ---------------------------------------------------------------------------


def test_over_budget_evicts_oldest_first(session, workbook):
    cap = 5
    evids = []
    for i in range(8):
        ev = _add_evidence(
            session, workbook_id=workbook.id, path=f"/ev/old_{i}.pdf", sha=f"sha{i}"
        )
        evids.append(ev.id)

    result = enforce_retention(session, workbook.id, cap=cap)

    assert result == 3  # 8 - 5 = 3 evicted
    remaining_count = _count_evidence(session, workbook.id)
    assert remaining_count == cap

    # Ledger: one row per eviction
    ledger_count = _count_ledger(session, workbook.id)
    assert ledger_count == 3

    # Oldest 3 ids were evicted (earliest inserted = smallest id)
    surviving_ids = set(
        session.exec(select(Evidence.id).where(Evidence.workbook_id == workbook.id)).all()
    )
    evicted_ids = set(evids[:3])  # 3 oldest
    assert not (evicted_ids & surviving_ids), "Oldest rows should have been evicted"

    # Each ledger row records the evicted_evidence_id
    ledger_rows = session.exec(
        select(EvidenceRetentionEvent).where(
            EvidenceRetentionEvent.workbook_id == workbook.id
        )
    ).all()
    recorded_ids = {row.evicted_evidence_id for row in ledger_rows}
    assert recorded_ids == evicted_ids


def test_ledger_fields_populated(session, workbook):
    """Ledger rows carry path, sha, title, and reason fields."""
    cap = 1
    ev = _add_evidence(session, workbook_id=workbook.id, path="/docs/policy.pdf", sha="aabbcc")
    ev.title = "Policy Doc"
    session.add(ev)
    session.commit()
    _add_evidence(session, workbook_id=workbook.id, path="/docs/plan.pdf", sha="ddeeff")

    enforce_retention(session, workbook.id, cap=cap)

    ledger = session.exec(
        select(EvidenceRetentionEvent).where(
            EvidenceRetentionEvent.workbook_id == workbook.id
        )
    ).one()
    assert ledger.evicted_evidence_id == ev.id
    assert ledger.evicted_path == "/docs/policy.pdf"
    assert ledger.evicted_sha256 == "aabbcc"
    assert ledger.reason == "cap_exceeded"


# ---------------------------------------------------------------------------
# Test 3 — safe-only refusal: all over-cap rows are load-bearing → evict 0
# ---------------------------------------------------------------------------


def test_evidence_tag_blocks_eviction(session, workbook):
    """EvidenceTag-referenced rows are never evicted."""
    cap = 1
    fw = Framework(name="NIST 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)
    ctrl = Control(framework_id=fw.id, control_id="AC-2", title="T", family="AC")
    session.add(ctrl)
    session.commit()
    session.refresh(ctrl)
    obj = Objective(
        control_id_fk=ctrl.id, objective_id="CCI-000015", source="CCI", text="t"
    )
    session.add(obj)
    session.commit()
    session.refresh(obj)

    ev_old = _add_evidence(session, workbook_id=workbook.id, path="/tagged.pdf", sha="aa")
    ev_new = _add_evidence(session, workbook_id=workbook.id, path="/newer.pdf", sha="bb")
    # Tag the old (first) evidence — it must be protected
    tag = EvidenceTag(evidence_id=ev_old.id, objective_id=obj.id, relevance=0.9, confidence=0.8)
    session.add(tag)
    session.commit()

    result = enforce_retention(session, workbook.id, cap=cap)
    # ev_old is tagged so can't be evicted; ev_new is safe but cap=1 and count=2
    # → need to evict 1; ev_old is skipped; ev_new should be evicted
    assert result == 1
    assert session.get(Evidence, ev_old.id) is not None, "Tagged evidence must survive"
    assert session.get(Evidence, ev_new.id) is None


def test_is_asset_list_blocks_eviction(session, workbook):
    cap = 1
    ev_asset = _add_evidence(
        session, workbook_id=workbook.id, path="/hw_sw.xlsx", sha="aa", is_asset_list=True
    )
    _add_evidence(session, workbook_id=workbook.id, path="/plain.pdf", sha="bb")

    result = enforce_retention(session, workbook.id, cap=cap)

    assert result == 1
    assert session.get(Evidence, ev_asset.id) is not None, "Asset list must survive"


def test_is_boundary_doc_blocks_eviction(session, workbook):
    cap = 1
    ev_bd = _add_evidence(
        session, workbook_id=workbook.id, path="/ssp.pdf", sha="aa", is_boundary_doc=True
    )
    _add_evidence(session, workbook_id=workbook.id, path="/plain.pdf", sha="bb")

    result = enforce_retention(session, workbook.id, cap=cap)

    assert result == 1
    assert session.get(Evidence, ev_bd.id) is not None, "Boundary doc must survive"


def test_supersession_anchor_blocks_eviction(session, workbook):
    """A row that another row supersedes_by_id references must not be evicted."""
    cap = 1
    ev_anchor = _add_evidence(session, workbook_id=workbook.id, path="/current.pdf", sha="aa")
    ev_old = _add_evidence(session, workbook_id=workbook.id, path="/legacy.pdf", sha="bb")
    # Make ev_old point TO ev_anchor as the superseding row
    ev_old.superseded_by_id = ev_anchor.id
    session.add(ev_old)
    session.commit()

    result = enforce_retention(session, workbook.id, cap=cap)

    # ev_anchor is the anchor (superseded_by_id from ev_old); ev_old is the one
    # that can be evicted since nothing references it as an anchor.
    assert result == 1
    assert session.get(Evidence, ev_anchor.id) is not None, "Anchor must survive"


def test_all_load_bearing_evicts_nothing(session, workbook):
    """When all over-cap rows are load-bearing, enforce_retention returns 0."""
    cap = 1
    ev1 = _add_evidence(
        session, workbook_id=workbook.id, path="/asset.xlsx", sha="aa", is_asset_list=True
    )
    ev2 = _add_evidence(
        session, workbook_id=workbook.id, path="/boundary.pdf", sha="bb", is_boundary_doc=True
    )

    result = enforce_retention(session, workbook.id, cap=cap)

    assert result == 0, "Nothing evicted — both are load-bearing"
    assert _count_evidence(session, workbook.id) == 2  # still over cap


# ---------------------------------------------------------------------------
# Test 4 — cap <= 0 disables enforcement
# ---------------------------------------------------------------------------


def test_cap_zero_disables_enforcement(session, workbook):
    for i in range(5):
        _add_evidence(session, workbook_id=workbook.id, path=f"/ev/{i}.pdf")
    result = enforce_retention(session, workbook.id, cap=0)
    assert result == 0
    assert _count_evidence(session, workbook.id) == 5


def test_cap_negative_disables_enforcement(session, workbook):
    for i in range(5):
        _add_evidence(session, workbook_id=workbook.id, path=f"/ev/{i}.pdf")
    result = enforce_retention(session, workbook.id, cap=-1)
    assert result == 0
    assert _count_evidence(session, workbook.id) == 5


# ---------------------------------------------------------------------------
# Test 5 — workbook isolation
# ---------------------------------------------------------------------------


def test_workbook_isolation(session, workbook, workbook2):
    """Only the over-cap workbook is trimmed; the other is untouched."""
    cap = 3
    for i in range(6):
        _add_evidence(session, workbook_id=workbook.id, path=f"/wb1/{i}.pdf", sha=f"wb1_{i}")
    for i in range(2):
        _add_evidence(session, workbook_id=workbook2.id, path=f"/wb2/{i}.pdf", sha=f"wb2_{i}")

    result = enforce_retention(session, workbook.id, cap=cap)

    assert result == 3
    assert _count_evidence(session, workbook.id) == 3
    # workbook2 must be completely untouched
    assert _count_evidence(session, workbook2.id) == 2


# ---------------------------------------------------------------------------
# Test 6 — large-N bulk insert (~30 100 rows, cap 30 000)
#
# Artifact-count derivation (10,000-person system):
#   A workforce of ~10k implies on the order of 10k user endpoints, plus
#   ~10-15% servers/network/appliance hosts → ~11-12k hosts in boundary.
#   In a granular per-host evidence model the assessor ingests roughly two
#   artifacts per host (e.g. a STIG CKL + an ACAS/config export), which
#   already lands at ~22-24k. Adding scan rollups, policy/SSP/CRM docs and
#   re-ingested supersession copies pushes a defensible upper bound to
#   ~30k. We use 30 000 as the cap because:
#     * it is a realistic worst case for the largest systems we assess, and
#     * it sits just below SQLite's SQLITE_MAX_VARIABLES = 32 766
#       bound-parameter cap, so the load-bearing exclusion walk in
#       enforce_retention is forced through 33+ chunked() batches
#       (IN_CLAUSE_CHUNK = 900) — exactly the path a real large run hits.
#   NB: 32 766 is a *bound-parameter* ceiling handled by chunked(), NOT a
#   row-count limit — SQLite itself holds billions of rows.
#
# This validates the N-independent code path via a real ~30 100-row table.
# bulk_save_objects keeps insert time well under a few seconds on SQLite.
# If this test is ever slow, the issue is not the retention logic but the
# bulk insert itself — the retention walk is O(n) in Python list iteration
# and O(1) per SQL DELETE, both fast.
# ---------------------------------------------------------------------------


def test_large_n_bulk_eviction(session, workbook):
    cap = 30_000
    n = 30_100
    rows = [
        Evidence(
            path=f"/bulk/{i}.pdf",
            sha256=f"sha{i:08d}",
            kind=EvidenceKind.PDF,
            size_bytes=1024,
            workbook_id=workbook.id,
        )
        for i in range(n)
    ]
    session.add_all(rows)
    session.commit()

    result = enforce_retention(session, workbook.id, cap=cap)

    assert result == 100  # n - cap
    remaining = _count_evidence(session, workbook.id)
    assert remaining == cap
    ledger = _count_ledger(session, workbook.id)
    assert ledger == 100
