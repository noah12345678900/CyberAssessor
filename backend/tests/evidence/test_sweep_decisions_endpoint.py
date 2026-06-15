"""Tests for ``POST /api/sharepoint/sweep/decisions`` — the fire-and-forget endpoint that
captures one ``SweepDecision`` row per candidate shown in
``SweepTriageDialog`` at Ingest click.

What we pin down:

1. **Persistence shape.** Each ``SweepDecisionEntry`` becomes exactly one
   ``SweepDecision`` row with ``signals`` / ``proposed_ccis`` JSON-encoded
   verbatim and ``weights_version_id`` carried through unchanged. The
   route response is the inserted count — no row IDs leaked, because the
   UI has no business knowing them.

2. **Empty-batch short-circuit.** An empty ``decisions`` list returns
   ``{"inserted": 0}`` without committing anything. The UI sends a
   payload on every Ingest, even when no candidates were surfaced; we
   must not write empty audit rows.

3. **Stale ``weights_version_id`` fallback.** If the row referenced by
   ``weights_version_id`` was deleted in between sweep and ingest
   (operators don't usually delete weight history, but the FK has to be
   satisfied either way), the endpoint falls back to the currently
   active row. The fallback is recorded by the resolved FK on every
   inserted row, not by mutating ``weights_version_id`` on the body.

4. **Hard refusal when no anchor exists.** If ``weights_version_id`` is
   unknown AND there is no active row, the endpoint returns 409 rather
   than silently dropping decisions or making up a weights ID. This is
   the "fresh DB with no seed" path — should never happen in production
   (``init_db`` always seeds v1) but the 409 documents the contract.

5. **Append-only idempotency.** Re-POSTing the same batch creates more
   rows, not a no-op. The endpoint is intentionally append-only because
   each click is a separate behavioral observation — collapsing dupes
   would lose the signal that "the operator made the same call twice."

We keep every batch in these tests below ``MIN_DECISIONS_FOR_ONLINE_FIT``
(25) on purpose: the route kicks a background SGD update thread above
that threshold, and that thread opens its own session via the global
``engine`` (not our test engine). Staying sub-threshold keeps the test
hermetic — the background task path is exercised separately in
``test_sweep_online_update.py``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.db import get_session  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Framework,
    SweepDecision,
    SweepWeights,
    Workbook,
)
from cybersecurity_assessor.server import create_app  # noqa: E402

# The sharepoint router mounts under /api/sharepoint; the decisions endpoint
# path on the router is /sweep/decisions, so the full URL is the concatenation.
DECISIONS_URL = "/api/sharepoint/sweep/decisions"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def env(tmp_path: Path):
    """Spin up an isolated in-memory DB + TestClient + seed a workbook.

    The workbook FK on ``SweepDecision`` is required; we don't need a
    real file on disk because no route in this test reads it. Returns a
    tuple of ``(client, engine, workbook_id)`` so individual tests can
    seed weight rows themselves — different tests want different
    starting states (active / no-active / stale).
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    def _override_get_session():
        with Session(engine) as s:
            yield s

    app = create_app()
    app.dependency_overrides[get_session] = _override_get_session

    wb_path = tmp_path / "demo.xlsx"
    wb_path.write_bytes(b"x")

    with Session(engine) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5")
        s.add(fw)
        s.commit()
        s.refresh(fw)

        wb = Workbook(path=str(wb_path), filename=wb_path.name, framework_id=fw.id)
        s.add(wb)
        s.commit()
        s.refresh(wb)
        wb_id = wb.id

    client = TestClient(app)
    try:
        yield client, engine, wb_id
    finally:
        client.close()


def _seed_active_weights(engine, *, source: str = "manual") -> int:
    """Insert one ``is_active=True`` SweepWeights row and return its id.

    Uses neutral hand-tuned-ish values; the endpoint doesn't read them,
    only the FK matters for these tests.
    """
    with Session(engine) as s:
        row = SweepWeights(
            source=source,
            weight_host=0.40,
            weight_control_id=0.30,
            weight_family=0.20,
            weight_crm_keyword=0.15,
            weight_doc_prefix=0.10,
            weight_priority_link=0.15,
            intercept=0.0,
            surface_threshold=0.30,
            precheck_threshold=0.60,
            n_decisions_seen=0,
            is_active=True,
        )
        s.add(row)
        s.commit()
        s.refresh(row)
        return row.id


def _decision_entry(
    *,
    name: str = "policy.pdf",
    path: str = "/lib/policy.pdf",
    score: float = 0.75,
    signals: list[str] | None = None,
    ccis: list[str] | None = None,
    included: bool = True,
    auto_prechecked: bool = True,
) -> dict:
    """JSON-shape one ``SweepDecisionEntry`` — keeps the call sites terse."""
    return {
        "candidate_path": path,
        "candidate_name": name,
        "score_at_decision": score,
        "signals": signals if signals is not None else ["host:server01"],
        "proposed_ccis": ccis if ccis is not None else ["CCI-000196"],
        "included": included,
        "auto_prechecked": auto_prechecked,
    }


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_post_decisions_persists_one_row_per_entry(env):
    """Three entries in → three SweepDecision rows out, each carrying the
    correct FK to the active weights row and the JSON-encoded signals/CCIS.

    We verify ``signals_json`` round-trips through ``json.loads`` — silent
    string-vs-list bugs in the serializer would break the SGD updater
    (which re-parses ``signals_json`` to recover features).
    """
    client, engine, wb_id = env
    weights_id = _seed_active_weights(engine)

    body = {
        "workbook_id": wb_id,
        "weights_version_id": weights_id,
        "fingerprint_snapshot": {"host_tokens": ["server01"]},
        "decisions": [
            _decision_entry(name="a.pdf", path="/x/a.pdf"),
            _decision_entry(
                name="b.pdf",
                path="/x/b.pdf",
                signals=["control:ac-2", "family:AC"],
                ccis=["CCI-000196", "CCI-002235"],
                included=False,
            ),
            _decision_entry(
                name="c.pdf",
                path="/x/c.pdf",
                signals=[],  # surface threshold reached zero signals — unusual but legal
                included=False,
                auto_prechecked=False,
            ),
        ],
    }
    r = client.post("/api/sharepoint/sweep/decisions", json=body)
    assert r.status_code == 200, r.text
    assert r.json() == {"inserted": 3}

    with Session(engine) as s:
        rows = s.exec(select(SweepDecision).order_by(SweepDecision.id)).all()
    assert [row.candidate_name for row in rows] == ["a.pdf", "b.pdf", "c.pdf"]
    assert all(row.workbook_id == wb_id for row in rows)
    assert all(row.weights_version_id == weights_id for row in rows)
    # signals_json is a JSON-encoded list, not a stringified Python repr.
    assert json.loads(rows[0].signals_json) == ["host:server01"]
    assert json.loads(rows[1].signals_json) == ["control:ac-2", "family:AC"]
    assert json.loads(rows[2].signals_json) == []
    # proposed_ccis_json same contract.
    assert json.loads(rows[1].proposed_ccis_json) == ["CCI-000196", "CCI-002235"]
    # included / auto_prechecked carry through.
    assert rows[0].included is True
    assert rows[0].auto_prechecked is True
    assert rows[1].included is False
    assert rows[2].auto_prechecked is False
    # fingerprint snapshot is serialized identically on every row (one snapshot
    # per batch, by design).
    assert json.loads(rows[0].fingerprint_snapshot_json) == {"host_tokens": ["server01"]}
    assert (
        rows[0].fingerprint_snapshot_json == rows[2].fingerprint_snapshot_json
    )


# ---------------------------------------------------------------------------
# Empty-batch short-circuit
# ---------------------------------------------------------------------------


def test_post_decisions_empty_list_returns_zero_and_writes_nothing(env):
    """Empty ``decisions`` → ``{"inserted": 0}``, zero SweepDecision rows.

    The early-return path must run BEFORE the weights resolver — verify
    that by NOT seeding any active row. If the resolver ran, this would
    409 instead of 200.
    """
    client, engine, wb_id = env
    # Deliberately no active weights seeded.

    body = {
        "workbook_id": wb_id,
        "weights_version_id": 999,  # nonexistent — would 409 if resolver ran
        "fingerprint_snapshot": {},
        "decisions": [],
    }
    r = client.post("/api/sharepoint/sweep/decisions", json=body)
    assert r.status_code == 200, r.text
    assert r.json() == {"inserted": 0}

    with Session(engine) as s:
        count = len(s.exec(select(SweepDecision)).all())
    assert count == 0


# ---------------------------------------------------------------------------
# Stale weights_version_id fallback
# ---------------------------------------------------------------------------


def test_post_decisions_falls_back_to_active_when_weights_id_unknown(env):
    """Unknown ``weights_version_id`` but active row exists → all rows are
    tagged with the active row's id, not the stale one from the body.

    Documents the FK-repair behavior: rather than 409-ing a triage
    session because the operator deleted a historical SweepWeights row
    mid-sweep, we anchor to the currently-active row.
    """
    client, engine, wb_id = env
    active_id = _seed_active_weights(engine)
    stale_id = active_id + 9999  # guaranteed unknown

    body = {
        "workbook_id": wb_id,
        "weights_version_id": stale_id,
        "fingerprint_snapshot": {},
        "decisions": [_decision_entry(), _decision_entry(name="b.pdf", path="/x/b.pdf")],
    }
    r = client.post("/api/sharepoint/sweep/decisions", json=body)
    assert r.status_code == 200, r.text
    assert r.json() == {"inserted": 2}

    with Session(engine) as s:
        rows = s.exec(select(SweepDecision)).all()
    assert len(rows) == 2
    # The fallback resolved every row to the active row's id.
    assert all(row.weights_version_id == active_id for row in rows)


# ---------------------------------------------------------------------------
# Hard refusal — no anchor at all
# ---------------------------------------------------------------------------


def test_post_decisions_409_when_weights_unknown_and_no_active(env):
    """Unknown ``weights_version_id`` AND no active row → 409, zero rows.

    This shouldn't happen in production (``init_db`` always seeds a v1
    row marked active), but the 409 is the documented contract for a
    bare DB or one where every row was manually deactivated.
    """
    client, engine, wb_id = env
    # No SweepWeights rows seeded at all.

    body = {
        "workbook_id": wb_id,
        "weights_version_id": 1,
        "fingerprint_snapshot": {},
        "decisions": [_decision_entry()],
    }
    r = client.post("/api/sharepoint/sweep/decisions", json=body)
    assert r.status_code == 409
    # FastAPI puts the message under "detail".
    assert "no active SweepWeights" in r.json()["detail"]

    with Session(engine) as s:
        count = len(s.exec(select(SweepDecision)).all())
    assert count == 0


# ---------------------------------------------------------------------------
# Append-only behavior
# ---------------------------------------------------------------------------


def test_post_decisions_is_append_only_under_repeated_post(env):
    """POSTing the same batch twice writes 2× the rows.

    Each click is a separate behavioral observation. Even if the
    operator re-clicks Ingest with no checkbox changes, we want both
    observations in the corpus — collapsing them would tell the SGD
    updater "this was decided once" when it was in fact decided twice.
    The UI debounces at its layer; the route is intentionally dumb.
    """
    client, engine, wb_id = env
    weights_id = _seed_active_weights(engine)

    body = {
        "workbook_id": wb_id,
        "weights_version_id": weights_id,
        "fingerprint_snapshot": {},
        "decisions": [
            _decision_entry(name="a.pdf", path="/x/a.pdf"),
            _decision_entry(name="b.pdf", path="/x/b.pdf"),
        ],
    }
    r1 = client.post("/api/sharepoint/sweep/decisions", json=body)
    r2 = client.post("/api/sharepoint/sweep/decisions", json=body)
    assert r1.status_code == 200 and r1.json() == {"inserted": 2}
    assert r2.status_code == 200 and r2.json() == {"inserted": 2}

    with Session(engine) as s:
        rows = s.exec(select(SweepDecision).order_by(SweepDecision.id)).all()
    assert len(rows) == 4
    # All four point at the same weights id — append-only doesn't fan out
    # FKs.
    assert {row.weights_version_id for row in rows} == {weights_id}
    # consumed_for_training defaults False on every fresh insert — the
    # SGD updater is the only thing that flips it.
    assert all(row.consumed_for_training is False for row in rows)
