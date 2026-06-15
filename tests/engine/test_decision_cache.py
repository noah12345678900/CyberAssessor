"""Tests for the decision fingerprint cache (kernel-pure).

The cache is the patent-kernel's determinism + cost-savings primitive:
a re-run over an unchanged (CcisRow + tagged_evidence + CRM context +
prompt + kernel version) tuple must return the prior ``Decision``
without burning an LLM call. These tests cover both halves —
fingerprint stability (and the four invalidation triggers) and the
lookup / store / replay round trip through ``Assessor`` itself.

A scratch in-memory SQLite session is wired per-test so the cache
doesn't leak across tests, and so tests don't depend on the developer's
real ``~/.cybersecurity-assessor/`` DB.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from cybersecurity_assessor import db as db_mod
from cybersecurity_assessor.engine import assessor as assessor_mod
from cybersecurity_assessor.engine import decision_cache
from cybersecurity_assessor.engine.assessor import Assessor, LlmProposal
from cybersecurity_assessor.engine.measurement import RunRecorder
from cybersecurity_assessor.excel.ccis_reader import CcisRow
from cybersecurity_assessor.models import ComplianceStatus, DecisionCache


# ---------------------------------------------------------------------------
# Module-wide: disable dual-pass for these tests
# ---------------------------------------------------------------------------
#
# Dual-pass doubles per-attempt proposal consumption — the cache contract
# (one fingerprint → one Decision) is orthogonal to dual-pass and pinning
# it off keeps the StubLlm proposal counts 1:1 with what the test asserts.


@pytest.fixture(autouse=True)
def _disable_dual_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(assessor_mod, "DUAL_PASS_ENABLED", False)


# ---------------------------------------------------------------------------
# Scratch SQLite session
# ---------------------------------------------------------------------------


@pytest.fixture
def session(monkeypatch: pytest.MonkeyPatch) -> Session:
    """Hermetic in-memory SQLModel session with the full schema.

    Each test gets a fresh engine + schema so cache state never leaks
    across tests. Two details make this hermetic for the decision cache:

    1. ``StaticPool`` keeps every connection pointed at the SAME in-memory
       database. ``Assessor._worker_cache_session`` opens its own
       ``Session(engine)`` on the calling thread for cache lookup/store, so
       without a shared pool that worker would see a separate, empty DB.

    2. We monkeypatch ``cybersecurity_assessor.db.engine`` to this engine.
       The worker session imports the engine from ``..db`` at call time —
       if we did not redirect it, the cache round-trip would hit the
       developer's real ``~/.cybersecurity-assessor/assessor.sqlite`` and
       these tests would pollute (and be polluted by) that file.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(db_mod, "engine", engine)
    with Session(engine) as s:
        yield s


# ---------------------------------------------------------------------------
# Test doubles (mirrors tests/test_assessor.py:StubLlm)
# ---------------------------------------------------------------------------


@dataclass
class StubLlm:
    proposals: list[LlmProposal]
    calls: list[dict] = field(default_factory=list)

    def propose(
        self,
        *,
        row: CcisRow,
        corrective_context: str | None = None,
        prior_attempts: list[LlmProposal] | None = None,
        tagged_evidence: str | None = None,
        crm_responsibility: str | None = None,
        boundary_brief: str | None = None,
    ) -> LlmProposal:
        self.calls.append({"cci_id": row.cci_id})
        if not self.proposals:
            raise AssertionError("StubLlm exhausted")
        return self.proposals.pop(0)

    def propose_twice(
        self,
        *,
        row: CcisRow,
        corrective_context: str | None = None,
        prior_attempts: list[LlmProposal] | None = None,
        tagged_evidence: str | None = None,
        crm_responsibility: str | None = None,
        boundary_brief: str | None = None,
    ) -> tuple[LlmProposal, LlmProposal]:
        a = self.propose(
            row=row,
            corrective_context=corrective_context,
            prior_attempts=prior_attempts,
            tagged_evidence=tagged_evidence,
            crm_responsibility=crm_responsibility,
            boundary_brief=boundary_brief,
        )
        b = self.propose(
            row=row,
            corrective_context=corrective_context,
            prior_attempts=prior_attempts,
            tagged_evidence=tagged_evidence,
            crm_responsibility=crm_responsibility,
            boundary_brief=boundary_brief,
        )
        return a, b


def _good_proposal() -> LlmProposal:
    """Validator-accepted proposal; mirrors test_assessor.py:test_llm_happy_path."""
    return LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Verified via USD00050010 §3.2 that automated provisioning "
            "is configured per the plan."
        ),
        input_tokens=100,
        output_tokens=50,
    )


def _llm_only_row(make_row) -> CcisRow:
    """A row that won't hit rule #8 — forces the LLM path."""
    return make_row(
        procedures="Examine account management documentation.",
        inherited="Local",
    )


# Tagged-evidence string that contains the doc token cited by
# ``_good_proposal``. Validator rule #11's unsupported_doc_citation check
# rejects any narrative citing tokens that don't appear in the evidence
# block, so the cache tests must hand in evidence that contains
# "USD00050010" or the orchestrator burns the proposal queue on retries
# before the cache hook ever fires.
_EV_BASE = "Tagged evidence excerpt: USD00050010 §3.2 — account management plan."


def _ev(suffix: str = "") -> str:
    """Cite-verifying evidence string with an optional suffix to vary the
    fingerprint across tests of cache-invalidation behavior."""
    return _EV_BASE + suffix


# ---------------------------------------------------------------------------
# Fingerprint stability
# ---------------------------------------------------------------------------


def test_fingerprint_stable_across_row_position(make_row):
    """``excel_row`` is intentionally excluded — re-ordered rows must
    hash identically so re-importing the same workbook into a different
    sheet position doesn't invalidate the cache."""
    row_a = make_row(excel_row=42)
    row_b = make_row(excel_row=999)
    fp_a = decision_cache.fingerprint(row=row_a, tagged_evidence="evidence", crm_context=None)
    fp_b = decision_cache.fingerprint(row=row_b, tagged_evidence="evidence", crm_context=None)
    assert fp_a == fp_b


def test_fingerprint_changes_on_evidence_change(make_row):
    """A tagged-evidence rewrite (re-ingest, new artifact) must miss."""
    row = make_row()
    fp_a = decision_cache.fingerprint(row=row, tagged_evidence="evidence v1", crm_context=None)
    fp_b = decision_cache.fingerprint(row=row, tagged_evidence="evidence v2", crm_context=None)
    assert fp_a != fp_b


def test_fingerprint_changes_on_kernel_version_bump(make_row, monkeypatch):
    """Kernel-logic changes are signaled by bumping KERNEL_VERSION; the
    fingerprint must move with it so reviewers re-evaluate every
    LLM-derived row under the new contract on the next run."""
    row = make_row()
    fp_a = decision_cache.fingerprint(row=row, tagged_evidence="ev", crm_context=None)
    monkeypatch.setattr(decision_cache, "KERNEL_VERSION", "999.0.0")
    fp_b = decision_cache.fingerprint(row=row, tagged_evidence="ev", crm_context=None)
    assert fp_a != fp_b


def test_fingerprint_changes_on_prompt_change(make_row, monkeypatch):
    """The system prompt is part of the contract — editing it must
    invalidate every cached entry without operator action."""
    row = make_row()
    fp_a = decision_cache.fingerprint(row=row, tagged_evidence="ev", crm_context=None)
    monkeypatch.setattr(decision_cache, "PROMPT_SHA", "deadbeef" * 8)
    fp_b = decision_cache.fingerprint(row=row, tagged_evidence="ev", crm_context=None)
    assert fp_a != fp_b


def test_fingerprint_epoch_zero_matches_legacy(make_row):
    """fix #7 — ``override_epoch=0`` (the never-overridden common case)
    must produce the BYTE-IDENTICAL fingerprint as omitting the kwarg.
    This preserves the entire pre-deploy decision cache and cross-workbook
    sharing for content that's never been manually corrected — the payload
    key is injected only when the epoch is truthy."""
    row = make_row()
    fp_legacy = decision_cache.fingerprint(
        row=row, tagged_evidence="ev", crm_context=None
    )
    fp_epoch0 = decision_cache.fingerprint(
        row=row, tagged_evidence="ev", crm_context=None, override_epoch=0
    )
    assert fp_legacy == fp_epoch0


def test_fingerprint_changes_on_override_epoch_bump(make_row):
    """fix #7 — bumping the per-objective override epoch must move the
    fingerprint so a re-run after a manual correction MISSES the cache and
    re-assesses fresh instead of replaying the superseded Decision."""
    row = make_row()
    fp_0 = decision_cache.fingerprint(
        row=row, tagged_evidence="ev", crm_context=None, override_epoch=0
    )
    fp_1 = decision_cache.fingerprint(
        row=row, tagged_evidence="ev", crm_context=None, override_epoch=1
    )
    fp_2 = decision_cache.fingerprint(
        row=row, tagged_evidence="ev", crm_context=None, override_epoch=2
    )
    assert fp_0 != fp_1
    assert fp_1 != fp_2
    assert fp_0 != fp_2


# ---------------------------------------------------------------------------
# Lookup / store / replay through Assessor
# ---------------------------------------------------------------------------


def test_cache_miss_calls_llm_and_stores(make_row, session):
    """First assess() over a new fingerprint → LLM call + cache row."""
    row = _llm_only_row(make_row)
    llm = StubLlm(proposals=[_good_proposal()])
    assessor = Assessor(llm=llm, cache_session=session)

    decision = assessor.assess(row, tagged_evidence=_ev())

    assert decision.accepted is True
    assert decision.source == "llm"
    assert decision.cache_source is None  # fresh — not a replay
    assert len(llm.calls) == 1

    # One row in the cache table after the store.
    rows = session.exec(select(DecisionCache)).all()
    assert len(rows) == 1
    assert rows[0].kernel_version == decision_cache.KERNEL_VERSION


def test_cache_hit_returns_replay_with_cache_source_set(make_row, session):
    """Second assess() over the same fingerprint replays from cache and
    stamps ``cache_source = "cache_hit"``. ``source`` keeps its
    original semantic value so export queries still see the verdict's
    true origin (``"llm"``)."""
    row = _llm_only_row(make_row)
    # Only one proposal queued — the second call MUST not hit the LLM.
    llm = StubLlm(proposals=[_good_proposal()])
    assessor = Assessor(llm=llm, cache_session=session)

    first = assessor.assess(row, tagged_evidence=_ev())
    second = assessor.assess(row, tagged_evidence=_ev())

    assert second.accepted is True
    assert second.source == "llm"  # original semantic source preserved
    assert second.cache_source == "cache_hit"
    # Narrative round-trips byte-for-byte (the whole point of replay).
    assert second.narrative == first.narrative
    assert second.status == first.status


def test_cache_hit_skips_llm(make_row, session):
    """Hit path must never reach the LLM. StubLlm with no remaining
    proposals would raise — the assertion is the absence of that raise."""
    row = _llm_only_row(make_row)
    # Seed the cache via a first assess().
    llm = StubLlm(proposals=[_good_proposal()])
    Assessor(llm=llm, cache_session=session).assess(row, tagged_evidence=_ev())
    assert len(llm.calls) == 1

    # Now build a second Assessor with an EMPTY proposal queue. If the
    # cache lookup misses for any reason, the StubLlm will raise on
    # propose() — the test fails loudly rather than silently re-burning.
    empty_llm = StubLlm(proposals=[])
    decision = Assessor(llm=empty_llm, cache_session=session).assess(
        row, tagged_evidence=_ev()
    )

    assert decision.cache_source == "cache_hit"
    assert empty_llm.calls == []  # never called


def test_cache_miss_on_evidence_change(make_row, session):
    """End-to-end invalidation: same row, different evidence → miss."""
    row = _llm_only_row(make_row)
    llm = StubLlm(proposals=[_good_proposal(), _good_proposal()])
    assessor = Assessor(llm=llm, cache_session=session)

    assessor.assess(row, tagged_evidence=_ev(" v1"))
    assessor.assess(row, tagged_evidence=_ev(" v2"))

    # Two distinct fingerprints → two LLM calls + two cache rows.
    assert len(llm.calls) == 2
    assert len(session.exec(select(DecisionCache)).all()) == 2


def test_cache_miss_after_override_epoch_bump(make_row, session):
    """fix #7 end-to-end — the silent-revert guard.

    Re-running an objective with a bumped ``override_epoch`` must MISS the
    content-addressed cache (even though row + evidence + CRM are byte
    identical) and call the LLM again, so a reviewer's manual correction
    is never clobbered by a replayed pre-override Decision. Epoch 0 then
    epoch 1 ⇒ two LLM calls + two cache rows; the epoch-1 run is fresh,
    not a replay."""
    row = _llm_only_row(make_row)
    llm = StubLlm(proposals=[_good_proposal(), _good_proposal()])
    assessor = Assessor(llm=llm, cache_session=session)

    first = assessor.assess(row, tagged_evidence=_ev(), override_epoch=0)
    second = assessor.assess(row, tagged_evidence=_ev(), override_epoch=1)

    # Distinct fingerprints → both reached the LLM, neither replayed.
    assert len(llm.calls) == 2
    assert first.cache_source is None
    assert second.cache_source is None
    assert len(session.exec(select(DecisionCache)).all()) == 2


def test_cache_hit_preserved_when_epoch_unchanged(make_row, session):
    """fix #7 — the epoch must not gratuitously break caching. With the
    SAME epoch on both runs the second assess() still replays from cache
    (the epoch is a tiebreaker on override, not a per-run nonce)."""
    row = _llm_only_row(make_row)
    llm = StubLlm(proposals=[_good_proposal()])  # one only — replay or bust
    assessor = Assessor(llm=llm, cache_session=session)

    assessor.assess(row, tagged_evidence=_ev(), override_epoch=3)
    second = assessor.assess(row, tagged_evidence=_ev(), override_epoch=3)

    assert second.cache_source == "cache_hit"
    assert len(llm.calls) == 1


def test_abstain_rows_not_cached(make_row, session):
    """Per the decision_cache module docstring: abstain rows are
    deliberately re-evaluated on the next run in case the kernel learns
    better between runs. Verify by triggering the no-llm-client abstain
    twice — each call must produce a fresh abstain, never a cache hit,
    and the cache table must stay empty."""
    row = _llm_only_row(make_row)
    assessor = Assessor(llm=None, cache_session=session)

    first = assessor.assess(row, tagged_evidence=_ev())
    second = assessor.assess(row, tagged_evidence=_ev())

    assert first.source == "abstain"
    assert second.source == "abstain"
    assert first.cache_source is None
    assert second.cache_source is None
    assert len(session.exec(select(DecisionCache)).all()) == 0


def test_rule_8a_not_cached(make_row, session):
    """Rule #8 short-circuits run before the cache lookup and are
    deterministic — caching them buys nothing. Verify by firing 8a
    twice and confirming the cache table stays empty."""
    row = make_row(
        procedures="Automatically compliant per assessment procedures.",
    )
    llm = StubLlm(proposals=[])  # would explode if called
    assessor = Assessor(llm=llm, cache_session=session)

    first = assessor.assess(row)
    second = assessor.assess(row)

    assert first.source == "rule_8a"
    assert second.source == "rule_8a"
    assert first.cache_source is None
    assert second.cache_source is None
    assert len(session.exec(select(DecisionCache)).all()) == 0


def test_recorder_cache_hit_aggregated(make_row, session):
    """``CciOutcome.cache_hit`` rolls up to ``AssessmentRun.cache_hits``
    via ``RunRecorder._apply_aggregates`` — the Runs page surfaces the
    counter ticking up as batch runs hit cache."""
    row = _llm_only_row(make_row)
    llm = StubLlm(proposals=[_good_proposal()])
    assessor = Assessor(llm=llm, cache_session=session)

    # Seed the cache with one fresh decision (no recorder — the miss
    # path is independently covered above).
    assessor.assess(row, tagged_evidence=_ev())

    # Now re-run under a recorder — this assess() should be a hit and
    # flag the outcome accordingly.
    recorder = RunRecorder.start(session, workbook_id=None)
    assessor.assess(row, tagged_evidence=_ev(), recorder=recorder)
    run = recorder.finish()

    assert run.cache_hits == 1
    assert len(recorder.outcomes) == 1
    assert recorder.outcomes[0].cache_hit is True


def test_cache_disabled_when_no_session(make_row):
    """Default (kernel-pure / session-free) construction must skip the
    cache entirely. This is the legacy test-contract guarantee — tests
    that instantiate ``Assessor(llm=...)`` get no cache pollution."""
    row = _llm_only_row(make_row)
    llm = StubLlm(proposals=[_good_proposal(), _good_proposal()])
    assessor = Assessor(llm=llm)  # no cache_session

    first = assessor.assess(row, tagged_evidence=_ev())
    second = assessor.assess(row, tagged_evidence=_ev())

    # Both calls hit the LLM; cache_source stays None on both.
    assert len(llm.calls) == 2
    assert first.cache_source is None
    assert second.cache_source is None
