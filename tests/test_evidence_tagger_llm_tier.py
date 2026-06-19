"""Tier 5-LLM "smart backstop" coverage — ``tagger._tag_via_llm``.

The deterministic tiers (1-4) are pinned in ``test_evidence_tagger.py``. The
LLM backstop — the path that asks a judge model whether an *under-tagged*
artifact is relevant to each TF-IDF-pre-selected candidate control — had no
collected coverage. This file pins its accept/abstain/error contract directly
against ``_tag_via_llm`` (the unit), plus two integration assertions through
``tag_evidence`` for the low-tag gate and the all-errors→TF-IDF fallback.

Design under test (current, parallel per-candidate fan-out — NOT the abandoned
"batch-then-verify" Lever-A design):

  * TF-IDF pre-selects candidates; when every cosine is 0.0 the selector falls
    back to ``ranked[:TOPK]`` (all controls, cid-sorted), so a token-disjoint
    artifact lets us drive the judge partition deterministically without TF-IDF
    in the way.
  * Phase 1 judges candidate[0] synchronously (seeds the prompt cache), then
    fans the rest out across a bounded thread pool.
  * Phase 2 applies verdicts in the original candidate order on the calling
    thread (``add`` is the sole, non-thread-safe EvidenceTag construction site).
  * A candidate is tagged iff its judge score >= ``_LLM_TIER_ACCEPT_SCORE`` (0.6).
    A score below it — OR a parse-error abstention (judge returns 0.0 without
    raising) — drops, never tags. A real API/network error (the judge call
    raises) increments ``errored`` and never tags.
  * The caller's TF-IDF-fallback trigger is ``attempted > 0 and
    errored == attempted`` (a total outage), NOT a confident all-abstain.

``feedback_precision_over_recall``: an abstention (low score or parse error)
must never become a tag — these tests pin exactly that.
"""

from __future__ import annotations

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from cybersecurity_assessor.evidence.tagger import (
    _LLM_TIER_ACCEPT_SCORE,
    _LLM_TIER_CONFIDENCE,
    _TIER3_RELEVANCE_CEIL,
    _TIER3_RELEVANCE_FLOOR,
    _TIER5_MIN_EXISTING,
    _tag_via_llm,
    tag_evidence,
)
from cybersecurity_assessor.models import (
    Control,
    Evidence,
    EvidenceKind,
    EvidenceTag,
    Framework,
    Objective,
)

# An artifact body whose tokens are disjoint from every control requirement
# text below, so every TF-IDF cosine is 0.0 and candidate selection falls back
# to the deterministic ``ranked[:TOPK]`` (all controls, cid-sorted). This takes
# TF-IDF out of the equation so these unit tests exercise the judge
# accept/abstain/error partition only, with verdicts supplied by the stub.
_DISJOINT_ARTIFACT = "qzx qzx zzy zzy wkk plover plover frob frob frob"


def _expected_relevance(score: float) -> float:
    """The relevance _tag_via_llm maps an accepted judge score to."""
    return round(
        _TIER3_RELEVANCE_FLOOR
        + (_TIER3_RELEVANCE_CEIL - _TIER3_RELEVANCE_FLOOR) * score,
        3,
    )


def _controls(specs: list[tuple[str, str]]) -> dict[str, list[Objective]]:
    """Build an ``all_by_control`` map (cid -> [Objective]) from (cid, text).

    Each control gets a single child Objective with a real ``id`` (the tagger
    skips ``obj.id is None``) so the fan-out tags exactly one row per accepted
    control — keeping the per-control hit count unambiguous.
    """
    by: dict[str, list[Objective]] = {}
    oid = 0
    for cid, text in specs:
        oid += 1
        by[cid] = [
            Objective(
                id=oid,
                control_id_fk=oid,
                objective_id=cid.upper(),
                text=text,
            )
        ]
    return by


def _recorder():
    """Return ``(tags, add)`` where ``add`` mirrors tag_evidence's ``_add``."""
    tags: list[dict] = []

    def add(objective_id, *, relevance, confidence, source, rationale):
        tags.append(
            {
                "objective_id": objective_id,
                "relevance": relevance,
                "confidence": confidence,
                "source": source,
                "rationale": rationale,
            }
        )

    return tags, add


def _cid_from_user_text(user_text: str) -> str:
    """Recover the control id from ``_llm_candidate_user_text``'s first line."""
    first = user_text.split("\n", 1)[0]
    return first.removeprefix("Control:").strip().upper()


class _StubJudge:
    """A stub LLM client exposing only ``judge_relevance`` (the path under test).

    ``scores`` : cid(upper) -> score the judge returns. Missing cids default
                 to 0.0 (a confident "not relevant").
    ``raise_for`` : True (every call raises) | a set of cid(upper) that raise |
                    None. A raise models a real API/network failure; the tagger
                    counts it as ``errored`` and never tags.
    ``parse_error_for`` : set of cid(upper) for which the judge returns the
                    ``(0.0, "[parse_error] ...")`` envelope WITHOUT raising —
                    the malformed-output abstention that must drop, not error.
    """

    def __init__(
        self,
        *,
        scores: dict[str, float] | None = None,
        raise_for=None,
        parse_error_for: set[str] | None = None,
    ):
        self.scores = {k.upper(): v for k, v in (scores or {}).items()}
        # Normalize cid sets to upper-case so callers can pass "au-12"; _judge
        # compares against the upper-case cid recovered from the user turn.
        if isinstance(raise_for, (set, frozenset)):
            self.raise_for = {c.upper() for c in raise_for}
        else:
            self.raise_for = raise_for
        self.parse_error_for = {c.upper() for c in (parse_error_for or set())}
        self.calls: list[str] = []  # cids actually judged

    def judge_relevance(self, system_blocks, user_text, *, model=None):
        cid = _cid_from_user_text(user_text)
        self.calls.append(cid)
        if self.raise_for is True or (
            isinstance(self.raise_for, (set, frozenset)) and cid in self.raise_for
        ):
            raise RuntimeError(f"judge endpoint down for {cid}")
        if cid in self.parse_error_for:
            # Mirrors client.judge_relevance's malformed-output fallback: a 0.0
            # score with a parse-error reason, returned (not raised).
            return 0.0, "[parse_error] expecting value", None
        return self.scores.get(cid, 0.0), f"reason-{cid}", None


def _run(client, specs):
    tags, add = _recorder()
    result = _tag_via_llm(
        _DISJOINT_ARTIFACT,
        client=client,
        judge_model="stub-judge",
        all_by_control=_controls(specs),
        artifact_title="stub artifact",
        add=add,
    )
    return result, tags


# ---------------------------------------------------------------------------
# Accept / abstain partition
# ---------------------------------------------------------------------------


def test_accept_at_or_above_threshold_tags_all_children():
    """A judge score >= 0.6 tags the control's child objective(s) as source=llm."""
    score = 0.90
    client = _StubJudge(scores={"ac-2": score})
    (hits, attempted, errored), tags = _run(client, [("ac-2", "account management")])

    assert client.calls == ["AC-2"]
    assert (hits, attempted, errored) == (1, 1, 0)
    assert len(tags) == 1
    tag = tags[0]
    assert tag["source"] == "llm"
    assert tag["confidence"] == _LLM_TIER_CONFIDENCE
    assert tag["relevance"] == _expected_relevance(score)
    assert "AC-2" in tag["rationale"]
    assert "reason-AC-2" in tag["rationale"]  # judge reasoning is carried through


def test_exact_threshold_is_inclusive_accept():
    """Score == _LLM_TIER_ACCEPT_SCORE (0.6) is an accept (>=, not >)."""
    client = _StubJudge(scores={"ac-2": _LLM_TIER_ACCEPT_SCORE})
    (hits, _attempted, _errored), tags = _run(client, [("ac-2", "account management")])
    assert hits == 1
    assert tags[0]["relevance"] == _expected_relevance(_LLM_TIER_ACCEPT_SCORE)


def test_below_threshold_abstains_no_tag():
    """A judge score < 0.6 is an abstention — dropped, never tagged."""
    client = _StubJudge(scores={"ac-2": 0.59})  # just under the accept floor
    (hits, attempted, errored), tags = _run(client, [("ac-2", "account management")])

    assert client.calls == ["AC-2"]
    assert (hits, attempted, errored) == (0, 1, 0)
    assert tags == []


def test_parse_error_abstention_drops_and_is_not_counted_errored():
    """A (0.0, "[parse_error]") verdict drops as an abstention, not an error.

    ``client.judge_relevance`` returns 0.0 for malformed model output WITHOUT
    raising; that is a confident "can't tell" → no tag, and crucially it must
    NOT increment ``errored`` (which would, if it were the only candidate,
    falsely trip the caller's outage→TF-IDF fallback).
    """
    client = _StubJudge(parse_error_for={"ac-2"})
    (hits, attempted, errored), tags = _run(client, [("ac-2", "account management")])

    assert (hits, attempted, errored) == (0, 1, 0)
    assert errored == 0, "a parse-error abstention is not an API error"
    assert tags == []


def test_mixed_accept_and_abstain():
    """Multiple candidates: only those clearing 0.6 tag; order-independent."""
    client = _StubJudge(scores={"ac-2": 0.95, "au-12": 0.20, "ia-2": 0.75})
    (hits, attempted, errored), tags = _run(
        client,
        [
            ("ac-2", "account management"),
            ("au-12", "audit record generation"),
            ("ia-2", "identification and authentication"),
        ],
    )

    assert sorted(client.calls) == ["AC-2", "AU-12", "IA-2"]
    assert (hits, attempted, errored) == (2, 3, 0)
    assert {t["relevance"] for t in tags} == {
        _expected_relevance(0.95),
        _expected_relevance(0.75),
    }
    tagged_controls = {  # AU-12 abstained → absent
        t["rationale"].split("for ", 1)[1].split(" ", 1)[0] for t in tags
    }
    assert tagged_controls == {"AC-2", "IA-2"}


# ---------------------------------------------------------------------------
# Error handling / outage detection
# ---------------------------------------------------------------------------


def test_api_error_counts_errored_and_does_not_tag():
    """A judge call that RAISES increments errored and produces no tag."""
    client = _StubJudge(raise_for={"ac-2"})
    (hits, attempted, errored), tags = _run(client, [("ac-2", "account management")])

    assert (hits, attempted, errored) == (0, 1, 1)
    assert tags == []


def test_total_outage_reports_errored_equals_attempted():
    """Every judge call raises → errored == attempted (the fallback trigger).

    The caller (``tag_evidence``) turns ``attempted > 0 and errored ==
    attempted`` into a TF-IDF Tier-5 fallback. This pins the signal the
    fallback depends on.
    """
    client = _StubJudge(raise_for=True)
    (hits, attempted, errored), tags = _run(
        client, [("ac-2", "account management"), ("au-12", "audit generation")]
    )

    assert hits == 0
    assert attempted == 2
    assert errored == attempted
    assert tags == []


def test_partial_error_is_not_an_outage():
    """One candidate accepts, another errors → errored < attempted.

    A working judge with a single transient failure must not look like a total
    outage; the caller keeps the partial result rather than spraying TF-IDF
    guesses on top of a functioning judge.
    """
    client = _StubJudge(scores={"ac-2": 0.92}, raise_for={"au-12"})
    (hits, attempted, errored), tags = _run(
        client, [("ac-2", "account management"), ("au-12", "audit generation")]
    )

    assert hits == 1
    assert attempted == 2
    assert errored == 1
    assert errored < attempted
    assert len(tags) == 1
    assert tags[0]["relevance"] == _expected_relevance(0.92)


# ---------------------------------------------------------------------------
# Degenerate input
# ---------------------------------------------------------------------------


def test_empty_all_by_control_returns_zeroes_and_no_judge_calls():
    """No candidate controls → (0, 0, 0) and the judge is never consulted."""
    client = _StubJudge(scores={"ac-2": 0.99})
    tags, add = _recorder()
    result = _tag_via_llm(
        _DISJOINT_ARTIFACT,
        client=client,
        judge_model="stub-judge",
        all_by_control={},
        artifact_title="stub artifact",
        add=add,
    )
    assert result == (0, 0, 0)
    assert client.calls == []
    assert tags == []


def test_accept_fans_out_to_every_child_objective():
    """An accepted control tags ALL of its child CCIs, not just the first.

    Mirrors the per-CCI architecture: each child Objective needs its own tag
    so its per-CCI evidence bundle is non-empty.
    """
    by = {
        "ac-2": [
            Objective(id=1, control_id_fk=1, objective_id="CCI-000015", text="a"),
            Objective(id=2, control_id_fk=1, objective_id="CCI-000017", text="b"),
        ]
    }
    tags, add = _recorder()
    (hits, attempted, errored) = _tag_via_llm(
        _DISJOINT_ARTIFACT,
        client=_StubJudge(scores={"ac-2": 0.80}),
        judge_model="stub-judge",
        all_by_control=by,
        artifact_title="stub artifact",
        add=add,
    )
    assert hits == 2  # one tag per child CCI
    assert attempted == 1  # but only ONE judge call for the control
    assert errored == 0
    assert {t["objective_id"] for t in tags} == {1, 2}


# ---------------------------------------------------------------------------
# Integration through tag_evidence — low-tag gate + outage fallback
# ---------------------------------------------------------------------------


@pytest.fixture
def session() -> Session:
    """In-memory catalog: AC-2 (two CCIs, one citing USD00050010) + AU-2."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    s = Session(engine)

    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    s.add(fw)
    s.flush()
    ac2 = Control(framework_id=fw.id, control_id="ac-2", title="Account Management", family="AC")
    au2 = Control(framework_id=fw.id, control_id="au-2", title="Audit Events", family="AU")
    s.add_all([ac2, au2])
    s.flush()
    s.add_all(
        [
            Objective(
                control_id_fk=ac2.id,
                objective_id="CCI-000015",
                text="Employ automated account management mechanisms.",
                implementation_guidance="Local IdAM tooling per USD00050010.",
            ),
            Objective(
                control_id_fk=ac2.id,
                objective_id="CCI-000017",
                text="Notify managers of account changes per USD00050010.",
                implementation_guidance="Account change notifications per USD00050010.",
            ),
            Objective(
                control_id_fk=au2.id,
                objective_id="CCI-000130",
                text="Generate audit records for defined events.",
            ),
        ]
    )
    s.commit()
    yield s
    s.close()


def _evidence(s: Session, **overrides) -> Evidence:
    defaults = dict(
        path="C:/fake/doc.pdf",
        sha256="deadbeef",
        kind=EvidenceKind.PDF,
        size_bytes=100,
        title="Doc",
        doc_number=None,
    )
    defaults.update(overrides)
    e = Evidence(**defaults)
    s.add(e)
    s.flush()
    return e


class _RecordingClient:
    """Minimal client that records whether judge_relevance was ever called."""

    def __init__(self, *, score: float = 0.9, raise_always: bool = False):
        self.score = score
        self.raise_always = raise_always
        self.call_count = 0

    def judge_relevance(self, system_blocks, user_text, *, model=None):
        self.call_count += 1
        if self.raise_always:
            raise RuntimeError("judge endpoint down")
        return self.score, "ok", None


def test_well_tagged_doc_never_invokes_the_judge(session):
    """A doc the deterministic tiers cover (>= _TIER5_MIN_EXISTING tags) skips
    the LLM entirely — the low-tag gate must protect the hot path from a call.

    The doc-number USD00050010 is cited by BOTH AC-2 CCIs, so Tier 1 produces
    two tags (== _TIER5_MIN_EXISTING) and the Tier-5 gate
    ``len(existing) < _TIER5_MIN_EXISTING`` is False.
    """
    assert _TIER5_MIN_EXISTING == 2  # guards the fixture's 2-CCI assumption
    e = _evidence(session, doc_number="USD00050010")
    client = _RecordingClient(score=0.9)
    result = tag_evidence(session, e, text="Account mgmt per USD00050010.", client=client)

    assert result.doc_number_hits >= 2
    assert client.call_count == 0, "well-tagged doc must not reach the judge"
    assert result.judge_invoked is False


def test_undertagged_doc_reaches_judge_and_tags_via_llm(session):
    """Prose with no doc/CCI/control-ID signal → judge consulted → source=llm.

    The body deliberately names no USD number, no CCI token, and no control ID,
    so Tiers 1-4 produce zero tags and the Tier-5 gate opens. With a client
    present, accepted candidates are tagged source="llm".
    """
    e = _evidence(session, doc_number=None)
    client = _RecordingClient(score=0.9)
    result = tag_evidence(
        session,
        e,
        text="Our team reviews who can access systems and revokes stale logins quarterly.",
        client=client,
    )

    assert client.call_count > 0
    assert result.judge_invoked is True
    llm_tags = session.exec(
        select(EvidenceTag)
        .where(EvidenceTag.evidence_id == e.id)
        .where(EvidenceTag.source == "llm")
    ).all()
    assert llm_tags, "an accepted judge verdict should persist a source=llm tag"
    assert all(t.confidence == _LLM_TIER_CONFIDENCE for t in llm_tags)


def test_judge_outage_falls_back_to_tfidf(session):
    """Every judge call errors → tag_evidence degrades to the TF-IDF Tier 5.

    With a judge that always raises, ``_tag_via_llm`` returns
    ``errored == attempted`` and ``tag_evidence`` runs the deterministic TF-IDF
    backstop instead of dropping the artifact. The fallback emits
    ``source in {auto, auto_review}`` (never ``llm``), proving we degraded to
    prior behavior rather than silently losing the backstop.
    """
    e = _evidence(session, doc_number=None)
    client = _RecordingClient(raise_always=True)
    # Body must (1) clear the deterministic Tier-5 substance gate
    # (_TIER5_MIN_BODY_TOKENS = 25 distinct significant tokens) and (2) share
    # vocabulary with AC-2's requirement text ("automated account management
    # mechanisms", "notify managers of account changes") so TF-IDF has a
    # non-zero cosine to fall back on once the judge is ruled out. A realistic
    # account-management SOP paragraph satisfies both.
    result = tag_evidence(
        session,
        e,
        text=(
            "This standard operating procedure governs account management "
            "across the enterprise. Automated provisioning mechanisms create, "
            "modify, disable, and remove privileged and standard user accounts "
            "according to documented role assignments. The identity team "
            "reviews account membership quarterly, revokes stale credentials, "
            "and notifies designated account managers whenever account changes, "
            "transfers, or terminations occur within the system boundary."
        ),
        client=client,
    )

    assert result.judge_invoked is True
    assert client.call_count > 0
    tags = session.exec(
        select(EvidenceTag).where(EvidenceTag.evidence_id == e.id)
    ).all()
    sources = {t.source for t in tags}
    assert "llm" not in sources, "an outage must not yield llm-sourced tags"
    assert sources & {"auto", "auto_review"}, "TF-IDF fallback should have tagged"
