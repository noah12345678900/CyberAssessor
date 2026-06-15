"""Golden tests for the per-CCI tagged-evidence builder.

``engine.evidence_bundle.build_tagged_evidence`` is the function that
turns ``EvidenceTag`` rows into the ``## tagged_evidence`` block the LLM
sees in ``assess_control.md``. It is on the hot path of every LLM-routed
CCI — get the ordering, the supersession filter, or the snippet budget
wrong and either (a) the model sees a stale doc, (b) it spends tokens
re-reading a low-relevance artifact ahead of a high-relevance one, or
(c) prompt caching breaks when an irrelevant tag pushes a relevant block
out of the prefix.

These are DB-shaped tests: in-memory SQLite + StaticPool (matches the
pattern in ``test_workbook_sync.py``) with hand-built ``Framework`` →
``Control`` → ``Objective`` → ``Evidence`` → ``EvidenceTag`` rows. No
LLM, no file extractor — extracted text is written straight to
``tmp_path`` so the head/tail truncation path is exercised on real
bytes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

# Ensure the backend package is importable when pytest is launched from any cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.engine.evidence_bundle import (  # noqa: E402
    HEAD_CHARS,
    PER_ARTIFACT_CHARS,
    TAIL_CHARS,
    build_tagged_evidence,
    build_tagged_evidence_with_payload,
)
from cybersecurity_assessor.engine.evidence_ranker import (  # noqa: E402
    DISPOSITION_DEFERRED,
    DISPOSITION_EXAMINED,
    OVERFLOW_ESCALATE,
    OVERFLOW_FINALIZE_ON_EXAMINED,
    OVERFLOW_NONE,
    REASON_TOKEN_BUDGET,
    RankerConfig,
)
from cybersecurity_assessor.models import (  # noqa: E402
    Control,
    Evidence,
    EvidenceKind,
    EvidenceTag,
    FindingStatus,
    Framework,
    Objective,
    StigFinding,
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
def objective(session) -> Objective:
    """Persist Framework → Control → Objective and return the Objective."""
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)

    ctrl = Control(
        framework_id=fw.id, control_id="AC-2", title="Account Management", family="AC"
    )
    session.add(ctrl)
    session.commit()
    session.refresh(ctrl)

    obj = Objective(
        control_id_fk=ctrl.id,
        objective_id="CCI-000015",
        source="CCI",
        text="The organization defines a frequency for account reviews.",
    )
    session.add(obj)
    session.commit()
    session.refresh(obj)
    return obj


def _add_evidence(
    session: Session,
    *,
    path: str,
    sha: str = "deadbeef",
    kind: EvidenceKind = EvidenceKind.PDF,
    title: str | None = "Account Management Plan",
    doc_number: str | None = "USD00050010",
    extracted_text_path: str | None = None,
    superseded_by_id: int | None = None,
    hosts: list[str] | None = None,
) -> Evidence:
    ev = Evidence(
        path=path,
        sha256=sha,
        kind=kind,
        size_bytes=1024,
        title=title,
        doc_number=doc_number,
        extracted_text_path=extracted_text_path,
        superseded_by_id=superseded_by_id,
        host_inventory=json.dumps(hosts) if hosts else None,
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    return ev


def _add_stig_finding(
    session: Session,
    *,
    evidence_id: int,
    rule_id: str,
    cci_refs: str,
    severity: str = "medium",
    status: FindingStatus = FindingStatus.OPEN,
    finding_details: str = "Setting not enforced.",
) -> StigFinding:
    """Persist a StigFinding for the corroboration tests.

    Mirrors the helper in test_generator_description.py — the assessor and
    POAM tests both exercise the shared corroboration module, so they
    should look familiar to a reader bouncing between the two.
    """
    f = StigFinding(
        evidence_id=evidence_id,
        rule_id=rule_id,
        cci_refs=cci_refs,
        severity=severity,
        status=status,
        finding_details=finding_details,
    )
    session.add(f)
    session.commit()
    session.refresh(f)
    return f


def _tag(
    session: Session,
    *,
    evidence_id: int,
    objective_id: int,
    relevance: float = 0.5,
    confidence: float = 0.5,
    source: str = "auto",
) -> EvidenceTag:
    t = EvidenceTag(
        evidence_id=evidence_id,
        objective_id=objective_id,
        relevance=relevance,
        confidence=confidence,
        source=source,
    )
    session.add(t)
    session.commit()
    session.refresh(t)
    return t


# ---------------------------------------------------------------------------
# Cache-preserving no-tags path
# ---------------------------------------------------------------------------


def test_returns_none_when_objective_has_no_tags(session, objective):
    """No EvidenceTag rows → None, so the prompt prefix stays cache-warm.

    This is load-bearing: the docstring (evidence_bundle.py:12-15) calls
    out that callers must skip the ``tagged_evidence`` placeholder when
    None so Anthropic/OpenAI prompt caching works on the (much more
    common) untagged CCI path. Don't change the contract to "" without
    auditing the prompt builder.
    """
    assert build_tagged_evidence(objective.id, session) is None


def test_returns_none_when_only_tagged_evidence_is_superseded(session, objective):
    """A row whose only artifact has superseded_by_id set → treated as no tags.

    The supersession filter (`Evidence.superseded_by_id.is_(None)`) is the
    third patent-supporting kernel guard's read-side enforcement. A
    superseded artifact must NEVER reach the LLM as "current evidence"
    — the supersession chain exists precisely so legacy USD docs don't
    come back as evidence after the new tier ships.
    """
    current = _add_evidence(session, path="file:///current.pdf", sha="aaa")
    legacy = _add_evidence(
        session,
        path="file:///legacy.pdf",
        sha="bbb",
        superseded_by_id=current.id,
    )
    # Tag ONLY the legacy artifact — the current one is not tagged to this CCI.
    _tag(session, evidence_id=legacy.id, objective_id=objective.id, relevance=0.9)

    assert build_tagged_evidence(objective.id, session) is None


# ---------------------------------------------------------------------------
# Ordering + cap
# ---------------------------------------------------------------------------


def test_sorts_by_relevance_then_confidence_descending(session, objective, tmp_path):
    """Higher relevance first; on tie, higher confidence wins.

    Sort tuple is ``(relevance, confidence)`` reverse=True — both fields
    descend together. Manual tags default 1.0/0.5; pin both axes so a
    future refactor that drops one field shows up immediately.
    """
    # All three have distinct extracted text so we can read back the order.
    paths = {}
    for tag_label in ("low_rel", "mid_rel_high_conf", "mid_rel_low_conf"):
        text_path = tmp_path / f"{tag_label}.txt"
        text_path.write_text(f"snippet for {tag_label}", encoding="utf-8")
        paths[tag_label] = str(text_path)

    low_rel = _add_evidence(
        session,
        path="file:///low.pdf",
        sha="111",
        title="LowRel",
        extracted_text_path=paths["low_rel"],
    )
    mid_high = _add_evidence(
        session,
        path="file:///midhigh.pdf",
        sha="222",
        title="MidRelHighConf",
        extracted_text_path=paths["mid_rel_high_conf"],
    )
    mid_low = _add_evidence(
        session,
        path="file:///midlow.pdf",
        sha="333",
        title="MidRelLowConf",
        extracted_text_path=paths["mid_rel_low_conf"],
    )

    _tag(session, evidence_id=low_rel.id, objective_id=objective.id, relevance=0.1, confidence=0.9)
    _tag(session, evidence_id=mid_high.id, objective_id=objective.id, relevance=0.7, confidence=0.9)
    _tag(session, evidence_id=mid_low.id, objective_id=objective.id, relevance=0.7, confidence=0.2)

    result = build_tagged_evidence(objective.id, session)
    assert result is not None

    # Title order in the rendered block reflects the sort.
    i_mid_high = result.index("MidRelHighConf")
    i_mid_low = result.index("MidRelLowConf")
    i_low = result.index("LowRel")
    assert i_mid_high < i_mid_low < i_low


def _seed_artifacts(session, objective, tmp_path, count, *, body=None):
    """Persist ``count`` tagged artifacts with distinct descending relevance.

    Each carries a ``unique-marker-{i}`` token so the rendered output can be
    probed for presence/absence. ``body`` lets a caller force large snippets
    (over-budget edge cases); default is a tiny sub-budget marker line.
    """
    for i in range(count):
        text_path = tmp_path / f"ev_{i}.txt"
        text = body(i) if body else f"unique-marker-{i}"
        text_path.write_text(text, encoding="utf-8")
        ev = _add_evidence(
            session,
            path=f"file:///ev{i}.pdf",
            sha=f"sha{i:03}",
            title=f"Artifact {i}",
            extracted_text_path=str(text_path),
        )
        # Distinct, descending relevance so ranking order is deterministic.
        _tag(
            session,
            evidence_id=ev.id,
            objective_id=objective.id,
            relevance=1.0 - (i * 0.05),
        )


def test_all_tiny_artifacts_examined_no_silent_cap(session, objective, tmp_path):
    """Token-budget contract: tiny artifacts ALL render — no fixed-N cap.

    The retired ``MAX_ARTIFACTS = 6`` cap silently dropped artifacts 7..N
    (never examined, never audited). Under the token-budget ranker every
    sub-budget artifact is examined. Seven (one past the old cap) all appear
    so a regression to a hard cap is caught.
    """
    _seed_artifacts(session, objective, tmp_path, 7)

    result = build_tagged_evidence(objective.id, session)
    assert result is not None
    for i in range(7):
        assert f"unique-marker-{i}" in result, f"missing artifact {i}"


def test_partition_is_total_no_artifact_dropped(session, objective, tmp_path):
    """examined + deferred == N for every (tiny or huge) artifact set.

    The core defensibility invariant: nothing is silently dropped. Even when
    the budget forces deferral, every candidate lands in exactly one audit
    disposition. Verified via the payload variant (which carries both
    examined and deferred rows).
    """
    _seed_artifacts(session, objective, tmp_path, 9)

    # Tiny budget forces all-but-one into deferred (top artifact always
    # admitted so the examined set is never empty).
    tiny = RankerConfig(token_budget=1)
    text, payload, overflow = build_tagged_evidence_with_payload(
        objective.id, session, config=tiny
    )
    assert text is not None

    examined = [p for p in payload if p.disposition == DISPOSITION_EXAMINED]
    deferred = [p for p in payload if p.disposition == DISPOSITION_DEFERRED]
    # Total partition — no row lost.
    assert len(examined) + len(deferred) == 9
    # Top-ranked single artifact admitted despite the 1-token budget.
    assert len(examined) == 1
    assert len(deferred) == 8
    # Every deferred row is fully audited (sha + reason captured).
    for p in deferred:
        assert p.deferred_reason == REASON_TOKEN_BUDGET
        assert p.chunk_sha
        assert p.chunk_text


def test_highest_relevance_examined_first(session, objective, tmp_path):
    """Under a partial budget the EXAMINED set is the highest-relevance prefix.

    Relevance descends with i (artifact 0 highest). A budget that admits
    exactly the first three must examine markers 0-2 and defer the rest —
    the audit trail must never examine a low-relevance artifact while a
    higher-relevance one is deferred.
    """
    # Each marker line is short; pick a budget that fits ~3 of them. Token
    # estimate is ceil(len/4); "unique-marker-0" is 15 chars → 4 tokens.
    _seed_artifacts(session, objective, tmp_path, 6)
    cfg = RankerConfig(token_budget=12)  # ~3 tiny artifacts
    _text, payload, _overflow = build_tagged_evidence_with_payload(
        objective.id, session, config=cfg
    )
    examined = [p for p in payload if p.disposition == DISPOSITION_EXAMINED]
    examined_relevances = sorted((p.relevance for p in examined), reverse=True)
    deferred = [p for p in payload if p.disposition == DISPOSITION_DEFERRED]
    # No deferred artifact outranks any examined one.
    if examined and deferred:
        assert min(examined_relevances) >= max(p.relevance for p in deferred)


def test_overflow_none_when_everything_fits(session, objective, tmp_path):
    """Generous default budget → OverflowDecision strategy == none."""
    _seed_artifacts(session, objective, tmp_path, 5)
    _text, payload, overflow = build_tagged_evidence_with_payload(
        objective.id, session
    )
    assert overflow.strategy == OVERFLOW_NONE
    assert overflow.deferred_count == 0
    assert all(p.disposition == DISPOSITION_EXAMINED for p in payload)


def test_overflow_escalates_when_high_relevance_deferred(
    session, objective, tmp_path
):
    """High-relevance artifacts deferred → escalate (verdict withheld).

    All seeded artifacts sit above the corroboration floor (0.35) because
    relevance starts at 1.0 and steps down by 0.05. A tiny budget therefore
    defers high-relevance evidence, which must escalate rather than quietly
    finalize on the examined subset — precision over recall.
    """
    _seed_artifacts(session, objective, tmp_path, 6)
    cfg = RankerConfig(token_budget=1)
    _text, _payload, overflow = build_tagged_evidence_with_payload(
        objective.id, session, config=cfg
    )
    assert overflow.strategy == OVERFLOW_ESCALATE
    assert overflow.deferred_count == 5


def test_overflow_finalizes_when_deferred_tail_is_corroboration(
    session, objective, tmp_path
):
    """Deferred tail all <= corroboration floor → finalize_on_examined.

    One strong artifact (relevance 0.9) plus low-signal corroboration
    (relevance 0.20, under the 0.35 floor). A budget that admits only the
    strong one defers pure corroboration, so the examined set carries the
    decision — the tail is still audited as deferred, just non-decisive.
    """
    strong = _add_evidence(
        session, path="file:///strong.pdf", sha="s001", title="Strong"
    )
    strong_text = tmp_path / "strong.txt"
    strong_text.write_text("strong-evidence", encoding="utf-8")
    strong.extracted_text_path = str(strong_text)
    session.add(strong)
    session.commit()
    _tag(session, evidence_id=strong.id, objective_id=objective.id, relevance=0.9)

    for i in range(3):
        weak = _add_evidence(
            session,
            path=f"file:///weak{i}.pdf",
            sha=f"w{i:03}",
            title=f"Weak {i}",
        )
        weak_text = tmp_path / f"weak{i}.txt"
        weak_text.write_text(f"weak-corroboration-{i}", encoding="utf-8")
        weak.extracted_text_path = str(weak_text)
        session.add(weak)
        session.commit()
        _tag(
            session,
            evidence_id=weak.id,
            objective_id=objective.id,
            relevance=0.20,
        )

    cfg = RankerConfig(token_budget=1)
    text, payload, overflow = build_tagged_evidence_with_payload(
        objective.id, session, config=cfg
    )
    assert text is not None
    assert "strong-evidence" in text
    assert overflow.strategy == OVERFLOW_FINALIZE_ON_EXAMINED
    assert overflow.deferred_count == 3


def test_single_oversized_artifact_still_examined(session, objective, tmp_path):
    """One artifact bigger than the budget is examined anyway (never empty).

    The ranker guarantees a non-empty examined set when evidence exists: a
    control whose only/top artifact is huge must still be assessed, not
    deferred wholesale into an empty prompt.
    """
    big_text = tmp_path / "big.txt"
    big_text.write_text("X" * (PER_ARTIFACT_CHARS * 2), encoding="utf-8")
    ev = _add_evidence(
        session,
        path="file:///big.pdf",
        sha="big001",
        title="Huge Artifact",
        extracted_text_path=str(big_text),
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id, relevance=0.9)

    cfg = RankerConfig(token_budget=1)
    text, payload, overflow = build_tagged_evidence_with_payload(
        objective.id, session, config=cfg
    )
    assert text is not None
    examined = [p for p in payload if p.disposition == DISPOSITION_EXAMINED]
    assert len(examined) == 1
    # Nothing deferred — it was the only artifact.
    assert overflow.strategy == OVERFLOW_NONE


# ---------------------------------------------------------------------------
# Snippet loader
# ---------------------------------------------------------------------------


def test_short_text_loaded_verbatim(session, objective, tmp_path):
    """Text below PER_ARTIFACT_CHARS → returned without truncation marker."""
    text_path = tmp_path / "short.txt"
    body = "Quarterly account review log; reviewer Noah Jaskolski; 2026-03-15."
    text_path.write_text(body, encoding="utf-8")

    ev = _add_evidence(
        session, path="file:///short.pdf", extracted_text_path=str(text_path)
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id, relevance=1.0)

    result = build_tagged_evidence(objective.id, session)
    assert result is not None
    assert body in result
    assert "[truncated" not in result


def test_long_text_head_tail_truncated(session, objective, tmp_path):
    """Text above PER_ARTIFACT_CHARS → head + truncation marker + tail.

    Compliance docs put load-bearing facts at the edges (titles, scope,
    signatures, dates). The middle is typically boilerplate that, if
    sampled, would crowd out the parts the LLM needs.
    """
    head = "H" * HEAD_CHARS
    middle = "M" * 5000
    tail = "T" * TAIL_CHARS
    body = head + middle + tail
    assert len(body) > PER_ARTIFACT_CHARS  # sanity

    text_path = tmp_path / "long.txt"
    text_path.write_text(body, encoding="utf-8")

    ev = _add_evidence(
        session, path="file:///long.pdf", extracted_text_path=str(text_path)
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id, relevance=1.0)

    result = build_tagged_evidence(objective.id, session)
    assert result is not None

    # Head and tail present verbatim; middle dropped; truncation note carries
    # the EXACT skipped-byte count so a reader can sanity-check the budget.
    expected_skipped = len(body) - HEAD_CHARS - TAIL_CHARS
    assert head in result
    assert tail in result
    assert "M" * 5000 not in result  # middle is gone
    assert f"[truncated {expected_skipped} chars]" in result


def test_missing_extracted_text_path_returns_placeholder(session, objective):
    """Evidence row with extracted_text_path=None → 'unavailable' placeholder.

    The LLM still needs to know the artifact exists (so it can cite it in
    a narrative); we just can't quote from it.
    """
    ev = _add_evidence(
        session,
        path="file:///binary_only.pdf",
        title="Binary-only artifact",
        extracted_text_path=None,
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id, relevance=1.0)

    result = build_tagged_evidence(objective.id, session)
    assert result is not None
    assert "(extracted text unavailable)" in result
    # The header still renders so the LLM knows the doc was tagged.
    assert "Binary-only artifact" in result


def test_nonexistent_extracted_text_file_returns_placeholder(
    session, objective, tmp_path
):
    """Evidence row points at a missing file → 'unavailable' placeholder.

    Guards the most likely failure mode in production: extracted_text was
    written to ``~/.cybersecurity-assessor/extracted_text/`` then later
    pruned. We don't want a stack trace on assess; we want a graceful
    "couldn't quote this one" so the LLM still sees the header.
    """
    ghost_path = tmp_path / "does_not_exist.txt"  # never created
    ev = _add_evidence(
        session,
        path="file:///ghost.pdf",
        extracted_text_path=str(ghost_path),
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id, relevance=1.0)

    result = build_tagged_evidence(objective.id, session)
    assert result is not None
    assert "(extracted text unavailable)" in result


# ---------------------------------------------------------------------------
# Block format (the LLM prompt contract)
# ---------------------------------------------------------------------------


def test_block_renders_title_kind_doc_number_relevance_and_triple_quoted_text(
    session, objective, tmp_path
):
    """Pins the exact shape ``llm/prompts/assess_control.md`` expects.

    If any of these labels (``title``, ``kind``, ``doc_number``,
    ``relevance``, the triple-quoted ``text``) is renamed or dropped the
    prompt template can no longer reference them. The header block IS
    the prompt contract.
    """
    text_path = tmp_path / "body.txt"
    text_path.write_text("Section 3.2 enumerates the review cadence.", encoding="utf-8")
    ev = _add_evidence(
        session,
        path="file:///plan.pdf",
        title="Account Management Plan",
        doc_number="USD00050010",
        kind=EvidenceKind.PDF,
        extracted_text_path=str(text_path),
    )
    _tag(
        session,
        evidence_id=ev.id,
        objective_id=objective.id,
        relevance=0.87,
        source="manual",
    )

    result = build_tagged_evidence(objective.id, session)
    assert result is not None
    assert result.startswith("## tagged_evidence\n")
    assert "- title: Account Management Plan" in result
    assert "  kind: pdf" in result  # enum.value, not Enum repr
    assert "  doc_number: USD00050010" in result
    # Two-decimal relevance + source tag.
    assert "  relevance: 0.87 (source=manual)" in result
    # Triple-quoted text block around the snippet.
    assert '  text: """\nSection 3.2 enumerates the review cadence.\n"""' in result


def test_title_falls_back_to_path_when_none(session, objective, tmp_path):
    """Evidence with title=None → URI used as the title line.

    Real-world rows from auto-ingest often have None title until the
    extractor metadata pass writes one. We don't want those to render
    as ``- title: None``.
    """
    text_path = tmp_path / "untitled.txt"
    text_path.write_text("body text", encoding="utf-8")
    ev = _add_evidence(
        session,
        path="file:///some/uri/untitled.pdf",
        title=None,
        doc_number=None,
        extracted_text_path=str(text_path),
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id, relevance=1.0)

    result = build_tagged_evidence(objective.id, session)
    assert result is not None
    assert "- title: file:///some/uri/untitled.pdf" in result
    # And doc_number line MUST NOT render when the field is None.
    assert "doc_number" not in result


def test_multiple_blocks_separated_by_blank_line(session, objective, tmp_path):
    """Two artifacts → blocks joined by ``\\n\\n`` (single blank line).

    Pin the separator so changes to the join character surface here. The
    prompt template uses the blank line as a soft delimiter; collapsing
    to "\\n" would merge two artifacts into what looks like one block.
    """
    for i, tag_label in enumerate(("alpha", "beta")):
        text_path = tmp_path / f"{tag_label}.txt"
        text_path.write_text(f"body of {tag_label}", encoding="utf-8")
        ev = _add_evidence(
            session,
            path=f"file:///{tag_label}.pdf",
            sha=f"s{i}",
            title=tag_label.upper(),
            extracted_text_path=str(text_path),
        )
        _tag(
            session,
            evidence_id=ev.id,
            objective_id=objective.id,
            relevance=1.0 - (i * 0.1),
        )

    result = build_tagged_evidence(objective.id, session)
    assert result is not None
    # The two block bodies are separated by a blank line.
    alpha_end = result.index('"""', result.index("ALPHA"))
    beta_start = result.index("- title: BETA")
    between = result[alpha_end:beta_start]
    # Allow for trailing/leading whitespace but must contain a blank line.
    assert "\n\n" in between


# ---------------------------------------------------------------------------
# Cross-objective isolation (defensive — bundle is per-CCI, not global)
# ---------------------------------------------------------------------------


def test_only_returns_tags_for_requested_objective(session, objective, tmp_path):
    """Tags on a different objective MUST NOT leak into the bundle.

    The builder filters on ``EvidenceTag.objective_id == objective_id``;
    pin that with a second CCI in the same session whose evidence would
    otherwise top the relevance sort.
    """
    # First, tag a high-relevance artifact to ``objective`` so we have a result
    # to inspect.
    our_text = tmp_path / "ours.txt"
    our_text.write_text("ours", encoding="utf-8")
    ours = _add_evidence(
        session, path="file:///ours.pdf", title="OURS", extracted_text_path=str(our_text)
    )
    _tag(session, evidence_id=ours.id, objective_id=objective.id, relevance=0.4)

    # Now a second objective on the same control with a higher-relevance tag.
    other_obj = Objective(
        control_id_fk=objective.control_id_fk,
        objective_id="CCI-999999",
        source="CCI",
        text="other",
    )
    session.add(other_obj)
    session.commit()
    session.refresh(other_obj)

    their_text = tmp_path / "theirs.txt"
    their_text.write_text("theirs", encoding="utf-8")
    theirs = _add_evidence(
        session,
        path="file:///theirs.pdf",
        sha="zzz",
        title="THEIRS",
        extracted_text_path=str(their_text),
    )
    _tag(session, evidence_id=theirs.id, objective_id=other_obj.id, relevance=0.99)

    result = build_tagged_evidence(objective.id, session)
    assert result is not None
    assert "OURS" in result
    assert "THEIRS" not in result


# ---------------------------------------------------------------------------
# Corroboration sections (## corroborating_findings, ## affected_hosts)
# ---------------------------------------------------------------------------
#
# Phase 1 wires the same StigFinding + host_inventory joins the POAM
# narrative uses into the upstream assessor bundle. The tests below mirror
# the corroboration-rule cases in tests/poam/test_generator_description.py
# so a future divergence shows up on BOTH sides (better to fail twice than
# silently drift).


def test_corroborating_findings_section_renders_when_cci_matches(
    session, objective, tmp_path
):
    """Tagged evidence + OPEN finding whose cci_refs cites THIS CCI → section appears."""
    text_path = tmp_path / "ckl.txt"
    text_path.write_text("ckl body", encoding="utf-8")
    ev = _add_evidence(
        session,
        path="file:///host-a.ckl",
        kind=EvidenceKind.STIG_CKL,
        title="host-a CKL",
        extracted_text_path=str(text_path),
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id, relevance=1.0)
    _add_stig_finding(
        session,
        evidence_id=ev.id,
        rule_id="SV-12345",
        cci_refs="CCI-000015",
        severity="high",
        finding_details="Account review interval not enforced on host-a.",
    )

    result = build_tagged_evidence(objective.id, session)
    assert result is not None
    assert "## corroborating_findings" in result
    assert "SV-12345" in result
    assert "(high)" in result
    # The SV-rule is bracketed (no V-number/group_id on this finding) and the
    # evidence label follows unbracketed so the LLM can cite the source CKL.
    assert "[SV-12345] host-a CKL" in result


def test_finding_with_unrelated_cci_is_suppressed(session, objective, tmp_path):
    """Tagged evidence + finding for a DIFFERENT CCI → section omitted entirely.

    This is the corroboration rule from feedback_corroborate_stig_findings.md:
    a single tagged CKL is not enough — the finding's own cci_refs must
    intersect the cluster CCI set. A CKL tagged to AC-2 routinely carries
    IA-5 / CM-6 findings; surfacing them would mis-attribute.
    """
    text_path = tmp_path / "noisy.txt"
    text_path.write_text("noisy ckl", encoding="utf-8")
    ev = _add_evidence(
        session, path="file:///noisy.ckl", extracted_text_path=str(text_path)
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id, relevance=1.0)
    _add_stig_finding(
        session,
        evidence_id=ev.id,
        rule_id="SV-NOISE",
        cci_refs="CCI-000200",  # different control family entirely
        severity="high",
        finding_details="Password complexity disabled.",
    )

    result = build_tagged_evidence(objective.id, session)
    assert result is not None
    assert "SV-NOISE" not in result
    # Precision over recall — empty header is worse than no section.
    assert "## corroborating_findings" not in result


def test_closed_finding_is_suppressed(session, objective, tmp_path):
    """NOT_A_FINDING status → finding does not surface (OPEN-only contract)."""
    text_path = tmp_path / "closed.txt"
    text_path.write_text("closed ckl", encoding="utf-8")
    ev = _add_evidence(
        session, path="file:///closed.ckl", extracted_text_path=str(text_path)
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id, relevance=1.0)
    _add_stig_finding(
        session,
        evidence_id=ev.id,
        rule_id="SV-CLOSED",
        cci_refs="CCI-000015",
        severity="high",
        status=FindingStatus.NOT_A_FINDING,
    )

    result = build_tagged_evidence(objective.id, session)
    assert result is not None
    assert "SV-CLOSED" not in result
    assert "## corroborating_findings" not in result


def test_affected_hosts_section_renders_from_inventory(session, objective, tmp_path):
    """Tagged evidence with host_inventory → ## affected_hosts section appears."""
    text_path = tmp_path / "inv.txt"
    text_path.write_text("inventory body", encoding="utf-8")
    ev = _add_evidence(
        session,
        path="file:///inv.ckl",
        extracted_text_path=str(text_path),
        hosts=["host-alpha", "host-beta", "host-gamma"],
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id, relevance=1.0)

    result = build_tagged_evidence(objective.id, session)
    assert result is not None
    assert "## affected_hosts (3)" in result
    assert "host-alpha" in result
    assert "host-beta" in result
    assert "host-gamma" in result


def test_tagged_but_no_findings_and_no_hosts_skips_both_sections(
    session, objective, tmp_path
):
    """Precision-over-recall guard: tags exist, but no findings + no inventory →
    only ## tagged_evidence renders. No empty corroborating_findings header,
    no zero-host affected_hosts header.
    """
    text_path = tmp_path / "policy.txt"
    text_path.write_text("policy-only narrative", encoding="utf-8")
    ev = _add_evidence(
        session,
        path="file:///policy.pdf",
        title="Policy Doc",
        extracted_text_path=str(text_path),
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id, relevance=1.0)

    result = build_tagged_evidence(objective.id, session)
    assert result is not None
    assert result.startswith("## tagged_evidence\n")
    assert "## corroborating_findings" not in result
    assert "## affected_hosts" not in result
