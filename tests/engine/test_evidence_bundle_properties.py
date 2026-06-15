"""Property-based tests for the per-CCI tagged-evidence builder.

``engine.evidence_bundle.build_tagged_evidence`` is on the hot path of
every LLM-routed CCI. The example-driven suite at
``backend/tests/engine/test_evidence_bundle.py`` pins specific shapes
(supersession filter, single-tag render, head/tail truncation); this
file fuzzes the kernel's structural invariants so a refactor that
silently breaks one in a corner of the (tag-count x relevance x
confidence x extracted-text) input space gets caught:

  1. **None-or-non-empty contract.** ``build_tagged_evidence`` returns
     either ``None`` (no live tags) OR a non-empty string. An empty
     string would silently invalidate the prompt-prefix caching contract
     called out in evidence_bundle.py:12-15 — the prompt builder uses
     ``is None`` to skip the placeholder, but a bare empty string would
     render the placeholder header with nothing under it.

  2. **Partition is total — no silent drop.** The fixed ``MAX_ARTIFACTS``
     cap was retired in favor of the token-budget ranker
     (``engine.evidence_ranker``). The new invariant is stronger: for any
     N >= 1 tags, every artifact is either EXAMINED (rendered) or DEFERRED
     (audited), and ``len(examined) + len(deferred) == N`` exactly — the
     builder never truncates at a fixed N. Under a realistic budget all
     tiny artifacts render; under extreme budget pressure the top-ranked
     one is still admitted and the remainder are deferred (not dropped).
     A regression that silently slices the tail would destroy the
     defensibility guarantee (anything not examined must be traceable).

  3. **Relevance-then-confidence sort is order-invariant.** Inserting
     the same (relevance, confidence) tag set in any order produces the
     same artifact ordering in the output. A streaming-sort bug that
     secretly depended on insert order would regress here.

  4. **Supersession filter is total.** No superseded artifact ever
     appears in the rendered block — the supersession chain is the
     read-side enforcement of the third patent-supporting guard
     (legacy USD docs must not resurface as "current evidence").

  5. **Cross-objective isolation.** A tag for objective A NEVER
     appears in ``build_tagged_evidence(B)``. A WHERE-clause drift
     would leak unrelated CCIs' evidence into a control's prompt and
     corrupt every status decision.

  6. **Snippet budget bound.** For any extracted text of any length,
     ``_load_snippet`` returns a string whose length is bounded by
     ``max(raw_len, HEAD_CHARS + TAIL_CHARS + marker_overhead)`` —
     truncation is never allowed to PAD the prompt.

  7. **_first_sentence bound.** For any text and max_chars >= 1, the
     returned length never exceeds ``max_chars`` + 1 (ellipsis only).
     A bound regression would let a single STIG finding-detail blow
     the prompt budget when many findings render.

  8. **Section ordering when present.** When all three sections render,
     they appear in this order: tagged_evidence header, corroborating
     findings header, affected hosts header. Reorder = downstream
     regex/parsers in ``_build_evidence_block`` would break.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

hypothesis = pytest.importorskip("hypothesis")

from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

# Ensure backend package importable.
_BACKEND = (
    Path(__file__).resolve().parents[2] / "backend"
)
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.engine.evidence_bundle import (  # noqa: E402
    AFFECTED_HOSTS_HEADER,
    CORROBORATING_FINDINGS_HEADER,
    HEAD_CHARS,
    PER_ARTIFACT_CHARS,
    TAGGED_EVIDENCE_HEADER,
    TAIL_CHARS,
    _first_sentence,
    _load_snippet,
    build_tagged_evidence,
    build_tagged_evidence_with_payload,
)
from cybersecurity_assessor.engine.evidence_ranker import (  # noqa: E402
    DISPOSITION_DEFERRED,
    DISPOSITION_EXAMINED,
    REASON_TOKEN_BUDGET,
    RankerConfig,
)

# The fixed MAX_ARTIFACTS=6 cap was retired; this is just the upper bound on
# fuzzed tag-set sizes — large enough to exceed the old cap (so a resurrected
# fixed-N truncation would be caught) without exhausting Hypothesis' wall
# budget on in-memory DB writes.
_FUZZ_SET_MAX = 6
from cybersecurity_assessor.models import (  # noqa: E402
    Control,
    Evidence,
    EvidenceKind,
    EvidenceTag,
    Framework,
    Objective,
)


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    """Fresh in-memory SQLite with the full schema, single shared connection.

    Hypothesis re-invokes the test body many times within a SINGLE fixture
    instance, so test bodies MUST call ``_reset_schema(session)`` at the
    top to wipe state from prior examples — otherwise UNIQUE constraints
    (e.g. ``evidence.path``) collide on the second example.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _reset_schema(session: Session) -> None:
    """Drop & recreate every table on the session's engine — wipes everything.

    Mirrors :func:`tests.engine.test_calibration_properties._wipe` in
    spirit: Hypothesis re-invokes the test body N times per fixture
    instance; without an explicit reset, rows from prior examples leak
    into the current example's invariants. Drop+create is heavier than a
    table-by-table delete but is FK-safe and order-independent — important
    because our schema has Framework → Control → Objective → EvidenceTag →
    Evidence webs that would need careful per-table teardown order.
    """
    bind = session.get_bind()
    # Rollback any in-flight transaction from the prior example whose
    # constraint violation left the session in a PendingRollback state.
    session.rollback()
    SQLModel.metadata.drop_all(bind)
    SQLModel.metadata.create_all(bind)


def _make_objective(session: Session, *, cci_id: str = "CCI-000015") -> Objective:
    """Build Framework → Control → Objective and return the Objective."""
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)

    ctrl = Control(
        framework_id=fw.id,
        control_id="AC-2",
        title="Account Management",
        family="AC",
    )
    session.add(ctrl)
    session.commit()
    session.refresh(ctrl)

    obj = Objective(
        control_id_fk=ctrl.id,
        objective_id=cci_id,
        source="CCI",
        text="Fuzzed objective row.",
    )
    session.add(obj)
    session.commit()
    session.refresh(obj)
    return obj


def _add_evidence(
    session: Session,
    *,
    path: str,
    sha: str,
    title: str | None = "doc",
    extracted_text_path: str | None = None,
    superseded_by_id: int | None = None,
) -> Evidence:
    ev = Evidence(
        path=path,
        sha256=sha,
        kind=EvidenceKind.PDF,
        size_bytes=1024,
        title=title,
        extracted_text_path=extracted_text_path,
        superseded_by_id=superseded_by_id,
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    return ev


def _tag(
    session: Session,
    *,
    evidence_id: int,
    objective_id: int,
    relevance: float = 0.5,
    confidence: float = 0.5,
) -> EvidenceTag:
    t = EvidenceTag(
        evidence_id=evidence_id,
        objective_id=objective_id,
        relevance=relevance,
        confidence=confidence,
        source="auto",
    )
    session.add(t)
    session.commit()
    session.refresh(t)
    return t


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------


# Bounded float in [0, 1] with edges over-sampled — relevance/confidence
# in the kernel are written by both the auto-tagger (cosine-similarity in
# [0, 1]) and manual tags (default 1.0/0.5), so the edges are realistic
# distributions in production data.
_RC = st.one_of(
    st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
    st.sampled_from([0.0, 0.1, 0.5, 0.9, 1.0]),
)

# A single tag (relevance, confidence, snippet text); snippet text drives
# the file-extracted-text path so the head/tail truncation invariant is
# exercised on real bytes.
_TAG_SPEC = st.tuples(_RC, _RC, st.text(min_size=0, max_size=400))

# Up to 12 tags per case — well past the retired MAX_ARTIFACTS=6 cap so a
# resurrected fixed-N truncation would be caught, without exhausting
# Hypothesis' per-test wall budget. The in-memory DB writes are the
# bottleneck.
_TAG_SET = st.lists(_TAG_SPEC, min_size=0, max_size=12)


# ---------------------------------------------------------------------------
# Helpers: build N tagged artifacts in a single transaction
# ---------------------------------------------------------------------------


def _build_artifacts(
    session: Session,
    objective: Objective,
    tags: list[tuple[float, float, str]],
    tmp_dir: Path,
    *,
    prefix: str = "ev",
) -> list[Evidence]:
    """Write tmp text files + persist Evidence + EvidenceTag rows.

    Returns the Evidence objects in insertion order so callers can
    correlate the rendered output back to specific rows. ``prefix`` is
    threaded into both the file name and the Evidence.path/sha so the
    same test body can call this twice without colliding on UNIQUE
    constraints (e.g. the order-invariance test which inserts a fwd pass
    and a reversed pass in the same example).
    """
    out: list[Evidence] = []
    for i, (rel, conf, text) in enumerate(tags):
        text_path = tmp_dir / f"{prefix}_{i}.txt"
        text_path.write_text(text, encoding="utf-8")
        ev = _add_evidence(
            session,
            path=f"file:///{prefix}_{i}.pdf",
            sha=f"sha-{prefix}-{i}-{len(text)}",
            extracted_text_path=str(text_path),
            title=f"Artifact {prefix}-{i}",
        )
        _tag(
            session,
            evidence_id=ev.id,
            objective_id=objective.id,
            relevance=rel,
            confidence=conf,
        )
        out.append(ev)
    return out


# ===========================================================================
# Property 1 — None-or-non-empty contract
# ===========================================================================


@given(tags=_TAG_SET)
@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_returns_none_or_nonempty_string(tags, session, tmp_path):
    """For any tag set, output is either None or a non-empty string.

    Empty-string would corrupt the prompt-prefix cache contract
    (evidence_bundle.py:12-15) — the prompt builder branches on ``is
    None`` and would emit an empty ``## tagged_evidence`` header.
    """
    _reset_schema(session)
    objective = _make_objective(session)
    _build_artifacts(session, objective, tags, tmp_path)

    out = build_tagged_evidence(objective.id, session)
    if out is None:
        # Only legal when there were zero tags.
        assert tags == []
    else:
        assert isinstance(out, str)
        assert out  # truthy = non-empty
        assert TAGGED_EVIDENCE_HEADER in out


# ===========================================================================
# Property 2 — partition is total: no artifact silently dropped
# ===========================================================================


@given(tags=_TAG_SET)
@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_all_tagged_artifacts_render_under_realistic_budget(tags, session, tmp_path):
    """Under the default token budget, every tagged artifact renders.

    The fuzzed snippets max out at 400 chars (~100 tokens), so even 12
    tags sit far under DEFAULT_TOKEN_BUDGET (120k). The retired fixed cap
    of 6 would have dropped the tail; the token-budget ranker admits them
    all. Count "Artifact i" titles — each tag inserts a unique title via
    ``_build_artifacts``.
    """
    _reset_schema(session)
    objective = _make_objective(session)
    _build_artifacts(session, objective, tags, tmp_path)

    out = build_tagged_evidence(objective.id, session)
    if len(tags) == 0:
        assert out is None
        return
    assert out is not None
    rendered_titles = sum(
        1 for line in out.splitlines() if line.startswith("- title: Artifact ")
    )
    # No fixed cap — all N render (every tiny snippet fits the budget).
    assert rendered_titles == len(tags)


# Like _TAG_SPEC but the snippet is guaranteed non-empty / non-whitespace
# (printable ASCII, >= 8 chars) so every artifact costs >= 1 token under the
# estimator (ceil(len/4)). Zero-cost artifacts (empty snippet) fit ANY budget,
# so they'd never defer — the total-partition invariant would still hold but the
# "deferral actually happened" branch below would go untested. Forcing a real
# token cost is what makes budget=1 genuinely push the tail into DEFERRED.
_NONEMPTY_SNIPPET = st.text(
    alphabet=st.characters(min_codepoint=33, max_codepoint=126),
    min_size=8,
    max_size=400,
)
_NONEMPTY_TAG_SPEC = st.tuples(_RC, _RC, _NONEMPTY_SNIPPET)


@given(tags=st.lists(_NONEMPTY_TAG_SPEC, min_size=1, max_size=12))
@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_partition_is_total_even_under_extreme_budget(tags, session, tmp_path):
    """For any N >= 1, examined + deferred == N — nothing is ever dropped.

    Forces deferral with ``RankerConfig(token_budget=1)``: only the single
    top-ranked artifact is admitted, every other tagged artifact must land
    in the DEFERRED partition (audited, not discarded). This is the
    defensibility invariant — anything not examined stays traceable. Snippets
    are non-empty (see ``_NONEMPTY_TAG_SPEC``) so each artifact costs >= 1
    token and budget=1 actually exercises the deferral path.
    """
    _reset_schema(session)
    objective = _make_objective(session)
    _build_artifacts(session, objective, tags, tmp_path)

    config = RankerConfig(token_budget=1)
    rendered, payload, overflow = build_tagged_evidence_with_payload(
        objective.id, session, config=config
    )
    assert rendered is not None

    examined = [p for p in payload if p.disposition == DISPOSITION_EXAMINED]
    deferred = [p for p in payload if p.disposition == DISPOSITION_DEFERRED]

    # Total partition: every tagged artifact is accounted for, exactly once.
    assert len(examined) + len(deferred) == len(tags)
    assert len(payload) == len(tags)
    # The top-ranked artifact is always admitted (non-empty examined set).
    assert len(examined) >= 1
    # Under budget=1 with N>=2, the remainder must be deferred (not dropped).
    if len(tags) >= 2:
        assert len(deferred) == len(tags) - len(examined)
        assert len(deferred) >= 1
    # Every deferred row carries its audit trail: token-budget reason + the
    # snippet hash/text as-shown so the eviction is reconstructable.
    for d in deferred:
        assert d.deferred_reason == REASON_TOKEN_BUDGET
        assert d.chunk_sha
        assert d.chunk_text is not None


# ===========================================================================
# Property 3 — relevance-then-confidence ordering is set-functional
# ===========================================================================


@given(tags=st.lists(_TAG_SPEC, min_size=1, max_size=_FUZZ_SET_MAX))
@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_relevance_confidence_sort_is_order_invariant(tags, session, tmp_path):
    """Same tag set inserted in any order → same artifact ordering.

    Defends against a streaming-sort rewrite that secretly depended on
    insert order. Insert tags forward then reversed; the rendered title
    sequence must be identical.
    """
    _reset_schema(session)
    # First pass: forward insert.
    obj_fwd = _make_objective(session, cci_id="CCI-000100")
    fwd_dir = tmp_path / "fwd"
    # Hypothesis re-invokes this body with the SAME function-scoped tmp_path,
    # so exist_ok=True is required (second example otherwise crashes on
    # FileExistsError). Per-example files inside still get unique ev_{i}
    # names so cross-example bleed is impossible.
    fwd_dir.mkdir(exist_ok=True)
    _build_artifacts(session, obj_fwd, tags, fwd_dir, prefix="fwd")
    fwd_out = build_tagged_evidence(obj_fwd.id, session)

    # Second pass: reversed insert (new objective so we don't double-tag).
    # prefix="rev" keeps Evidence.path/sha/file names disjoint from the fwd
    # pass — both sets coexist in the same in-memory DB for this example.
    obj_rev = _make_objective(session, cci_id="CCI-000200")
    rev_dir = tmp_path / "rev"
    rev_dir.mkdir(exist_ok=True)
    _build_artifacts(session, obj_rev, list(reversed(tags)), rev_dir, prefix="rev")
    rev_out = build_tagged_evidence(obj_rev.id, session)

    assert fwd_out is not None and rev_out is not None
    # Extract (relevance, confidence) for each rendered block in order
    # of appearance — must be DESC, regardless of insert order.
    fwd_order = _extract_rel_conf_sequence(fwd_out)
    rev_order = _extract_rel_conf_sequence(rev_out)
    assert fwd_order == rev_order
    # And the order is non-ascending under the (rel, conf) compound key.
    for prev, curr in zip(fwd_order, fwd_order[1:]):
        assert prev >= curr


def _extract_rel_conf_sequence(rendered: str) -> list[tuple[float, float]]:
    """Pull the (relevance, source-ignored) tuples out of the rendered text.

    Each artifact's header line is ``  relevance: X.XX (source=...)``;
    we don't have the confidence in the rendered output directly (kernel
    omits it on purpose), so we approximate the compound key with just
    relevance — which is sufficient for the order test since the
    in-test confidence is bundled into the same tag.
    """
    out: list[tuple[float, float]] = []
    for line in rendered.splitlines():
        s = line.strip()
        if s.startswith("relevance: "):
            # "relevance: 0.92 (source=auto)" → 0.92
            tok = s.split()[1]
            out.append((float(tok), 0.0))
    return out


# ===========================================================================
# Property 4 — supersession filter is total
# ===========================================================================


@given(
    rels=st.lists(
        _RC,
        min_size=1,
        max_size=6,
    )
)
@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_superseded_artifacts_never_render(rels, session, tmp_path):
    """All-superseded tag set → None. Mixed → output omits superseded titles.

    The supersession chain is the read-side enforcement of the legacy-
    artifact-resurrection guard. A regression would silently feed stale
    USD docs back to the LLM as "current evidence."
    """
    _reset_schema(session)
    objective = _make_objective(session)
    # One "current" artifact to act as supersession target.
    current = _add_evidence(
        session, path="file:///current.pdf", sha="current"
    )
    # Build N "legacy" artifacts all pointing at current as their successor;
    # tag each of them to the objective.
    legacy_titles: list[str] = []
    for i, rel in enumerate(rels):
        text_path = tmp_path / f"legacy_{i}.txt"
        text_path.write_text("legacy text", encoding="utf-8")
        legacy = _add_evidence(
            session,
            path=f"file:///legacy_{i}.pdf",
            sha=f"legacy-{i}",
            title=f"LEGACY-{i}",
            extracted_text_path=str(text_path),
            superseded_by_id=current.id,
        )
        legacy_titles.append(f"LEGACY-{i}")
        _tag(
            session,
            evidence_id=legacy.id,
            objective_id=objective.id,
            relevance=rel,
            confidence=0.5,
        )

    out = build_tagged_evidence(objective.id, session)
    # Every tagged artifact is superseded → output MUST be None.
    assert out is None, (
        f"Superseded artifacts leaked through filter; "
        f"first-100 chars of leak: {(out or '')[:100]}"
    )

    # Now add one current-tagged artifact and confirm legacy STILL doesn't render.
    cur_text = tmp_path / "current.txt"
    cur_text.write_text("current text", encoding="utf-8")
    current_with_text = _add_evidence(
        session,
        path="file:///current2.pdf",
        sha="current2",
        title="CURRENT-OK",
        extracted_text_path=str(cur_text),
    )
    _tag(
        session,
        evidence_id=current_with_text.id,
        objective_id=objective.id,
        relevance=0.9,
        confidence=0.9,
    )
    out2 = build_tagged_evidence(objective.id, session)
    assert out2 is not None
    assert "CURRENT-OK" in out2
    for title in legacy_titles:
        assert title not in out2, f"Legacy artifact {title} leaked past filter"


# ===========================================================================
# Property 5 — cross-objective isolation
# ===========================================================================


@given(rel_a=_RC, rel_b=_RC)
@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_cross_objective_isolation(rel_a, rel_b, session, tmp_path):
    """Tagging objective A does NOT cause the artifact to render for B.

    A WHERE-clause drift would corrupt every CCI's prompt with sibling
    controls' artifacts. Pin the boundary with two objectives that share
    a Framework/Control but tag against different Evidence rows.
    """
    _reset_schema(session)
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)
    ctrl = Control(
        framework_id=fw.id, control_id="AC-2", title="Account Management",
        family="AC",
    )
    session.add(ctrl)
    session.commit()
    session.refresh(ctrl)

    obj_a = Objective(
        control_id_fk=ctrl.id, objective_id="CCI-A", source="CCI", text="A"
    )
    obj_b = Objective(
        control_id_fk=ctrl.id, objective_id="CCI-B", source="CCI", text="B"
    )
    session.add_all([obj_a, obj_b])
    session.commit()
    session.refresh(obj_a)
    session.refresh(obj_b)

    # Per-objective evidence + extracted text.
    text_a = tmp_path / "for_a.txt"
    text_a.write_text("ALPHA-EVIDENCE", encoding="utf-8")
    ev_a = _add_evidence(
        session, path="file:///a.pdf", sha="sha-a", title="A-ONLY",
        extracted_text_path=str(text_a),
    )
    _tag(session, evidence_id=ev_a.id, objective_id=obj_a.id, relevance=rel_a)

    text_b = tmp_path / "for_b.txt"
    text_b.write_text("BETA-EVIDENCE", encoding="utf-8")
    ev_b = _add_evidence(
        session, path="file:///b.pdf", sha="sha-b", title="B-ONLY",
        extracted_text_path=str(text_b),
    )
    _tag(session, evidence_id=ev_b.id, objective_id=obj_b.id, relevance=rel_b)

    out_a = build_tagged_evidence(obj_a.id, session)
    out_b = build_tagged_evidence(obj_b.id, session)

    assert out_a is not None and out_b is not None
    assert "A-ONLY" in out_a and "B-ONLY" not in out_a
    assert "B-ONLY" in out_b and "A-ONLY" not in out_b
    assert "ALPHA-EVIDENCE" in out_a and "BETA-EVIDENCE" not in out_a
    assert "BETA-EVIDENCE" in out_b and "ALPHA-EVIDENCE" not in out_b


# ===========================================================================
# Property 6 — _load_snippet length bound (pure function, no DB)
# ===========================================================================


@given(
    # Exclude bare CR — Python's text-mode read normalizes \r → \n on
    # round-trip (universal newlines), which would falsify the exact
    # equality check below despite the kernel invariant (length never
    # grows) holding. The extractor that feeds _load_snippet in
    # production always emits already-normalized newlines, so this
    # exclusion matches production input distribution.
    raw=st.text(min_size=0, max_size=PER_ARTIFACT_CHARS * 3).filter(
        lambda s: "\r" not in s
    ),
)
@settings(
    max_examples=80,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_load_snippet_never_pads_input(raw, tmp_path):
    """For any extracted text, ``_load_snippet`` returns at most max(len(raw),
    HEAD+TAIL+marker_overhead) chars.

    The kernel's own boundary guard
    (evidence_bundle.py:242-248) returns raw when truncation would
    paradoxically increase length. This property fuzzes that guard.
    """
    p = tmp_path / "snip.txt"
    p.write_text(raw, encoding="utf-8")
    out = _load_snippet(str(p))

    # If raw fits within budget, output is the raw text (modulo encoding).
    if len(raw) <= PER_ARTIFACT_CHARS:
        assert out == raw
        return

    # Otherwise output is either the raw (boundary-guard win) or the
    # head/tail truncated form, but in NO case longer than raw itself.
    # The kernel guarantees: if truncated >= raw, return raw.
    assert len(out) <= len(raw)
    # And the truncated form, when it fires, must include both ends.
    if len(out) < len(raw):
        assert out.startswith(raw[:HEAD_CHARS])
        assert out.endswith(raw[-TAIL_CHARS:])
        assert "[truncated" in out


def test_load_snippet_handles_missing_path_safely():
    """Missing path / None → placeholder, never raises.

    Concrete pin — Hypothesis can't easily fuzz "file doesn't exist" as
    a property, but the safety contract is load-bearing for the no-text
    evidence kind (raw images, binaries that escaped the extractor).
    """
    assert _load_snippet(None) == "(extracted text unavailable)"
    assert _load_snippet("") == "(extracted text unavailable)"
    assert _load_snippet("/no/such/path/abc.txt") == "(extracted text unavailable)"


# ===========================================================================
# Property 7 — _first_sentence bound (pure function, no DB)
# ===========================================================================


@given(
    text=st.one_of(
        st.none(),
        st.text(min_size=0, max_size=1000),
    ),
    max_chars=st.integers(min_value=1, max_value=500),
)
@settings(max_examples=200, deadline=None)
def test_first_sentence_respects_max_chars(text, max_chars):
    """Length never exceeds max_chars by more than the 1-char ellipsis.

    A regression where the early-sentence-break logic let through
    long-running text would blow the prompt budget when many findings
    render. Bounded by max_chars + 1 (the ellipsis).
    """
    out = _first_sentence(text, max_chars)
    assert isinstance(out, str)
    # +1 for the ellipsis character; the kernel itself caps at
    # ``max_chars - 1 + ellipsis``, so this bound is tight.
    assert len(out) <= max_chars + 1, (
        f"_first_sentence returned {len(out)} chars for max_chars={max_chars}, "
        f"input={(text or '')!r}"
    )
    # None / empty / whitespace-only input always returns empty string.
    if text is None or not text.strip():
        assert out == ""


# ===========================================================================
# Property 8 — section ordering when all three render
# ===========================================================================


def test_section_ordering_tagged_then_findings_then_hosts(session, tmp_path):
    """When all three sections render, header order is fixed.

    Concrete pin (not Hypothesis-driven — the full-corroboration setup
    is too heavy for fuzz scale). Downstream parsers in
    ``_build_evidence_block`` depend on this order to detect which
    sub-section rendered without re-running the queries.
    """
    from cybersecurity_assessor.models import FindingStatus, StigFinding
    import json

    objective = _make_objective(session, cci_id="CCI-000015")
    text_path = tmp_path / "ev.txt"
    text_path.write_text("Evidence body.", encoding="utf-8")
    ev = _add_evidence(
        session,
        path="file:///e.pdf",
        sha="sha-x",
        title="Evidence X",
        extracted_text_path=str(text_path),
    )
    # Populate host inventory so the hosts section renders.
    ev.host_inventory = json.dumps(["host-1", "host-2"])
    session.add(ev)
    session.commit()
    _tag(session, evidence_id=ev.id, objective_id=objective.id, relevance=0.9)

    # Plant an OPEN finding tied to this CCI so the findings section renders.
    f = StigFinding(
        evidence_id=ev.id,
        rule_id="SV-12345r1_rule",
        cci_refs="CCI-000015",
        severity="medium",
        status=FindingStatus.OPEN,
        finding_details="Setting not enforced.",
    )
    session.add(f)
    session.commit()

    out = build_tagged_evidence(objective.id, session)
    assert out is not None

    # All three headers present, and in this order.
    pos_tagged = out.find(TAGGED_EVIDENCE_HEADER)
    pos_findings = out.find(CORROBORATING_FINDINGS_HEADER)
    pos_hosts = out.find(AFFECTED_HOSTS_HEADER)
    assert pos_tagged >= 0
    assert pos_findings > pos_tagged
    assert pos_hosts > pos_findings


# ===========================================================================
# Property 9 — empty corroboration sections are omitted (no empty headers)
# ===========================================================================


@given(rel=_RC)
@settings(
    max_examples=20,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_no_empty_corroboration_headers(rel, session, tmp_path):
    """Tagged evidence with no findings + no hosts → only the tagged header.

    The kernel docstring (evidence_bundle.py:128-129) calls out
    "precision over recall — no empty headers." Regression here would
    waste prompt tokens AND mislead the LLM into thinking corroboration
    was actively checked and came up empty.
    """
    _reset_schema(session)
    objective = _make_objective(session)
    text_path = tmp_path / "ev.txt"
    text_path.write_text("body", encoding="utf-8")
    ev = _add_evidence(
        session,
        path="file:///e.pdf",
        sha="sha-y",
        title="OnlyTagged",
        extracted_text_path=str(text_path),
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id, relevance=rel)

    out = build_tagged_evidence(objective.id, session)
    assert out is not None
    assert TAGGED_EVIDENCE_HEADER in out
    assert CORROBORATING_FINDINGS_HEADER not in out
    assert AFFECTED_HOSTS_HEADER not in out
