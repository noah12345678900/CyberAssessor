"""Property-based tests for the supersession map's pure helpers.

This module is the **patent-supporting** deterministic rewrite layer.
Every behavior here gates two patent claims:

  1. **"Every reported hit = one actual rewrite."** ``find_stale_references``
     and ``rewrite_narrative`` MUST agree on what counts as a stale
     reference. If they drift, the review UI shows phantom hits the
     writer never recorded — or worse, records rewrites the reviewer
     never saw — and the audit trail loses coherence.

  2. **"Deterministic short-circuits are one SQL query away."** Each
     rewrite is supposed to be reproducible from inputs alone, so
     ``rewrite_narrative`` must be:
       * **idempotent** — running the output through it again is a no-op
       * **case-insensitive in match, case-preserving in current phrase**
       * **longest-match-first** so a more specific legacy title never
         gets shadowed by a shorter one it contains (substring overlap)

The shipped registry (``_LEGACY_TO_CURRENT`` / ``_SSAA_TO_SDA_MAPPINGS``)
ships **empty** — it once held one program's verbatim doc map and was
scrubbed so no program data is baked into the app. The fuzzing corpus and
the seed-dependent invariants below are therefore driven by a fictional
synthetic registry installed via the ``synthetic_registry`` fixture; the
strategy phrase pool is built from that same synthetic constant (NOT the
now-empty shipped registry, which would make ``st.sampled_from`` raise at
import time). A dedicated test pins that the shipped registry stays empty.

In-scope helpers:

    ``_normalize_cci_id``           — coerces 'CCI-15' / '15' → 'CCI-000015'
    ``rewrite_narrative``           — public rewriter, returns SupersessionResult
    ``find_stale_references``       — public stale-reference reporter
    ``lookup_verified_sda_mapping`` — CCI → verified SDA Req lookup
    ``na_reconsideration_warning``  — NA-status reconsideration trigger
    ``resolve_current_evidence_id`` — chain walker with cycle protection

Cross-helper invariants pinned here:

  * ``find_stale_references(t)`` legacy-phrase set ==
    ``rewrite_narrative(t).hits`` legacy-phrase set (patent claim #1)
  * ``rewrite_narrative(rewrite_narrative(t).rewritten_text).hits == []``
    for any text (idempotence — patent claim #2)
  * ``resolve_current_evidence_id`` terminates within ``max_hops`` for
    any well-formed chain AND for any cyclic chain (cycle protection)
"""

from __future__ import annotations

import re

import pytest
from sqlmodel import Session, SQLModel, create_engine

hypothesis = pytest.importorskip("hypothesis")

from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from cybersecurity_assessor.engine import supersession  # noqa: E402
from cybersecurity_assessor.engine.supersession import (  # noqa: E402
    ReconsiderationWarning,
    SupersessionEntry,
    SupersessionResult,
    VerifiedSdaMapping,
    _normalize_cci_id,
    find_stale_references,
    lookup_verified_sda_mapping,
    na_reconsideration_warning,
    resolve_current_evidence_id,
    rewrite_narrative,
)
from cybersecurity_assessor.models import Evidence, EvidenceKind  # noqa: E402


# ---------------------------------------------------------------------------
# Fictional synthetic registry — NO program data. Longest legacy strings
# come first within an overlap group so the matcher picks the most specific
# match first. Mirrors the shape used by the golden / unit test files so the
# whole supersession suite shares one synthetic vocabulary.
# ---------------------------------------------------------------------------

_FAKE_ENTRIES: list[SupersessionEntry] = [
    SupersessionEntry(
        legacy="Acme Widget Legacy Operations User Guide",
        current="ACME-DOC-0010 Acme Widget Operations Plan Rev 2",
        sharepoint_folder=None,
        notes=None,
    ),
    SupersessionEntry(
        legacy="Acme Widget Legacy Operations Plan",
        current="ACME-DOC-0010 Acme Widget Operations Plan Rev 2",
        sharepoint_folder=None,
        notes=None,
    ),
    SupersessionEntry(
        legacy="Acme Widget Legacy Auditing Procedures",
        current="ACME-DOC-0021 Acme Widget Auditing Procedures Rev 1",
        sharepoint_folder=None,
        notes=None,
    ),
    # Full form must out-rank the bare acronym (listed first / longer).
    SupersessionEntry(
        legacy="System Security Authorization Agreement",
        current="ACME-DOC-0030 Acme Widget Security Plan Rev 3",
        sharepoint_folder=None,
        notes=None,
    ),
    SupersessionEntry(
        legacy="SSAA",
        current="ACME-DOC-0030 Acme Widget Security Plan Rev 3",
        sharepoint_folder=None,
        notes=None,
    ),
]

_FAKE_MAPPINGS: list[VerifiedSdaMapping] = [
    VerifiedSdaMapping(
        cci_id="CCI-001485",
        control_id="au-2",
        sda_req_number="#29",
        shall_statement="The system shall generate audit records for the defined auditable events.",
    ),
    VerifiedSdaMapping(
        cci_id="CCI-000767",
        control_id="ia-2.3",
        sda_req_number="#12",
        shall_statement="The system shall implement multifactor authentication for local access.",
    ),
    VerifiedSdaMapping(
        cci_id="CCI-001941",
        control_id="ia-2.8",
        sda_req_number="#14",
        shall_statement="The system shall implement replay-resistant authentication.",
    ),
]


def _compiled(entries: list[SupersessionEntry]):
    return [(re.compile(re.escape(e.legacy), re.IGNORECASE), e) for e in entries]


@pytest.fixture
def synthetic_registry(monkeypatch):
    """Install the fictional registry so the rewrite machinery can be
    fuzzed without baking program data into the test suite."""
    monkeypatch.setattr(supersession, "_LEGACY_TO_CURRENT", _FAKE_ENTRIES)
    monkeypatch.setattr(supersession, "_COMPILED_PATTERNS", _compiled(_FAKE_ENTRIES))
    monkeypatch.setattr(supersession, "_SSAA_TO_SDA_MAPPINGS", _FAKE_MAPPINGS)
    return supersession


# Health-check suppression: the synthetic_registry fixture is function-scoped
# but only mutates module globals once; running every hypothesis example
# against the same patched registry is exactly the intent, so silence the
# function-scoped-fixture warning (and the occasional too-slow example).
_REGISTRY_SETTINGS = settings(
    suppress_health_check=[
        HealthCheck.function_scoped_fixture,
        HealthCheck.too_slow,
    ]
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Build the fuzzing phrase pool from the SYNTHETIC constant, not the shipped
# (empty) registry — otherwise st.sampled_from([]) raises InvalidArgument at
# import time and the whole module fails to collect.
_LEGACY_PHRASES = [e.legacy for e in _FAKE_ENTRIES]


def _maybe_recase(s: str) -> st.SearchStrategy[str]:
    """Return a strategy that yields the phrase in random upper/lower casings."""
    return st.lists(
        st.sampled_from([str.upper, str.lower, str.title, lambda x: x]),
        min_size=len(s),
        max_size=len(s),
    ).map(lambda fns: "".join(f(c) for f, c in zip(fns, s)))


legacy_phrase_strategy = st.sampled_from(_LEGACY_PHRASES).flatmap(_maybe_recase)

filler_strategy = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
    min_size=0,
    max_size=40,
)

# Narratives: 0-4 random legacy phrases interleaved with filler.
narrative_strategy = st.lists(
    st.one_of(legacy_phrase_strategy, filler_strategy),
    min_size=0,
    max_size=8,
).map(" ".join)


# ---------------------------------------------------------------------------
# Shipped registry is scrubbed (no program data baked in)
# ---------------------------------------------------------------------------


def test_shipped_registry_is_empty():
    assert supersession._LEGACY_TO_CURRENT == []
    assert supersession._COMPILED_PATTERNS == []
    assert supersession._SSAA_TO_SDA_MAPPINGS == []


# ---------------------------------------------------------------------------
# _normalize_cci_id
# ---------------------------------------------------------------------------


@given(st.integers(min_value=0, max_value=9_999_999))
def test_normalize_cci_id_canonical_form(n):
    """Any digit-bearing input lands on 'CCI-NNNNNN' (6-digit pad)."""
    out = _normalize_cci_id(str(n))
    assert out == f"CCI-{n:06d}"


@given(st.integers(min_value=0, max_value=9_999_999))
def test_normalize_cci_id_idempotent(n):
    """Normalizing twice equals normalizing once."""
    once = _normalize_cci_id(str(n))
    twice = _normalize_cci_id(once)
    assert once == twice


@given(st.text(alphabet=st.characters(blacklist_categories=("N",)), max_size=20))
def test_normalize_cci_id_no_digits_passes_through(s):
    """Inputs with no digits return unchanged (no crash, no silent rename)."""
    assert _normalize_cci_id(s) == s


@given(st.sampled_from(["CCI-15", "cci 15", "15", "CCI 000015", "  CCI-15  "]))
def test_normalize_cci_id_known_variants_canonicalize_to_15(s):
    assert _normalize_cci_id(s) == "CCI-000015"


# ---------------------------------------------------------------------------
# rewrite_narrative — totality, idempotence, change-flag invariants
# ---------------------------------------------------------------------------


@given(narrative_strategy)
@_REGISTRY_SETTINGS
def test_rewrite_narrative_returns_result_type(synthetic_registry, text):
    """Total over the narrative corpus — no crashes, returns SupersessionResult."""
    res = rewrite_narrative(text)
    assert isinstance(res, SupersessionResult)
    assert isinstance(res.rewritten_text, str)
    assert isinstance(res.hits, list)


def test_rewrite_narrative_empty_string():
    res = rewrite_narrative("")
    assert res.rewritten_text == ""
    assert res.hits == []
    assert res.changed is False


@given(narrative_strategy)
@_REGISTRY_SETTINGS
def test_rewrite_narrative_changed_iff_hits_nonempty(synthetic_registry, text):
    """``changed`` is bool(hits). Two ways to ask the same question must agree."""
    res = rewrite_narrative(text)
    assert res.changed == bool(res.hits)


@given(narrative_strategy)
@_REGISTRY_SETTINGS
def test_rewrite_narrative_is_idempotent(synthetic_registry, text):
    """Running the rewrite on its own output produces no new hits.

    This is the patent's reproducibility claim: a downstream consumer
    that re-runs the rewriter on stored narratives must not invent new
    edits. If a 'current' phrase happens to contain a 'legacy' phrase as
    a substring, idempotence would silently break — guard against it.
    """
    first = rewrite_narrative(text)
    second = rewrite_narrative(first.rewritten_text)
    assert second.hits == [], (
        f"second-pass produced hits {second.hits} on already-rewritten text"
    )
    assert second.rewritten_text == first.rewritten_text


@given(narrative_strategy)
@_REGISTRY_SETTINGS
def test_rewrite_narrative_hits_legacy_phrases_only(synthetic_registry, text):
    """Each hit's legacy phrase must be one of the registered entries."""
    res = rewrite_narrative(text)
    known = {e.legacy for e in _FAKE_ENTRIES}
    for legacy, _current in res.hits:
        assert legacy in known


@given(narrative_strategy)
@_REGISTRY_SETTINGS
def test_rewrite_narrative_current_phrases_appear_post_rewrite(synthetic_registry, text):
    """Every recorded hit's current-phrase must end up in the output text."""
    res = rewrite_narrative(text)
    for _legacy, current in res.hits:
        assert current in res.rewritten_text


# ---------------------------------------------------------------------------
# find_stale_references — totality & dedup
# ---------------------------------------------------------------------------


@given(narrative_strategy)
@_REGISTRY_SETTINGS
def test_find_stale_references_returns_entry_list(synthetic_registry, text):
    out = find_stale_references(text)
    assert isinstance(out, list)
    for e in out:
        assert isinstance(e, SupersessionEntry)


def test_find_stale_references_empty():
    assert find_stale_references("") == []


@given(narrative_strategy)
@_REGISTRY_SETTINGS
def test_find_stale_references_no_duplicates(synthetic_registry, text):
    """Each legacy entry appears at most once in the report."""
    out = find_stale_references(text)
    legacy_phrases = [e.legacy for e in out]
    assert len(legacy_phrases) == len(set(legacy_phrases))


# ---------------------------------------------------------------------------
# PATENT CRITICAL — find_stale_references ↔ rewrite_narrative agreement
# ---------------------------------------------------------------------------


@given(narrative_strategy)
@_REGISTRY_SETTINGS
def test_stale_set_equals_rewrite_hits_set(synthetic_registry, text):
    """``find_stale_references`` and ``rewrite_narrative`` MUST report the
    same set of legacy phrases. This is the patent-claim invariant
    explicitly named in the supersession.py docstring.
    """
    stale = {e.legacy for e in find_stale_references(text)}
    hits = {legacy for legacy, _ in rewrite_narrative(text).hits}
    assert stale == hits, (
        f"phantom-hit drift: stale={stale - hits}, rewrite-only={hits - stale}"
    )


# ---------------------------------------------------------------------------
# lookup_verified_sda_mapping
# ---------------------------------------------------------------------------


@given(st.text(max_size=20))
def test_lookup_verified_sda_total(s):
    """Returns VerifiedSdaMapping or None — never raises (registry-agnostic)."""
    out = lookup_verified_sda_mapping(s)
    assert out is None or isinstance(out, VerifiedSdaMapping)


def test_lookup_verified_sda_known_ccis_resolve(synthetic_registry):
    """Each seeded mapping must be findable via its canonical CCI id."""
    for m in _FAKE_MAPPINGS:
        assert synthetic_registry.lookup_verified_sda_mapping(m.cci_id) is m


@given(cci=st.sampled_from([m.cci_id for m in _FAKE_MAPPINGS]))
@_REGISTRY_SETTINGS
def test_lookup_verified_sda_unnormalized_input_resolves(synthetic_registry, cci):
    """Variants like 'cci 1485' should still resolve via _normalize_cci_id."""
    bare = cci.split("-", 1)[1].lstrip("0") or "0"
    assert synthetic_registry.lookup_verified_sda_mapping(bare) is not None
    assert synthetic_registry.lookup_verified_sda_mapping(cci.lower()) is not None


def test_lookup_verified_sda_none_when_registry_empty():
    """No fixture → shipped empty mappings → always None."""
    assert lookup_verified_sda_mapping("CCI-001485") is None


# ---------------------------------------------------------------------------
# na_reconsideration_warning
# ---------------------------------------------------------------------------


@given(
    st.text(max_size=20),
    st.one_of(st.none(), st.text(max_size=20)),
    st.one_of(st.none(), st.text(max_size=80)),
)
def test_na_reconsideration_total(cci, status, prior):
    out = na_reconsideration_warning(cci, status, prior)
    assert out is None or isinstance(out, ReconsiderationWarning)


@given(status=st.sampled_from(["Compliant", "Non-Compliant", "compliant", "other"]))
@_REGISTRY_SETTINGS
def test_na_reconsideration_skips_non_na_status(synthetic_registry, status):
    """Returns None unless current status is exactly 'not applicable' (ci-insensitive)."""
    out = na_reconsideration_warning("CCI-001485", status, "Prior cited the SSAA.")
    assert out is None


@given(prior=st.sampled_from([None, ""]))
@_REGISTRY_SETTINGS
def test_na_reconsideration_skips_empty_prior(synthetic_registry, prior):
    out = na_reconsideration_warning("CCI-001485", "Not Applicable", prior)
    assert out is None


def test_na_reconsideration_emits_warning_for_known_cci_with_ssaa_in_prior(
    synthetic_registry,
):
    out = synthetic_registry.na_reconsideration_warning(
        "CCI-001485",
        "Not Applicable",
        "Prior assessor cited the SSAA Requirements for this CCI.",
    )
    assert out is not None
    assert out.severity == "warning"
    assert "Req #29" in out.message


def test_na_reconsideration_emits_info_for_unknown_cci_with_ssaa_in_prior(
    synthetic_registry,
):
    """A CCI without a verified SDA mapping should still surface as info-level."""
    out = synthetic_registry.na_reconsideration_warning(
        "CCI-999999",
        "Not Applicable",
        "Per SSAA scope, this is N/A.",
    )
    assert out is not None
    assert out.severity == "info"


def test_na_reconsideration_silent_when_registry_empty():
    """No fixture → no SSAA-bearing compiled patterns → always None even when
    the prior text mentions the SSAA."""
    out = na_reconsideration_warning(
        "CCI-001485",
        "Not Applicable",
        "Prior assessor cited the SSAA Requirements for this CCI.",
    )
    assert out is None


# ---------------------------------------------------------------------------
# resolve_current_evidence_id — chain walker
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _add_evidence(session: Session, **kw) -> Evidence:
    ev = Evidence(
        kind=kw.pop("kind", EvidenceKind.DOCX),
        path=kw.pop("path", "doc.docx"),
        sha256=kw.pop("sha256", "0" * 64),
        size_bytes=kw.pop("size_bytes", 1),
        **kw,
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    return ev


def test_resolve_returns_same_id_when_no_chain(session):
    ev = _add_evidence(session)
    assert resolve_current_evidence_id(session, ev.id) == ev.id


def test_resolve_walks_to_terminal(session):
    a = _add_evidence(session, path="a.docx")
    b = _add_evidence(session, path="b.docx")
    c = _add_evidence(session, path="c.docx")
    a.superseded_by_id = b.id
    b.superseded_by_id = c.id
    session.add(a)
    session.add(b)
    session.commit()
    assert resolve_current_evidence_id(session, a.id) == c.id


def test_resolve_breaks_cycle_safely(session):
    """A 2-row cycle must terminate without recursion, returning a stable id."""
    a = _add_evidence(session, path="a.docx")
    b = _add_evidence(session, path="b.docx")
    a.superseded_by_id = b.id
    b.superseded_by_id = a.id
    session.add(a)
    session.add(b)
    session.commit()
    result = resolve_current_evidence_id(session, a.id, max_hops=8)
    # Result must be one of the two ids — not a stack overflow, not an exception.
    assert result in {a.id, b.id}


def test_resolve_respects_max_hops(session):
    """A chain longer than max_hops returns the last hop visited, not the terminal."""
    chain: list[Evidence] = [_add_evidence(session, path=f"e{i}.docx") for i in range(6)]
    for prev, nxt in zip(chain, chain[1:]):
        prev.superseded_by_id = nxt.id
        session.add(prev)
    session.commit()
    # With max_hops=2, we walk e0 -> e1 -> e2, then stop. Result should be e2.
    out = resolve_current_evidence_id(session, chain[0].id, max_hops=2)
    assert out == chain[2].id


def test_resolve_missing_row_returns_input(session):
    """A nonexistent id should not crash — it just returns what was passed in."""
    assert resolve_current_evidence_id(session, 9_999_999) == 9_999_999


def test_resolve_logs_cycle_detection(session, caplog):
    """Cycle path must emit a warning so an operator can find the bad data."""
    a = _add_evidence(session, path="a.docx")
    b = _add_evidence(session, path="b.docx")
    a.superseded_by_id = b.id
    b.superseded_by_id = a.id
    session.add(a)
    session.add(b)
    session.commit()
    with caplog.at_level("WARNING", logger="cybersecurity_assessor.engine.supersession"):
        resolve_current_evidence_id(session, a.id)
    assert any("cycle detected" in r.message for r in caplog.records)


def test_resolve_logs_max_hops_exhaustion(session, caplog):
    """Reaching max_hops without a terminal must emit a warning."""
    chain: list[Evidence] = [_add_evidence(session, path=f"e{i}.docx") for i in range(5)]
    for prev, nxt in zip(chain, chain[1:]):
        prev.superseded_by_id = nxt.id
        session.add(prev)
    session.commit()
    with caplog.at_level("WARNING", logger="cybersecurity_assessor.engine.supersession"):
        resolve_current_evidence_id(session, chain[0].id, max_hops=2)
    assert any("max_hops=2 reached" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Sanity — pattern table compile invariant (against the synthetic registry)
# ---------------------------------------------------------------------------


def test_compiled_patterns_match_seed_table_length(synthetic_registry):
    """Every legacy entry has exactly one compiled pattern in the same order.

    Order matters because the rewriter walks longest-first by virtue of
    the seed-table ordering — if the lengths drift, the silent breakage
    is "shorter pattern shadows longer one".
    """
    compiled = synthetic_registry._COMPILED_PATTERNS
    entries = synthetic_registry._LEGACY_TO_CURRENT
    assert len(compiled) == len(entries)
    for (_pattern, entry), seed_entry in zip(compiled, entries):
        assert entry is seed_entry


def test_seed_table_orders_longest_first_within_overlap_groups(synthetic_registry):
    """Any pair (i, j) with i<j whose phrases share a substring relationship
    must have the longer phrase at index i. Catches accidental reorders
    that would silently flip which 'SSAA'-prefixed match wins.
    """
    seeds = list(synthetic_registry._LEGACY_TO_CURRENT)
    for i, e_i in enumerate(seeds):
        for e_j in seeds[i + 1 :]:
            if e_i.legacy.lower() in e_j.legacy.lower():
                # Shorter (e_i) listed before longer (e_j) — that's a bug.
                # The acceptable case is the reverse: longer first.
                pytest.fail(
                    f"order bug: {e_i.legacy!r} (idx {i}) is a substring of "
                    f"{e_j.legacy!r} listed later — longer must come first"
                )
