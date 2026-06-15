"""Golden tests for the document-supersession rewriter (deterministic kernel #3).

``engine.supersession`` is the third deterministic kernel guard: it catches
stale doc citations the LLM cannot know about on its own. Without this
rewrite, an LLM that pulled a legacy doc title out of col U (previous
results) would carry the dead reference straight into col Q — the validator
would let it through (a doc citation is not the ONLY accepted primary
source) and the assessor would file a Compliant narrative pointing at a doc
that has been superseded.

The shipped registry (``_LEGACY_TO_CURRENT`` / ``_SSAA_TO_SDA_MAPPINGS``)
ships **empty** — it held one program's verbatim doc map and was scrubbed
so no program data is baked into the app. These tests therefore exercise
the rewrite machinery against a fictional synthetic registry installed via
the ``synthetic_registry`` fixture (longest-match-first ordering matters).
A dedicated test pins that the shipped registry stays empty.

Most tests are pure-function over hand-built strings; the
``resolve_current_evidence_id`` tests at the end stand up an in-memory
SQLite session (StaticPool, matching the other engine test files) so
the self-FK chain walk runs against a real ``Evidence`` table — that path
is fully data-driven and needs no registry.
"""

from __future__ import annotations

import re
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
from cybersecurity_assessor.engine import supersession as ss  # noqa: E402
from cybersecurity_assessor.engine.supersession import (  # noqa: E402
    ReconsiderationWarning,
    SupersessionEntry,
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
# match first. Distinct legacies that collapse onto the same target exercise
# the many-legacies → one-current behavior.
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
        legacy="Acme Widget Legacy Scan Cycle Procedures",
        current="ACME-DOC-0040 Acme Widget Scanning How-To Procedures",
        sharepoint_folder=None,
        notes=None,
    ),
    SupersessionEntry(
        legacy="Acme Widget Legacy Scan Analysis Procedures",
        current="ACME-DOC-0040 Acme Widget Scanning How-To Procedures",
        sharepoint_folder=None,
        notes=None,
    ),
    SupersessionEntry(
        legacy="Acme Widget T1 Auditing Procedures",
        current="Acme Widget Auditing Procedures",
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


@pytest.fixture
def synthetic_registry(monkeypatch):
    """Install a fictional registry so the rewrite machinery can be
    exercised without baking program data into the test suite."""
    monkeypatch.setattr(ss, "_LEGACY_TO_CURRENT", _FAKE_ENTRIES)
    monkeypatch.setattr(
        ss,
        "_COMPILED_PATTERNS",
        [(re.compile(re.escape(e.legacy), re.IGNORECASE), e) for e in _FAKE_ENTRIES],
    )
    monkeypatch.setattr(ss, "_SSAA_TO_SDA_MAPPINGS", _FAKE_MAPPINGS)
    return ss


# ---------------------------------------------------------------------------
# Shipped registry is scrubbed (no program data baked in)
# ---------------------------------------------------------------------------


def test_shipped_registry_is_empty():
    """The shipped app carries no seeded program data."""
    assert ss._LEGACY_TO_CURRENT == []
    assert ss._COMPILED_PATTERNS == []
    assert ss._SSAA_TO_SDA_MAPPINGS == []


def test_rewrite_no_op_with_shipped_empty_registry():
    """With the empty shipped registry, even legacy-looking text is untouched."""
    text = "Per the Acme Widget Legacy Operations User Guide §3, accounts are reviewed."
    result = rewrite_narrative(text)
    assert result.rewritten_text == text
    assert result.hits == []
    assert not result.changed


# ---------------------------------------------------------------------------
# rewrite_narrative — the core legacy → current mapping (synthetic registry)
# ---------------------------------------------------------------------------


def test_rewrite_swaps_legacy_for_current(synthetic_registry):
    """Legacy phrase → current citation, hit recorded as a pair."""
    text = "Per the Acme Widget Legacy Operations User Guide §3, accounts are reviewed quarterly."

    result = synthetic_registry.rewrite_narrative(text)

    assert "Acme Widget Legacy Operations User Guide" not in result.rewritten_text
    assert "ACME-DOC-0010 Acme Widget Operations Plan Rev 2" in result.rewritten_text
    assert result.changed
    assert (
        "Acme Widget Legacy Operations User Guide",
        "ACME-DOC-0010 Acme Widget Operations Plan Rev 2",
    ) in result.hits


def test_rewrite_idempotent(synthetic_registry):
    """Running rewrite twice yields the same text and zero new hits on round 2."""
    text = (
        "Per the Acme Widget Legacy Operations User Guide §3 and per SSAA scope, "
        "the system inherits authentication."
    )

    first = synthetic_registry.rewrite_narrative(text)
    second = synthetic_registry.rewrite_narrative(first.rewritten_text)

    assert second.rewritten_text == first.rewritten_text
    assert second.hits == []  # nothing left to rewrite
    assert not second.changed


def test_rewrite_case_insensitive(synthetic_registry):
    """Mixed-case legacy phrase still rewrites (re.IGNORECASE on the patterns)."""
    text = "acme widget legacy operations USER GUIDE was last updated 2023."

    result = synthetic_registry.rewrite_narrative(text)

    assert "ACME-DOC-0010" in result.rewritten_text
    assert any("User Guide" in legacy for legacy, _ in result.hits)


def test_rewrite_longest_match_first(synthetic_registry):
    """User Guide entry must rewrite BEFORE the Plan entry on overlapping text.

    Both legacy strings map to the same current doc, but the User Guide
    pattern is listed first in the registry (the more specific match). Pin
    the ordering so a future edit that accidentally reorders them shows up
    immediately.
    """
    text = (
        "Refer to the Acme Widget Legacy Operations User Guide for procedure detail "
        "and the Acme Widget Legacy Operations Plan for top-level policy."
    )

    result = synthetic_registry.rewrite_narrative(text)

    # Both legacies present in the source → both should appear as hits, in
    # User-Guide-first order.
    legacies = [legacy for legacy, _ in result.hits]
    assert "Acme Widget Legacy Operations User Guide" in legacies
    assert "Acme Widget Legacy Operations Plan" in legacies
    assert legacies.index("Acme Widget Legacy Operations User Guide") < legacies.index(
        "Acme Widget Legacy Operations Plan"
    )


def test_rewrite_distinct_legacies_collapse_to_same_target(synthetic_registry):
    """Two distinct legacy phrases that map to the same current doc both fire.

    Verifies many-legacies → one-current: if registry ordering ever changed
    such that one phrase consumed the other, this would catch it.
    """
    text = (
        "Cycle steps from Acme Widget Legacy Scan Cycle Procedures §5 and analysis "
        "steps from Acme Widget Legacy Scan Analysis Procedures §6."
    )

    result = synthetic_registry.rewrite_narrative(text)

    assert "Acme Widget Legacy Scan Cycle Procedures" not in result.rewritten_text
    assert "Acme Widget Legacy Scan Analysis Procedures" not in result.rewritten_text
    assert "ACME-DOC-0040 Acme Widget Scanning How-To Procedures" in result.rewritten_text
    legacies = {legacy for legacy, _ in result.hits}
    assert "Acme Widget Legacy Scan Cycle Procedures" in legacies
    assert "Acme Widget Legacy Scan Analysis Procedures" in legacies


def test_rewrite_drops_prefix_variant(synthetic_registry):
    """A 'T1' prefixed legacy is rewritten to its un-prefixed successor.

    Pin that this variant is rewritten on its own and not silently swept
    by another pattern.
    """
    text = "Per Acme Widget T1 Auditing Procedures §4.0, audits run quarterly."

    result = synthetic_registry.rewrite_narrative(text)

    assert "Acme Widget T1 Auditing Procedures" not in result.rewritten_text
    assert "Acme Widget Auditing Procedures" in result.rewritten_text
    assert result.changed
    assert (
        "Acme Widget T1 Auditing Procedures",
        "Acme Widget Auditing Procedures",
    ) in result.hits


def test_rewrite_empty_string_no_op():
    """Empty input returns empty result, no hits, not changed."""
    result = rewrite_narrative("")

    assert result.rewritten_text == ""
    assert result.hits == []
    assert not result.changed


def test_rewrite_bare_ssaa_acronym_swept_by_longer_form(synthetic_registry):
    """When a longer SSAA phrasing rewrites first, the bare 'SSAA' is consumed.

    Because ``rewrite_narrative`` writes back into ``out`` after each
    pattern, the bare-acronym entry (last in the list) doesn't double-fire
    on text that originally contained 'System Security Authorization
    Agreement' — the longer phrase already turned that span into the
    target citation. This pins that behavior so we don't accidentally
    re-introduce double-rewrites.
    """
    text = "Per the System Security Authorization Agreement, the CCI is N/A."

    result = synthetic_registry.rewrite_narrative(text)

    # The long form fired.
    assert any(legacy == "System Security Authorization Agreement" for legacy, _ in result.hits)
    # The bare 'SSAA' MUST NOT also fire — there's no remaining 'SSAA' in out.
    assert not any(legacy == "SSAA" for legacy, _ in result.hits)
    assert "SSAA" not in result.rewritten_text


# ---------------------------------------------------------------------------
# find_stale_references — dedup + non-destructive surface
# ---------------------------------------------------------------------------


def test_find_stale_references_returns_dedup_list(synthetic_registry):
    """Two occurrences of the same legacy → one entry returned."""
    text = (
        "Acme Widget Legacy Operations Plan §1 is cited here, and again the "
        "Acme Widget Legacy Operations Plan §2 is cited there."
    )

    refs = synthetic_registry.find_stale_references(text)

    plan_hits = [r for r in refs if r.legacy == "Acme Widget Legacy Operations Plan"]
    assert len(plan_hits) == 1
    # And the text itself is NOT modified (find_stale_references is read-only).
    assert "Acme Widget Legacy Operations Plan" in text


def test_find_stale_references_empty_input_returns_empty_list():
    assert find_stale_references("") == []


def test_find_stale_references_empty_when_registry_empty():
    """Shipped empty registry → nothing flagged even for legacy-looking text."""
    text = "Acme Widget Legacy Operations Plan §1 is cited here."
    assert find_stale_references(text) == []


# ---------------------------------------------------------------------------
# Verified SDA mapping lookup
# ---------------------------------------------------------------------------


def test_lookup_verified_sda_mapping_known_cci(synthetic_registry):
    """CCI-001485 → au-2 Req #29 (the AU mapping in the synthetic table)."""
    m = synthetic_registry.lookup_verified_sda_mapping("CCI-001485")

    assert m is not None
    assert m.control_id == "au-2"
    assert m.sda_req_number == "#29"
    assert "auditable events" in m.shall_statement.lower()


def test_lookup_verified_sda_mapping_normalizes_unpadded_id(synthetic_registry):
    """The CCI normalizer pads to 6 digits — 'CCI-1485' resolves the same row."""
    m_padded = synthetic_registry.lookup_verified_sda_mapping("CCI-001485")
    m_unpadded = synthetic_registry.lookup_verified_sda_mapping("CCI-1485")

    assert m_unpadded is not None
    assert m_unpadded == m_padded


def test_lookup_verified_sda_mapping_unknown_cci(synthetic_registry):
    """Unmapped CCI returns None."""
    assert synthetic_registry.lookup_verified_sda_mapping("CCI-999999") is None


def test_lookup_verified_sda_mapping_none_when_registry_empty():
    """Shipped empty mappings → always None."""
    assert lookup_verified_sda_mapping("CCI-001485") is None


# ---------------------------------------------------------------------------
# NA reconsideration warning (the accuracy guard)
# ---------------------------------------------------------------------------


def test_na_reconsideration_warning_fires_for_mapped_cci_with_ssaa_prior(synthetic_registry):
    """NA + prior_results cites SSAA + CCI is in the verified table → 'warning'."""
    w = synthetic_registry.na_reconsideration_warning(
        cci_id="CCI-001485",  # mapped to au-2 #29
        current_status="Not Applicable",
        prior_results_text="Per SSAA scope, this CCI is N/A for the ground segment.",
    )

    assert w is not None
    assert w.severity == "warning"
    assert "CCI-001485" in w.message
    assert "#29" in w.message


def test_na_reconsideration_warning_info_for_unmapped_cci_with_ssaa_prior(synthetic_registry):
    """NA + SSAA prior + CCI NOT in verified table → 'info' (still flag, gentler)."""
    w = synthetic_registry.na_reconsideration_warning(
        cci_id="CCI-999999",  # unmapped
        current_status="Not Applicable",
        prior_results_text="Prior assessor: not applicable per SSAA.",
    )

    assert w is not None
    assert w.severity == "info"
    assert "CCI-999999" in w.message


def test_na_reconsideration_warning_skips_non_na_status(synthetic_registry):
    """current_status=Compliant → returns None even with SSAA prior."""
    w = synthetic_registry.na_reconsideration_warning(
        cci_id="CCI-001485",
        current_status="Compliant",
        prior_results_text="Per SSAA scope, this CCI was previously N/A.",
    )
    assert w is None


def test_na_reconsideration_warning_skips_when_prior_has_no_ssaa(synthetic_registry):
    """NA + prior with no SSAA mention → None (no stale citation to challenge)."""
    w = synthetic_registry.na_reconsideration_warning(
        cci_id="CCI-001485",
        current_status="Not Applicable",
        prior_results_text="Not applicable; system does not have wireless interfaces.",
    )
    assert w is None


def test_na_reconsideration_warning_skips_when_prior_results_missing(synthetic_registry):
    """NA + no prior_results → None (nothing to reconsider against)."""
    w = synthetic_registry.na_reconsideration_warning(
        cci_id="CCI-001485",
        current_status="Not Applicable",
        prior_results_text=None,
    )
    assert w is None


def test_na_reconsideration_warning_status_match_is_case_insensitive(synthetic_registry):
    """'not applicable' / 'NOT APPLICABLE' / 'Not Applicable' all qualify."""
    for s in ("not applicable", "NOT APPLICABLE", "Not Applicable"):
        w = synthetic_registry.na_reconsideration_warning(
            cci_id="CCI-001485",
            current_status=s,
            prior_results_text="Per the SSAA, N/A.",
        )
        assert isinstance(w, ReconsiderationWarning), f"failed for status={s!r}"
        assert w.severity == "warning"


def test_na_reconsideration_warning_silent_when_registry_empty():
    """Shipped empty registry → no SSAA-bearing patterns → always None."""
    w = na_reconsideration_warning(
        cci_id="CCI-001485",
        current_status="Not Applicable",
        prior_results_text="Per SSAA scope, this CCI is N/A.",
    )
    assert w is None


# ---------------------------------------------------------------------------
# _normalize_cci_id — the no-digit fallthrough
# ---------------------------------------------------------------------------


def test_normalize_cci_id_pads_unpadded_form():
    """Sanity: the happy path that lookup_verified_sda_mapping exercises."""
    assert _normalize_cci_id("CCI-1485") == "CCI-001485"
    assert _normalize_cci_id("cci 15") == "CCI-000015"
    assert _normalize_cci_id("15") == "CCI-000015"


def test_normalize_cci_id_returns_input_unchanged_when_no_digits():
    """No digits in input → return verbatim.

    Pins the fallthrough branch in ``_normalize_cci_id``. The function is
    normally fed canonical-ish CCI strings ('CCI-001485', 'CCI-1485', '15')
    so the regex match almost always succeeds. The defensive branch fires
    on caller bugs — e.g. a UI control that hands ``cci_id=""`` or a typo'd
    placeholder like ``cci_id="N/A"`` to ``lookup_verified_sda_mapping``.
    Drop the branch and the function would raise ``AttributeError: 'NoneType'
    object has no attribute 'group'`` instead of returning a non-matching
    string that produces a clean ``None`` from the mapping lookup; pin the
    contract: no digits → return as-is, no raise.
    """
    # Empty string — _normalize_cci_id uses ``cci or ""`` for None safety;
    # an empty string still returns "" because there's no digit to extract.
    assert _normalize_cci_id("") == ""
    # Pure letters — no digit substring, falls through.
    assert _normalize_cci_id("foo") == "foo"
    # Placeholder text the UI might send by mistake; lookup must return None,
    # not crash.
    assert _normalize_cci_id("N/A") == "N/A"
    assert lookup_verified_sda_mapping("N/A") is None


# ---------------------------------------------------------------------------
# resolve_current_evidence_id — supersession chain walk
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    """In-memory SQLite for the Evidence-table chain-walk tests."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _make_evidence(
    session: Session,
    *,
    path: str,
    superseded_by_id: int | None = None,
) -> Evidence:
    """Create + flush an Evidence row so ``id`` is assigned."""
    ev = Evidence(
        path=path,
        sha256="0" * 64,
        kind=EvidenceKind.PDF,
        size_bytes=1,
        superseded_by_id=superseded_by_id,
    )
    session.add(ev)
    session.flush()  # assigns ev.id without committing the txn
    return ev


def test_resolve_current_evidence_id_terminal_row_returns_input(session):
    """No supersession set → ``resolve_current_evidence_id`` returns input id.

    Pins the early-return for the ``superseded_by_id is None`` branch. Most
    Evidence rows in the wild are terminal (current); this is the hot path.
    If it ever started walking past terminal, queries that resolve "show me
    the canonical evidence for this row" would touch the DB once per row
    when they should be a single get + early return.
    """
    ev = _make_evidence(session, path="file:///tmp/current.pdf")

    assert resolve_current_evidence_id(session, ev.id) == ev.id


def test_resolve_current_evidence_id_walks_one_hop_chain(session):
    """A → B chain → ``resolve_current_evidence_id(A.id) == B.id``.

    Pins the normal one-hop chain walk. Chains are 1-2 deep in practice
    (a legacy doc → its current replacement); the one-hop case is
    overwhelmingly the common one.
    """
    current = _make_evidence(session, path="file:///tmp/current_doc.pdf")
    legacy = _make_evidence(
        session,
        path="file:///tmp/legacy_doc.pdf",
        superseded_by_id=current.id,
    )

    assert resolve_current_evidence_id(session, legacy.id) == current.id


def test_resolve_current_evidence_id_walks_multi_hop_chain(session):
    """A → B → C chain → ``resolve_current_evidence_id(A.id) == C.id``.

    Two-hop chains do happen (a doc gets superseded once, then the
    replacement is itself replaced). Pin that the loop actually iterates;
    a regression that turned the for-loop into ``if`` would silently
    return the middle of the chain on every two-hop case.
    """
    c = _make_evidence(session, path="file:///tmp/c.pdf")
    b = _make_evidence(session, path="file:///tmp/b.pdf", superseded_by_id=c.id)
    a = _make_evidence(session, path="file:///tmp/a.pdf", superseded_by_id=b.id)

    assert resolve_current_evidence_id(session, a.id) == c.id


def test_resolve_current_evidence_id_breaks_cycle(session):
    """A → B → A cycle → returns the last-seen id without infinite-looping.

    Pins the cycle guard. A cycle is a data bug (assessor manually pointed
    a "current" row back at its predecessor) but it MUST NOT hang the
    assessment pass. The guard returns the id we were about to revisit —
    not necessarily semantically "right" but deterministic and bounded.
    """
    a = _make_evidence(session, path="file:///tmp/a.pdf")
    b = _make_evidence(session, path="file:///tmp/b.pdf", superseded_by_id=a.id)
    # Close the cycle: a → b.
    a.superseded_by_id = b.id
    session.add(a)
    session.flush()

    # Starting at A: A → B → (would revisit A) → returns B (the last good id
    # before we would have looped back).
    result = resolve_current_evidence_id(session, a.id)
    assert result == b.id


def test_resolve_current_evidence_id_missing_row_returns_input(session):
    """Input id has no Evidence row → returns input id unchanged.

    Pins the ``row is None`` branch. Caller hands in a stale id (e.g. an
    Evidence row that was deleted between the parent query and this
    resolver call); the function MUST return a valid int rather than raise
    — downstream code uses the return value to set ``citation_evidence_id``
    on a Citation row, and a raise would abort the whole assessor pass for
    an unrelated row.
    """
    # 999_999 is well past any flushed id in this clean session.
    assert resolve_current_evidence_id(session, 999_999) == 999_999


def test_resolve_current_evidence_id_max_hops_caps_walk(session):
    """Chain deeper than ``max_hops`` → loop exits, returns the last-walked id.

    Pins the final ``return current_id`` — the fall-through after the
    for-loop exhausts ``max_hops``. Real chains aren't this deep, but the
    cap is the second line of defense behind the cycle guard (in case bad
    data produces a long-but-non-cyclic chain). Drop the cap and a
    million-row pathological chain would hold the txn open scanning
    Evidence; pin the cap so future-us doesn't "simplify" the resolver by
    removing the for-loop bound.
    """
    # Build a 4-deep chain: a → b → c → d (d is terminal).
    d = _make_evidence(session, path="file:///tmp/d.pdf")
    c = _make_evidence(session, path="file:///tmp/c.pdf", superseded_by_id=d.id)
    b = _make_evidence(session, path="file:///tmp/b.pdf", superseded_by_id=c.id)
    a = _make_evidence(session, path="file:///tmp/a.pdf", superseded_by_id=b.id)

    # With max_hops=2 we can only walk a → b → c; the loop exits with
    # current_id = c.id and falls through to ``return current_id``.
    assert resolve_current_evidence_id(session, a.id, max_hops=2) == c.id
    # And the natural max_hops (8) is more than enough for this chain.
    assert resolve_current_evidence_id(session, a.id) == d.id
