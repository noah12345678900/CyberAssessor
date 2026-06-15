"""Property-based tests for ``engine.decision_cache``.

The example-driven suite in ``backend/tests/engine/test_decision_cache.py``
pins specific shapes (one-row hit, miss after edit, miss after KERNEL_VERSION
bump). This file fuzzes the fingerprint contract so a refactor that breaks
an invariant in a corner of the (CcisRow × evidence × CrmContext) input
space is caught before it ships.

The fingerprint is the patent-supporting "did we already decide this?"
oracle. Its correctness has two halves — both are pinned here:

  1. **Stability / determinism.** Same (row, evidence, crm) → same
     sha256, byte-for-byte, across calls. A non-deterministic fingerprint
     would cache-miss on every call, defeating the whole module's
     purpose. JSON payload uses ``sort_keys=True, separators=(",", ":")``
     specifically to make this hold across dict-iteration-order changes.

  2. **Field-exclusion contract.** ``excel_row`` and ``raw`` must NEVER
     change the fingerprint. ``excel_row`` is just a workbook position
     (re-ordering rows shouldn't invalidate decisions); ``raw`` is the
     openpyxl metadata blob, irrelevant to the decision. A refactor that
     accidentally included either would invalidate every cache entry on
     every re-parse — every workbook reopen would burn money on
     re-running the LLM.

  3. **Field-inclusion contract.** Changing ANY of the kernel-relevant
     fields (cci_id, control_id, ap_acronym, implementation_status,
     designation, narrative, definition, guidance, procedures,
     inherited, remote_inheritance, previous_status, previous_results)
     MUST change the fingerprint. A field that silently fell out of the
     payload would let stale cached decisions survive an edit that
     should have invalidated them — the user reviews a confidence
     verdict that no longer reflects the row.

  4. **Evidence sha contract.** Different ``tagged_evidence`` strings →
     different fingerprints. ``None`` and ``""`` both → the same
     empty-sha branch (documented contract). Whitespace-only evidence
     is NOT folded to empty — it hashes normally — defending against a
     refactor that "helpfully" stripped evidence and lost the signal
     that whitespace-only is itself a content state.

  5. **CRM payload contract.** Different CRM responsibility or narrative
     on the row's control → different fingerprint. CRM ``None`` and "CRM
     attached but silent on this control" both collapse to ``{"present":
     False}`` — cleanly distinguishing "no CRM" from "CRM, no entry" is
     not the contract here; the contract is "the LLM saw no CRM signal"
     and both states present that to the LLM identically.

  6. **Format invariants.** Output is a 64-char lowercase hex string.
     A future swap to e.g. blake2b would silently shorten; pinning the
     format catches it.

These tests do NOT exercise the persistence layer (``lookup`` / ``store``
/ ``replay``) — those depend on a live ``Decision`` instance, which
``assessor.py`` constructs and which has a deep dependency tree.
The DB roundtrip is covered by the example-driven suite.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")

from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

# Backend package on path — property tests live at repo-root tests/engine/,
# so parents[2] points at backend/.
_BACKEND = Path(__file__).resolve().parents[2] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.engine.crm_context import (  # noqa: E402
    CrmContext,
    CrmEntry,
)
from cybersecurity_assessor.engine.decision_cache import (  # noqa: E402
    KERNEL_VERSION,
    PROMPT_SHA,
    _crm_fingerprint_payload,
    _row_fingerprint_payload,
    fingerprint,
)
from cybersecurity_assessor.excel.ccis_reader import CcisRow  # noqa: E402


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------


# Short printable text — keeps Hypothesis fast and avoids C0 control
# chars that openpyxl rejects (they never reach the fingerprint via the
# real path so excluding them from the strategy is faithful to production).
_TEXT = st.text(
    alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E),
    min_size=0,
    max_size=30,
)

# Some fields can be None or text; mirror the CcisRow Optional[str] shape.
_OPT_TEXT = st.one_of(st.none(), st.just(""), _TEXT)

# Canonical control_id forms that _normalize_control accepts.
_CONTROL_ID = st.sampled_from(
    ["AC-2", "AC-2(1)", "AC-3", "AC-6", "AU-2", "IA-5", "CM-7", "SI-4"]
)

# CCI ids in canonical "CCI-NNNNNN" form.
_CCI_ID = st.builds(
    lambda n: f"CCI-{n:06d}",
    st.integers(min_value=1, max_value=999999),
)

# Responsibility values that build_crm_context emits.
_RESPONSIBILITY = st.sampled_from(
    ["customer", "provider", "hybrid", "inherited", "not_applicable"]
)


def _build_row(
    *,
    excel_row: int = 100,
    control_id: str = "AC-2",
    cci_id: str | None = "CCI-000015",
    ap_acronym: str | None = "AC-2.1",
    implementation_status: str | None = "Implemented",
    designation: str | None = "Common",
    narrative: str | None = "Stock narrative for AC-2.",
    definition: str | None = "AC-2 definition",
    guidance: str | None = "AC-2 guidance",
    procedures: str | None = "Procedure A",
    inherited: str | None = "Local",
    remote_inheritance: str | None = None,
    previous_status: str | None = "Compliant",
    previous_results: str | None = "Prior results.",
    raw: dict | None = None,
) -> CcisRow:
    """Build a CcisRow with sensible defaults; only overrides shift the
    fingerprint when the field is in the inclusion set.

    Fields NOT exercised by the fingerprint (``status``, ``date_tested``,
    ``tester``, ``results``, ``previous_date``, ``previous_tester``,
    ``required``) are set to fixed defaults — the property tests below
    don't fuzz them because they're not in ``_row_fingerprint_payload``.
    """
    return CcisRow(
        excel_row=excel_row,
        required=True,
        control_id=control_id,
        ap_acronym=ap_acronym,
        cci_id=cci_id,
        implementation_status=implementation_status,
        designation=designation,
        narrative=narrative,
        definition=definition,
        guidance=guidance,
        procedures=procedures,
        inherited=inherited,
        remote_inheritance=remote_inheritance,
        status=None,
        date_tested=None,
        tester=None,
        results=None,
        previous_status=previous_status,
        previous_date=None,
        previous_tester=None,
        previous_results=previous_results,
        raw=raw if raw is not None else {},
    )


def _build_crm_context(
    control_id: str | None,
    responsibility: str | None,
    narrative: str | None,
) -> CrmContext | None:
    """Build a CrmContext keyed on the OSCAL form of ``control_id``.

    The fingerprint path normalizes the row's control_id through
    ``_normalize_control`` then ``_ccis_to_oscal_control_id`` before
    lookup; we mirror that by lower-casing the input here so the test
    context actually matches the row.
    """
    if control_id is None:
        return None
    if responsibility is None:
        # CRM attached but no entry for this control.
        return CrmContext(by_control={})
    oscal_id = control_id.lower().replace("(", ".").replace(")", "")
    entry = CrmEntry(
        control_id=oscal_id,
        responsibility=responsibility,
        narrative=narrative,
        source_baseline_id=1,
    )
    return CrmContext(by_control={oscal_id: entry})


# ---------------------------------------------------------------------------
# Format invariants — every fingerprint is a 64-char lowercase hex string
# ---------------------------------------------------------------------------


@given(
    cci_id=_CCI_ID,
    narrative=_OPT_TEXT,
    evidence=_OPT_TEXT,
)
@settings(max_examples=100, deadline=None)
def test_fingerprint_is_sha256_hex(cci_id, narrative, evidence):
    """Output is a 64-char lowercase hex string for any input.

    A future swap to a different hash (blake2b → 128 chars; md5 → 32)
    would silently shorten or lengthen the column. The DecisionCache PK
    column would still accept it, but byte-stability across the prior
    cache becomes impossible — every entry written under the old hash
    would be unreachable from new code.
    """
    row = _build_row(cci_id=cci_id, narrative=narrative)
    fp = fingerprint(row=row, tagged_evidence=evidence, crm_context=None)
    assert isinstance(fp, str)
    assert len(fp) == 64
    assert fp == fp.lower()
    int(fp, 16)  # raises if not hex


# ---------------------------------------------------------------------------
# Determinism — same inputs → same fingerprint, twice
# ---------------------------------------------------------------------------


@given(
    cci_id=_CCI_ID,
    narrative=_OPT_TEXT,
    evidence=_OPT_TEXT,
    crm_resp=st.one_of(st.none(), _RESPONSIBILITY),
    crm_narr=_OPT_TEXT,
)
@settings(max_examples=100, deadline=None)
def test_fingerprint_is_deterministic(
    cci_id, narrative, evidence, crm_resp, crm_narr
):
    """Same (row, evidence, crm) → same fingerprint, twice.

    The cache miss-rate is bounded by this property. A non-deterministic
    fingerprint (e.g. one that included ``id(row)`` or wall-clock time
    by accident) would cache-miss every call and the whole module's
    cost savings would silently regress to zero.
    """
    row = _build_row(cci_id=cci_id, narrative=narrative)
    ctx = _build_crm_context(row.control_id, crm_resp, crm_narr)
    fp1 = fingerprint(row=row, tagged_evidence=evidence, crm_context=ctx)
    fp2 = fingerprint(row=row, tagged_evidence=evidence, crm_context=ctx)
    assert fp1 == fp2


@given(
    cci_id=_CCI_ID,
    narrative=_OPT_TEXT,
    evidence=_OPT_TEXT,
)
@settings(max_examples=80, deadline=None)
def test_fingerprint_stable_across_raw_dict_key_order(cci_id, narrative, evidence):
    """The ``raw`` blob's key order MUST NOT change the fingerprint.

    ``raw`` is *excluded* entirely; this is a "belt and suspenders"
    sanity check that confirms the exclusion holds regardless of how
    openpyxl orders its column-letter keys (CPython dict ordering means
    a future Python release could re-order parser output — the cache
    must be robust to that).
    """
    row_a = _build_row(
        cci_id=cci_id, narrative=narrative,
        raw={"A": 1, "B": 2, "C": 3, "D": 4},
    )
    row_b = _build_row(
        cci_id=cci_id, narrative=narrative,
        raw={"D": 4, "C": 3, "B": 2, "A": 1},
    )
    fp_a = fingerprint(row=row_a, tagged_evidence=evidence, crm_context=None)
    fp_b = fingerprint(row=row_b, tagged_evidence=evidence, crm_context=None)
    assert fp_a == fp_b


# ---------------------------------------------------------------------------
# Field-exclusion contract — excel_row + raw never affect the fingerprint
# ---------------------------------------------------------------------------


@given(
    cci_id=_CCI_ID,
    excel_row_a=st.integers(min_value=2, max_value=10000),
    excel_row_b=st.integers(min_value=2, max_value=10000),
    evidence=_OPT_TEXT,
)
@settings(max_examples=100, deadline=None)
def test_excel_row_is_excluded_from_fingerprint(
    cci_id, excel_row_a, excel_row_b, evidence
):
    """Changing ``excel_row`` MUST NOT change the fingerprint.

    Workbook re-saves frequently shift physical row indices (a sort,
    a manual row insert by the user). If those shifts invalidated the
    cache, every "open the workbook in Excel and save" round-trip would
    burn a full LLM run on every CCI. Excluding excel_row is the entire
    reason ``_row_fingerprint_payload`` exists.
    """
    row_a = _build_row(cci_id=cci_id, excel_row=excel_row_a)
    row_b = _build_row(cci_id=cci_id, excel_row=excel_row_b)
    fp_a = fingerprint(row=row_a, tagged_evidence=evidence, crm_context=None)
    fp_b = fingerprint(row=row_b, tagged_evidence=evidence, crm_context=None)
    assert fp_a == fp_b


@given(
    cci_id=_CCI_ID,
    raw_a=st.dictionaries(
        keys=st.sampled_from(["A", "B", "C", "D", "E"]),
        values=_OPT_TEXT,
        min_size=0, max_size=5,
    ),
    raw_b=st.dictionaries(
        keys=st.sampled_from(["A", "B", "C", "D", "E"]),
        values=_OPT_TEXT,
        min_size=0, max_size=5,
    ),
    evidence=_OPT_TEXT,
)
@settings(max_examples=80, deadline=None)
def test_raw_dict_is_excluded_from_fingerprint(cci_id, raw_a, raw_b, evidence):
    """Changing ``row.raw`` MUST NOT change the fingerprint.

    ``raw`` carries openpyxl metadata (cell types, number formats) that
    don't influence the decision. A regression that included raw would
    invalidate the cache on every re-parse, since openpyxl populates
    raw fresh each time.
    """
    row_a = _build_row(cci_id=cci_id, raw=raw_a)
    row_b = _build_row(cci_id=cci_id, raw=raw_b)
    fp_a = fingerprint(row=row_a, tagged_evidence=evidence, crm_context=None)
    fp_b = fingerprint(row=row_b, tagged_evidence=evidence, crm_context=None)
    assert fp_a == fp_b


# ---------------------------------------------------------------------------
# Field-inclusion contract — every included field, when changed, changes
# the fingerprint
# ---------------------------------------------------------------------------


_INCLUDED_FIELDS_BY_NAME = (
    "cci_id",
    "control_id",
    "ap_acronym",
    "implementation_status",
    "designation",
    "narrative",
    "definition",
    "guidance",
    "procedures",
    "inherited",
    "remote_inheritance",
    "previous_status",
    "previous_results",
)


@pytest.mark.parametrize("field_name", _INCLUDED_FIELDS_BY_NAME)
@given(
    base_value=_TEXT.filter(lambda s: s != ""),
    other_value=_TEXT.filter(lambda s: s != ""),
)
@settings(max_examples=40, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def test_included_field_change_changes_fingerprint(
    field_name, base_value, other_value
):
    """Changing any of the 13 kernel-relevant fields → different fingerprint.

    The fingerprint payload is the SOURCE OF TRUTH for "what content
    invalidates a cached decision". A refactor that dropped a field from
    ``_row_fingerprint_payload`` would let an edit to that field survive
    silently — the reviewer would read a stale verdict and never know.
    This parametrized property pins every included field at once.
    """
    if base_value == other_value:
        # Hypothesis can sample the same value into both; in that case the
        # property is vacuously true. Skip rather than asserting equality
        # on what would then be identical inputs.
        return
    overrides_a = {field_name: base_value}
    overrides_b = {field_name: other_value}
    row_a = _build_row(**overrides_a)
    row_b = _build_row(**overrides_b)
    fp_a = fingerprint(row=row_a, tagged_evidence=None, crm_context=None)
    fp_b = fingerprint(row=row_b, tagged_evidence=None, crm_context=None)
    assert fp_a != fp_b, (
        f"field '{field_name}': changing {base_value!r} → {other_value!r} "
        f"left the fingerprint unchanged — the field has silently fallen "
        f"out of _row_fingerprint_payload"
    )


# ---------------------------------------------------------------------------
# Evidence sha contract
# ---------------------------------------------------------------------------


def test_evidence_none_and_empty_string_collide():
    """``None`` and ``""`` both → empty-sha branch → same fingerprint.

    Documented contract on ``fingerprint``: the empty-sha branch fires
    on falsy evidence. ``None`` (no evidence ever attached) and ``""``
    (evidence ingested but resulted in an empty join) are interchangeable
    from the LLM's perspective — both presented "no evidence" to the
    decision step.
    """
    row = _build_row()
    fp_none = fingerprint(row=row, tagged_evidence=None, crm_context=None)
    fp_empty = fingerprint(row=row, tagged_evidence="", crm_context=None)
    assert fp_none == fp_empty


@given(
    evidence_a=_TEXT.filter(lambda s: s.strip() != ""),
    evidence_b=_TEXT.filter(lambda s: s.strip() != ""),
)
@settings(max_examples=80, deadline=None)
def test_different_evidence_means_different_fingerprint(evidence_a, evidence_b):
    """Different non-empty evidence → different fingerprint.

    The evidence sha is the bridge between "we tagged a new piece of
    evidence" and "re-decide this control". A regression that dropped
    the evidence sha from the payload would mean re-tagging evidence
    never invalidated cached decisions on the controls that evidence
    supports.
    """
    if evidence_a == evidence_b:
        return  # vacuously true; skip the same-input pair
    row = _build_row()
    fp_a = fingerprint(row=row, tagged_evidence=evidence_a, crm_context=None)
    fp_b = fingerprint(row=row, tagged_evidence=evidence_b, crm_context=None)
    assert fp_a != fp_b


@given(evidence=_TEXT.filter(lambda s: s.strip() != "" and s != ""))
@settings(max_examples=40, deadline=None)
def test_whitespace_only_evidence_is_not_folded_to_empty(evidence):
    """Whitespace-only evidence is NOT folded into the empty-sha branch.

    A future "be helpful and strip whitespace" change in ``fingerprint``
    would lose the "user attached whitespace-only evidence" signal —
    that's a real content state (often a paste mistake the reviewer
    needs to see), and folding it would invalidate decisions silently.
    The current contract: only literal None / "" hit the empty branch.
    """
    whitespace = " " * len(evidence)
    if not whitespace.strip() == "":
        return  # generated text wasn't actually whitespace-only
    row = _build_row()
    fp_empty = fingerprint(row=row, tagged_evidence=None, crm_context=None)
    fp_ws = fingerprint(row=row, tagged_evidence=whitespace, crm_context=None)
    # Whitespace-only is content; must hash differently than "no evidence".
    if whitespace:
        assert fp_empty != fp_ws


# ---------------------------------------------------------------------------
# CRM payload contract
# ---------------------------------------------------------------------------


def test_crm_none_and_empty_context_collide():
    """``crm_context=None`` and ``CrmContext.empty()`` → same fingerprint.

    Both present "no CRM signal on this row" to the LLM identically.
    The fingerprint contract collapses them to ``{"present": False}``.
    A refactor that distinguished them would split the cache for no
    semantic benefit.
    """
    row = _build_row()
    fp_none = fingerprint(row=row, tagged_evidence=None, crm_context=None)
    fp_empty = fingerprint(
        row=row, tagged_evidence=None, crm_context=CrmContext.empty()
    )
    assert fp_none == fp_empty


def test_crm_with_entry_for_other_control_does_not_match():
    """CRM with entries only for OTHER controls → ``{"present": False}``.

    A CRM that carries entries for IA-5 doesn't change the AC-2
    fingerprint. Lookups are per-control; the fingerprint MUST reflect
    only the row's own CRM entry. Otherwise a CRM re-upload would
    invalidate every cached decision in the workbook.
    """
    row = _build_row(control_id="AC-2")
    ctx_unrelated = CrmContext(
        by_control={
            "ia-5": CrmEntry(
                control_id="ia-5",
                responsibility="inherited",
                narrative="From AWS GovCloud.",
                source_baseline_id=1,
            )
        }
    )
    fp_none = fingerprint(row=row, tagged_evidence=None, crm_context=None)
    fp_unrelated = fingerprint(
        row=row, tagged_evidence=None, crm_context=ctx_unrelated
    )
    assert fp_none == fp_unrelated


@given(
    resp_a=_RESPONSIBILITY,
    resp_b=_RESPONSIBILITY,
)
@settings(max_examples=50, deadline=None)
def test_different_crm_responsibility_means_different_fingerprint(resp_a, resp_b):
    """Changing CRM responsibility on the row's control → different fingerprint.

    The LLM short-circuit logic in the assessor depends on CRM
    responsibility (provider/inherited → short-circuit; customer →
    full assessment). Caching a decision keyed on the assumption of
    "provider" then silently reusing it after the CRM flips to
    "customer" would replay a free-pass on a control the user now
    owns end-to-end.
    """
    if resp_a == resp_b:
        return
    row = _build_row(control_id="AC-2")
    ctx_a = _build_crm_context("AC-2", resp_a, "narr")
    ctx_b = _build_crm_context("AC-2", resp_b, "narr")
    fp_a = fingerprint(row=row, tagged_evidence=None, crm_context=ctx_a)
    fp_b = fingerprint(row=row, tagged_evidence=None, crm_context=ctx_b)
    assert fp_a != fp_b


@given(
    narr_a=_TEXT.filter(lambda s: s != ""),
    narr_b=_TEXT.filter(lambda s: s != ""),
)
@settings(max_examples=40, deadline=None)
def test_different_crm_narrative_means_different_fingerprint(narr_a, narr_b):
    """Changing the CRM-row narrative → different fingerprint.

    The narrative is part of what the LLM saw; a corrected CRM
    narrative must re-evaluate the decision. A regression that dropped
    ``narrative`` from ``_crm_fingerprint_payload`` would silently
    reuse stale decisions across CRM corrections.
    """
    if narr_a == narr_b:
        return
    row = _build_row(control_id="AC-2")
    ctx_a = _build_crm_context("AC-2", "inherited", narr_a)
    ctx_b = _build_crm_context("AC-2", "inherited", narr_b)
    fp_a = fingerprint(row=row, tagged_evidence=None, crm_context=ctx_a)
    fp_b = fingerprint(row=row, tagged_evidence=None, crm_context=ctx_b)
    assert fp_a != fp_b


# ---------------------------------------------------------------------------
# Payload structure invariants — what _row_fingerprint_payload returns
# ---------------------------------------------------------------------------


@given(
    cci_id=st.one_of(st.none(), _CCI_ID),
    narrative=_OPT_TEXT,
    designation=_OPT_TEXT,
)
@settings(max_examples=80, deadline=None)
def test_row_payload_has_no_excluded_keys(cci_id, narrative, designation):
    """``_row_fingerprint_payload`` MUST NOT carry excel_row, raw, status,
    date_tested, tester, results, previous_date, previous_tester, required.

    These fields are either physical-position metadata or write-side
    columns the kernel produces — including them would either
    invalidate the cache on cosmetic changes (re-orderings) or create
    a circular dependency (writing the decision invalidates the cache
    for that decision).
    """
    row = _build_row(
        cci_id=cci_id, narrative=narrative, designation=designation
    )
    payload = _row_fingerprint_payload(row)
    excluded = {
        "excel_row",
        "raw",
        "status",
        "date_tested",
        "tester",
        "results",
        "previous_date",
        "previous_tester",
        "required",
    }
    leaked = excluded & set(payload.keys())
    assert leaked == set(), (
        f"excluded keys leaked into fingerprint payload: {leaked}"
    )


def test_row_payload_has_exactly_the_documented_inclusion_set():
    """``_row_fingerprint_payload`` carries EXACTLY the 13 included fields.

    Pins the contract as a set equality. A future field added to the
    row that should affect caching MUST be added to this list (and the
    parametrized inclusion test above) intentionally — silently growing
    or shrinking the payload would invalidate every prior cache entry.
    """
    row = _build_row()
    payload = _row_fingerprint_payload(row)
    expected = set(_INCLUDED_FIELDS_BY_NAME)
    assert set(payload.keys()) == expected


# ---------------------------------------------------------------------------
# CRM payload structure invariants
# ---------------------------------------------------------------------------


def test_crm_payload_no_context_yields_present_false():
    """``_crm_fingerprint_payload(row, None)`` → ``{"present": False}``."""
    row = _build_row()
    assert _crm_fingerprint_payload(row, None) == {"present": False}


def test_crm_payload_no_control_id_yields_present_false():
    """A row without a control_id → ``{"present": False}`` regardless of CRM.

    Defensive — a malformed CCIS row with no control_id can't look up
    a CRM entry anyway; we collapse to the no-CRM branch rather than
    crash on ``_normalize_control(None)``.
    """
    row = _build_row(control_id="")
    ctx = _build_crm_context("AC-2", "inherited", "narr")
    assert _crm_fingerprint_payload(row, ctx) == {"present": False}


@given(resp=_RESPONSIBILITY, narr=_OPT_TEXT)
@settings(max_examples=40, deadline=None)
def test_crm_payload_with_entry_carries_present_true_and_fields(resp, narr):
    """When CRM has an entry for the row's control → payload has the
    expected key set.

    Pins the shape so a refactor that dropped ``responsibility`` or
    ``narrative`` from the payload would fail loudly here rather than
    silently equalizing fingerprints across CRM corrections.
    """
    row = _build_row(control_id="AC-2")
    ctx = _build_crm_context("AC-2", resp, narr)
    payload = _crm_fingerprint_payload(row, ctx)
    assert payload["present"] is True
    assert payload["responsibility"] == resp
    # narrative falls through ``entry.narrative or ""`` — both None and ""
    # become "".
    assert payload["narrative"] == (narr or "")
    assert "control_id" in payload
    assert "source_baseline_id" in payload


# ---------------------------------------------------------------------------
# JSON encoding invariants — payload is sorted-keys + compact separators
# ---------------------------------------------------------------------------


def test_payload_envelope_has_stable_top_level_keys():
    """The envelope dict contains exactly: kernel_version, prompt_sha,
    kernel_config, validator_phrase_sha, row, evidence_sha, crm,
    audit_citations, boundary_sha.

    This is the contract that ``fingerprint`` will not drift to include
    or exclude top-level keys without a corresponding KERNEL_VERSION
    bump. ``kernel_config`` was added in v0.3 (audit item #4) so a flip
    of CONFIDENCE_THRESHOLD / DUAL_PASS_ENABLED auto-invalidates cached
    decisions without needing a manual KERNEL_VERSION bump. The
    ``audit_citations`` bool was added in Audit v1 so a flag-OFF cache
    hit can't silently satisfy a flag-ON re-run (which would replay a
    citation-free Decision and leave the audit trail empty). The
    ``boundary_sha`` was added in Boundary v1 (KERNEL_VERSION→0.9.0) so
    the same CCI + evidence + CRM tuple assessed under two different
    system boundaries doesn't replay one boundary's narrative for the
    other (cross-boundary evidence misattribution).

    Finding #12 — ``validator_phrase_sha`` was added so an edit to the
    validator's classification phrase tables (_AFFIRMING/_NA/_GAP)
    auto-invalidates cached decisions whose narrative classification
    depended on the old phrase set, without relying on a manual
    KERNEL_VERSION bump. Adding this key intentionally invalidates the
    entire pre-deploy cache once (expected for a correctness fix); the
    envelope reconstruction below is updated to match.

    Asserted by reconstructing the envelope locally and diffing the key
    set against ``fingerprint``'s expected behavior.
    """
    from cybersecurity_assessor.engine.assessor import kernel_config_signature
    from cybersecurity_assessor.engine.decision_cache import (
        VALIDATOR_PHRASE_SHA,
    )

    row = _build_row()
    fp = fingerprint(row=row, tagged_evidence=None, crm_context=None)
    # The fingerprint is opaque; we can only sanity-check the envelope
    # via fingerprint stability across a re-encode of an equivalent dict.
    # The actual envelope reconstruction is a regression-style check —
    # build a payload here matching the documented contract and assert
    # fingerprint(this) sha-256s back to fp.
    import hashlib

    envelope = {
        "kernel_version": KERNEL_VERSION,
        "prompt_sha": PROMPT_SHA,
        "kernel_config": kernel_config_signature(),
        "validator_phrase_sha": VALIDATOR_PHRASE_SHA,
        "row": _row_fingerprint_payload(row),
        "evidence_sha": "",
        "crm": {"present": False},
        "audit_citations": False,
        "boundary_sha": "",
    }
    encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    assert fp == expected, (
        "fingerprint envelope drifted from the documented contract "
        "(kernel_version, prompt_sha, kernel_config, validator_phrase_sha, "
        "row, evidence_sha, crm, audit_citations, boundary_sha)."
    )
