"""Property-based tests for the rules engine (SKILL.md Rule #8).

These tests fill the gaps left by ``test_properties.py``, which already
covers the rule-8a/8b/8c routing happy-paths and 8b-over-8a precedence.

Invariants pinned here:

* **Determinism.** ``classify_row`` is a pure function — same row in,
  same result out, always. Hashed by repeated calls, not by observation
  of internal state. If a future refactor introduces module-level state
  (cache, random sampling), this test fires.

* **Trigger-column honesty.** When the result reports
  ``trigger_column='K'``, the trigger phrase MUST actually appear in
  ``row.procedures`` (col K), not in col J or col L. The downstream
  audit log relies on this to point reviewers at the cell that fired.

* **Col K wins over col J.** The rules engine iterates
  ``(("K", procedures), ("J", guidance))`` in that order, so when the
  same trigger sits in both columns, col K must be reported. A refactor
  that reorders the tuple silently relocates audit pointers.

* **Structural 8a (col L).** When col L names an internal source (not
  "Local", not a CSP hint), the row routes to ``COMPLIANT_8A`` with
  ``trigger_column='L'`` — provided no K/J trigger fired first.

* **"Local" never auto-anythings.** Col L = "Local" (case-insensitive)
  MUST NOT fire structural 8a — "Local" is the assertion that the org
  owns the implementation, which is the opposite of inheritance.

* **8b in K/J beats structural 8a in L.** Even if col L names a clean
  internal source, an 8b trigger in K or J must still route the row to
  NOT_APPLICABLE_8B. The 8b-first ordering protects against the
  historical LLM failure of writing Compliant against a CSP-implemented
  row.

* **Empty/None row text never raises.** Any combination of None and
  empty strings across guidance/procedures/inherited must produce a
  clean ``NO_AUTO_RULE`` result, never an exception.
"""

from __future__ import annotations

import pytest

hypothesis = pytest.importorskip("hypothesis")

from hypothesis import assume, given  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from cybersecurity_assessor.engine.rules import (  # noqa: E402
    _COL_L_EXTERNAL_HINTS,
    _R8A_INHERITANCE_INTERNAL,
    _R8A_TRIGGERS,
    _R8B_NA_SCOPE_PHRASES,
    AutoStatusVerdict,
    classify_row,
)
from cybersecurity_assessor.excel.ccis_reader import CcisRow  # noqa: E402
from cybersecurity_assessor.models import ComplianceStatus  # noqa: E402


# ---------------------------------------------------------------------------
# Row builder — matches test_properties.py so test surface is consistent
# ---------------------------------------------------------------------------

_NEUTRAL_GUIDANCE = (
    "Automated mechanisms support the management of information system accounts."
)
_NEUTRAL_PROCEDURES = "Examine account management documentation; verify automation."


def _row(**overrides) -> CcisRow:
    defaults = dict(
        excel_row=42,
        required=True,
        control_id="AC-2(1)",
        ap_acronym="AC-2.1",
        cci_id="CCI-000015",
        implementation_status="Implemented",
        designation="Hybrid",
        narrative=None,
        definition="The organization employs automated mechanisms.",
        guidance=_NEUTRAL_GUIDANCE,
        procedures=_NEUTRAL_PROCEDURES,
        inherited="Local",
        remote_inheritance=None,
        status=None,
        date_tested=None,
        tester=None,
        results=None,
        previous_status=None,
        previous_date=None,
        previous_tester=None,
        previous_results=None,
    )
    defaults.update(overrides)
    return CcisRow(**defaults)


# ---------------------------------------------------------------------------
# Determinism — classify_row is a pure function
# ---------------------------------------------------------------------------


@given(
    procedures=st.text(max_size=400),
    guidance=st.text(max_size=400),
    inherited=st.text(max_size=80),
)
def test_classify_row_is_deterministic(
    procedures: str, guidance: str, inherited: str
) -> None:
    """Same row in → same result out, always.

    The rules engine is the deterministic short-circuit layer. A
    flaky verdict (caching gone wrong, random sampling, time-dependent
    branch) would silently corrupt the audit trail — two reviewers
    looking at the same row could see different verdicts.
    """
    row = _row(procedures=procedures, guidance=guidance, inherited=inherited)
    r1 = classify_row(row)
    r2 = classify_row(row)
    assert r1.verdict is r2.verdict
    assert r1.status is r2.status
    assert r1.narrative == r2.narrative
    assert r1.rule == r2.rule
    assert r1.trigger_phrase == r2.trigger_phrase
    assert r1.trigger_column == r2.trigger_column


# ---------------------------------------------------------------------------
# Trigger-column honesty
# ---------------------------------------------------------------------------


@given(
    procedures=st.text(max_size=300),
    guidance=st.text(max_size=300),
    inherited=st.text(max_size=80),
)
def test_trigger_column_actually_contains_trigger_phrase(
    procedures: str, guidance: str, inherited: str
) -> None:
    """When the result names a trigger column, the phrase MUST live there.

    The audit pipeline highlights the named cell to the reviewer. If a
    refactor swaps col K/J/L assignments, reviewers get pointed at the
    wrong cell — a silent regression with no test coverage today.
    """
    row = _row(procedures=procedures, guidance=guidance, inherited=inherited)
    result = classify_row(row)
    if result.trigger_phrase is None:
        # NO_AUTO_RULE — nothing to check.
        return
    phrase = result.trigger_phrase.lower()
    cell_map = {
        "J": (row.guidance or "").lower(),
        "K": (row.procedures or "").lower(),
        "L": (row.inherited or "").lower(),
    }
    cell_text = cell_map.get(result.trigger_column or "", "")
    assert phrase in cell_text, (
        f"trigger_phrase {result.trigger_phrase!r} reported in col "
        f"{result.trigger_column!r} but not found there. "
        f"verdict={result.verdict!r} cell={cell_text!r}"
    )


# ---------------------------------------------------------------------------
# Col K wins over col J when both contain the same trigger
# ---------------------------------------------------------------------------


@given(
    r8a=st.sampled_from(_R8A_TRIGGERS),
    noise_k=st.text(max_size=100),
    noise_j=st.text(max_size=100),
)
def test_col_k_precedence_over_col_j_for_same_trigger(
    r8a: str, noise_k: str, noise_j: str
) -> None:
    """Same 8a trigger in both K and J → result reports col K.

    The rules engine iterates ``(("K", procedures), ("J", guidance))``;
    a refactor that swaps the order would silently break the convention
    that col K is the more authoritative source.

    Filter cases where the noise injects an earlier-in-tuple 8a
    trigger. (NA scope phrases are inert in K/J under v0.11.0 — they
    only fire from col Q/U — so no 8b filter is needed.)
    """
    procedures = f"{noise_k} {r8a} {noise_k}"
    guidance = f"{noise_j} {r8a} {noise_j}"
    proc_lower = procedures.lower()
    # Skip if noise in K injects an 8a trigger that appears earlier in
    # the _R8A_TRIGGERS tuple than our injected one — the engine would
    # pick that as the trigger_phrase and the column would still be K
    # (so the invariant holds), but the assertion below on phrase
    # equality would fail.
    earlier_triggers = _R8A_TRIGGERS[: _R8A_TRIGGERS.index(r8a)]
    if any(t in proc_lower for t in earlier_triggers):
        return
    row = _row(procedures=procedures, guidance=guidance, inherited="Local")
    result = classify_row(row)
    assert result.verdict is AutoStatusVerdict.COMPLIANT_8A
    assert result.trigger_column == "K"
    assert result.trigger_phrase == r8a


# ---------------------------------------------------------------------------
# Structural 8a (col L)
# ---------------------------------------------------------------------------


@given(
    col_l_source=st.sampled_from(
        ["DoW Enterprise", "Parent System", "DoD-level", "SDA Common Services"]
    ),
)
def test_col_l_names_internal_source_routes_to_8a_structural(
    col_l_source: str,
) -> None:
    """Col L with a non-Local, non-CSP value fires structural 8a.

    Guards the rules.py:188-199 branch. Uses neutral guidance/procedures
    so no K/J trigger fires first (which would override the L verdict).
    """
    row = _row(
        guidance=_NEUTRAL_GUIDANCE,
        procedures=_NEUTRAL_PROCEDURES,
        inherited=col_l_source,
    )
    result = classify_row(row)
    assert result.verdict is AutoStatusVerdict.COMPLIANT_8A
    assert result.status is ComplianceStatus.COMPLIANT
    assert result.rule == "8a"
    assert result.trigger_column == "L"
    assert result.trigger_phrase == col_l_source


@given(local_variant=st.sampled_from(["Local", "local", "LOCAL", " Local ", "Local "]))
def test_col_l_local_never_fires_structural_8a(local_variant: str) -> None:
    """Col L = "Local" (any case, any whitespace) MUST NOT fire structural 8a.

    "Local" is the assertion that the org owns the implementation —
    the opposite of inheritance. A regression here would falsely mark
    every locally-implemented control as auto-Compliant.
    """
    row = _row(
        guidance=_NEUTRAL_GUIDANCE,
        procedures=_NEUTRAL_PROCEDURES,
        inherited=local_variant,
    )
    result = classify_row(row)
    assert result.verdict is AutoStatusVerdict.NO_AUTO_RULE


@given(csp_hint=st.sampled_from(_COL_L_EXTERNAL_HINTS))
def test_col_l_with_csp_hint_does_not_fire_8a(csp_hint: str) -> None:
    """Col L containing a CSP hint MUST NOT fire structural 8a.

    The structural-8a branch checks ``_value_names_external_csp`` and
    falls through if matched. Without that guard, a row claiming
    inheritance from AWS/Azure/GCP would silently become auto-Compliant
    instead of routing to the LLM (or 8b if K/J have a trigger).
    """
    row = _row(
        guidance=_NEUTRAL_GUIDANCE,
        procedures=_NEUTRAL_PROCEDURES,
        inherited=f"Inherited from {csp_hint}",
    )
    result = classify_row(row)
    # Either NO_AUTO_RULE (no K/J/L trigger) or UNCLEAR_8C (if the
    # phrase "inherited from" trips the bare-inheritance branch in K/J).
    # In neither case may it be COMPLIANT_8A.
    assert result.verdict is not AutoStatusVerdict.COMPLIANT_8A


# ---------------------------------------------------------------------------
# Col L as a yes/no FLAG (eMASS "Inherited?" convention) — must NOT be read
# as a source name. Regression for the bug where col L = "No" (control needs
# testing) silently fired structural 8a → Compliant.
# ---------------------------------------------------------------------------


@given(
    not_inherited=st.sampled_from(
        ["No", "no", "NO", " No ", "N", "False", "Not Inherited", "None", "N/A", "NA"]
    ),
)
def test_col_l_no_flag_does_not_fire_8a(not_inherited: str) -> None:
    """Col L = "No" (and not-inherited synonyms) means the control is NOT
    inherited and needs a normal assessment — it must never be treated as an
    inheritance source named "No" and auto-Compliant'd.
    """
    row = _row(
        guidance=_NEUTRAL_GUIDANCE,
        procedures=_NEUTRAL_PROCEDURES,
        inherited=not_inherited,
    )
    result = classify_row(row)
    assert result.verdict is AutoStatusVerdict.NO_AUTO_RULE
    assert result.status is None


@given(
    yes_flag=st.sampled_from(["Yes", "yes", "YES", " Yes ", "Y", "True", "Inherited"]),
)
def test_col_l_yes_flag_without_source_is_unclear_8c(yes_flag: str) -> None:
    """Col L = "Yes" says the control IS inherited but names no source, so we
    can't tell internal (8a→Compliant) from external CSP (8b→NA). It must
    escalate (UNCLEAR_8C), never auto-Compliant on a bare "Yes".
    """
    row = _row(
        guidance=_NEUTRAL_GUIDANCE,
        procedures=_NEUTRAL_PROCEDURES,
        inherited=yes_flag,
    )
    result = classify_row(row)
    assert result.verdict is AutoStatusVerdict.UNCLEAR_8C
    assert result.status is None


# ---------------------------------------------------------------------------
# 8b in col Q/U beats structural 8a in L
# ---------------------------------------------------------------------------


@given(
    r8b=st.sampled_from(_R8B_NA_SCOPE_PHRASES),
    col_l_source=st.sampled_from(
        ["DoW Enterprise", "Parent System", "DoD-level"]
    ),
)
def test_8b_in_qu_beats_structural_8a_in_l(r8b: str, col_l_source: str) -> None:
    """NA scope-exclusion in col Q beats a clean internal-source col L.

    v0.11.0 step order: the Q/U scope-exclusion recognizer (step 3a) runs
    before the structural col-L branch (step 4). So a documented "not
    applicable" in the human-authored rationale must flip the row to NA
    even when col L names a clean internal inheritance source that would
    otherwise fire structural 8a. This protects against the failure mode
    where an inherited-from-parent col L silently overrides a reviewer's
    explicit scope-out.
    """
    row = _row(
        guidance=_NEUTRAL_GUIDANCE,
        procedures=_NEUTRAL_PROCEDURES,
        results=f"{r8b}",
        inherited=col_l_source,
    )
    result = classify_row(row)
    assert result.verdict is AutoStatusVerdict.NOT_APPLICABLE_8B
    assert result.rule == "8b"
    assert result.status is ComplianceStatus.NOT_APPLICABLE
    assert result.trigger_column == "Q"


# ---------------------------------------------------------------------------
# Empty/None-tolerance
# ---------------------------------------------------------------------------


@given(
    procedures=st.one_of(st.none(), st.just("")),
    guidance=st.one_of(st.none(), st.just("")),
    inherited=st.one_of(st.none(), st.just(""), st.just("Local")),
)
def test_empty_or_none_text_routes_to_no_auto_rule(
    procedures, guidance, inherited
) -> None:
    """A row with empty/None text fields produces NO_AUTO_RULE — no crash."""
    row = _row(procedures=procedures, guidance=guidance, inherited=inherited)
    result = classify_row(row)
    assert result.verdict is AutoStatusVerdict.NO_AUTO_RULE
    assert result.status is None
    assert result.rule is None
    assert result.narrative is None
    assert result.trigger_phrase is None
    assert result.trigger_column is None


# ---------------------------------------------------------------------------
# Internal-inheritance qualifier phrases route to 8a (not 8c)
# ---------------------------------------------------------------------------


@given(
    qualifier=st.sampled_from(_R8A_INHERITANCE_INTERNAL),
    prefix=st.text(max_size=100),
    suffix=st.text(max_size=100),
)
def test_internal_inheritance_qualifier_routes_to_8a(
    qualifier: str, prefix: str, suffix: str
) -> None:
    """Qualified "inherited from <internal>" phrases route to 8a, not 8c.

    The qualifier list captures the patterns ("inherited from DOD",
    "inherited from the enterprise", …) that disambiguate the bare
    "inherited from" — a regression that promotes these to UNCLEAR_8C
    would burn LLM calls on rows the rules engine should have handled.
    """
    procedures = f"{prefix} {qualifier} {suffix}"
    proc_lower = procedures.lower()
    # NA scope phrases are inert in K/J under v0.11.0 (they only fire from
    # col Q/U), so no 8b skip is needed here — the noise lives in col K.
    # Skip only if noise injects an explicit 8a trigger that fires earlier
    # in the tuple than the inheritance branch (8a explicit runs before
    # 8a inheritance — see rules.py:162-186).
    if any(t in proc_lower for t in _R8A_TRIGGERS):
        return
    row = _row(procedures=procedures, guidance=_NEUTRAL_GUIDANCE, inherited="Local")
    result = classify_row(row)
    assert result.verdict is AutoStatusVerdict.COMPLIANT_8A
    assert result.rule == "8a"
    assert result.status is ComplianceStatus.COMPLIANT
