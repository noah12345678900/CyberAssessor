"""Property-based tests for the pure helpers inside the assessor orchestrator.

The big ``Assessor`` orchestrator is integration-shaped — its end-to-end
behavior is pinned by the 7+ regression files in
``backend/tests/engine/test_assessor_*.py`` (rule branches, no-evidence
short-circuit, dual-scope CRM, v0.2 gates, …). What those tests do NOT
cover is the *small pure helpers* that the orchestrator delegates to.
Each one is a self-contained string-or-flag transform with a real
invariant the regression tests only touch in passing.

Invariants pinned here:

* **``_boundary_conflict`` is a narrative-vs-status pure gate.** Returns
  ``None`` whenever the proposed status is ``NOT_APPLICABLE`` (the
  boundary phrase is consistent with NA — it's the whole point of NA).
  Returns ``None`` when narrative or status is absent. Returns a non-
  None triage string when the narrative contains a boundary phrase
  (``outside boundary`` / ``out of scope`` / ``not in scope`` /
  ``not within boundary``) AND the proposed status is Compliant or
  Non-Compliant. The output names the matched phrase verbatim and the
  conflicting status value — both required by the UI callout that
  surfaces the conflict to the reviewer.

* **``Assessor._render_hybrid_block`` always emits a well-formed block.**
  Output starts with the ``## responsibility_split`` header, names the
  control_id, and ends with the ``instructions:`` line. When the CRM
  carries a narrative for a scope, that narrative appears verbatim in
  the output; when it doesn't, the fallback "infer the customer half"
  text appears instead. Single-scope (cloud-only) entries use the
  legacy ``customer_narrative_from_crm:`` template that older prompt
  versions key on; dual-scope entries use the ``scope: dual`` template
  with per-scope sections. A future refactor that drops the legacy
  branch breaks every prompt template still referencing the
  un-suffixed field name.

* **``Assessor._initial_corrective_context`` only fires for 8c.**
  Returns ``None`` for COMPLIANT_8A / NOT_APPLICABLE_8B / NO_AUTO_RULE
  (those verdicts are already terminal — there's no LLM call to seed).
  Returns a non-empty string for UNCLEAR_8C, and that string MUST name
  the trigger column and trigger phrase verbatim so the LLM can locate
  the row text the rule fired on.

* **``Assessor._build_corrective_context`` preserves rejection order
  and pins the previous proposal.** The numbered rejection list must
  reflect the input order 1..N. The previous status and narrative MUST
  appear verbatim so the LLM sees exactly what it last proposed. The
  UNCLEAR_8C reminder appears iff the original verdict was UNCLEAR_8C
  — otherwise the reminder would mis-fire on a 8a / 8b / NO_AUTO row.

* **Determinism.** Every helper is a pure function: same input ->
  same output, always. A flaky output (random sampling, time-dependent
  branch, module-level state) would silently destabilize the audit
  trail.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")

from hypothesis import given  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

# Backend lives one level below the repo root and isn't a published
# package; the property tests pull it onto sys.path the same way the
# other tests/engine/*_properties.py suites do.
_BACKEND = Path(__file__).resolve().parents[2] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor.engine.assessor import (  # noqa: E402
    Assessor,
    _boundary_conflict,
)
from cybersecurity_assessor.engine.crm_context import CrmEntry  # noqa: E402
from cybersecurity_assessor.engine.rules import (  # noqa: E402
    AutoStatusResult,
    AutoStatusVerdict,
)
from cybersecurity_assessor.engine.validator import RejectionReason  # noqa: E402
from cybersecurity_assessor.excel.ccis_reader import CcisRow  # noqa: E402
from cybersecurity_assessor.models import ComplianceStatus  # noqa: E402


# ---------------------------------------------------------------------------
# Strategy helpers
# ---------------------------------------------------------------------------

# The four boundary phrases the regex literally matches. Used both to
# build "definitely-firing" narratives and to assert the matched phrase
# is echoed in the output triage message.
_BOUNDARY_PHRASES = (
    "outside boundary",
    "outside the boundary",
    "out of scope",
    "not in scope",
    "not within boundary",
    "not within the boundary",
)

# The five canonical CRM responsibility values, plus None for "scope
# unspecified". The on-prem / cloud columns are independent — we sample
# them with a small product to keep the example space tight.
_RESPONSIBILITIES = (
    "customer",
    "provider",
    "hybrid",
    "inherited",
    "not_applicable",
    None,
)

# Statuses the boundary conflict gate has opinions about. NA is the
# "no conflict" path; the others are the "fire" path.
_NON_NA_STATUSES = (
    ComplianceStatus.COMPLIANT,
    ComplianceStatus.NON_COMPLIANT,
)


def _make_entry(
    *,
    control_id: str = "ac-2",
    responsibility: str | None = "hybrid",
    narrative: str | None = None,
    responsibility_onprem: str | None = None,
    narrative_onprem: str | None = None,
) -> CrmEntry:
    return CrmEntry(
        control_id=control_id,
        responsibility=responsibility,
        narrative=narrative,
        source_baseline_id=1,
        responsibility_onprem=responsibility_onprem,
        narrative_onprem=narrative_onprem,
    )


def _make_row(**overrides) -> CcisRow:
    """CcisRow with neutral text. Mirrors test_rules_properties._row."""
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
        guidance="Examine account management documentation.",
        procedures="Examine the system.",
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


def _auto(verdict: AutoStatusVerdict, **overrides) -> AutoStatusResult:
    defaults = dict(
        verdict=verdict,
        status=None,
        narrative=None,
        rule=None,
        trigger_phrase=None,
        trigger_column=None,
        reason=None,
    )
    defaults.update(overrides)
    return AutoStatusResult(**defaults)


# ---------------------------------------------------------------------------
# _boundary_conflict
# ---------------------------------------------------------------------------


@given(
    narrative=st.one_of(
        st.none(),
        st.text(max_size=400),
        st.sampled_from(_BOUNDARY_PHRASES),
    ),
)
def test_boundary_conflict_returns_none_for_na_status(narrative: str | None) -> None:
    """NA + any narrative (even one that names the boundary explicitly)
    is consistent — that's exactly what NA means. The gate exists to
    catch the LLM hedging "this is outside our boundary" while ALSO
    proposing Compliant / Non-Compliant; on NA there's no conflict to
    surface."""
    assert _boundary_conflict(narrative, ComplianceStatus.NOT_APPLICABLE) is None


@given(narrative=st.one_of(st.none(), st.text(max_size=400)))
def test_boundary_conflict_returns_none_when_status_missing(
    narrative: str | None,
) -> None:
    """No proposed status -> nothing to conflict against. The
    orchestrator calls the gate during the LLM-accept path, so a None
    status here represents a parse-error code path; surfacing a
    boundary triage message would just add noise to a row that already
    failed for a different reason."""
    assert _boundary_conflict(narrative, None) is None


@given(
    status=st.sampled_from(_NON_NA_STATUSES),
    narrative=st.one_of(st.none(), st.just(""), st.just("   ")),
)
def test_boundary_conflict_returns_none_when_narrative_empty(
    status: ComplianceStatus, narrative: str | None
) -> None:
    """No narrative text -> no regex match possible. Whitespace-only
    narratives are treated as empty by the same falsiness check."""
    # The implementation tests ``not narrative`` (whitespace strings
    # that aren't empty would still pass through to the regex, but the
    # regex won't match) — assert both paths return None.
    result = _boundary_conflict(narrative, status)
    assert result is None


@given(
    status=st.sampled_from(_NON_NA_STATUSES),
    phrase=st.sampled_from(_BOUNDARY_PHRASES),
    prefix=st.text(max_size=80),
    suffix=st.text(max_size=80),
)
def test_boundary_conflict_fires_on_phrase_with_non_na_status(
    status: ComplianceStatus, phrase: str, prefix: str, suffix: str,
) -> None:
    """When the narrative contains any boundary phrase and the proposed
    status is Compliant or Non-Compliant, the gate MUST return a
    triage string. The output must name BOTH the matched phrase (so
    the reviewer can find it in the narrative) and the conflicting
    status value (so the reviewer sees the contradiction without
    re-deriving it)."""
    narrative = f"{prefix} {phrase} {suffix}".strip()
    result = _boundary_conflict(narrative, status)
    assert result is not None
    # Regex is case-insensitive; the matched phrase is echoed exactly
    # as it appeared in the source string.
    assert phrase.lower() in result.lower()
    assert status.value in result


@given(
    status=st.sampled_from(_NON_NA_STATUSES),
    # Text with no boundary keywords. Hypothesis text() can synthesize
    # "out of scope" by accident; we filter explicitly to keep this
    # property unambiguous.
    narrative=st.text(max_size=200).filter(
        lambda s: not any(p in s.lower() for p in (
            "outside boundary", "outside the boundary", "out of scope",
            "not in scope", "not within boundary", "not within the boundary",
        ))
    ),
)
def test_boundary_conflict_returns_none_without_phrase(
    status: ComplianceStatus, narrative: str
) -> None:
    """A non-NA status with a narrative that DOESN'T contain any
    boundary phrase must NOT trip the gate. The regex is the entire
    decision boundary; if it doesn't match, there's no conflict."""
    assert _boundary_conflict(narrative, status) is None


@given(
    status=st.sampled_from(list(ComplianceStatus)),
    narrative=st.one_of(st.none(), st.text(max_size=200)),
)
def test_boundary_conflict_is_deterministic(
    status: ComplianceStatus, narrative: str | None
) -> None:
    """Pure function: same input -> same output, always. Catches a
    future refactor that introduces module-level state (e.g. an LRU
    cache keyed on something that drifts, or a random tiebreak)."""
    r1 = _boundary_conflict(narrative, status)
    r2 = _boundary_conflict(narrative, status)
    assert r1 == r2


# ---------------------------------------------------------------------------
# Assessor._render_hybrid_block
# ---------------------------------------------------------------------------


@given(
    control_id=st.sampled_from(["ac-2", "ac-2.1", "au-12", "cm-6", "sc-7"]),
    cloud_r=st.sampled_from(["customer", "hybrid", "provider", "inherited"]),
    cloud_narr=st.one_of(st.none(), st.text(min_size=1, max_size=200)),
)
def test_hybrid_block_single_scope_uses_legacy_template(
    control_id: str, cloud_r: str, cloud_narr: str | None,
) -> None:
    """When only the cloud-scope responsibility is set (legacy single-
    column CRM), the renderer MUST emit the original
    ``customer_narrative_from_crm:`` field. Prompt templates that
    haven't been updated for dual-scope key on this exact field name
    — silently switching them to ``customer_narrative_from_crm_cloud:``
    would make the prompt skip the customer-narrative block entirely.
    """
    entry = _make_entry(
        control_id=control_id,
        responsibility=cloud_r,
        narrative=cloud_narr,
        responsibility_onprem=None,
        narrative_onprem=None,
    )
    block = Assessor()._render_hybrid_block(entry)
    assert block.startswith("## responsibility_split\n")
    assert f"control: {control_id}" in block
    # Legacy field name is the load-bearing prompt-template hook.
    assert "customer_narrative_from_crm:" in block
    # Dual template is NOT used for single-scope.
    assert "scope: dual" not in block
    # Cloud responsibility appears in the legacy ``responsibility:`` line.
    assert f"responsibility: {cloud_r}" in block
    assert "instructions:" in block


@given(
    control_id=st.sampled_from(["ac-2", "ac-2.1", "au-12", "cm-6", "sc-7"]),
    cloud_r=st.sampled_from(["customer", "hybrid", "provider", "inherited"]),
    onprem_r=st.sampled_from(["customer", "hybrid", "provider", "inherited"]),
    cloud_narr=st.one_of(st.none(), st.text(min_size=1, max_size=200)),
    onprem_narr=st.one_of(st.none(), st.text(min_size=1, max_size=200)),
)
def test_hybrid_block_dual_scope_uses_dual_template(
    control_id: str,
    cloud_r: str,
    onprem_r: str,
    cloud_narr: str | None,
    onprem_narr: str | None,
) -> None:
    """When both cloud and on-prem responsibilities are set, the
    renderer MUST emit the dual-scope template with the
    ``scope: dual`` marker line and per-scope responsibility fields
    (``cloud_responsibility:`` / ``on_prem_responsibility:``). The
    prompt's narrative_cloud / narrative_on_prem output fields key
    on these to keep the two scopes' findings separate."""
    entry = _make_entry(
        control_id=control_id,
        responsibility=cloud_r,
        narrative=cloud_narr,
        responsibility_onprem=onprem_r,
        narrative_onprem=onprem_narr,
    )
    block = Assessor()._render_hybrid_block(entry)
    assert block.startswith("## responsibility_split\n")
    assert f"control: {control_id}" in block
    assert "scope: dual" in block
    assert f"cloud_responsibility: {cloud_r}" in block
    assert f"on_prem_responsibility: {onprem_r}" in block
    # Dual template MUST NOT emit the legacy un-suffixed field — it
    # would shadow the per-scope fields in older prompt templates.
    assert "customer_narrative_from_crm:" not in block
    assert "instructions:" in block


@given(
    cloud_narr=st.text(min_size=3, max_size=200),
    onprem_narr=st.text(min_size=3, max_size=200),
)
def test_hybrid_block_includes_provided_narratives_verbatim(
    cloud_narr: str, onprem_narr: str,
) -> None:
    """When the CRM supplies a customer-side narrative for either
    scope, the renderer MUST embed it verbatim. The whole point of the
    block is to hand the LLM the customer's own words about what they
    own — paraphrasing or truncating would change the assessment."""
    entry = _make_entry(
        responsibility="hybrid",
        narrative=cloud_narr,
        responsibility_onprem="customer",
        narrative_onprem=onprem_narr,
    )
    block = Assessor()._render_hybrid_block(entry)
    assert cloud_narr in block
    assert onprem_narr in block


@given(
    cloud_r=st.sampled_from(["customer", "hybrid"]),
    onprem_r=st.sampled_from(["customer", "hybrid"]),
)
def test_hybrid_block_falls_back_to_default_text_when_narratives_missing(
    cloud_r: str, onprem_r: str,
) -> None:
    """When the CRM didn't supply a narrative for a specified scope,
    the renderer MUST emit the "No customer-side narrative supplied"
    fallback text so the prompt template can still render — without
    it the field would be blank and the LLM would have no instructions
    for that half."""
    entry = _make_entry(
        responsibility=cloud_r,
        narrative=None,
        responsibility_onprem=onprem_r,
        narrative_onprem=None,
    )
    block = Assessor()._render_hybrid_block(entry)
    # The fallback wording appears at least once per missing-narrative
    # scope. Don't pin the exact count — leave room for the template to
    # evolve — but at minimum the marker phrase must appear.
    assert "No customer-side narrative supplied" in block


@given(
    cloud_r=st.sampled_from(_RESPONSIBILITIES),
    onprem_r=st.sampled_from(_RESPONSIBILITIES),
    cloud_narr=st.one_of(st.none(), st.text(max_size=120)),
    onprem_narr=st.one_of(st.none(), st.text(max_size=120)),
)
def test_hybrid_block_is_deterministic(
    cloud_r: str | None,
    onprem_r: str | None,
    cloud_narr: str | None,
    onprem_narr: str | None,
) -> None:
    """Same entry -> same block, always. The renderer is the
    prompt-fragment building function — a flaky output would surface
    to the LLM and confuse caching."""
    entry = _make_entry(
        responsibility=cloud_r,
        narrative=cloud_narr,
        responsibility_onprem=onprem_r,
        narrative_onprem=onprem_narr,
    )
    a = Assessor()
    assert a._render_hybrid_block(entry) == a._render_hybrid_block(entry)


# ---------------------------------------------------------------------------
# Assessor._initial_corrective_context
# ---------------------------------------------------------------------------


@given(
    verdict=st.sampled_from(
        [
            AutoStatusVerdict.COMPLIANT_8A,
            AutoStatusVerdict.NOT_APPLICABLE_8B,
            AutoStatusVerdict.NO_AUTO_RULE,
        ]
    ),
)
def test_initial_corrective_context_none_for_non_8c_verdicts(
    verdict: AutoStatusVerdict,
) -> None:
    """8a / 8b are deterministic verdicts the orchestrator short-
    circuits on — the LLM is never called, so seeding corrective
    context would be dead code. NO_AUTO_RULE means no rule fired, so
    the LLM gets a fresh prompt; no rule-hint to pin."""
    auto = _auto(verdict, trigger_phrase="some phrase", trigger_column="K")
    assert Assessor()._initial_corrective_context(auto) is None


@given(
    trigger_column=st.sampled_from(["J", "K", "L"]),
    trigger_phrase=st.text(min_size=1, max_size=80),
)
def test_initial_corrective_context_fires_for_8c_with_phrase_and_column(
    trigger_column: str, trigger_phrase: str,
) -> None:
    """For UNCLEAR_8C, the LLM gets a corrective-context hint that
    MUST name the column (so the LLM looks at the right cell) and the
    triggering phrase (so the LLM sees the ambiguous text verbatim)."""
    auto = _auto(
        AutoStatusVerdict.UNCLEAR_8C,
        trigger_phrase=trigger_phrase,
        trigger_column=trigger_column,
        rule="8c",
    )
    result = Assessor()._initial_corrective_context(auto)
    assert result is not None
    assert f"col {trigger_column}" in result
    assert trigger_phrase in result


@given(
    verdict=st.sampled_from(list(AutoStatusVerdict)),
    trigger_phrase=st.one_of(st.none(), st.text(max_size=40)),
    trigger_column=st.one_of(st.none(), st.sampled_from(["J", "K", "L"])),
)
def test_initial_corrective_context_is_deterministic(
    verdict: AutoStatusVerdict,
    trigger_phrase: str | None,
    trigger_column: str | None,
) -> None:
    """Same auto-result -> same hint string, always."""
    auto = _auto(
        verdict,
        trigger_phrase=trigger_phrase,
        trigger_column=trigger_column,
    )
    a = Assessor()
    assert a._initial_corrective_context(auto) == a._initial_corrective_context(auto)


# ---------------------------------------------------------------------------
# Assessor._build_corrective_context
# ---------------------------------------------------------------------------


@st.composite
def _rejection_list(draw) -> list[tuple[RejectionReason, str]]:
    """Strategy: a list of (RejectionReason, message) pairs.

    Always at least one rejection — the orchestrator only calls
    ``_build_corrective_context`` when at least one rejection actually
    fired, so the empty-list case is unreachable in practice.
    """
    n = draw(st.integers(min_value=1, max_value=5))
    out: list[tuple[RejectionReason, str]] = []
    for _ in range(n):
        reason = draw(st.sampled_from(list(RejectionReason)))
        # Keep messages short to bound the example size; the contract
        # under test doesn't care about message length.
        msg = draw(st.text(min_size=1, max_size=60))
        out.append((reason, msg))
    return out


@given(
    rejections=_rejection_list(),
    last_status=st.sampled_from(list(ComplianceStatus)),
    last_narrative=st.text(min_size=1, max_size=120),
)
def test_build_corrective_context_pins_previous_proposal(
    rejections: list[tuple[RejectionReason, str]],
    last_status: ComplianceStatus,
    last_narrative: str,
) -> None:
    """The previous proposal MUST appear verbatim (both status and
    narrative). The whole point of the corrective context is to show
    the LLM exactly what it last tried; paraphrasing would let the
    LLM "fix" something different from what was actually rejected."""
    result = Assessor()._build_corrective_context(
        row=_make_row(),
        auto=_auto(AutoStatusVerdict.NO_AUTO_RULE),
        rejections=rejections,
        last_status=last_status,
        last_narrative=last_narrative,
    )
    assert "rejected by the deterministic validator" in result
    assert last_status.value in result
    assert last_narrative in result


@given(rejections=_rejection_list())
def test_build_corrective_context_preserves_rejection_order(
    rejections: list[tuple[RejectionReason, str]],
) -> None:
    """The numbered list MUST reflect input order. The LLM uses the
    numbering to address each issue in turn; if we reorder, the
    "address issue #2" instruction targets the wrong rejection."""
    result = Assessor()._build_corrective_context(
        row=_make_row(),
        auto=_auto(AutoStatusVerdict.NO_AUTO_RULE),
        rejections=rejections,
        last_status=ComplianceStatus.NON_COMPLIANT,
        last_narrative="placeholder narrative",
    )
    # Find the positions where each numbered rejection appears. They
    # must be monotonically increasing.
    last_pos = -1
    for i, (reason, msg) in enumerate(rejections, start=1):
        marker = f"{i}. [{reason.value}]"
        pos = result.find(marker)
        assert pos != -1, f"missing rejection marker {marker!r} in:\n{result}"
        assert pos > last_pos, (
            f"rejection {i} appeared before rejection {i - 1} in output"
        )
        last_pos = pos
        # Message text appears alongside the marker.
        assert msg in result


@given(
    verdict=st.sampled_from(
        [
            AutoStatusVerdict.COMPLIANT_8A,
            AutoStatusVerdict.NOT_APPLICABLE_8B,
            AutoStatusVerdict.NO_AUTO_RULE,
        ]
    ),
    rejections=_rejection_list(),
)
def test_build_corrective_context_no_8c_reminder_for_non_8c(
    verdict: AutoStatusVerdict,
    rejections: list[tuple[RejectionReason, str]],
) -> None:
    """The 8c reminder line MUST NOT appear when the original verdict
    wasn't UNCLEAR_8C — the reminder would be a lie (no 8c rule fired)
    and would push the LLM to escalate Non-Compliant on rows where it
    shouldn't."""
    result = Assessor()._build_corrective_context(
        row=_make_row(),
        auto=_auto(verdict),
        rejections=rejections,
        last_status=ComplianceStatus.COMPLIANT,
        last_narrative="placeholder",
    )
    assert "rule #8c is still in effect" not in result


@given(rejections=_rejection_list())
def test_build_corrective_context_includes_8c_reminder_for_8c(
    rejections: list[tuple[RejectionReason, str]],
) -> None:
    """For UNCLEAR_8C the reminder MUST appear so the LLM doesn't
    revert to a 8c-failing proposal on the retry round."""
    result = Assessor()._build_corrective_context(
        row=_make_row(),
        auto=_auto(AutoStatusVerdict.UNCLEAR_8C),
        rejections=rejections,
        last_status=ComplianceStatus.NON_COMPLIANT,
        last_narrative="placeholder",
    )
    assert "rule #8c is still in effect" in result


@given(
    verdict=st.sampled_from(list(AutoStatusVerdict)),
    rejections=_rejection_list(),
    last_status=st.sampled_from(list(ComplianceStatus)),
    last_narrative=st.text(min_size=1, max_size=80),
)
def test_build_corrective_context_is_deterministic(
    verdict: AutoStatusVerdict,
    rejections: list[tuple[RejectionReason, str]],
    last_status: ComplianceStatus,
    last_narrative: str,
) -> None:
    """Same inputs -> same string, always. The corrective context is
    part of the prompt; flakiness would defeat prompt caching."""
    a = Assessor()
    args = dict(
        row=_make_row(),
        auto=_auto(verdict),
        rejections=rejections,
        last_status=last_status,
        last_narrative=last_narrative,
    )
    assert a._build_corrective_context(**args) == a._build_corrective_context(**args)
