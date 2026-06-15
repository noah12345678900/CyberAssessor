"""Golden tests for the deterministic rule #8 classifier.

Rule #8 (``engine/rules.classify_row``) is one of the four patent-supporting
guards. It short-circuits the LLM whenever cols K / J / L / Q / U
unambiguously dictate the verdict, preventing the model from making the
8a-vs-8b call itself (a path where it has historically gotten it wrong by
defaulting to one side).

Doctrine pinned here:
    * Inherited / CSP-provided controls are **Compliant**, never NA — the
      control IS satisfied, just not by us directly.
    * NA is reserved for an **explicit documented scope exclusion** in the
      assessor's own rationale (col Q results / col U previous_results),
      NOT the generic DISA template boilerplate in K/J.
    * Col K is authoritative: a DoD-auto "automatically compliant" in K
      claims the row Compliant before any NA recognizer can see it.

Each test below pins a specific path through the check order documented
in ``classify_row``:

    1. Rule 8a explicit phrases (cols K, then J) — Compliant (runs first).
    2. Rule 8a qualified ``inherited from <internal>`` (cols K, then J).
    3a. Col Q/U explicit scope-exclusion (COMPLIANCE_GUARD-gated) → NA.
    3b. Col Q/U CSP / external-inheritance → Compliant.
    4. Rule 8a structural — col L non-empty, not "Local", not naming a CSP.
    5. Rule 8c — bare ``inherited from`` with no qualifier → UNCLEAR.
    6. NO_AUTO_RULE — row goes to normal LLM-driven assessment.

These are pure-function tests over hand-built ``CcisRow`` instances — no
DB, no LLM, no I/O. If any of these regress, the kernel's accuracy claim
regresses with them.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the backend package is importable when pytest is launched from any cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor.engine.rules import (  # noqa: E402
    AutoStatusVerdict,
    _infer_external_provider,
    classify_row,
)
from cybersecurity_assessor.excel.ccis_reader import CcisRow  # noqa: E402
from cybersecurity_assessor.models import ComplianceStatus  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row(
    *,
    guidance: str | None = None,
    procedures: str | None = None,
    inherited: str | None = None,
    narrative: str | None = None,
    results: str | None = None,
    previous_results: str | None = None,
    cci_id: str | None = "CCI-000001",
    control_id: str = "AC-1",
) -> CcisRow:
    """Build a minimal CcisRow with sensible defaults for rule-#8 testing.

    The fields rule #8 reads (``guidance``=J, ``procedures``=K,
    ``inherited``=L, ``results``=Q, ``previous_results``=U, plus
    ``narrative``=F for completeness) are exposed as knobs. Everything else
    gets a benign default so the row is well-formed.
    """
    return CcisRow(
        excel_row=10,
        required=True,
        control_id=control_id,
        ap_acronym=f"{control_id}.1",
        cci_id=cci_id,
        implementation_status=None,
        designation=None,
        narrative=narrative,
        definition=None,
        guidance=guidance,
        procedures=procedures,
        inherited=inherited,
        remote_inheritance=None,
        status=None,
        date_tested=None,
        tester=None,
        results=results,
        previous_status=None,
        previous_date=None,
        previous_tester=None,
        previous_results=previous_results,
    )


# ---------------------------------------------------------------------------
# Rule 8b (documented scope exclusion in col Q / U → Not Applicable)
# ---------------------------------------------------------------------------


def test_8b_scope_exclusion_in_col_q():
    """Col Q documents an explicit scope exclusion → NOT_APPLICABLE_8B, rule='8b'.

    NA is recovered from the assessor's own rationale in col Q, NOT the DISA
    template text in K/J. A CSP phrase in K/J is inert by design (see the
    inheritance-Compliant tests below).
    """
    row = _row(results="Not required for GOCO; this CCI is out of the assessed boundary.")

    result = classify_row(row)

    assert result.verdict is AutoStatusVerdict.NOT_APPLICABLE_8B
    assert result.status is ComplianceStatus.NOT_APPLICABLE
    assert result.rule == "8b"
    assert result.trigger_column == "Q"
    assert result.trigger_phrase == "not required for goco"
    # Narrative is NA-class for the validator and names the source column.
    assert "Not applicable —" in result.narrative
    assert "Assessment Results (col Q)" in result.narrative


def test_8b_scope_exclusion_in_col_u_falls_through_from_q():
    """Col Q empty but col U carries the scope rationale → 8b, trigger_column='U'."""
    row = _row(previous_results="Per system scoping, this CCI is not applicable to the enclave.")

    result = classify_row(row)

    assert result.verdict is AutoStatusVerdict.NOT_APPLICABLE_8B
    assert result.rule == "8b"
    assert result.trigger_column == "U"
    assert result.trigger_phrase == "per system scoping, this cci is not applicable"
    assert "Previous Results (col U)" in result.narrative


def test_8b_scope_exclusion_suppressed_by_compliance_guard():
    """A compliance claim in the SAME rationale blocks the NA lane (Compliant wins).

    Guards row-261-class gold: the human wrote a scope phrase AND an explicit
    compliance claim; the verdict is Compliant, so the deterministic layer must
    NOT flip it to NA. With no other trigger the row falls through to the LLM.
    """
    row = _row(
        results=(
            "Not required per SSAA for the legacy segment, however compliance is satisfied "
            "at the program level."
        )
    )

    result = classify_row(row)

    assert result.verdict is not AutoStatusVerdict.NOT_APPLICABLE_8B
    assert result.verdict is AutoStatusVerdict.NO_AUTO_RULE


# ---------------------------------------------------------------------------
# Inheritance / CSP-provided in col Q / U → Compliant (NOT Not Applicable)
# ---------------------------------------------------------------------------


def test_csp_inheritance_in_col_q_is_compliant():
    """Col Q says the control is implemented by AWS → COMPLIANT_8A, not NA.

    Doctrine: inherited / CSP-provided controls are Compliant. The verbatim
    trigger ("implemented by aws") is an NA-class phrase in the validator, so
    the narrative paraphrases the provider instead of quoting it.
    """
    row = _row(results="Transmission confidentiality is implemented by AWS at the platform layer.")

    result = classify_row(row)

    assert result.verdict is AutoStatusVerdict.COMPLIANT_8A
    assert result.status is ComplianceStatus.COMPLIANT
    assert result.rule == "8a"
    assert result.trigger_column == "Q"
    assert result.trigger_phrase == "implemented by aws"
    assert "AWS" in result.narrative
    # Compliant-class narrative; must NOT quote the NA-class trigger verbatim.
    assert "confirmed via" in result.narrative.lower()
    assert "implemented by aws" not in result.narrative.lower()


def test_csp_inheritance_in_col_u_is_compliant():
    """CSP attribution in col U also resolves Compliant, trigger_column='U'."""
    row = _row(previous_results="Flaw remediation is provided by the CSP under the shared model.")

    result = classify_row(row)

    assert result.verdict is AutoStatusVerdict.COMPLIANT_8A
    assert result.rule == "8a"
    assert result.trigger_column == "U"
    assert "the cloud service provider (CSP)" in result.narrative


# ---------------------------------------------------------------------------
# Rule 8a explicit / qualified inheritance (Compliant)
# ---------------------------------------------------------------------------


def test_8a_explicit_phrase_in_col_k():
    """Col K = 'automatically compliant' → COMPLIANT_8A, rule='8a'."""
    row = _row(procedures="This CCI is automatically compliant; no system-level evidence required.")

    result = classify_row(row)

    assert result.verdict is AutoStatusVerdict.COMPLIANT_8A
    assert result.status is ComplianceStatus.COMPLIANT
    assert result.rule == "8a"
    assert result.trigger_column == "K"
    assert result.trigger_phrase == "automatically compliant"
    # Narrative quotes the trigger verbatim so an assessor can audit the call.
    assert '"automatically compliant"' in result.narrative


def test_8a_qualified_inheritance_internal():
    """Col K cites a NAMED internal source → 8a (not the bare-inherited 8c path)."""
    row = _row(procedures="This control is inherited from the enterprise IAM tier.")

    result = classify_row(row)

    assert result.verdict is AutoStatusVerdict.COMPLIANT_8A
    assert result.rule == "8a"
    assert result.trigger_phrase == "inherited from the enterprise"


def test_8a_structural_col_l_internal():
    """Col L = 'DoW Enterprise' (not Local, not a CSP) → 8a structural, col='L'."""
    row = _row(inherited="DoW Enterprise")

    result = classify_row(row)

    assert result.verdict is AutoStatusVerdict.COMPLIANT_8A
    assert result.rule == "8a"
    assert result.trigger_column == "L"
    assert result.trigger_phrase == "DoW Enterprise"
    # Structural narrative names col L verbatim.
    assert 'col L = "DoW Enterprise"' in result.narrative


def test_8a_structural_skipped_when_col_l_is_local():
    """Col L = 'Local' means we own it locally → falls through, no auto-rule fires."""
    row = _row(inherited="Local")

    result = classify_row(row)

    assert result.verdict is AutoStatusVerdict.NO_AUTO_RULE
    assert result.rule is None


def test_8a_structural_skipped_when_col_l_names_csp():
    """Col L naming a CSP (e.g. 'AWS') without an 8b text trigger falls through to 8c."""
    # Force a bare 'inherited from' so the 8c branch fires; otherwise the test
    # would land on NO_AUTO_RULE which doesn't distinguish 'skipped col L' from
    # 'nothing at all'.
    row = _row(inherited="AWS GovCloud", procedures="Per inheritance — inherited from upstream service.")

    result = classify_row(row)

    # Must NOT be 8a structural even though col L is populated.
    assert result.verdict is AutoStatusVerdict.UNCLEAR_8C
    assert result.rule == "8c"


# ---------------------------------------------------------------------------
# Rule 8c (ambiguous — escalate)
# ---------------------------------------------------------------------------


def test_8c_bare_inherited_from_no_source():
    """Col K says 'inherited from <unknown>' → UNCLEAR_8C, reason names the col."""
    row = _row(procedures="Capability is inherited from upstream provisioning.")

    result = classify_row(row)

    assert result.verdict is AutoStatusVerdict.UNCLEAR_8C
    assert result.status is None
    assert result.narrative is None  # 8c goes to LLM; no auto-narrative
    assert result.rule == "8c"
    assert result.trigger_column == "K"
    assert result.trigger_phrase == "inherited from"
    assert result.reason is not None
    assert 'Col K says "inherited from"' in result.reason


# ---------------------------------------------------------------------------
# Check-order regressions (the part that matters most for accuracy)
# ---------------------------------------------------------------------------


def test_check_order_col_k_8a_beats_col_q_na():
    """Col K = DoD-auto Compliant AND col Q = scope-exclusion; col K wins.

    Col K is authoritative (feedback_colk_authoritative): an "automatically
    compliant" in K claims the row Compliant before the col-Q NA recognizer
    runs. This is the rows-126/263 case — the human marked them NA but col K
    says DoD-auto, so the deterministic layer (correctly) returns Compliant.
    The check order is load-bearing.
    """
    row = _row(
        procedures="This CCI is automatically compliant; covered at the DoD level.",
        results="Not required for GOCO per system scoping.",
    )

    result = classify_row(row)

    assert result.verdict is AutoStatusVerdict.COMPLIANT_8A
    assert result.rule == "8a"
    assert result.trigger_column == "K"


def test_no_auto_rule_for_gap_row():
    """Plain narrative describing a gap, no triggers → NO_AUTO_RULE (LLM path)."""
    row = _row(
        narrative="The system has not yet implemented this capability; remediation is planned.",
        guidance="Implement the control per NIST guidance.",
        procedures="Examine documented procedures and interview personnel.",
        inherited="Local",
    )

    result = classify_row(row)

    assert result.verdict is AutoStatusVerdict.NO_AUTO_RULE
    assert result.status is None
    assert result.narrative is None
    assert result.rule is None
    assert result.trigger_phrase is None
    assert result.trigger_column is None


# ---------------------------------------------------------------------------
# Narrative-template guarantees (these feed the validator on the next pass)
# ---------------------------------------------------------------------------


def test_8a_text_narrative_uses_col_label():
    """8a text narrative names the human-readable column label, not just 'col K'."""
    row = _row(procedures="This row is automatically compliant.")

    result = classify_row(row)

    assert "Assessment Procedures (col K)" in result.narrative


def test_8a_text_narrative_from_col_j_uses_guidance_label():
    """Same for col J — the label switches to 'Implementation Guidance'."""
    row = _row(guidance="Coverage is automatically compliant under DoD-wide IAM.")

    result = classify_row(row)

    assert result.trigger_column == "J"
    assert "Implementation Guidance (col J)" in result.narrative


def test_csp_compliant_narrative_names_provider_explicitly():
    """CSP-inherit narrative (col Q) surfaces the branded provider → COMPLIANT.

    Doctrine: inherited / CSP-provided controls are Compliant, never NA.
    "provided by gcp" in col Q resolves COMPLIANT_8A; the narrative paraphrases
    the branded provider (GCP) instead of quoting the NA-class trigger verbatim.
    """
    row = _row(results="Fully provided by GCP at the infrastructure layer.")

    result = classify_row(row)

    assert result.verdict is AutoStatusVerdict.COMPLIANT_8A
    assert result.rule == "8a"
    assert result.trigger_phrase == "provided by gcp"
    assert "GCP" in result.narrative
    # Compliant-class narrative must NOT quote the NA-class trigger verbatim.
    assert "provided by gcp" not in result.narrative.lower()


def test_csp_generic_trigger_names_cloud_service_provider():
    """Generic CSP phrase (no brand) in col Q → COMPLIANT, narrative says 'cloud service provider (CSP)'.

    Pins rules._infer_external_provider's CSP / cloud-service-provider branch —
    the one that fires BEFORE the final 'external service provider' catch-all.
    Reachable through the ``_R8A_CSP_INHERIT_PHRASES`` entries
    ("implemented by the csp", "provided by the csp", "implemented by the cloud
    service provider", "inherited from the csp", ...). A regression here would
    silently downgrade the provider name to the generic catch-all, and the
    validator's primary-citation check (which reads provider names) would then
    emit a 'missing primary source' note on an otherwise correct 8a verdict.
    """
    row = _row(results="This control is implemented by the CSP and requires no local action.")

    result = classify_row(row)

    assert result.verdict is AutoStatusVerdict.COMPLIANT_8A
    assert result.rule == "8a"
    assert result.trigger_phrase == "implemented by the csp"
    # The generic-CSP narrative names the umbrella term — distinct from the
    # AWS / Azure / GCP branded paths above.
    assert "the cloud service provider (CSP)" in result.narrative


def test_csp_cloud_service_provider_phrase_also_names_csp():
    """The 'cloud service provider' trigger in col Q hits the same branch → COMPLIANT.

    Belt-and-braces with the CSP test above — confirms the alternate phrasing
    ("implemented by the cloud service provider") routes through the same
    _infer_external_provider fallback. Two separate triggers map to one
    narrative; both must land consistently or the validator sees ambiguous
    citations downstream.
    """
    row = _row(results="This control is implemented by the cloud service provider at the platform layer.")

    result = classify_row(row)

    assert result.verdict is AutoStatusVerdict.COMPLIANT_8A
    assert result.rule == "8a"
    assert "the cloud service provider (CSP)" in result.narrative


def test_infer_external_provider_unbranded_fallthrough():
    """rules._infer_external_provider catch-all → 'an external service provider'.

    Every entry in ``_R8A_CSP_INHERIT_PHRASES`` names a brand or the CSP
    umbrella term (aws / azure / gcp / csp / cloud service provider), so the
    final catch-all in _infer_external_provider is unreachable through
    classify_row today. Pin it with a direct unit call so a future refactor
    that adds an unbranded provider trigger (e.g. boundary language) doesn't
    silently strip the fallback — the validator's primary-citation check
    downstream expects SOMETHING nameable in the narrative even when nothing
    brandable is present.
    """
    assert _infer_external_provider("handled off-site by a partner org") == (
        "an external service provider"
    )
