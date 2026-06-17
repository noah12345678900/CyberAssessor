"""Multi-scope_label masking regression — the masked-customer short-circuit bug.

Companion to ``test_assessor_dualscope_crm.py`` (single-CRM dual-column
cloud/on-prem) and ``test_crm_context_edges.py`` (data-layer characterization
of the masking risk). Those two files pinned the *symptom* at the data layer:
when two CRMs cover one control under different ``scope_label``s and the
newest attach is deterministic (inherited/provider/NA), the legacy
``by_control`` map keeps ONLY that newest attach — masking an earlier
customer/hybrid scope. ``test_crm_context_edges.py`` deliberately asserts
``lookup() == "inherited"`` (latest-wins) and notes the consumer must
compensate.

This file pins the *fix* at the consumer layer (``Assessor._run``): even
though ``lookup()`` still returns the masking "inherited" entry, the
per-scope ``by_control_impls`` slices carry a customer-owned scope, so the
assessor MUST NOT short-circuit to COMPLIANT-by-inheritance. It routes to
the LLM with a slice-aware ``## responsibility_split`` block that enumerates
EVERY scope — cloud platforms first, the synthesized On-Premises slice last
— so each boundary is assessed and the per-scope impl rows carry distinct
verdicts/narratives.

Precision over recall: never let "inherited" on the latest attach silently
drop the customer half of an earlier-attached scope.
"""

from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- register tables
from cybersecurity_assessor.baselines.scope_labels import ON_PREM_LABEL  # noqa: E402
from cybersecurity_assessor.engine.assessor import Assessor, LlmProposal  # noqa: E402
from cybersecurity_assessor.engine.crm_context import (  # noqa: E402
    CrmContext,
    CrmEntry,
    ImplementationSlice,
)
from cybersecurity_assessor.models import ComplianceStatus  # noqa: E402

# Reuse the single test scaffolding surface (StubLlmClient records every
# call; _row builds a minimal CcisRow). Same import the dual-scope suite uses.
from tests.engine.test_assessor_e2e import StubLlmClient, _row  # noqa: E402


def _masked_customer_context() -> CrmContext:
    """Two CRMs on ``ac-2``: AWS GovCloud 'customer' (older) + Azure 'inherited' (newer).

    Mirrors what ``build_crm_context`` produces for that attach sequence:

    * ``by_control`` keeps ONLY the newest attach (Azure 'inherited') —
      latest-wins masking, exactly what ``test_crm_context_edges.py`` pins.
    * ``by_control_impls`` preserves BOTH cloud slices plus the synthesized
      On-Premises customer slice (cloud platforms first, on-prem last),
      because at least one cloud slice is customer-owned.
    """
    return CrmContext(
        by_control={
            "ac-2": CrmEntry(
                control_id="ac-2",
                responsibility="inherited",  # masking entry — newest attach
                narrative="Inherited from Azure Active Directory baseline.",
                source_baseline_id=2,
            )
        },
        by_control_impls={
            "ac-2": [
                ImplementationSlice(
                    scope_label="AWS GovCloud",
                    responsibility="customer",
                    narrative="Customer manages IAM roles in AWS GovCloud.",
                    source_baseline_id=1,
                ),
                ImplementationSlice(
                    scope_label="Azure",
                    responsibility="inherited",
                    narrative="Inherited from Azure Active Directory baseline.",
                    source_baseline_id=2,
                ),
                # Synthesized On-Premises slice (customer-owned cloud slice →
                # the customer's work shows up on the on-prem footprint too).
                ImplementationSlice(
                    scope_label=ON_PREM_LABEL,
                    responsibility="customer",
                    narrative=None,
                    source_baseline_id=None,
                ),
            ]
        },
    )


def test_masked_customer_multiscope_does_not_short_circuit():
    """lookup()=='inherited' but a customer slice exists → LLM runs, no short-circuit.

    The legacy entry alone would short-circuit to COMPLIANT-by-inheritance
    (``test_crm_inherited_short_circuits`` proves that). Here the per-scope
    slices carry an AWS GovCloud 'customer' verdict, so the assessor must
    route to the LLM instead of silently dropping the customer half.
    """
    row = _row(control_id="AC-2")
    crm = _masked_customer_context()

    # Sanity: the masking entry really would short-circuit on its own.
    assert crm.lookup("ac-2").responsibility == "inherited"

    stub = StubLlmClient(
        [
            LlmProposal(
                status=ComplianceStatus.COMPLIANT,
                narrative=(
                    "Customer-managed IAM roles are documented in USD00050010 "
                    "§4 and verified via the AWS GovCloud account access review."
                ),
                confidence=0.95,
            )
        ]
    )
    assessor = Assessor(llm=stub)

    decision = assessor.assess(
        row,
        crm_context=crm,
        tagged_evidence="## evidence_bundle\n- USD00050010 §4 (IAM access review)",
    )

    # The customer-owned slice forces a real assessment.
    assert decision.source == "llm", (
        "masked-customer multi-scope must NOT short-circuit to "
        f"crm_inherited; got source={decision.source!r}"
    )
    assert len(stub.calls) == 1, (
        "LLM must be consulted exactly once for the customer-owned half; "
        f"got calls={stub.calls!r}"
    )


def test_masked_customer_multiscope_renders_slice_aware_block():
    """The LLM sees a slice-aware ``## responsibility_split`` block naming every scope.

    The entry-based block can only describe the latest attach (Azure
    'inherited') — it cannot see the AWS GovCloud customer half at all. The
    slice-aware block enumerates all three scopes in order: cloud platforms
    first, On-Premises last.
    """
    row = _row(control_id="AC-2")
    crm = _masked_customer_context()
    stub = StubLlmClient(
        [
            LlmProposal(
                status=ComplianceStatus.COMPLIANT,
                narrative=(
                    "Customer-managed IAM roles are documented in USD00050010 "
                    "§4 and verified via the AWS GovCloud account access review."
                ),
                confidence=0.95,
            )
        ]
    )
    assessor = Assessor(llm=stub)

    assessor.assess(
        row,
        crm_context=crm,
        tagged_evidence="## evidence_bundle\n- USD00050010 §4 (IAM access review)",
    )

    sent = stub.calls[0]["tagged_evidence"]
    assert sent is not None
    assert sent.startswith("## responsibility_split"), (
        f"slice-aware hybrid block must lead the bundle; got: {sent[:80]!r}"
    )
    # Slice-aware marker distinguishes this from the entry-based dual block
    # ("scope: dual") and the single-scope block.
    assert "scope: multi" in sent, (
        f"expected slice-aware multi-scope block; got: {sent!r}"
    )
    # Every scope must be named — including the AWS GovCloud customer half
    # the legacy entry-based block could never see.
    assert "scope_label: AWS GovCloud" in sent
    assert "scope_label: Azure" in sent
    assert f"scope_label: {ON_PREM_LABEL}" in sent
    # Per-scope verdicts present so the LLM can tell them apart.
    assert "responsibility: customer" in sent
    assert "responsibility: inherited" in sent
    # The CRM-authored customer narrative rides along.
    assert "Customer manages IAM roles in AWS GovCloud" in sent
    # Cloud-first / on-prem-last ordering: every cloud scope appears before
    # the synthesized On-Premises slice in the rendered block.
    aws_pos = sent.index("scope_label: AWS GovCloud")
    azure_pos = sent.index("scope_label: Azure")
    onprem_pos = sent.index(f"scope_label: {ON_PREM_LABEL}")
    assert aws_pos < onprem_pos and azure_pos < onprem_pos, (
        "On-Premises slice must render last (cloud platforms first)"
    )
    # The original evidence bundle is still appended after the block.
    assert "## evidence_bundle" in sent


def test_masked_provider_only_multiscope_still_short_circuits():
    """Recall guard: all-inheritable multi-scope (no customer slice) DOES short-circuit.

    The fix must only suppress the short-circuit when a customer/hybrid
    slice actually exists. Two cloud scopes that are both inheritable
    (provider + inherited) carry no customer-side work, so no On-Premises
    slice is synthesized and the control still short-circuits — exactly as a
    single inherited CRM would. Over-suppressing here would spuriously force
    the LLM on genuinely fully-inherited controls.
    """
    row = _row(control_id="AC-2")
    crm = CrmContext(
        by_control={
            "ac-2": CrmEntry(
                control_id="ac-2",
                responsibility="inherited",
                narrative="Inherited from Azure AD baseline.",
                source_baseline_id=2,
            )
        },
        by_control_impls={
            "ac-2": [
                ImplementationSlice(
                    scope_label="AWS GovCloud",
                    responsibility="provider",
                    narrative="AWS owns this at the platform layer.",
                    source_baseline_id=1,
                ),
                ImplementationSlice(
                    scope_label="Azure",
                    responsibility="inherited",
                    narrative="Inherited from Azure AD baseline.",
                    source_baseline_id=2,
                ),
                # No customer/hybrid slice → build_crm_context synthesizes
                # NO On-Premises slice, so none is present here.
            ]
        },
    )
    stub = StubLlmClient([])  # empty queue — any LLM call would AssertionError
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row, crm_context=crm)

    assert decision.source == "crm_inherited", (
        "all-inheritable multi-scope must still short-circuit; "
        f"got source={decision.source!r}"
    )
    assert decision.status is ComplianceStatus.COMPLIANT
    assert stub.calls == [], (
        "LLM must not be consulted when no slice is customer-owned; "
        f"got calls={stub.calls!r}"
    )


def test_multitenant_empty_slices_does_not_short_circuit():
    """Multi-tenant workbook, a control with NO per-scope slices → no short-circuit.

    The empty-slices masking hole: scope attribution is missing for AC-17 (its
    by_control_impls entry is empty — e.g. a CRM lacked a scope_label for it),
    but the workbook is genuinely multi-tenant: OTHER controls' slices reveal
    two distinct tenant labels (AWS GovCloud + Azure Government). The single
    latest-attach-wins ``lookup()`` entry ("inherited") must NOT short-circuit
    to COMPLIANT — that would mask the other tenant's customer obligation with
    no LLM call. distinct_scope_label_count >= 2 forces the LLM path.
    """
    crm = CrmContext(
        by_control={
            "ac-17": CrmEntry(
                control_id="ac-17", responsibility="inherited",
                narrative="inherited (latest attach)", source_baseline_id=2,
                responsibility_onprem=None,
            ),
        },
        # AC-17 has NO slices, but another control reveals two tenant labels so
        # the workbook is recognized as multi-tenant.
        by_control_impls={
            "ac-2": [
                ImplementationSlice(
                    scope_label="AWS GovCloud", responsibility="customer",
                    narrative="c", source_baseline_id=1,
                ),
                ImplementationSlice(
                    scope_label="Azure Government", responsibility="inherited",
                    narrative="i", source_baseline_id=2,
                ),
            ],
        },
    )
    assert crm.distinct_scope_label_count == 2
    assert crm.lookup("ac-17").responsibility == "inherited"  # would short-circuit alone

    row = _row(control_id="AC-17")
    stub = StubLlmClient(
        [
            LlmProposal(
                status=ComplianceStatus.NON_COMPLIANT,
                narrative="Remote-access configuration not evidenced; POA&M required.",
                confidence=0.8,
            )
        ]
    )
    decision = Assessor(llm=stub).assess(row, crm_context=crm)
    assert decision.source == "llm", (
        "multi-tenant control with empty slices must route to the LLM, not "
        f"short-circuit to crm_inherited; got source={decision.source!r}"
    )
    assert len(stub.calls) == 1


def test_single_tenant_empty_slices_still_short_circuits():
    """Single-tenant (no 2nd scope label) + empty slices → short-circuit preserved.

    With fewer than two distinct tenant labels there is no second tenant to
    mask, so the deterministic inherited short-circuit remains correct and must
    NOT regress to an unnecessary LLM call.
    """
    crm = CrmContext(
        by_control={
            "ac-17": CrmEntry(
                control_id="ac-17", responsibility="inherited",
                narrative="inherited via enterprise service", source_baseline_id=1,
                responsibility_onprem=None,
            ),
        },
        by_control_impls={},  # no labels anywhere -> single-tenant signal
    )
    assert crm.distinct_scope_label_count == 0

    row = _row(control_id="AC-17")
    stub = StubLlmClient([])  # no proposals — must NOT be called
    decision = Assessor(llm=stub).assess(row, crm_context=crm)
    assert decision.source != "llm", (
        "single-tenant inherited control must short-circuit, not call the LLM; "
        f"got source={decision.source!r}"
    )
    assert decision.status == ComplianceStatus.COMPLIANT
    assert len(stub.calls) == 0
