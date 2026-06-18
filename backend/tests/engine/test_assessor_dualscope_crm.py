"""End-to-end tests for the dual-scope CRM short-circuit logic.

The single-scope variants live in ``test_assessor_e2e.py`` (those existed
before the cloud/on-prem split). This file pins the *combined-scope*
semantics introduced by ``lucky-sleeping-parasol.md``:

  1. **Both scopes inheritable** (e.g. cloud=inherited, on_prem=inherited)
     → short-circuits to Compliant with ``source='crm_inherited'``.
     LLM must NOT be called.
  2. **Mixed scopes** (cloud=provider, on_prem=customer) → NO short-circuit.
     LLM IS called and the responsibility-split block names BOTH scopes.
  3. **Cloud-only inherited, on-prem omitted** → still short-circuits.
     Backward compat for the AWS-GovCloud-template CRMs that don't have
     an on-prem column.

The first variant is the one the user explicitly called out in the plan:
"Both inherited → short-circuits (Compliant, no LLM call)."
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the backend package is importable when pytest is launched from any cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- register tables
from cybersecurity_assessor.engine.assessor import Assessor, LlmProposal  # noqa: E402
from cybersecurity_assessor.engine.crm_context import (  # noqa: E402
    CrmContext,
    CrmEntry,
    ImplementationSlice,
)
from cybersecurity_assessor.excel.ccis_reader import CcisRow  # noqa: E402
from cybersecurity_assessor.models import ComplianceStatus  # noqa: E402

# Re-use the StubLlmClient and _row factory from the e2e suite so we stay
# on a single test scaffolding surface. Importing avoids duplicating the
# shim (and keeps any future StubLlmClient changes one-call away).
from tests.engine.test_assessor_e2e import StubLlmClient, _row  # noqa: E402


def test_dualscope_both_inherited_short_circuits_no_llm():
    """cloud=inherited AND on_prem=inherited → Compliant, LLM not called."""
    row = _row(control_id="PE-1")
    crm = CrmContext(
        by_control={
            "pe-1": CrmEntry(
                control_id="pe-1",
                responsibility="inherited",
                narrative="Customer fully inherits AWS physical-environmental controls.",
                source_baseline_id=1,
                responsibility_onprem="inherited",
                narrative_onprem="On-prem facility inherits corporate physical security policy.",
            )
        }
    )
    stub = StubLlmClient([])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row, crm_context=crm)

    assert decision.source == "crm_inherited"
    assert decision.accepted is True
    assert decision.status is ComplianceStatus.COMPLIANT
    assert stub.calls == [], (
        "LLM must not be called when both scopes are inheritable; "
        f"got calls={stub.calls!r}"
    )


def test_multi_crm_inherited_short_circuit_carries_every_cloud_narrative():
    """Two inherited CRMs (AWS + Azure) → parent Decision cites BOTH clouds.

    Regression for the "only Microsoft" symptom: the short-circuit Decision
    is built around the single latest-attach ``CrmEntry`` (Azure), so its
    ``narrative`` / ``narrative_cloud`` mention only Azure. The per-scope
    slices carry BOTH clouds' verbatim CRM text, and ``_finalize_crm_decision``
    must fold them into ``narratives_by_scope`` so the parent Decision — and
    every downstream consumer (``plan_implementations`` →
    ``compose_rolled_narrative`` → parent ``narrative_q``) — surfaces AWS AND
    Microsoft, not just the latest attach.
    """
    row = _row(control_id="PE-3")
    crm = CrmContext(
        by_control={
            # latest-attach-wins single entry = Azure (Microsoft) only.
            "pe-3": CrmEntry(
                control_id="pe-3",
                responsibility="inherited",
                narrative="Microsoft Azure Government enforces datacenter physical access.",
                source_baseline_id=2,
            )
        },
        by_control_impls={
            "pe-3": [
                ImplementationSlice(
                    scope_label="AWS GovCloud",
                    responsibility="inherited",
                    narrative="AWS GovCloud datacenters enforce physical access controls.",
                    source_baseline_id=1,
                ),
                ImplementationSlice(
                    scope_label="Azure Government",
                    responsibility="inherited",
                    narrative="Microsoft Azure Government enforces datacenter physical access.",
                    source_baseline_id=2,
                ),
            ]
        },
    )
    stub = StubLlmClient([])
    decision = Assessor(llm=stub).assess(row, crm_context=crm)

    assert decision.source == "crm_inherited"
    assert decision.status is ComplianceStatus.COMPLIANT
    assert stub.calls == []
    # The parent Decision now carries a per-scope narrative for EACH cloud.
    assert set(decision.narratives_by_scope) == {"AWS GovCloud", "Azure Government"}
    assert "AWS GovCloud" in decision.narratives_by_scope
    assert (
        "AWS GovCloud datacenters"
        in decision.narratives_by_scope["AWS GovCloud"]
    )
    assert (
        "Microsoft Azure Government"
        in decision.narratives_by_scope["Azure Government"]
    )


def test_dualscope_mixed_provider_and_customer_does_not_short_circuit():
    """cloud=provider, on_prem=customer → LLM IS called with dual hybrid block."""
    row = _row(
        control_id="PE-3",
        definition="Physical access controls at the facility.",
    )
    crm = CrmContext(
        by_control={
            "pe-3": CrmEntry(
                control_id="pe-3",
                responsibility="provider",
                narrative="Cloud-side: AWS owns physical access controls for the GovCloud datacenters.",
                source_baseline_id=1,
                responsibility_onprem="customer",
                narrative_onprem=(
                    "On-prem: Customer owns badge readers, escort logs, "
                    "and quarterly access reviews per USD00050010."
                ),
            )
        }
    )
    stub = StubLlmClient(
        [
            # Narrative must classify as COMPLIANCE_AFFIRMING — "documented in"
            # + "verified via" are the validator's required affirming phrases.
            # An earlier draft used "reviewed quarterly per …; provider-owned
            # and out of customer scope" which had no affirming phrase and
            # tripped status_narrative_mismatch on retry.
            LlmProposal(
                status=ComplianceStatus.COMPLIANT,
                narrative=(
                    "On-prem badge-reader access controls are documented in "
                    "USD00050010 §4.1 and verified via quarterly log review of "
                    "the production access roster."
                ),
                confidence=0.95,
            )
        ]
    )
    assessor = Assessor(llm=stub)

    decision = assessor.assess(
        row,
        crm_context=crm,
        tagged_evidence=(
            "## evidence_bundle\n- USD00050010 §4.1 (badge-reader log review)"
        ),
    )

    # LLM must run because at least one scope is customer-owned.
    assert decision.source == "llm"
    assert decision.accepted is True
    assert len(stub.calls) == 1

    sent = stub.calls[0]["tagged_evidence"]
    assert sent is not None
    assert sent.startswith("## responsibility_split"), (
        f"dual-scope hybrid block must be first; got: {sent[:80]!r}"
    )
    # Dual-scope marker — distinguishes the dual rendering from the legacy
    # single-scope hybrid block.
    assert "scope: dual" in sent, (
        f"expected dual-scope block (cloud + on-prem); got: {sent!r}"
    )
    # Both scopes' verdicts and narratives must be present so the LLM can
    # tell them apart.
    assert "cloud_responsibility: provider" in sent
    assert "on_prem_responsibility: customer" in sent
    assert "customer_narrative_from_crm_cloud:" in sent
    assert "customer_narrative_from_crm_on_prem:" in sent
    assert "AWS owns physical access controls" in sent
    assert "Customer owns badge readers" in sent
    # The original evidence bundle must still be appended.
    assert "## evidence_bundle" in sent


def test_dualscope_cloud_only_inherited_backward_compat():
    """cloud=inherited, on_prem=None → still short-circuits (legacy AWS GovCloud template)."""
    row = _row(control_id="PE-12")
    crm = CrmContext(
        by_control={
            "pe-12": CrmEntry(
                control_id="pe-12",
                responsibility="inherited",
                narrative="Customer fully inherits AWS datacenter emergency lighting.",
                source_baseline_id=1,
                # on-prem unspecified — legacy single-column CRM
                responsibility_onprem=None,
                narrative_onprem=None,
            )
        }
    )
    stub = StubLlmClient([])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row, crm_context=crm)

    assert decision.source == "crm_inherited"
    assert decision.accepted is True
    assert decision.status is ComplianceStatus.COMPLIANT
    assert stub.calls == [], (
        "single-scope inherited must still short-circuit (backward compat); "
        f"got calls={stub.calls!r}"
    )


def test_dualscope_cloud_inherited_onprem_customer_does_not_short_circuit():
    """cloud=inherited (would short-circuit alone), on_prem=customer → LLM runs.

    Pins the user's plan requirement: "Cloud provider, on-prem customer →
    full LLM assessment (no short-circuit)." This is the symmetric case
    where the cloud scope is inheritable but the on-prem half still needs
    a real assessment.
    """
    row = _row(control_id="PE-6")
    crm = CrmContext(
        by_control={
            "pe-6": CrmEntry(
                control_id="pe-6",
                responsibility="inherited",
                narrative="Cloud: Inherited from AWS physical access monitoring.",
                source_baseline_id=1,
                responsibility_onprem="customer",
                narrative_onprem="On-prem: Customer owns CCTV with 90-day retention.",
            )
        }
    )
    stub = StubLlmClient(
        [
            # Same affirming-phrase constraint as the mixed-scope test — bare
            # "verified with 90-day retention" doesn't match _AFFIRMING_PHRASES;
            # "documented in … verified via …" does.
            LlmProposal(
                status=ComplianceStatus.COMPLIANT,
                narrative=(
                    "On-prem CCTV deployment is documented in USD00050010 §5 "
                    "and verified via the 90-day retention configuration on the "
                    "local NVR."
                ),
                confidence=0.9,
            )
        ]
    )
    assessor = Assessor(llm=stub)

    decision = assessor.assess(
        row,
        crm_context=crm,
        tagged_evidence="## evidence_bundle\n- USD00050010 §5 (CCTV retention)",
    )

    # On-prem customer-owned half forces a real assessment even though
    # the cloud half alone would have short-circuited.
    assert decision.source == "llm"
    assert len(stub.calls) == 1
    sent = stub.calls[0]["tagged_evidence"]
    assert "scope: dual" in sent
    assert "cloud_responsibility: inherited" in sent
    assert "on_prem_responsibility: customer" in sent


# ---------------------------------------------------------------------------
# AU-6 phantom-cloud guard — per-scope narratives require real CRM context
# ---------------------------------------------------------------------------


def test_no_crm_drops_phantom_cloud_narrative():
    """AU-6 bug: LLM emits narrative_cloud from workbook text, but NO CRM attached.

    The demo AU-6 column-F text says 'differs by cloud: AWS GovCloud … Azure
    Government …', so the model emits a narrative_cloud field even with zero CRM
    overlay. The assessor used to persist it unconditionally → a cloud narrative
    on a control with no cloud scope. With no customer-owned slice the per-scope
    cloud/on-prem fields (and narratives_by_scope) must be dropped; only the
    single column-Q narrative survives.
    """
    row = _row(control_id="AU-6", cci_id="CCI-000148")
    proposal = LlmProposal(
        status=ComplianceStatus.NON_COMPLIANT,
        narrative=(
            "On the on-prem enclave, weekly audit review is substantiated by "
            "audit_log_review_2026-05-19; POA&M opened."
        ),
        narrative_cloud=(
            "No audit-review evidence was located for the AWS GovCloud or "
            "Azure Government review split. POA&M opened."
        ),
        narrative_on_prem="Weekly audit-record review on the on-prem enclave.",
        confidence=0.82,
    )
    stub = StubLlmClient([proposal] * 5)
    decision = Assessor(llm=stub).assess(
        row,
        tagged_evidence="## evidence_bundle\n- audit_log_review_2026-05-19",
        crm_context=CrmContext.empty(),
    )
    assert decision.source == "llm"
    assert decision.narrative_cloud is None, (
        "phantom cloud narrative must be dropped when no CRM is attached"
    )
    assert decision.narrative_on_prem is None
    assert decision.narratives_by_scope == {}
    # The single canonical narrative is preserved.
    assert decision.narrative and "on-prem enclave" in decision.narrative


def test_customer_crm_keeps_per_scope_narratives():
    """Guard boundary: a real customer-owned slice KEEPS per-scope narratives.

    Same control, but with both CRMs attached (AWS hybrid + Azure customer +
    synthesized On-Premises). A customer-owned slice exists, so the gate is a
    no-op: narrative_cloud / narrative_on_prem / narratives_by_scope all
    persist. Confirms the AU-6 fix doesn't wipe legitimate multi-scope output.
    """
    row = _row(control_id="AU-6", cci_id="CCI-000148")
    crm = CrmContext(
        by_control_impls={
            "au-6": [
                ImplementationSlice("AWS GovCloud", "hybrid", "AWS shares review", 1),
                ImplementationSlice("Azure Government", "customer", "Azure customer review", 2),
                ImplementationSlice("On-Premises", "customer", None, None),
            ]
        }
    )
    proposal = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative="Weekly audit review confirmed via USD123 across scopes.",
        narrative_cloud="AWS GovCloud shares SOC review; Azure customer runs Sentinel, confirmed via USD123.",
        narrative_on_prem="On-prem weekly review confirmed via USD123.",
        confidence=0.9,
    )
    stub = StubLlmClient([proposal] * 6)
    decision = Assessor(llm=stub).assess(
        row,
        tagged_evidence="## responsibility_split\n## evidence_bundle\n- USD123",
        crm_context=crm,
    )
    assert decision.source == "llm"
    assert decision.narrative_cloud is not None
    assert decision.narrative_on_prem is not None
    assert set(decision.narratives_by_scope) >= {"AWS GovCloud", "Azure Government"}
