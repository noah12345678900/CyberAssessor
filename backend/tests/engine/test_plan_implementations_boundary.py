"""Boundary-preservation pin for ``plan_implementations`` — v0.2 multi-impl.

Mirrors the four boundary-test controls baked into
``Downloads/make_demo_crms.py`` (MA-4, PE-3, CP-7, CP-8). Those rows
exercise the impl-plan branches that decide WHERE the per-slice
narrative comes from:

  * ``provider`` / ``inherited`` → narrative is the CRM's verbatim text
    (with a generic fallback ONLY if the CRM left it blank).
  * ``not_applicable``           → same: CRM text passes through verbatim.
  * ``customer`` / ``hybrid``    → narrative is OVERWRITTEN with the
    Decision's narrative; the CRM's customer-side text is dropped.

The third bullet is the v0.2 gap: a single LLM Decision fans out to every
customer-owned slice, so the AWS-hybrid and Azure-hybrid impl rows for the
same CCI carry IDENTICAL narratives. Per-cloud LLM differentiation is
deferred. This file pins the current contract so the deferred work can't
land without a flagged red test.

If a future regression collapses MA-4 / PE-3 / CP-8 onto the Decision
narrative (e.g. someone simplifies the branch into "always use Decision
text"), the demo CRMs would silently start showing identical sentences on
both cloud rows — and the auditor would lose the provider-specific text
that justifies inheritance. Pinning the three preservation paths here
forces that regression to surface as a test failure first.
"""

from __future__ import annotations

import sys
from pathlib import Path

from cybersecurity_assessor.models import ComplianceStatus, NarrativeClass

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor.engine.assessor import (  # noqa: E402
    Decision,
    ImplementationPlan,
    compute_rollup_status,
    plan_implementations,
)
from cybersecurity_assessor.engine.crm_context import (  # noqa: E402
    ImplementationSlice,
)


# ---------------------------------------------------------------------------
# Fixture helpers — match what the demo CRMs ship and what a real assess
# call would produce on the customer side.
# ---------------------------------------------------------------------------

_AWS_LABEL = "AWS GovCloud"
_AZURE_LABEL = "Azure Government"
_ONPREM_LABEL = "On-Premises"

# Verbatim text from make_demo_crms.py for the four boundary controls. Kept
# as constants so a drift between demo file and test surfaces cleanly.
_MA4_AWS_NARR = (
    "AWS engineering performs all nonlocal maintenance on the GovCloud "
    "control plane via FedRAMP-authorized bastions; customer has no "
    "maintenance access to the hypervisor."
)
_MA4_AZURE_NARR = (
    "Microsoft platform engineering performs nonlocal maintenance on "
    "Azure Government fabric via FedRAMP High + DoD IL5 controlled-access "
    "workflows; customer has no fabric maintenance path."
)
_PE3_AWS_NARR = (
    "AWS GovCloud datacenters enforce multi-factor physical access, 24x7 "
    "guards, mantrap entry, and biometric verification per SOC 2 / "
    "FedRAMP High audits."
)
_PE3_AZURE_NARR = (
    "Azure Government datacenters are operated by screened US persons in "
    "DoD IL5-accredited facilities with mantrap entry, biometric "
    "verification, and 24x7 guards per the Microsoft FedRAMP High SSP."
)
_CP7_AWS_NARR = (
    "Customer architects multi-AZ + cross-region (us-gov-west-1 / "
    "us-gov-east-1) deployments; AWS provides the redundant region "
    "infrastructure."
)
_CP7_AZURE_NARR = (
    "Customer deploys across Azure Government paired regions (USGov "
    "Virginia / USGov Arizona) using Availability Zones; Microsoft "
    "maintains the underlying regional fabric."
)
_CP8_AWS_NARR = (
    "Telecommunications services are abstracted by the AWS GovCloud "
    "backbone and are not customer-selectable; control is not applicable "
    "at the IaaS consumer layer."
)
_CP8_AZURE_NARR = (
    "Telecommunications services are provided by the Azure Government "
    "backbone and are not customer-selectable; control is not applicable "
    "at the PaaS/IaaS consumer layer."
)


def _decision(
    *,
    status: ComplianceStatus | None = ComplianceStatus.COMPLIANT,
    narrative: str = "Examined the policy and confirmed it is in place.",
) -> Decision:
    """A reasonable Decision stand-in — the LLM-produced verdict that the
    customer/hybrid slices will mirror. Hard-abstain uses status=None.
    """
    return Decision(
        cci_id="CCI-000123",
        excel_row=42,
        accepted=status is not None,
        status=status,
        narrative=narrative if status else None,
        narrative_class=NarrativeClass.COMPLIANCE_AFFIRMING,
        source="llm",
        rule=None,
    )


def _by_label(plans: list[ImplementationPlan]) -> dict[str, ImplementationPlan]:
    """Lookup helper — asserts no duplicate labels, then keys by scope."""
    out: dict[str, ImplementationPlan] = {}
    for p in plans:
        assert p.scope_label not in out, (
            f"duplicate plan for {p.scope_label} — plan_implementations "
            f"should emit one row per slice"
        )
        out[p.scope_label] = p
    return out


# ---------------------------------------------------------------------------
# MA-4: both clouds inherited. Pin verbatim passthrough on BOTH rows AND
# pin that the two narratives DIFFER (boundary preserved end-to-end).
# ---------------------------------------------------------------------------


def test_ma4_dual_inherited_preserves_per_cloud_narrative_verbatim() -> None:
    slices = [
        ImplementationSlice(
            scope_label=_AWS_LABEL,
            responsibility="inherited",
            narrative=_MA4_AWS_NARR,
            source_baseline_id=1,
        ),
        ImplementationSlice(
            scope_label=_AZURE_LABEL,
            responsibility="inherited",
            narrative=_MA4_AZURE_NARR,
            source_baseline_id=2,
        ),
    ]
    plans = _by_label(plan_implementations(_decision(), slices))

    assert plans[_AWS_LABEL].narrative == _MA4_AWS_NARR
    assert plans[_AZURE_LABEL].narrative == _MA4_AZURE_NARR
    assert plans[_AWS_LABEL].narrative != plans[_AZURE_LABEL].narrative

    # Verdict on inheritance branch is always COMPLIANT, regardless of the
    # Decision (the Decision is a customer-side fact; inherited slices
    # ignore it). Source baseline FKs round-trip so the impl row knows
    # which CRM produced it.
    assert plans[_AWS_LABEL].status is ComplianceStatus.COMPLIANT
    assert plans[_AZURE_LABEL].status is ComplianceStatus.COMPLIANT
    assert plans[_AWS_LABEL].source_baseline_id == 1
    assert plans[_AZURE_LABEL].source_baseline_id == 2

    # Cloud-specific tokens survive the round trip — if a future refactor
    # ran the narrative through a sanitizer that stripped vendor names,
    # these would silently break.
    assert "GovCloud control plane" in plans[_AWS_LABEL].narrative
    assert "Azure Government fabric" in plans[_AZURE_LABEL].narrative


# ---------------------------------------------------------------------------
# PE-3: both clouds provider. Same shape as MA-4 but exercises the
# ``provider`` half of ``_INHERITABLE_RESPONSIBILITIES``.
# ---------------------------------------------------------------------------


def test_pe3_dual_provider_preserves_per_cloud_narrative_verbatim() -> None:
    slices = [
        ImplementationSlice(
            scope_label=_AWS_LABEL,
            responsibility="provider",
            narrative=_PE3_AWS_NARR,
            source_baseline_id=1,
        ),
        ImplementationSlice(
            scope_label=_AZURE_LABEL,
            responsibility="provider",
            narrative=_PE3_AZURE_NARR,
            source_baseline_id=2,
        ),
    ]
    plans = _by_label(plan_implementations(_decision(), slices))

    assert plans[_AWS_LABEL].narrative == _PE3_AWS_NARR
    assert plans[_AZURE_LABEL].narrative == _PE3_AZURE_NARR

    # Per-platform compliance language survives — the AWS row should still
    # mention SOC 2 / FedRAMP High audits, the Azure row should still
    # mention DoD IL5 facilities. A regression that merged provider rows
    # would lose one of these.
    assert "SOC 2 / FedRAMP High" in plans[_AWS_LABEL].narrative
    assert "DoD IL5-accredited" in plans[_AZURE_LABEL].narrative

    # Decision was COMPLIANT but the provider branch ignores it — the
    # status comes from the inheritance verdict, not the Decision.
    assert plans[_AWS_LABEL].status is ComplianceStatus.COMPLIANT
    assert plans[_AZURE_LABEL].status is ComplianceStatus.COMPLIANT


# ---------------------------------------------------------------------------
# CP-7: both clouds hybrid → on-prem residual gets synthesized upstream.
# This is the v0.2 GAP exposer — pins that today the customer-owned rows
# all share the Decision narrative (NOT the CRM text), so when the
# per-cloud LLM slice work lands the test author MUST update this case.
# ---------------------------------------------------------------------------


def test_cp7_real_cloud_slices_share_decision_synth_onprem_abstains() -> None:
    """Real CRM cloud slices mirror the Decision; synthesized on-prem ABSTAINS.

    The two real cloud hybrid slices (source_baseline_id set) still receive the
    single Decision narrative — per-cloud LLM differentiation remains a future
    slice. But the SYNTHESIZED On-Premises slice (source_baseline_id=None, no
    per-scope narrative) must NOT inherit the COMPLIANT verdict: it carries no
    CRM and no evidence, so the phantom-scope guard emits it as an abstain
    (status=None) flagged for reviewer follow-up rather than a false pass.
    """
    decision_text = "Reviewed multi-region failover runbook RB-DR-007."
    slices = [
        ImplementationSlice(
            scope_label=_AWS_LABEL,
            responsibility="hybrid",
            narrative=_CP7_AWS_NARR,
            source_baseline_id=1,
        ),
        ImplementationSlice(
            scope_label=_AZURE_LABEL,
            responsibility="hybrid",
            narrative=_CP7_AZURE_NARR,
            source_baseline_id=2,
        ),
        # On-prem residual is synthesized by crm_context.build_crm_context
        # when any cloud slice is customer/hybrid; we simulate that synthesis
        # here by including a customer-owned on-prem slice with no source
        # baseline (matches what the synth code emits).
        ImplementationSlice(
            scope_label=_ONPREM_LABEL,
            responsibility="customer",
            narrative=None,
            source_baseline_id=None,
        ),
    ]
    plans = _by_label(
        plan_implementations(
            _decision(narrative=decision_text), slices
        )
    )

    # The two REAL cloud slices still mirror the single Decision narrative.
    assert plans[_AWS_LABEL].narrative == decision_text
    assert plans[_AZURE_LABEL].narrative == decision_text
    assert plans[_AWS_LABEL].status is ComplianceStatus.COMPLIANT
    assert plans[_AZURE_LABEL].status is ComplianceStatus.COMPLIANT

    # The SYNTHESIZED on-prem slice abstains — no false COMPLIANT, no shared
    # decision narrative; it carries the reviewer-follow-up stub instead.
    assert plans[_ONPREM_LABEL].status is None
    assert plans[_ONPREM_LABEL].narrative != decision_text
    assert "on-prem" in plans[_ONPREM_LABEL].narrative.lower()

    # The CRM-supplied per-cloud text should NOT have leaked into the plan
    # (the impl plan replaces it). Pin the negation so a future refactor
    # that tries to "preserve everything" doesn't accidentally double up.
    assert "us-gov-west-1" not in plans[_AWS_LABEL].narrative
    assert "USGov Virginia" not in plans[_AZURE_LABEL].narrative

    # Source baseline FKs still route correctly — the synth on-prem row
    # gets source_baseline_id=None, the cloud rows keep their CRM FKs.
    assert plans[_AWS_LABEL].source_baseline_id == 1
    assert plans[_AZURE_LABEL].source_baseline_id == 2
    assert plans[_ONPREM_LABEL].source_baseline_id is None


# ---------------------------------------------------------------------------
# CP-8: both clouds not_applicable. NA branch preserves CRM text verbatim,
# even when the Decision (which the NA branch ignores) said COMPLIANT.
# ---------------------------------------------------------------------------


def test_cp8_dual_na_preserves_per_cloud_narrative_verbatim() -> None:
    slices = [
        ImplementationSlice(
            scope_label=_AWS_LABEL,
            responsibility="not_applicable",
            narrative=_CP8_AWS_NARR,
            source_baseline_id=1,
        ),
        ImplementationSlice(
            scope_label=_AZURE_LABEL,
            responsibility="not_applicable",
            narrative=_CP8_AZURE_NARR,
            source_baseline_id=2,
        ),
    ]
    plans = _by_label(plan_implementations(_decision(), slices))

    assert plans[_AWS_LABEL].narrative == _CP8_AWS_NARR
    assert plans[_AZURE_LABEL].narrative == _CP8_AZURE_NARR
    assert plans[_AWS_LABEL].status is ComplianceStatus.NOT_APPLICABLE
    assert plans[_AZURE_LABEL].status is ComplianceStatus.NOT_APPLICABLE

    # The two narratives MUST differ — if a regression collapsed both
    # platforms onto one NA narrative, an auditor reading the eMASS export
    # would see "AWS GovCloud" and "Azure Government" rows with identical
    # text, hiding the per-platform NA rationale.
    assert plans[_AWS_LABEL].narrative != plans[_AZURE_LABEL].narrative


# ---------------------------------------------------------------------------
# Cross-cutting: hard abstain on the Decision drops customer/hybrid slices
# but KEEPS the deterministic (provider/inherited/NA) slices.
# ---------------------------------------------------------------------------


def test_abstain_keeps_deterministic_slices_drops_customer_owned() -> None:
    """Mixed slice set + Decision.status=None: the provider/inherited/NA
    rows still land (their verdict is independent of the LLM); the
    customer/hybrid rows are dropped so the reviewer-flagged parent
    Assessment doesn't get falsely-promoted impl rows under it.
    """
    slices = [
        ImplementationSlice(  # provider — survives abstain
            scope_label=_AWS_LABEL,
            responsibility="provider",
            narrative=_PE3_AWS_NARR,
            source_baseline_id=1,
        ),
        ImplementationSlice(  # not_applicable — survives abstain
            scope_label=_AZURE_LABEL,
            responsibility="not_applicable",
            narrative=_CP8_AZURE_NARR,
            source_baseline_id=2,
        ),
        ImplementationSlice(  # customer — DROPPED on abstain
            scope_label=_ONPREM_LABEL,
            responsibility="customer",
            narrative=None,
            source_baseline_id=None,
        ),
    ]
    plans = _by_label(plan_implementations(_decision(status=None), slices))

    # Updated 2026-06-19: on a hard abstain, customer/hybrid slices are now
    # EMITTED with status=None for reviewer visibility (assessor.py
    # plan_implementations customer branch) rather than DROPPED. The reviewer
    # sets each scope's status on the detail page. So the On-Premises customer
    # slice is present with status=None; the deterministic clouds are unchanged.
    assert set(plans.keys()) == {_AWS_LABEL, _AZURE_LABEL, _ONPREM_LABEL}
    assert plans[_ONPREM_LABEL].status is None
    assert plans[_AWS_LABEL].status is ComplianceStatus.COMPLIANT
    assert plans[_AZURE_LABEL].status is ComplianceStatus.NOT_APPLICABLE
    # CRM text still passed through verbatim — abstain doesn't affect
    # deterministic-branch narratives.
    assert plans[_AWS_LABEL].narrative == _PE3_AWS_NARR
    assert plans[_AZURE_LABEL].narrative == _CP8_AZURE_NARR


# ---------------------------------------------------------------------------
# Generic-fallback contract: when the CRM left the narrative blank for an
# inheritance/NA slice, plan_implementations supplies a synthetic stub
# (so an impl row never has empty narrative). Pin both halves.
# ---------------------------------------------------------------------------


def test_inheritance_blank_narrative_falls_back_to_generic_stub() -> None:
    slices = [
        ImplementationSlice(
            scope_label=_AWS_LABEL,
            responsibility="inherited",
            narrative=None,  # CRM left it blank
            source_baseline_id=1,
        ),
        ImplementationSlice(
            scope_label=_AZURE_LABEL,
            responsibility="not_applicable",
            narrative=None,
            source_baseline_id=2,
        ),
    ]
    plans = _by_label(plan_implementations(_decision(), slices))

    # Fallback stubs name the scope_label so the auditor can tell which
    # platform's CRM was sparse without diffing files.
    assert _AWS_LABEL in plans[_AWS_LABEL].narrative
    assert _AZURE_LABEL in plans[_AZURE_LABEL].narrative
    # They are NOT the Decision narrative — that mistake would mislabel
    # an inheritance row as a customer-side affirmation.
    assert plans[_AWS_LABEL].narrative != _decision().narrative
    assert plans[_AZURE_LABEL].narrative != _decision().narrative


def test_evidenced_cloud_scope_plus_synth_onprem_does_not_clean_compliant() -> None:
    """Make-or-break: one EVIDENCED customer scope + un-evidenced synth on-prem.

    AC-17-style: AWS GovCloud customer scope was genuinely assessed (has a
    per-scope narrative), Azure is inherited, and the synthesized On-Premises
    scope has no evidence. The on-prem slice must abstain so the package does
    NOT present a clean, fully-Compliant control resting on one evidenced scope.
    The evidenced cloud scope keeps its real verdict.
    """
    slices = [
        ImplementationSlice(
            scope_label=_AWS_LABEL, responsibility="customer",
            narrative=None, source_baseline_id=1,
        ),
        ImplementationSlice(
            scope_label=_AZURE_LABEL, responsibility="inherited",
            narrative="Inherited via managed Azure Bastion.", source_baseline_id=2,
        ),
        ImplementationSlice(
            scope_label=_ONPREM_LABEL, responsibility="customer",
            narrative=None, source_baseline_id=None,
        ),
    ]
    decision = _decision(narrative="AWS Client VPN + conditional access verified.")
    # The LLM produced a per-scope narrative ONLY for the evidenced AWS scope.
    decision.narratives_by_scope = {
        _AWS_LABEL: "AWS Client VPN with conditional access verified per USD20240622."
    }
    plans = _by_label(plan_implementations(decision, slices))

    assert plans[_AWS_LABEL].status is ComplianceStatus.COMPLIANT
    assert plans[_AZURE_LABEL].status is ComplianceStatus.COMPLIANT  # inherited
    assert plans[_ONPREM_LABEL].status is None  # phantom abstains
    # Worst-of rollup over the real evidenced scopes is COMPLIANT, but the
    # on-prem impl row is an honest abstain (needs-review), not a fabricated pass.
    rollup = compute_rollup_status([p.status for p in plans.values()])
    assert rollup is ComplianceStatus.COMPLIANT
    assert any(p.status is None for p in plans.values()), (
        "the synthesized on-prem scope must surface as an abstain row"
    )


def test_single_customer_scope_still_compliant_not_over_abstained() -> None:
    """Make-or-break (no regression): the normal single-customer-scope control.

    One CRM, customer responsibility, NO narratives_by_scope map (the common
    case). The fix must NOT over-abstain this — the slice has a real CRM
    baseline (source_baseline_id set), so the phantom-scope guard does not
    apply and it keeps the Decision's COMPLIANT verdict via the canonical
    narrative fallback.
    """
    slices = [
        ImplementationSlice(
            scope_label=_AWS_LABEL, responsibility="customer",
            narrative=None, source_baseline_id=1,
        ),
    ]
    plans = _by_label(plan_implementations(_decision(narrative="verified"), slices))
    assert plans[_AWS_LABEL].status is ComplianceStatus.COMPLIANT
    assert plans[_AWS_LABEL].narrative == "verified"
