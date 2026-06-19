"""Regression: PE-family controls don't auto-pass on CSP inheritance alone.

PE-3 bug (user-found): a physical-access control marked `inherited` on every
cloud scope short-circuited to fully-Compliant with NO On-Premises scope —
silently dropping any on-prem facility. CSP physical inheritance cannot cover
a customer-operated data center, so an all-inherited PE control with no
declared On-Premises responsibility is NOT certifiable on inheritance alone.

When no on-prem evidence is tagged, the guard produces a DETERMINISTIC
Non-Compliant (clouds Compliant-by-inheritance, On-Premises NC for the missing
facility) — consistent with the app's universal "no evidence -> Non-Compliant"
baseline (_finalize_no_evidence_decision). When on-prem evidence IS present,
the control routes to the LLM so the procedural-vs-technical judgment is made
normally (a facility access plan can satisfy it). The guard does NOT fire when:
  * the CRM explicitly declares an On-Premises responsibility (CRM complete),
  * an On-Premises slice is present, or
  * the control is non-physical (normal inheritance short-circuit stands).
"""

from __future__ import annotations

from cybersecurity_assessor.engine.assessor import Assessor, _is_physical_family
from cybersecurity_assessor.engine.crm_context import (
    CrmContext,
    CrmEntry,
    ImplementationSlice,
)
from cybersecurity_assessor.excel.ccis_reader import CcisRow
from cybersecurity_assessor.models import ComplianceStatus


def _row(control_id: str, col_l: str = "Local") -> CcisRow:
    # col_l drives the FLEX (On-Premises/workbook) slice status under the
    # pie-slice model. Default "Local" → ASSESS (customer-owned flex slice;
    # NC when no evidence). Pass a named source ("DoW Enterprise") for the
    # INHERITED path, or "Yes" for the ESCALATE (bare-inherited) path.
    return CcisRow(
        excel_row=5,
        required=True,
        control_id=control_id,
        ap_acronym=control_id,
        cci_id="CCI-000919",
        implementation_status=None,
        designation=None,
        narrative=None,
        definition="Physical access control.",
        guidance=None,
        procedures=None,
        inherited=col_l,
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


def _both_clouds_inherited(
    control_oscal: str, *, onprem=False, onprem_resp=None, synth_onprem=False
):
    impls = [
        ImplementationSlice("AWS GovCloud", "inherited", "AWS inherited", 1),
        ImplementationSlice("Azure Government", "inherited", "Azure inherited", 2),
    ]
    if onprem:
        impls.append(ImplementationSlice("On-Premises", "inherited", "on-prem inherited", 3))
    elif synth_onprem:
        # Mirrors what build_crm_context synthesizes for a PE-family all-
        # inherited control: a customer On-Premises slice with no narrative.
        impls.append(ImplementationSlice("On-Premises", "customer", None, None))
    entry = CrmEntry(
        control_id=control_oscal,
        responsibility="inherited",
        narrative="Customer fully inherits.",
        source_baseline_id=1,
        responsibility_onprem=onprem_resp,
        narrative_onprem="on-prem facility inherited" if onprem_resp else None,
    )
    return CrmContext(by_control={control_oscal: entry}, by_control_impls={control_oscal: impls})


def test_col_l_assess_clouds_inherited_no_evidence_is_deterministic_nc():
    """Pie-slice model: clouds inherited + synthesized flex slice + col L =
    "Local" (ASSESS) + NO flex evidence -> deterministic Non-Compliant (clouds
    Compliant-by-inheritance, flex On-Premises NC), no LLM. The flex gap is a
    finding, not an abstain (owner decision: blank narrative under forced-assess
    -> NC)."""
    d = Assessor(llm=None).assess(
        _row("PE-3", col_l="Local"),
        crm_context=_both_clouds_inherited("pe-3", synth_onprem=True),
    )
    assert d.source == "crm_physical_onprem_gap"
    assert d.status is ComplianceStatus.NON_COMPLIANT
    assert d.needs_review is False
    # Per-scope statuses: clouds Compliant, On-Premises Non-Compliant.
    assert d.statuses_by_scope["On-Premises"] == "Non-Compliant"
    assert d.statuses_by_scope["AWS GovCloud"] == "Compliant"
    assert d.statuses_by_scope["Azure Government"] == "Compliant"


def test_col_l_named_source_clouds_inherited_short_circuits_compliant():
    """Pie-slice model: clouds inherited + synthesized flex slice + col L names
    an inheritance source ("DoW Enterprise" -> INHERITED) -> whole control
    short-circuits Compliant; the flex slice carries Compliant via col L (no
    LLM, no NC). This is the col-L INHERITED path."""
    d = Assessor(llm=None).assess(
        _row("PE-3", col_l="DoW Enterprise"),
        crm_context=_both_clouds_inherited("pe-3", synth_onprem=True),
    )
    assert d.source == "crm_inherited"
    assert d.status is ComplianceStatus.COMPLIANT
    assert d.needs_review is False
    assert d.statuses_by_scope.get("On-Premises") == "Compliant"


def test_col_l_wins_outright_over_crm_onprem_label_conflict1():
    """Conflict 1: col L = named source (INHERITED) but CRM responsibility_onprem
    = "customer". Owner decision: COLUMN L WINS OUTRIGHT. The flex slice is
    Compliant-by-inheritance and the CRM "customer" label does NOT force an
    assessment. No KeyError from the dual-scope narrative machinery."""
    d = Assessor(llm=None).assess(
        _row("PE-3", col_l="DoW Enterprise"),
        crm_context=_both_clouds_inherited(
            "pe-3", synth_onprem=True, onprem_resp="customer"
        ),
    )
    assert d.source == "crm_inherited"
    assert d.status is ComplianceStatus.COMPLIANT
    assert d.statuses_by_scope.get("On-Premises") == "Compliant"


def test_col_l_assess_with_crm_onprem_na_label_still_assesses():
    """NA escape hatch REMOVED: col L = "Local" (ASSESS) + CRM
    responsibility_onprem = "not_applicable". Column L wins — the flex slice is
    still ASSESSED (deterministic NC with no evidence), NOT skipped to Compliant
    by the CRM NA label."""
    d = Assessor(llm=None).assess(
        _row("PE-3", col_l="Local"),
        crm_context=_both_clouds_inherited(
            "pe-3", synth_onprem=True, onprem_resp="not_applicable"
        ),
    )
    assert d.source == "crm_physical_onprem_gap"
    assert d.status is ComplianceStatus.NON_COMPLIANT
    assert d.statuses_by_scope["On-Premises"] == "Non-Compliant"


def test_col_l_bare_yes_escalates_flex_slice():
    """col L = bare "Yes" (inherited, source unnamed -> ESCALATE) + clouds
    inherited + NO evidence -> abstain/needs_review on the flex slice (8c
    semantics): can't distinguish internal inheritance from external CSP."""
    d = Assessor(llm=None).assess(
        _row("PE-3", col_l="Yes"),
        crm_context=_both_clouds_inherited("pe-3", synth_onprem=True),
    )
    assert d.status is None
    assert d.needs_review is True
    assert d.rule == "8c"


def test_pe_family_with_explicit_onprem_responsibility_short_circuits():
    """If the CRM declares on-prem responsibility, the guard is a no-op."""
    d = Assessor(llm=None).assess(
        _row("PE-3"), crm_context=_both_clouds_inherited("pe-3", onprem_resp="inherited")
    )
    assert d.source == "crm_inherited"
    assert d.status is ComplianceStatus.COMPLIANT
    assert d.needs_review is False


def test_pe_family_with_explicit_onprem_slice_short_circuits():
    """An explicit On-Premises slice means on-prem was considered -> no abstain."""
    d = Assessor(llm=None).assess(
        _row("PE-3"), crm_context=_both_clouds_inherited("pe-3", onprem=True)
    )
    assert d.source == "crm_inherited"
    assert d.status is ComplianceStatus.COMPLIANT


def test_non_physical_all_inherited_still_short_circuits():
    """AC-1 (non-physical) all-inherited must still auto-pass — no regression."""
    d = Assessor(llm=None).assess(_row("AC-1"), crm_context=_both_clouds_inherited("ac-1"))
    assert d.source == "crm_inherited"
    assert d.status is ComplianceStatus.COMPLIANT
    assert d.needs_review is False


def test_pe_family_with_onprem_evidence_routes_to_llm():
    """When on-prem facility evidence IS tagged, PE-3 must NOT short-circuit
    to the deterministic NC — it routes to the LLM so the procedural-vs-
    technical judgment is applied (a facility access plan could satisfy it).

    With llm=None and evidence present, the kernel falls through to the
    no-llm-client abstain — what matters here is that it did NOT take the
    deterministic gap path (source != crm_physical_onprem_gap) and did NOT
    auto-pass (source != crm_inherited)."""
    from cybersecurity_assessor.engine.evidence_bundle import EvidenceBlock

    ev = EvidenceBlock(
        text="## evidence_bundle\n- USD-FACILITY Physical Access Plan §3 (badge logs)",
        has_artifacts=True,
        has_coverage=False,
        has_findings=False,
        has_hosts=False,
        has_nonscan_artifact=True,
    )
    d = Assessor(llm=None).assess(
        _row("PE-3"),
        crm_context=_both_clouds_inherited("pe-3", synth_onprem=True),
        tagged_evidence=ev.text,
        evidence_block=ev,
    )
    assert d.source != "crm_physical_onprem_gap", "evidence present must not hit the deterministic gap path"
    assert d.source != "crm_inherited", "must not auto-pass when on-prem evidence needs assessment"


def test_is_physical_family_helper():
    assert _is_physical_family("PE-3")
    assert _is_physical_family("pe-3 (1)")
    assert _is_physical_family("PE-13")
    assert not _is_physical_family("AC-17")
    assert not _is_physical_family("SC-13")
    assert not _is_physical_family(None)


def test_pe3_nc_survives_persist_end_to_end():
    """The headline regression: the deterministic PE-3 NC must SURVIVE the
    save. persist_assessment_with_impls re-derives per-scope plans from
    crm_context + the Decision's statuses_by_scope; the parent must remain
    Non-Compliant (not clobbered back to Compliant) and the On-Premises impl
    row must persist as NON_COMPLIANT."""
    from datetime import datetime, timezone

    from sqlalchemy.pool import StaticPool
    from sqlmodel import Session, SQLModel, create_engine, select

    from cybersecurity_assessor.engine.impl_persistence import (
        persist_assessment_with_impls,
    )
    from cybersecurity_assessor.models import Assessment, AssessmentImplementation

    crm = _both_clouds_inherited("pe-3", synth_onprem=True)
    d = Assessor(llm=None).assess(_row("PE-3"), crm_context=crm)
    assert d.status is ComplianceStatus.NON_COMPLIANT  # assess-time

    eng = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(eng)
    with Session(eng) as s:
        asmt = Assessment(
            workbook_id=1,
            objective_id=10,
            excel_row=5,
            status=d.status,
            tester="t",
            date_tested=datetime.now(timezone.utc),
            narrative_q=d.narrative,
            narrative_class=d.narrative_class,
        )
        pk = persist_assessment_with_impls(
            s, assessment=asmt, decision=d, crm_context=crm, control_id="PE-3", is_new=True
        )
        s.commit()
        reloaded = s.get(Assessment, pk)
        # The clobber bug: this used to come back COMPLIANT.
        assert reloaded.status is ComplianceStatus.NON_COMPLIANT
        impls = {
            im.scope_label: im.status
            for im in s.exec(
                select(AssessmentImplementation).where(
                    AssessmentImplementation.assessment_id == pk
                )
            )
        }
        assert impls["On-Premises"] is ComplianceStatus.NON_COMPLIANT
        assert impls["AWS GovCloud"] is ComplianceStatus.COMPLIANT
        assert impls["Azure Government"] is ComplianceStatus.COMPLIANT


def test_build_crm_context_synthesizes_onprem_per_control():
    """build_crm_context adds a customer flex (On-Premises) slice for ANY
    control that has cloud CRM slices but no explicit on-prem slice —
    PER-CONTROL, family-agnostic. The slice's ROUTING responsibility is always
    "customer" (the CRM responsibility_onprem is a display LABEL only; status is
    decided later by the kernel from Column L — no CRM NA escape hatch)."""
    from sqlalchemy.pool import StaticPool
    from sqlmodel import Session, SQLModel, create_engine
    from datetime import datetime, timezone

    from cybersecurity_assessor.engine.crm_context import build_crm_context
    from cybersecurity_assessor.models import (
        Baseline,
        BaselineControl,
        BaselineSourceType,
        Control,
        Framework,
        Workbook,
        WorkbookOverlay,
    )

    def _crm(s, fw_id, wb_id, ctrl_id, label, resp, onprem=None):
        b = Baseline(framework_id=fw_id, name=f"CRM-{ctrl_id}-{label}", source_type=BaselineSourceType.CRM, scope_label=label)
        s.add(b); s.commit(); s.refresh(b)
        s.add(BaselineControl(baseline_id=b.id, control_id=ctrl_id, in_scope=True, responsibility=resp, responsibility_narrative=f"{label} {resp}", responsibility_onprem=onprem))
        s.add(WorkbookOverlay(workbook_id=wb_id, baseline_id=b.id, attached_at=datetime.now(timezone.utc)))
        s.commit()

    # --- Hybrid workbook: AC-2 has a customer cloud scope (footprint signal),
    #     AU-2 (non-PE) and PE-3 are all-inherited → BOTH get an On-Prem slice.
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    with Session(eng) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5"); s.add(fw); s.commit(); s.refresh(fw)
        wb = Workbook(id=1, path="/tmp/x.xlsx", filename="x.xlsx", framework_id=fw.id); s.add(wb); s.commit()
        ids = {}
        for oscal, fam in (("ac-2", "AC"), ("au-2", "AU"), ("pe-3", "PE")):
            c = Control(framework_id=fw.id, control_id=oscal, title=oscal, family=fam); s.add(c); s.commit(); s.refresh(c); ids[oscal] = c.id
        _crm(s, fw.id, 1, ids["ac-2"], "AWS GovCloud", "customer")   # footprint
        _crm(s, fw.id, 1, ids["ac-2"], "Azure Government", "inherited")
        _crm(s, fw.id, 1, ids["au-2"], "AWS GovCloud", "inherited")  # all-inherited non-PE
        _crm(s, fw.id, 1, ids["au-2"], "Azure Government", "inherited")
        _crm(s, fw.id, 1, ids["pe-3"], "AWS GovCloud", "inherited")  # all-inherited PE
        _crm(s, fw.id, 1, ids["pe-3"], "Azure Government", "inherited")
        ctx = build_crm_context(1, s)
        for oscal in ("au-2", "pe-3"):
            labels = {sl.scope_label: sl.responsibility for sl in ctx.implementations(oscal)}
            assert "On-Premises" in labels, f"{oscal} must get On-Premises (hybrid wb); got {labels}"
            assert labels["On-Premises"] == "customer"

    # --- Per-control: an all-inherited control in an otherwise cloud-only
    #     workbook STILL gets a synthesized customer On-Premises slice
    #     (overlay-default-local — blank on-prem column = customer-owned).
    eng2 = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng2)
    with Session(eng2) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5"); s.add(fw); s.commit(); s.refresh(fw)
        wb = Workbook(id=1, path="/tmp/y.xlsx", filename="y.xlsx", framework_id=fw.id); s.add(wb); s.commit()
        c = Control(framework_id=fw.id, control_id="pe-3", title="pe-3", family="PE"); s.add(c); s.commit(); s.refresh(c)
        _crm(s, fw.id, 1, c.id, "AWS GovCloud", "inherited")
        _crm(s, fw.id, 1, c.id, "Azure Government", "inherited")
        ctx = build_crm_context(1, s)
        labels = {sl.scope_label: sl.responsibility for sl in ctx.implementations("pe-3")}
        assert "On-Premises" in labels, f"per-control synthesis must add on-prem; got {labels}"
        assert labels["On-Premises"] == "customer"

    # --- NA escape hatch REMOVED (col L is now the status authority): even
    #     when the CRM declares on-prem = not_applicable, the synthesized flex
    #     slice's ROUTING responsibility is "customer" (the CRM label no longer
    #     sets status). Status is decided later by the kernel from column L.
    eng3 = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng3)
    with Session(eng3) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5"); s.add(fw); s.commit(); s.refresh(fw)
        wb = Workbook(id=1, path="/tmp/z.xlsx", filename="z.xlsx", framework_id=fw.id); s.add(wb); s.commit()
        c = Control(framework_id=fw.id, control_id="ac-17", title="ac-17", family="AC"); s.add(c); s.commit(); s.refresh(c)
        _crm(s, fw.id, 1, c.id, "AWS GovCloud", "inherited", onprem="not_applicable")
        _crm(s, fw.id, 1, c.id, "Azure Government", "inherited", onprem="not_applicable")
        ctx = build_crm_context(1, s)
        labels = {sl.scope_label: sl.responsibility for sl in ctx.implementations("ac-17")}
        assert labels.get("On-Premises") == "customer", (
            f"NA escape removed — flex routing responsibility is customer; got {labels}"
        )


def test_narrative_onprem_kept_on_flex_slice():
    """KEEP regression: the CRM's narrative_onprem (the ONLY customer-authored
    on-prem prose for the LLM) must still flow onto the synthesized flex slice's
    narrative, even though col L now owns the slice STATUS."""
    from sqlalchemy.pool import StaticPool
    from sqlmodel import Session, SQLModel, create_engine
    from datetime import datetime, timezone

    from cybersecurity_assessor.engine.crm_context import build_crm_context
    from cybersecurity_assessor.models import (
        Baseline,
        BaselineControl,
        BaselineSourceType,
        Control,
        Framework,
        Workbook,
        WorkbookOverlay,
    )

    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    with Session(eng) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5"); s.add(fw); s.commit(); s.refresh(fw)
        wb = Workbook(id=1, path="/tmp/n.xlsx", filename="n.xlsx", framework_id=fw.id); s.add(wb); s.commit()
        c = Control(framework_id=fw.id, control_id="ac-2", title="ac-2", family="AC")
        s.add(c); s.commit(); s.refresh(c)
        b = Baseline(framework_id=fw.id, name="CRM-aws", source_type=BaselineSourceType.CRM, scope_label="AWS GovCloud")
        s.add(b); s.commit(); s.refresh(b)
        s.add(BaselineControl(
            baseline_id=b.id, control_id=c.id, in_scope=True,
            responsibility="inherited", responsibility_narrative="cloud inh",
            responsibility_onprem="customer",
            responsibility_onprem_narrative="Customer runs badge readers on-prem per SOP-12.",
        ))
        s.add(WorkbookOverlay(workbook_id=1, baseline_id=b.id, attached_at=datetime.now(timezone.utc)))
        s.commit()
        ctx = build_crm_context(1, s)
        flex = next(sl for sl in ctx.implementations("ac-2") if sl.scope_label == "On-Premises")
        assert flex.narrative == "Customer runs badge readers on-prem per SOP-12.", (
            f"narrative_onprem must reach the flex slice; got {flex.narrative!r}"
        )
        # And the routing responsibility is still "customer" (label-only NA gone).
        assert flex.responsibility == "customer"


def test_no_crm_col_l_named_source_whole_control_8a_no_regression():
    """No-CRM single-boundary workbook: col L naming an inheritance source
    still short-circuits the WHOLE control via rule 8a (the scope-down only
    applies when cloud CRM slices are present). No regression for the common
    eMASS-only workbook."""
    d = Assessor(llm=None).assess(
        _row("PE-3", col_l="DoW Enterprise"),
        crm_context=CrmContext.empty(),
    )
    assert d.source == "rule_8a"
    assert d.status is ComplianceStatus.COMPLIANT
    assert d.needs_review is False
