"""Tests for poam/generator.py — NC clustering + idempotent draft generation.

Covers:
  - Pure helpers (base_control_id, _format_security_control_number,
    _format_controls_aps) at the unit level.
  - generate_for_workbook end-to-end: no NCs, single-CCI cluster, multi-CCI
    cluster across base + enhancements, idempotence on re-run, stale-link
    pruning when an NC is reassessed Compliant.
  - Severity-aware milestone seeding: completion date drives off the
    highest-severity STIG finding (CAT-I=30d / CAT-II=90d / CAT-III=365d);
    each unique rule (top 3) gets its own milestone alongside the generic one.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlmodel import select

from cybersecurity_assessor.models import (
    ComplianceStatus,
    Evidence,
    EvidenceKind,
    EvidenceTag,
    FindingStatus,
    Poam,
    PoamMilestone,
    PoamObjective,
    PoamStatus,
    RiskLevel,
    StigFinding,
)
from cybersecurity_assessor.poam.generator import (
    _format_controls_aps,
    _format_security_control_number,
    _prune_stale_poam_links,
    base_control_id,
    generate_for_workbook,
)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


class TestBaseControlId:
    def test_strips_single_digit_enhancement(self) -> None:
        assert base_control_id("AC-2(3)") == "AC-2"

    def test_strips_multi_digit_enhancement(self) -> None:
        assert base_control_id("SI-3(12)") == "SI-3"

    def test_passes_through_base_control(self) -> None:
        assert base_control_id("AC-2") == "AC-2"

    def test_trims_whitespace(self) -> None:
        assert base_control_id("  SI-3(1)  ") == "SI-3"

    def test_unrecognized_id_passes_through_verbatim(self) -> None:
        # Don't silently merge IDs we don't understand.
        assert base_control_id("WEIRD-FORMAT") == "WEIRD-FORMAT"
        assert base_control_id("AC2") == "AC2"  # missing dash


class TestFormatSecurityControlNumber:
    def test_sorts_base_before_enhancements(self) -> None:
        out = _format_security_control_number({"SI-3", "SI-3(2)", "SI-3(1)"})
        assert out == "SI-3, SI-3(1), SI-3(2)"

    def test_sorts_enhancements_numerically(self) -> None:
        # Lexically "(10)" sorts before "(2)" — guard against that bug.
        out = _format_security_control_number({"SI-3", "SI-3(10)", "SI-3(2)"})
        assert out == "SI-3, SI-3(2), SI-3(10)"

    def test_single_control(self) -> None:
        assert _format_security_control_number({"AC-2"}) == "AC-2"


class TestFormatControlsAps:
    def test_emass_style_dotted_cci_passes_through(self) -> None:
        # AC-2.1 is already the AP form eMASS expects in col D.
        out = _format_controls_aps(["AC-2"], ["AC-2.1"])
        assert out == "AC-2.1"

    def test_parenthesised_cci_passes_through(self) -> None:
        out = _format_controls_aps(["AC-2(3)"], ["AC-2(3).5"])
        assert out == "AC-2(3).5"

    def test_disa_cci_falls_back_to_parenthetical(self) -> None:
        out = _format_controls_aps(["AC-2"], ["CCI-000015"])
        assert out == "AC-2 (CCI-000015)"

    def test_joins_multiple_with_comma_space(self) -> None:
        out = _format_controls_aps(["AC-2", "AC-2"], ["CCI-000015", "AC-2.1"])
        assert out == "AC-2 (CCI-000015), AC-2.1"


# ---------------------------------------------------------------------------
# generate_for_workbook integration
# ---------------------------------------------------------------------------


class TestGenerateForWorkbook:
    def test_no_assessments_returns_empty(self, session, poam_catalog) -> None:
        wb = poam_catalog["workbook"]
        created = generate_for_workbook(wb.id, session).created
        assert created == []
        assert session.exec(select(Poam)).all() == []

    def test_only_compliant_assessments_returns_empty(
        self, session, poam_catalog, assess
    ) -> None:
        wb = poam_catalog["workbook"]
        assess(wb.id, poam_catalog["objectives"]["AC-2"].id, ComplianceStatus.COMPLIANT)
        created = generate_for_workbook(wb.id, session).created
        assert created == []

    def test_single_nc_creates_one_poam_with_seeded_milestone(
        self, session, poam_catalog, assess
    ) -> None:
        wb = poam_catalog["workbook"]
        ac2_obj = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2_obj.id, ComplianceStatus.NON_COMPLIANT)

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        assert len(created) == 1
        poam = created[0]
        assert poam.control_cluster == "AC-2"
        assert poam.security_control_number == "AC-2"
        assert poam.status == PoamStatus.DRAFT
        # Per alembic 0008 provenance contract: no STIG findings in this
        # fixture → impact is NOT auto-seeded (no defensible STIG source),
        # so impact + likelihood fall back to the documented MODERATE
        # baseline default badged source="default". The "default" badge
        # (vs "auto") keeps provenance honest while guaranteeing the POAM
        # carries risk information instead of empty cells. The visible
        # "why" columns stay NULL for un-owned defaults (the badge says
        # enough; the literal lives only in the audit trail).
        assert poam.likelihood == RiskLevel.MODERATE
        assert poam.likelihood_source == "default"
        assert poam.likelihood_rationale is None
        assert poam.impact == RiskLevel.MODERATE
        assert poam.impact_source == "default"
        assert poam.impact_rationale is None
        # raw_severity / residual_risk computed for list-sort UX via
        # DEFAULT_LIKELIHOOD × DEFAULT_IMPACT (both MODERATE).
        assert poam.raw_severity == RiskLevel.MODERATE
        assert poam.residual_risk == RiskLevel.MODERATE
        assert poam.residual_risk_source is None
        assert poam.residual_risk_rationale is None
        assert poam.scheduled_completion_date is not None
        # Single-CCI vuln description embeds the objective text verbatim.
        assert "AC-2" in poam.vulnerability_description
        assert ac2_obj.text in poam.vulnerability_description

        # One PoamObjective link + one seeded open milestone.
        links = session.exec(
            select(PoamObjective).where(PoamObjective.poam_id == poam.id)
        ).all()
        assert len(links) == 1
        assert links[0].objective_id == ac2_obj.id
        assert links[0].status_at_creation == ComplianceStatus.NON_COMPLIANT

        milestones = session.exec(
            select(PoamMilestone).where(PoamMilestone.poam_id == poam.id)
        ).all()
        assert len(milestones) == 1
        assert milestones[0].completion_date is None
        assert "AC-2" in milestones[0].description

    def test_base_plus_enhancements_collapse_into_one_poam(
        self, session, poam_catalog, assess
    ) -> None:
        wb = poam_catalog["workbook"]
        objs = poam_catalog["objectives"]
        assess(wb.id, objs["SI-3"].id, ComplianceStatus.NON_COMPLIANT)
        assess(wb.id, objs["SI-3(1)"].id, ComplianceStatus.NON_COMPLIANT)
        assess(wb.id, objs["SI-3(2)"].id, ComplianceStatus.NON_COMPLIANT)

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        assert len(created) == 1
        poam = created[0]
        assert poam.control_cluster == "SI-3"
        assert poam.security_control_number == "SI-3, SI-3(1), SI-3(2)"
        # Multi-CCI cluster gets the enriched-narrative summary line that
        # names every covered control id.
        assert (
            "3 assessment objectives non-compliant" in poam.vulnerability_description
        )
        assert "SI-3, SI-3(1), SI-3(2)" in poam.vulnerability_description
        # Failing-CCI enumeration section is present and lists each CCI.
        assert "**Failing assessment objectives:**" in poam.vulnerability_description
        assert "CCI-001240" in poam.vulnerability_description
        assert "CCI-001241" in poam.vulnerability_description
        assert "CCI-001242" in poam.vulnerability_description

        links = session.exec(
            select(PoamObjective).where(PoamObjective.poam_id == poam.id)
        ).all()
        assert len(links) == 3
        linked_ids = {link.objective_id for link in links}
        assert linked_ids == {
            objs["SI-3"].id,
            objs["SI-3(1)"].id,
            objs["SI-3(2)"].id,
        }

    def test_distinct_base_controls_get_distinct_poams(
        self, session, poam_catalog, assess
    ) -> None:
        wb = poam_catalog["workbook"]
        objs = poam_catalog["objectives"]
        assess(wb.id, objs["AC-2"].id, ComplianceStatus.NON_COMPLIANT)
        assess(wb.id, objs["SI-3"].id, ComplianceStatus.NON_COMPLIANT)

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        clusters = sorted(p.control_cluster for p in created)
        assert clusters == ["AC-2", "SI-3"]

    def test_rerun_is_idempotent(self, session, poam_catalog, assess) -> None:
        """Second invocation must not create duplicate POAMs."""
        wb = poam_catalog["workbook"]
        assess(
            wb.id,
            poam_catalog["objectives"]["AC-2"].id,
            ComplianceStatus.NON_COMPLIANT,
        )

        first = generate_for_workbook(wb.id, session).created
        session.commit()
        assert len(first) == 1

        second = generate_for_workbook(wb.id, session).created
        session.commit()
        assert second == []  # nothing new created

        all_poams = session.exec(select(Poam)).all()
        assert len(all_poams) == 1

    def test_rerun_does_not_overwrite_assessor_edits(
        self, session, poam_catalog, assess
    ) -> None:
        """User edits to existing POAM survive re-running the generator."""
        wb = poam_catalog["workbook"]
        assess(
            wb.id,
            poam_catalog["objectives"]["AC-2"].id,
            ComplianceStatus.NON_COMPLIANT,
        )
        created = generate_for_workbook(wb.id, session).created
        session.commit()
        poam = created[0]

        # Assessor adjusts risk + status.
        poam.likelihood = RiskLevel.HIGH
        poam.impact = RiskLevel.HIGH
        poam.status = PoamStatus.ONGOING
        poam.comments = "assessor edited this"
        session.add(poam)
        session.commit()

        generate_for_workbook(wb.id, session)
        session.commit()
        session.refresh(poam)

        assert poam.likelihood == RiskLevel.HIGH
        assert poam.impact == RiskLevel.HIGH
        assert poam.status == PoamStatus.ONGOING
        assert poam.comments == "assessor edited this"


# ---------------------------------------------------------------------------
# Stale link pruning
# ---------------------------------------------------------------------------


class TestPruneStalePoamLinks:
    def test_keeps_links_when_assessment_still_nc(
        self, session, poam_catalog, assess
    ) -> None:
        wb = poam_catalog["workbook"]
        assess(
            wb.id,
            poam_catalog["objectives"]["AC-2"].id,
            ComplianceStatus.NON_COMPLIANT,
        )
        generate_for_workbook(wb.id, session)
        session.commit()

        deleted = _prune_stale_poam_links(wb.id, session)
        session.commit()
        assert deleted == 0
        assert len(session.exec(select(Poam)).all()) == 1
        assert len(session.exec(select(PoamObjective)).all()) == 1

    def test_removes_poam_when_only_link_becomes_compliant(
        self, session, poam_catalog, assess
    ) -> None:
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        a = assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)
        generate_for_workbook(wb.id, session)
        session.commit()
        assert session.exec(select(Poam)).first() is not None

        # Reassess: Compliant.
        a.status = ComplianceStatus.COMPLIANT
        session.add(a)
        session.commit()

        deleted = _prune_stale_poam_links(wb.id, session)
        session.commit()
        assert deleted == 1
        assert session.exec(select(Poam)).all() == []
        assert session.exec(select(PoamObjective)).all() == []
        assert session.exec(select(PoamMilestone)).all() == []

    def test_keeps_poam_when_one_of_many_links_becomes_compliant(
        self, session, poam_catalog, assess
    ) -> None:
        wb = poam_catalog["workbook"]
        objs = poam_catalog["objectives"]
        a1 = assess(wb.id, objs["SI-3"].id, ComplianceStatus.NON_COMPLIANT)
        assess(wb.id, objs["SI-3(1)"].id, ComplianceStatus.NON_COMPLIANT)
        generate_for_workbook(wb.id, session)
        session.commit()

        poams_before = session.exec(select(Poam)).all()
        assert len(poams_before) == 1
        assert (
            len(session.exec(select(PoamObjective)).all()) == 2
        ), "expected two CCI links before pruning"

        # One of the two CCIs becomes Compliant.
        a1.status = ComplianceStatus.COMPLIANT
        session.add(a1)
        session.commit()

        deleted = _prune_stale_poam_links(wb.id, session)
        session.commit()
        assert deleted == 0  # POAM not removed — still has the other link
        assert len(session.exec(select(Poam)).all()) == 1
        # Stale link is gone; remaining link is the still-NC enhancement.
        remaining_links = session.exec(select(PoamObjective)).all()
        assert len(remaining_links) == 1
        assert remaining_links[0].objective_id == objs["SI-3(1)"].id

    def test_generate_heals_then_creates(self, session, poam_catalog, assess) -> None:
        """generate_for_workbook prunes first, then rebuilds — re-running after
        an NC→Compliant transition must drop the stale POAM and not re-create
        one for the now-compliant CCI."""
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        a = assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)
        generate_for_workbook(wb.id, session)
        session.commit()
        assert len(session.exec(select(Poam)).all()) == 1

        # Reassess: Compliant.
        a.status = ComplianceStatus.COMPLIANT
        session.add(a)
        session.commit()

        created = generate_for_workbook(wb.id, session).created
        session.commit()
        assert created == []
        assert session.exec(select(Poam)).all() == []


# ---------------------------------------------------------------------------
# CRM responsibility filtering (v0.2 — CRM ingestion overlay)
# ---------------------------------------------------------------------------


class TestCrmResponsibilityFilter:
    """Provider / inherited / not_applicable suppress POAMs; hybrid annotates.

    Builds a synthetic CrmContext via monkeypatch instead of seeding
    Baseline/BaselineControl/WorkbookOverlay rows — these tests focus on
    the generator's filter wiring; build_crm_context has its own coverage
    in the engine test suite.
    """

    def _patch_crm(self, monkeypatch, entries):
        from cybersecurity_assessor.engine.crm_context import CrmContext, CrmEntry

        by_control = {
            cid: CrmEntry(
                control_id=cid,
                responsibility=resp,
                narrative=narr,
                source_baseline_id=999,
            )
            for cid, resp, narr in entries
        }
        ctx = CrmContext(by_control=by_control)
        monkeypatch.setattr(
            "cybersecurity_assessor.poam.generator.build_crm_context",
            lambda workbook_id, s: ctx,
        )

    def test_provider_responsibility_suppresses_poam(
        self, session, poam_catalog, assess, monkeypatch
    ) -> None:
        # Workbook fixture stores control_id in CCIS form ("AC-2"); the
        # generator normalizes via _ccis_to_oscal_control_id, so CRM
        # entries are keyed in OSCAL canonical form ("ac-2").
        self._patch_crm(monkeypatch, [("ac-2", "provider", None)])
        wb = poam_catalog["workbook"]
        assess(wb.id, poam_catalog["objectives"]["AC-2"].id, ComplianceStatus.NON_COMPLIANT)

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        assert created == []
        assert session.exec(select(Poam)).all() == []

    def test_inherited_responsibility_suppresses_poam(
        self, session, poam_catalog, assess, monkeypatch
    ) -> None:
        self._patch_crm(monkeypatch, [("ac-2", "inherited", "Covered by parent ATO.")])
        wb = poam_catalog["workbook"]
        assess(wb.id, poam_catalog["objectives"]["AC-2"].id, ComplianceStatus.NON_COMPLIANT)

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        assert created == []

    def test_not_applicable_responsibility_suppresses_poam(
        self, session, poam_catalog, assess, monkeypatch
    ) -> None:
        self._patch_crm(monkeypatch, [("ac-2", "not_applicable", None)])
        wb = poam_catalog["workbook"]
        assess(wb.id, poam_catalog["objectives"]["AC-2"].id, ComplianceStatus.NON_COMPLIANT)

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        assert created == []

    def test_customer_responsibility_does_not_filter(
        self, session, poam_catalog, assess, monkeypatch
    ) -> None:
        # Customer = local ownership, same path as no-overlay-attached.
        self._patch_crm(monkeypatch, [("ac-2", "customer", "Customer owns.")])
        wb = poam_catalog["workbook"]
        assess(wb.id, poam_catalog["objectives"]["AC-2"].id, ComplianceStatus.NON_COMPLIANT)

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        assert len(created) == 1
        # Customer-owned narratives are NOT prepended — no hybrid block.
        assert "Responsibility split" not in created[0].vulnerability_description

    def test_hybrid_keeps_poam_and_prepends_split_block(
        self, session, poam_catalog, assess, monkeypatch
    ) -> None:
        narrative = "Customer configures policies; provider hosts the engine."
        self._patch_crm(monkeypatch, [("si-3", "hybrid", narrative)])
        wb = poam_catalog["workbook"]
        # SI-3 cluster has one item in this fixture.
        assess(wb.id, poam_catalog["objectives"]["SI-3"].id, ComplianceStatus.NON_COMPLIANT)

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        assert len(created) == 1
        text = created[0].vulnerability_description
        assert "Responsibility split (from CRM overlay)" in text
        assert "si-3" in text
        assert narrative in text
        # Original vulnerability text still present after the prepended block.
        assert "SI-3" in text

    def test_mixed_cluster_drops_provider_items_keeps_others(
        self, session, poam_catalog, assess, monkeypatch
    ) -> None:
        """SI-3 + SI-3(1) + SI-3(2) cluster where SI-3(1) is provider-owned.

        Result: one POAM with only SI-3 and SI-3(2) attached. SI-3(1)
        gets dropped at the item level — the cluster as a whole still
        warrants remediation for the customer-owned portions.
        """
        self._patch_crm(monkeypatch, [("si-3.1", "provider", None)])
        wb = poam_catalog["workbook"]
        for ctl_id in ("SI-3", "SI-3(1)", "SI-3(2)"):
            assess(
                wb.id,
                poam_catalog["objectives"][ctl_id].id,
                ComplianceStatus.NON_COMPLIANT,
            )

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        assert len(created) == 1
        poam = created[0]
        # Only SI-3 and SI-3(2) survived the filter — SI-3(1) was provider.
        links = session.exec(
            select(PoamObjective).where(PoamObjective.poam_id == poam.id)
        ).all()
        objective_ids = {link.objective_id for link in links}
        assert objective_ids == {
            poam_catalog["objectives"]["SI-3"].id,
            poam_catalog["objectives"]["SI-3(2)"].id,
        }
        # security_control_number reflects the surviving items only.
        assert "SI-3(1)" not in poam.security_control_number
        assert "SI-3" in poam.security_control_number
        assert "SI-3(2)" in poam.security_control_number

    def test_entire_cluster_provider_owned_creates_no_poam(
        self, session, poam_catalog, assess, monkeypatch
    ) -> None:
        """All cluster items provider-owned → cluster yields no POAM."""
        self._patch_crm(
            monkeypatch,
            [
                ("si-3", "provider", None),
                ("si-3.1", "provider", None),
                ("si-3.2", "provider", None),
            ],
        )
        wb = poam_catalog["workbook"]
        for ctl_id in ("SI-3", "SI-3(1)", "SI-3(2)"):
            assess(
                wb.id,
                poam_catalog["objectives"][ctl_id].id,
                ComplianceStatus.NON_COMPLIANT,
            )

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        assert created == []


# ---------------------------------------------------------------------------
# Severity-aware milestone seeding
# ---------------------------------------------------------------------------


def _add_stig_evidence(session, *, path: str) -> Evidence:
    """Tiny Evidence row stand-in for a CKL; only the FK matters here."""
    ev = Evidence(
        path=path,
        sha256=f"sha-{path}",
        kind=EvidenceKind.STIG_CKL,
        size_bytes=1,
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    return ev


def _tag_evidence(session, evidence_id: int, objective_id: int) -> None:
    session.add(
        EvidenceTag(
            evidence_id=evidence_id,
            objective_id=objective_id,
            relevance=1.0,
            confidence=0.9,
            source="manual",
        )
    )
    session.commit()


def _add_stig_finding(
    session,
    evidence_id: int,
    *,
    rule_id: str,
    cci: str,
    severity: str = "medium",
    detail: str = "Setting not enforced per baseline.",
    status: FindingStatus = FindingStatus.OPEN,
) -> StigFinding:
    f = StigFinding(
        evidence_id=evidence_id,
        rule_id=rule_id,
        cci_refs=cci,
        severity=severity,
        status=status,
        finding_details=detail,
    )
    session.add(f)
    session.commit()
    session.refresh(f)
    return f


def _days_until(d: datetime) -> float:
    """Tolerant horizon comparison — wall-clock drift between POAM creation
    and assertion ought to be milliseconds, but allow a buffer so CI never
    flakes on slow runners. Coerces naive datetimes (SQLite round-trips strip
    tzinfo) to UTC so the subtraction never throws."""
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return (d - datetime.now(timezone.utc)).total_seconds() / 86400.0


class TestSeverityAwareMilestones:
    def test_cat_i_finding_drives_30_day_horizon_and_rule_milestone(
        self, session, poam_catalog, assess
    ) -> None:
        """One high-severity STIG finding → ~30-day completion + two
        milestones (generic + per-rule)."""
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        ev = _add_stig_evidence(session, path="file:///ckl/cat1.ckl")
        _tag_evidence(session, ev.id, ac2.id)
        _add_stig_finding(
            session,
            ev.id,
            rule_id="SV-CAT1",
            cci="CCI-000015",
            severity="high",
            detail="Privileged account review interval not enforced.",
        )

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        assert len(created) == 1
        poam = created[0]
        # Horizon: 30 days ± 1 day buffer for clock drift.
        assert poam.scheduled_completion_date is not None
        horizon = _days_until(poam.scheduled_completion_date)
        assert 29.0 <= horizon <= 31.0, f"expected ~30d, got {horizon}d"

        milestones = session.exec(
            select(PoamMilestone)
            .where(PoamMilestone.poam_id == poam.id)
            .order_by(PoamMilestone.id)
        ).all()
        assert len(milestones) == 2
        # First milestone is always the lead remediation task, now grounded in
        # the control's own requirement text (Control.statement/title) per the
        # grounded-remediation slice.
        assert "Develop and implement controls satisfying" in milestones[0].description
        assert "AC-2" in milestones[0].description
        # Second milestone names the corroborating rule + finding detail.
        assert "Remediate SV-CAT1" in milestones[1].description
        assert "Privileged account review" in milestones[1].description
        # All seeded milestones share the cluster's completion date.
        for ms in milestones:
            assert ms.scheduled_date == poam.scheduled_completion_date
            assert ms.completion_date is None

    def test_cat_ii_finding_keeps_90_day_horizon(
        self, session, poam_catalog, assess
    ) -> None:
        """Medium severity matches the legacy default — 90-day completion."""
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        ev = _add_stig_evidence(session, path="file:///ckl/cat2.ckl")
        _tag_evidence(session, ev.id, ac2.id)
        _add_stig_finding(
            session,
            ev.id,
            rule_id="SV-CAT2",
            cci="CCI-000015",
            severity="medium",
        )

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        poam = created[0]
        horizon = _days_until(poam.scheduled_completion_date)
        assert 89.0 <= horizon <= 91.0, f"expected ~90d, got {horizon}d"
        milestones = session.exec(
            select(PoamMilestone).where(PoamMilestone.poam_id == poam.id)
        ).all()
        assert len(milestones) == 2

    def test_no_findings_falls_back_to_90_day_horizon_and_single_milestone(
        self, session, poam_catalog, assess
    ) -> None:
        """Cluster has no tagged STIG findings → DEFAULT_LIKELIHOOD ×
        DEFAULT_IMPACT (both MODERATE) fallback in ``compute_risk`` →
        90d horizon, single generic milestone. Per alembic 0008,
        ``likelihood`` / ``impact`` themselves stay NULL (no defensible
        source) — only the derived ``raw_severity`` / ``residual_risk``
        carry the MODERATE fallback. Preserves the pre-Phase-2 horizon
        on no-evidence rows."""
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        poam = created[0]
        horizon = _days_until(poam.scheduled_completion_date)
        assert 89.0 <= horizon <= 91.0, f"expected ~90d, got {horizon}d"
        milestones = session.exec(
            select(PoamMilestone).where(PoamMilestone.poam_id == poam.id)
        ).all()
        assert len(milestones) == 1
        # Lead milestone is grounded in the control requirement (the fixture
        # seeds Control.title), not the bare placeholder.
        assert "Develop and implement controls satisfying" in milestones[0].description
        assert "AC-2" in milestones[0].description

    def test_mixed_severities_highest_wins_top_three_rules_seeded(
        self, session, poam_catalog, assess
    ) -> None:
        """Cluster with high + medium + low + extra → 30-day horizon
        (highest wins) and four milestones total (generic + top-3 rules).
        Verifies the dedup-by-rule-id cap as well."""
        wb = poam_catalog["workbook"]
        objs = poam_catalog["objectives"]
        assess(wb.id, objs["SI-3"].id, ComplianceStatus.NON_COMPLIANT)
        assess(wb.id, objs["SI-3(1)"].id, ComplianceStatus.NON_COMPLIANT)

        ev1 = _add_stig_evidence(session, path="file:///ckl/mix-a.ckl")
        ev2 = _add_stig_evidence(session, path="file:///ckl/mix-b.ckl")
        _tag_evidence(session, ev1.id, objs["SI-3"].id)
        _tag_evidence(session, ev2.id, objs["SI-3(1)"].id)
        # Five findings of varying severity; cap is 3 unique rules so
        # SV-EXTRA should NOT make it into the seeded milestone set.
        _add_stig_finding(
            session, ev1.id, rule_id="SV-HIGH",
            cci="CCI-001240", severity="high",
            detail="AV signatures stale on more than 25% of endpoints.",
        )
        _add_stig_finding(
            session, ev1.id, rule_id="SV-MED",
            cci="CCI-001240", severity="medium",
            detail="Real-time scan disabled on workstation image.",
        )
        _add_stig_finding(
            session, ev2.id, rule_id="SV-LOW",
            cci="CCI-001241", severity="low",
            detail="Log rotation interval exceeds policy.",
        )
        _add_stig_finding(
            session, ev2.id, rule_id="SV-EXTRA",
            cci="CCI-001241", severity="low",
            detail="Should not be seeded — over the 3-rule cap.",
        )
        # Duplicate rule_id — must not double-count against the cap.
        _add_stig_finding(
            session, ev2.id, rule_id="SV-HIGH",
            cci="CCI-001241", severity="high",
            detail="Same rule on a second host.",
        )

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        assert len(created) == 1
        poam = created[0]
        # Highest severity wins the horizon → 30 days, not 90 or 365.
        horizon = _days_until(poam.scheduled_completion_date)
        assert 29.0 <= horizon <= 31.0, f"expected ~30d, got {horizon}d"

        milestones = session.exec(
            select(PoamMilestone)
            .where(PoamMilestone.poam_id == poam.id)
            .order_by(PoamMilestone.id)
        ).all()
        # 1 generic + 3 unique rules (HIGH, MED, LOW). SV-EXTRA excluded
        # by the cap; the second SV-HIGH is deduped by rule_id.
        assert len(milestones) == 4
        descs = [m.description for m in milestones]
        assert "Develop and implement controls satisfying" in descs[0]
        rule_block = " ".join(descs[1:])
        assert "SV-HIGH" in rule_block
        assert "SV-MED" in rule_block
        assert "SV-LOW" in rule_block
        assert "SV-EXTRA" not in rule_block

    def test_rerun_does_not_seed_or_overwrite_milestones(
        self, session, poam_catalog, assess
    ) -> None:
        """Milestones live on the create-path only. Once a POAM exists,
        re-running the generator must NOT touch milestones — even after
        new STIG findings get tagged — so assessor edits in the UI survive.

        The vulnerability_description still rewrites (covered by
        test_generator_description.py); milestones do not.
        """
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        # First run — single milestone seeded (no STIG context yet).
        created = generate_for_workbook(wb.id, session).created
        session.commit()
        assert len(created) == 1
        poam_id = created[0].id
        original_completion = created[0].scheduled_completion_date

        # Assessor edits the seeded milestone in the UI.
        seeded = session.exec(
            select(PoamMilestone).where(PoamMilestone.poam_id == poam_id)
        ).all()
        assert len(seeded) == 1
        seeded[0].description = "ASSESSOR-EDITED MILESTONE TEXT"
        seeded[0].scheduled_date = datetime.now(timezone.utc) + timedelta(days=14)
        session.add(seeded[0])
        session.commit()
        edited_desc = seeded[0].description
        edited_date = seeded[0].scheduled_date

        # Now a high-severity STIG finding shows up — narrative will rewrite
        # (DRAFT, unlocked) but milestones MUST stay frozen.
        ev = _add_stig_evidence(session, path="file:///ckl/late.ckl")
        _tag_evidence(session, ev.id, ac2.id)
        _add_stig_finding(
            session, ev.id, rule_id="SV-LATECOMER",
            cci="CCI-000015", severity="high",
            detail="Late-arriving finding that must not seed a milestone.",
        )

        generate_for_workbook(wb.id, session)
        session.commit()

        # Milestone count and content unchanged.
        after = session.exec(
            select(PoamMilestone).where(PoamMilestone.poam_id == poam_id)
        ).all()
        assert len(after) == 1
        assert after[0].description == edited_desc
        assert after[0].scheduled_date == edited_date
        # Completion date on the POAM also unchanged — rewrite only touches
        # narrative + updated_at, not scheduled_completion_date.
        refreshed = session.get(Poam, poam_id)
        assert refreshed.scheduled_completion_date == original_completion
