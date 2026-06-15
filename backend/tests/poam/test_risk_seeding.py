"""Tests for poam/risk.py STIG-severity → impact seeding and the audit-trail
helper used at generation time.

Covers two layers:

  - **Unit** — ``seed_impact_from_stig`` mapping for high/medium/low/unknown/
    None and the casing tolerance the generator relies on; ``record_risk_change``
    field-name validation + dedup behavior.

  - **Integration** — ``generate_for_workbook`` end-to-end: a non-compliant
    objective + tagged STIG finding seeds ``impact`` from the finding's
    severity, stamps ``impact_source = "auto"`` plus a citation rationale
    referencing the rule_id, and writes a matching ``PoamRiskHistory`` row.

Lives under ``backend/tests/poam/`` (alongside ``test_generator.py``) because
the integration tests reuse the same ``poam_catalog`` + ``assess`` fixtures
from this directory's ``conftest.py``.
"""

from __future__ import annotations

import pytest
from sqlmodel import select

from cybersecurity_assessor.models import (
    ComplianceStatus,
    Evidence,
    EvidenceKind,
    EvidenceTag,
    FindingStatus,
    PoamRiskHistory,
    RiskLevel,
    StigFinding,
)
from cybersecurity_assessor.poam.generator import generate_for_workbook
from cybersecurity_assessor.poam.risk import (
    RISK_HISTORY_FIELDS,
    record_risk_change,
    seed_impact_from_stig,
)


# ---------------------------------------------------------------------------
# Unit — seed_impact_from_stig mapping
# ---------------------------------------------------------------------------


class TestSeedImpactFromStig:
    def test_cat_i_high_maps_to_high(self) -> None:
        assert seed_impact_from_stig("high") == RiskLevel.HIGH

    def test_cat_ii_medium_maps_to_moderate(self) -> None:
        assert seed_impact_from_stig("medium") == RiskLevel.MODERATE

    def test_cat_iii_low_maps_to_low(self) -> None:
        assert seed_impact_from_stig("low") == RiskLevel.LOW

    def test_unknown_severity_returns_none(self) -> None:
        # Anything not in the canonical 3-CAT taxonomy abstains — the
        # generator leaves impact NULL rather than guessing.
        assert seed_impact_from_stig("informational") is None
        assert seed_impact_from_stig("critical") is None
        assert seed_impact_from_stig("") is None

    def test_null_severity_returns_none(self) -> None:
        assert seed_impact_from_stig(None) is None

    def test_casing_normalized(self) -> None:
        # CKL/ACAS exporters disagree on case — the helper must accept all.
        assert seed_impact_from_stig("HIGH") == RiskLevel.HIGH
        assert seed_impact_from_stig("Medium") == RiskLevel.MODERATE
        assert seed_impact_from_stig("LoW") == RiskLevel.LOW


# ---------------------------------------------------------------------------
# Unit — record_risk_change field-name validation + dedup
# ---------------------------------------------------------------------------


class TestRecordRiskChange:
    def test_rejects_unknown_field(self, session) -> None:
        with pytest.raises(ValueError, match="PoamRiskHistory.field"):
            record_risk_change(
                session,
                poam_id=1,
                field="not_a_real_field",
                prev_value=None,
                new_value=RiskLevel.HIGH,
                actor="test",
            )

    def test_accepts_canonical_fields(self, session) -> None:
        for i, field in enumerate(RISK_HISTORY_FIELDS):
            row = record_risk_change(
                session,
                poam_id=100 + i,
                field=field,
                prev_value=None,
                new_value=RiskLevel.MODERATE,
                actor="test",
            )
            assert row is not None
            assert row.field == field

    def test_returns_none_when_nothing_changed(self, session) -> None:
        # Same value, same rationale, same source ⇒ no audit row.
        row = record_risk_change(
            session,
            poam_id=200,
            field="impact",
            prev_value=RiskLevel.HIGH,
            new_value=RiskLevel.HIGH,
            actor="test",
            prev_rationale="same",
            new_rationale="same",
            prev_source="manual",
            new_source="manual",
        )
        assert row is None

    def test_records_rationale_only_change(self, session) -> None:
        # Assessor sharpens the wording but keeps MODERATE → still records.
        row = record_risk_change(
            session,
            poam_id=201,
            field="impact",
            prev_value=RiskLevel.MODERATE,
            new_value=RiskLevel.MODERATE,
            actor="noah",
            prev_rationale="seeded default",
            new_rationale="confirmed via boundary review",
            prev_source="auto",
            new_source="manual",
        )
        assert row is not None
        # Persistence string is the RiskLevel enum value (title-case).
        assert row.prev_value == "Moderate"
        assert row.new_value == "Moderate"
        assert row.prev_rationale == "seeded default"
        assert row.new_rationale == "confirmed via boundary review"

    def test_coerces_enum_to_persistence_string(self, session) -> None:
        row = record_risk_change(
            session,
            poam_id=202,
            field="impact",
            prev_value=None,
            new_value=RiskLevel.HIGH,
            actor="test",
        )
        assert row is not None
        # Audit row stores the persistence string (title-case enum value),
        # never the enum repr.
        assert row.new_value == "High"
        assert "RiskLevel" not in (row.new_value or "")


# ---------------------------------------------------------------------------
# Integration — generator stamps provenance from STIG findings
# ---------------------------------------------------------------------------


def _add_stig_evidence(session, *, path: str) -> Evidence:
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
    fix_text: str | None = None,
) -> StigFinding:
    f = StigFinding(
        evidence_id=evidence_id,
        rule_id=rule_id,
        cci_refs=cci,
        severity=severity,
        status=status,
        finding_details=detail,
        fix_text=fix_text,
    )
    session.add(f)
    session.commit()
    session.refresh(f)
    return f


class TestGeneratorSeedsImpactFromStig:
    def test_cat_i_finding_seeds_high_impact_with_auto_provenance(
        self, session, poam_catalog, assess
    ) -> None:
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        ev = _add_stig_evidence(session, path="file:///ckl/cat1.ckl")
        _tag_evidence(session, ev.id, ac2.id)
        _add_stig_finding(
            session,
            ev.id,
            rule_id="SV-1001",
            cci="CCI-000015",
            severity="high",
        )

        created = generate_for_workbook(wb.id, session).created
        session.commit()
        assert len(created) == 1
        poam = created[0]

        assert poam.impact == RiskLevel.HIGH
        assert poam.impact_source == "auto"
        assert poam.impact_rationale is not None
        assert "SV-1001" in poam.impact_rationale
        assert "high" in poam.impact_rationale.lower()

        # Likelihood has no STIG/CVSS signal to ground it, so it is seeded
        # with the MODERATE baseline default badged source="default" (an
        # honest un-owned value, not a STIG-derived "auto" call) rather
        # than left NULL — a POAM must always carry risk information. The
        # visible likelihood_rationale is left NULL for un-owned defaults
        # (the source badge says enough; the descriptive literal lives only
        # in the PoamRiskHistory audit row).
        assert poam.likelihood == RiskLevel.MODERATE
        assert poam.likelihood_source == "default"
        assert poam.likelihood_rationale is None

    def test_cat_ii_finding_seeds_moderate_impact(
        self, session, poam_catalog, assess
    ) -> None:
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        ev = _add_stig_evidence(session, path="file:///ckl/cat2.ckl")
        _tag_evidence(session, ev.id, ac2.id)
        _add_stig_finding(
            session,
            ev.id,
            rule_id="SV-2002",
            cci="CCI-000015",
            severity="medium",
        )

        created = generate_for_workbook(wb.id, session).created
        session.commit()
        poam = created[0]

        assert poam.impact == RiskLevel.MODERATE
        assert poam.impact_source == "auto"
        assert poam.impact_rationale is not None
        assert "SV-2002" in poam.impact_rationale

    def test_cat_iii_finding_seeds_low_impact(
        self, session, poam_catalog, assess
    ) -> None:
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        ev = _add_stig_evidence(session, path="file:///ckl/cat3.ckl")
        _tag_evidence(session, ev.id, ac2.id)
        _add_stig_finding(
            session,
            ev.id,
            rule_id="SV-3003",
            cci="CCI-000015",
            severity="low",
        )

        created = generate_for_workbook(wb.id, session).created
        session.commit()
        poam = created[0]

        assert poam.impact == RiskLevel.LOW
        assert poam.impact_source == "auto"

    def test_no_finding_seeds_moderate_default(
        self, session, poam_catalog, assess
    ) -> None:
        """No corroborating STIG finding → no "auto" seed, but the POAM
        still carries risk information: impact + likelihood fall back to
        the documented MODERATE baseline default, badged source="default".
        The "default" badge keeps provenance honest (un-owned starting
        value, NOT a STIG-derived "auto" call) so it never masquerades as
        evidence — while guaranteeing a POAM never ships with empty risk
        cells (the gap the assessor reported).
        """
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        created = generate_for_workbook(wb.id, session).created
        session.commit()
        poam = created[0]

        assert poam.impact == RiskLevel.MODERATE
        assert poam.impact_source == "default"
        # Un-owned baseline defaults leave the visible "why" column NULL —
        # the source badge already marks them un-owned. The descriptive
        # literal is preserved in the audit trail (asserted below), not on
        # the POAM row.
        assert poam.impact_rationale is None
        assert poam.likelihood == RiskLevel.MODERATE
        assert poam.likelihood_source == "default"
        assert poam.likelihood_rationale is None
        # raw_severity / residual_risk are populated from the defaults too.
        assert poam.raw_severity == RiskLevel.MODERATE
        assert poam.residual_risk == RiskLevel.MODERATE

        # Provenance is not lost: the audit trail still carries the
        # descriptive "baseline default pending review" literal for both
        # fields, so a 3PAO can still answer "where did this value come from?"
        rows = session.exec(
            select(PoamRiskHistory).where(PoamRiskHistory.poam_id == poam.id)
        ).all()
        impact_audit = next(r for r in rows if r.field == "impact")
        likelihood_audit = next(r for r in rows if r.field == "likelihood")
        assert impact_audit.new_rationale is not None
        assert "baseline default" in impact_audit.new_rationale.lower()
        assert likelihood_audit.new_rationale is not None
        assert "baseline default" in likelihood_audit.new_rationale.lower()

    def test_seeded_impact_writes_audit_row(
        self, session, poam_catalog, assess
    ) -> None:
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        ev = _add_stig_evidence(session, path="file:///ckl/audit.ckl")
        _tag_evidence(session, ev.id, ac2.id)
        _add_stig_finding(
            session,
            ev.id,
            rule_id="SV-AUD",
            cci="CCI-000015",
            severity="high",
        )

        created = generate_for_workbook(wb.id, session).created
        session.commit()
        poam = created[0]

        rows = session.exec(
            select(PoamRiskHistory).where(PoamRiskHistory.poam_id == poam.id)
        ).all()
        # Four rows: likelihood + impact + raw_severity + residual_risk.
        # likelihood + impact are now ALWAYS seeded ("auto" when a STIG
        # finding grounds impact, "default" otherwise), so both get a row.
        fields = {r.field for r in rows}
        assert fields == {"likelihood", "impact", "raw_severity", "residual_risk"}

        impact_row = next(r for r in rows if r.field == "impact")
        assert impact_row.prev_value is None
        # Persistence string is the title-case RiskLevel enum value.
        assert impact_row.new_value == "High"
        assert impact_row.new_source == "auto"
        assert impact_row.actor == "system:generator"
        assert impact_row.new_rationale is not None
        assert "SV-AUD" in impact_row.new_rationale

        # Likelihood has no STIG grounding so its audit row carries the
        # "default" badge, distinguishing it from the STIG-derived impact.
        likelihood_row = next(r for r in rows if r.field == "likelihood")
        assert likelihood_row.new_value == "Moderate"
        assert likelihood_row.new_source == "default"

    def test_unknown_severity_falls_back_to_default(
        self, session, poam_catalog, assess
    ) -> None:
        """An exotic severity string (e.g. CVSS-style "informational") is
        not mapped to a CAT level, so impact is NOT badged "auto" — but the
        POAM still carries the MODERATE baseline default badged "default"
        rather than shipping an empty risk cell."""
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        ev = _add_stig_evidence(session, path="file:///ckl/unknown.ckl")
        _tag_evidence(session, ev.id, ac2.id)
        _add_stig_finding(
            session,
            ev.id,
            rule_id="SV-WEIRD",
            cci="CCI-000015",
            severity="informational",
        )

        created = generate_for_workbook(wb.id, session).created
        session.commit()
        poam = created[0]
        assert poam.impact == RiskLevel.MODERATE
        assert poam.impact_source == "default"


# ---------------------------------------------------------------------------
# Integration — generator populates Mitigations + Resources required
# ---------------------------------------------------------------------------


class TestGeneratorPopulatesMitigationsAndResources:
    """The screenshot bug: a generated POAM rendered blank Mitigations and
    Resources required cells. The generator must always populate both — the
    Mitigations field grounded in verbatim STIG fix text when available (or
    the requirement-anchored remediation sentence as a fallback), and the
    Resources field as an explicitly-labeled, un-costed labor estimate.
    """

    def test_stig_fix_text_quoted_verbatim_in_mitigations(
        self, session, poam_catalog, assess
    ) -> None:
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        fix = "Set the registry value HKLM\\...\\AuditPolicy to 1 per the baseline."
        ev = _add_stig_evidence(session, path="file:///ckl/mit.ckl")
        _tag_evidence(session, ev.id, ac2.id)
        _add_stig_finding(
            session,
            ev.id,
            rule_id="SV-MIT-1",
            cci="CCI-000015",
            severity="medium",
            fix_text=fix,
        )

        created = generate_for_workbook(wb.id, session).created
        session.commit()
        poam = created[0]

        # Mitigations carries the verbatim fix text, attributed to the rule_id,
        # under the "verbatim STIG fix text" header.
        assert poam.mitigations is not None
        assert fix in poam.mitigations
        assert "SV-MIT-1" in poam.mitigations
        assert "verbatim STIG fix text" in poam.mitigations

    def test_resources_required_is_labeled_uncosted_estimate(
        self, session, poam_catalog, assess
    ) -> None:
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        created = generate_for_workbook(wb.id, session).created
        session.commit()
        poam = created[0]

        assert poam.resources_required is not None
        # Never masquerades as a final number — the assessor owns the estimate.
        assert "pending assessor" in poam.resources_required.lower()
        assert "ISSO" in poam.resources_required

    def test_no_stig_finding_falls_back_to_grounded_remediation(
        self, session, poam_catalog, assess
    ) -> None:
        """No STIG fix text to quote → Mitigations anchors to the control's own
        requirement (here AC-2's title) rather than rendering blank, and
        Resources is still populated."""
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        created = generate_for_workbook(wb.id, session).created
        session.commit()
        poam = created[0]

        assert poam.mitigations is not None
        assert poam.mitigations.strip() != ""
        # Requirement-anchored fallback (no verbatim STIG header).
        assert "verbatim STIG fix text" not in poam.mitigations
        assert "AC-2" in poam.mitigations
        assert poam.resources_required is not None
        assert poam.resources_required.strip() != ""

    def test_rewrite_backfills_blank_existing_draft(
        self, session, poam_catalog, assess
    ) -> None:
        """A pre-fix DRAFT POAM with blank Mitigations/Resources gets backfilled
        on the next generate pass (the screenshot bug's repair path)."""
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        ev = _add_stig_evidence(session, path="file:///ckl/backfill.ckl")
        _tag_evidence(session, ev.id, ac2.id)
        _add_stig_finding(
            session,
            ev.id,
            rule_id="SV-BF-1",
            cci="CCI-000015",
            severity="medium",
            fix_text="Disable the legacy protocol per the STIG.",
        )

        poam = generate_for_workbook(wb.id, session).created[0]
        session.commit()

        # Simulate a pre-fix row: blank out both fields, then regenerate.
        poam.mitigations = ""
        poam.resources_required = None
        session.add(poam)
        session.commit()

        result = generate_for_workbook(wb.id, session)
        session.commit()
        session.refresh(poam)

        assert poam in result.rewritten
        assert "SV-BF-1" in (poam.mitigations or "")
        assert (poam.resources_required or "").strip() != ""

    def test_rewrite_preserves_assessor_edited_mitigations(
        self, session, poam_catalog, assess
    ) -> None:
        """An assessor who has written into Mitigations keeps their text — the
        generator only backfills when the field is empty, never clobbers."""
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        ev = _add_stig_evidence(session, path="file:///ckl/keep.ckl")
        _tag_evidence(session, ev.id, ac2.id)
        _add_stig_finding(
            session,
            ev.id,
            rule_id="SV-KEEP-1",
            cci="CCI-000015",
            severity="medium",
            fix_text="Auto-generated fix that must NOT overwrite the edit.",
        )

        poam = generate_for_workbook(wb.id, session).created[0]
        session.commit()

        assessor_text = "Compensating control: host isolated on a dedicated VLAN."
        poam.mitigations = assessor_text
        session.add(poam)
        session.commit()

        generate_for_workbook(wb.id, session)
        session.commit()
        session.refresh(poam)

        assert poam.mitigations == assessor_text
        assert "Auto-generated fix" not in poam.mitigations
