"""Tests for the enriched vulnerability_description builder and the
DRAFT-rewrite / narrative-lock semantics added in the description-enrichment
slice.

Covers:
  - Section composition: summary line, failing-CCI enumeration, corroborating
    STIG findings, affected hosts, assessor narrative excerpts.
  - Precision-over-recall: missing sources omit their section silently
    (no empty headers).
  - Corroboration: STIG findings only surface when they are BOTH tagged to a
    cluster objective AND share a CCI with the cluster.
  - Re-run semantics: DRAFT POAMs rewrite when narrative changes; locked or
    non-DRAFT rows are left alone.
  - Near-Excel-limit (32000) cap with priority-ordered section trimming as a
    last-resort safety net (tests shrink the cap via monkeypatch to exercise it).
"""

from __future__ import annotations

import json

from cybersecurity_assessor.models import (
    ComplianceStatus,
    Evidence,
    EvidenceKind,
    EvidenceTag,
    FindingStatus,
    Poam,
    PoamStatus,
    RiskLevel,
    StigFinding,
)
from cybersecurity_assessor.poam.generator import generate_for_workbook


# ---------------------------------------------------------------------------
# Small helpers — keep test setup terse without re-deriving the catalog
# ---------------------------------------------------------------------------


def _add_evidence(session, *, path: str, hosts: list[str] | None = None) -> Evidence:
    ev = Evidence(
        path=path,
        sha256=f"sha-{path}",
        kind=EvidenceKind.STIG_CKL,
        size_bytes=1,
        host_inventory=json.dumps(hosts) if hosts else None,
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    return ev


def _tag(session, evidence_id: int, objective_id: int) -> None:
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


def _add_finding(
    session,
    evidence_id: int,
    *,
    rule_id: str,
    cci: str,
    severity: str = "medium",
    detail: str = "Setting not enforced.",
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


# ---------------------------------------------------------------------------
# Section composition
# ---------------------------------------------------------------------------


class TestSingleCciDescription:
    def test_summary_and_cci_section_present_no_optional_sections(
        self, session, poam_catalog, assess
    ) -> None:
        """No findings, no hosts → summary + CCI enumeration + narrative excerpt.

        The assess fixture seeds narrative_q="Test narrative." so the excerpt
        section appears; findings + hosts sections must NOT appear (precision
        over recall — no empty headers).
        """
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        assert len(created) == 1
        text = created[0].vulnerability_description

        # Summary line uses singular wording with the (control X) clause.
        assert "AC-2: 1 assessment objective non-compliant" in text
        assert "(control AC-2)" in text
        # CCI enumeration header + the one CCI ID present.
        assert "**Failing assessment objectives:**" in text
        assert "CCI-000015" in text
        # No corroborating findings / hosts → those headers must be absent.
        assert "Corroborating scan/STIG findings" not in text
        assert "Affected hosts" not in text
        # Default narrative excerpt block is present.
        assert "**Assessor narrative excerpts:**" in text
        assert "Test narrative." in text


class TestMultiCciWithStigFindings:
    def test_findings_surface_when_tagged_and_cci_matches(
        self, session, poam_catalog, assess
    ) -> None:
        wb = poam_catalog["workbook"]
        objs = poam_catalog["objectives"]
        assess(wb.id, objs["SI-3"].id, ComplianceStatus.NON_COMPLIANT)
        assess(wb.id, objs["SI-3(1)"].id, ComplianceStatus.NON_COMPLIANT)

        # Two evidence rows, each tagged to a different objective in cluster.
        ev1 = _add_evidence(session, path="file:///ckl/host-a.ckl")
        ev2 = _add_evidence(session, path="file:///ckl/host-b.ckl")
        _tag(session, ev1.id, objs["SI-3"].id)
        _tag(session, ev2.id, objs["SI-3(1)"].id)
        _add_finding(
            session, ev1.id, rule_id="SV-001", cci="CCI-001240",
            severity="high", detail="AV signature update interval exceeds policy.",
        )
        _add_finding(
            session, ev2.id, rule_id="SV-002", cci="CCI-001241",
            severity="medium", detail="Real-time scan disabled on workstation image.",
        )

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        text = created[0].vulnerability_description
        assert "**Corroborating scan/STIG findings:**" in text
        assert "SV-001" in text
        assert "SV-002" in text
        # Severity-sorted: high should appear before medium.
        assert text.index("SV-001") < text.index("SV-002")

    def test_finding_with_unrelated_cci_is_suppressed(
        self, session, poam_catalog, assess
    ) -> None:
        """A STIG finding tagged to the cluster but whose cci_refs lists no
        cluster CCI must NOT surface — that's the corroboration rule."""
        wb = poam_catalog["workbook"]
        objs = poam_catalog["objectives"]
        assess(wb.id, objs["SI-3"].id, ComplianceStatus.NON_COMPLIANT)

        ev = _add_evidence(session, path="file:///ckl/multi.ckl")
        _tag(session, ev.id, objs["SI-3"].id)
        # cci_refs is for a DIFFERENT control family (IA-5).
        _add_finding(
            session, ev.id, rule_id="SV-NOISE", cci="CCI-000200",
            severity="high", detail="Password complexity disabled.",
        )

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        text = created[0].vulnerability_description
        assert "SV-NOISE" not in text
        assert "Corroborating scan/STIG findings" not in text

    def test_closed_finding_is_suppressed(
        self, session, poam_catalog, assess
    ) -> None:
        """Only OPEN findings should appear in the narrative."""
        wb = poam_catalog["workbook"]
        objs = poam_catalog["objectives"]
        assess(wb.id, objs["SI-3"].id, ComplianceStatus.NON_COMPLIANT)

        ev = _add_evidence(session, path="file:///ckl/closed.ckl")
        _tag(session, ev.id, objs["SI-3"].id)
        _add_finding(
            session, ev.id, rule_id="SV-CLOSED", cci="CCI-001240",
            severity="high", status=FindingStatus.NOT_A_FINDING,
        )

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        text = created[0].vulnerability_description
        assert "SV-CLOSED" not in text
        assert "Corroborating scan/STIG findings" not in text


class TestAffectedHosts:
    def test_hosts_section_populated_from_evidence_inventory(
        self, session, poam_catalog, assess
    ) -> None:
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        ev = _add_evidence(
            session,
            path="file:///ckl/ac2.ckl",
            hosts=["host-alpha", "host-beta", "host-gamma"],
        )
        _tag(session, ev.id, ac2.id)

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        text = created[0].vulnerability_description
        assert "**Affected hosts (3):**" in text
        assert "host-alpha" in text
        assert "host-beta" in text
        assert "host-gamma" in text

    def test_host_cap_at_20_with_overflow_suffix(
        self, session, poam_catalog, assess
    ) -> None:
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        many_hosts = [f"host-{i:03d}" for i in range(25)]
        ev = _add_evidence(session, path="file:///ckl/big.ckl", hosts=many_hosts)
        _tag(session, ev.id, ac2.id)

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        text = created[0].vulnerability_description
        assert "**Affected hosts (25):**" in text
        # Overflow suffix names the omitted count.
        assert "(+5 more)" in text
        # First host shown; 21st (host-020) should NOT be in the rendered list
        # — verify by checking it isn't followed by ", host-020".
        assert "host-000" in text
        # Hosts past the cap are excluded from the comma-separated list.
        # Search for "host-020," (with comma) or "host-020 (+" — neither
        # should appear; only the parenthesised overflow note.
        assert ", host-020" not in text


# ---------------------------------------------------------------------------
# Re-run / rewrite semantics
# ---------------------------------------------------------------------------


class TestRerunRewritesDraft:
    def test_draft_unlocked_text_updates_when_evidence_changes(
        self, session, poam_catalog, assess
    ) -> None:
        """Run #1 builds POAM with no findings; run #2 — after STIG ingest —
        rewrites the same DRAFT POAM with the findings section added."""
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        created_first = generate_for_workbook(wb.id, session).created
        session.commit()
        assert len(created_first) == 1
        poam_id = created_first[0].id
        before = created_first[0].vulnerability_description
        assert "Corroborating scan/STIG findings" not in before

        # Now STIG findings get ingested + tagged.
        ev = _add_evidence(session, path="file:///ckl/late.ckl")
        _tag(session, ev.id, ac2.id)
        _add_finding(
            session, ev.id, rule_id="SV-LATE", cci="CCI-000015",
            severity="medium", detail="Account review interval not enforced.",
        )

        result_second = generate_for_workbook(wb.id, session)
        session.commit()

        # No new POAM — only a rewrite — so created list is empty and the
        # rewrite bucket has exactly the one row we rebuilt.
        assert result_second.created == []
        assert [p.id for p in result_second.rewritten] == [poam_id]

        # The original row's text changed in place.
        poam = session.get(Poam, poam_id)
        assert poam is not None
        assert poam.vulnerability_description != before
        assert "**Corroborating scan/STIG findings:**" in poam.vulnerability_description
        assert "SV-LATE" in poam.vulnerability_description

    def test_locked_narrative_is_not_overwritten(
        self, session, poam_catalog, assess
    ) -> None:
        """narrative_locked=True is honored even on DRAFT rows."""
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        created = generate_for_workbook(wb.id, session).created
        session.commit()
        poam = created[0]
        poam.vulnerability_description = "ASSESSOR-AUTHORED TEXT"
        poam.narrative_locked = True
        session.add(poam)
        session.commit()
        poam_id = poam.id

        # Add evidence that WOULD trigger a rewrite if unlocked.
        ev = _add_evidence(session, path="file:///ckl/ignored.ckl", hosts=["h1"])
        _tag(session, ev.id, ac2.id)
        _add_finding(
            session, ev.id, rule_id="SV-X", cci="CCI-000015",
            severity="high", detail="Should not appear in locked narrative.",
        )

        result = generate_for_workbook(wb.id, session)
        session.commit()

        refreshed = session.get(Poam, poam_id)
        assert refreshed.vulnerability_description == "ASSESSOR-AUTHORED TEXT"
        # The locked row must show up in locked_skipped — not rewritten,
        # not unchanged. The UI surfaces this bucket to the assessor as
        # "N locked edits preserved", which is the whole point of the lock.
        assert [p.id for p in result.locked_skipped] == [poam_id]
        assert result.rewritten == []

    def test_non_draft_status_is_not_overwritten(
        self, session, poam_catalog, assess
    ) -> None:
        """ONGOING / COMPLETED / RISK_ACCEPTED rows skip the rewrite gate even
        when narrative_locked is False — their text is part of the workflow
        record."""
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        created = generate_for_workbook(wb.id, session).created
        session.commit()
        poam = created[0]
        poam.status = PoamStatus.ONGOING
        poam.vulnerability_description = "IN-FLIGHT REMEDIATION NOTE"
        # Deliberately leave narrative_locked False — status alone should gate.
        session.add(poam)
        session.commit()
        poam_id = poam.id

        # Add evidence that WOULD rewrite if status was DRAFT.
        ev = _add_evidence(session, path="file:///ckl/skip.ckl")
        _tag(session, ev.id, ac2.id)
        _add_finding(
            session, ev.id, rule_id="SV-SKIP", cci="CCI-000015",
            severity="high", detail="Must not overwrite ongoing POAM.",
        )

        result = generate_for_workbook(wb.id, session)
        session.commit()

        refreshed = session.get(Poam, poam_id)
        assert refreshed.vulnerability_description == "IN-FLIGHT REMEDIATION NOTE"
        assert refreshed.status == PoamStatus.ONGOING
        # Non-draft rows go in their own bucket so the UI flash can
        # distinguish them from locked-edit preservation.
        assert [p.id for p in result.non_draft_skipped] == [poam_id]
        assert result.rewritten == []

    def test_rewrite_preserves_assessor_risk_edits(
        self, session, poam_catalog, assess
    ) -> None:
        """Rewriting the description doesn't touch risk fields the assessor
        has tuned."""
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

        created = generate_for_workbook(wb.id, session).created
        session.commit()
        poam = created[0]
        poam.likelihood = RiskLevel.HIGH
        poam.impact = RiskLevel.HIGH
        session.add(poam)
        session.commit()
        poam_id = poam.id

        # Add evidence so a rewrite happens.
        ev = _add_evidence(session, path="file:///ckl/risk.ckl")
        _tag(session, ev.id, ac2.id)
        _add_finding(
            session, ev.id, rule_id="SV-R", cci="CCI-000015",
            severity="medium", detail="Some new finding.",
        )

        generate_for_workbook(wb.id, session)
        session.commit()

        refreshed = session.get(Poam, poam_id)
        assert refreshed.likelihood == RiskLevel.HIGH
        assert refreshed.impact == RiskLevel.HIGH
        assert "SV-R" in refreshed.vulnerability_description


# ---------------------------------------------------------------------------
# Cap behavior
# ---------------------------------------------------------------------------


class TestDescriptionCap:
    def test_excerpts_trimmed_first_when_over_cap(
        self, session, poam_catalog, assess, monkeypatch
    ) -> None:
        """When the composed text would exceed _VULN_DESC_CAP, the excerpt
        section is dropped before findings/hosts/CCI sections.

        We shrink the cap to a value that fits summary + CCI list + findings +
        hosts but NOT the excerpts; that proves trim ordering without needing
        to manufacture 4 KB of plausible content.
        """
        monkeypatch.setattr(
            "cybersecurity_assessor.poam.generator._VULN_DESC_CAP", 400
        )
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        # Long single-sentence narrative — _first_sentence will return up to
        # 240 chars, large enough that its removal moves the total below cap.
        long_narrative = (
            "A long assessor narrative that takes up plenty of column-D real "
            "estate when rendered as an excerpt and pushes the composed text "
            "above the cap so the trimmer has to do real work here"
        )
        assess(
            wb.id,
            ac2.id,
            ComplianceStatus.NON_COMPLIANT,
            narrative=long_narrative,
        )

        ev = _add_evidence(
            session, path="file:///ckl/cap.ckl", hosts=["cap-host-1"]
        )
        _tag(session, ev.id, ac2.id)
        _add_finding(
            session, ev.id, rule_id="SV-CAP", cci="CCI-000015",
            severity="medium", detail="Some short finding.",
        )

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        text = created[0].vulnerability_description
        assert len(text) <= 400
        # Excerpt section was the casualty.
        assert "**Assessor narrative excerpts:**" not in text
        # Higher-priority sections survive intact.
        assert "**Failing assessment objectives:**" in text
        assert "**Corroborating scan/STIG findings:**" in text
        assert "SV-CAP" in text
        assert "**Affected hosts" in text
        assert "cap-host-1" in text

    def test_hosts_trimmed_before_findings_or_cci_list(
        self, session, poam_catalog, assess, monkeypatch
    ) -> None:
        """Cap below summary + CCI + findings + hosts but above summary + CCI
        + findings → hosts section gets dropped, findings stay."""
        monkeypatch.setattr(
            "cybersecurity_assessor.poam.generator._VULN_DESC_CAP", 350
        )
        wb = poam_catalog["workbook"]
        ac2 = poam_catalog["objectives"]["AC-2"]
        assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT, narrative="x")

        # Lots of hosts so the hosts section is the biggest optional block.
        ev = _add_evidence(
            session,
            path="file:///ckl/many.ckl",
            hosts=[f"verylonghostname-{i:04d}" for i in range(20)],
        )
        _tag(session, ev.id, ac2.id)
        _add_finding(
            session, ev.id, rule_id="SV-Z", cci="CCI-000015",
            severity="medium", detail="Short.",
        )

        created = generate_for_workbook(wb.id, session).created
        session.commit()

        text = created[0].vulnerability_description
        assert len(text) <= 350
        # Hosts dropped first after excerpts.
        assert "**Affected hosts" not in text
        assert "verylonghostname-0000" not in text
        # CCI list still intact.
        assert "**Failing assessment objectives:**" in text
