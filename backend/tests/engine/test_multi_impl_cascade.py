"""End-to-end cascade pin: Assessment + N AssessmentImplementation rows.

The persistence helper, the SAR _gather JOIN, and the POAM scope_label
cluster-key live in three separate modules and each has its own focused
test coverage. None of those tests currently builds an Assessment with
real child impl rows AND then drives BOTH the SAR exporter and the POAM
generator off the same fixture.

The gap matters: a regression in any single hop (e.g. SAR drops the
``.in_(...)`` JOIN, or POAM's cluster tuple stops including scope_label)
would let the unit tests stay green while the user-visible reports
silently flatten multi-scope findings back to a single row. This test
pins the cascade as one transaction so that breakage anywhere in the
chain — persistence → DB → SAR rollup → POAM clustering — surfaces.

Shape under test:
    AC-2 assessed NC overall, with two scope slices both NC:
        AWS GovCloud:  NC (provider-side compensating control failed)
        Azure Government: NC (customer-side misconfiguration)
    Expected:
        SAR _gather: data.rows has the AC-2 CCI; row.implementations has
            both scope_labels, both NC.
        POAM generate: TWO distinct draft POAMs, one per scope_label —
            the cluster key includes scope_label so the AWS finding and
            the Azure finding are remediated independently.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

# Make the backend package importable from any pytest cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.excel.ccis_reader import CcisIndex, CcisRow  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Assessment,
    AssessmentImplementation,
    ComplianceStatus,
    Control,
    Framework,
    NarrativeClass,
    Objective,
    Poam,
    Workbook,
)
from cybersecurity_assessor.poam.generator import generate_for_workbook  # noqa: E402
from cybersecurity_assessor.reports import sar as sar_module  # noqa: E402


# ---------------------------------------------------------------------------
# Fixture helpers (local — kept off the conftest fixtures since this file
# needs both reports/sar and poam/generator wired against one engine).
# ---------------------------------------------------------------------------


def _make_ccis_row(*, cci_id: str, control_id: str, excel_row: int) -> CcisRow:
    """Workbook-side stub with col-N empty so the DB overlay drives status.

    Matches the pattern from ``tests/reports/test_sar.py`` so the SAR's
    flatten loop falls through to the assessment row we just inserted.
    """
    return CcisRow(
        excel_row=excel_row,
        required=True,
        control_id=control_id,
        ap_acronym=f"{control_id}.1",
        cci_id=cci_id,
        implementation_status=None,
        designation=None,
        narrative=None,
        definition="The organization manages information system accounts.",
        guidance=None,
        procedures="Examine: account management procedures.",
        inherited=None,
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


def _seed(session: Session, wb_path: Path) -> tuple[Workbook, Objective]:
    """Seed Framework + Control + Objective + Workbook. Returns (wb, obj)."""
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)

    ctrl = Control(
        framework_id=fw.id,
        control_id="AC-2",
        title="Account Management",
        family="AC",
    )
    session.add(ctrl)
    session.commit()
    session.refresh(ctrl)

    obj = Objective(
        control_id_fk=ctrl.id,
        objective_id="CCI-000015",
        source="CCI",
        text="Define and document the types of accounts allowed.",
    )
    session.add(obj)
    session.commit()
    session.refresh(obj)

    wb = Workbook(path=str(wb_path), filename=wb_path.name, framework_id=fw.id)
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb, obj


def _make_assessment_with_impls(
    session: Session, *, workbook_id: int, objective_id: int
) -> Assessment:
    """Insert one parent Assessment + two NC child impls (AWS + Azure).

    Mirrors what ``persist_assessment_with_impls`` would have written
    after a per-scope assess run produced two NC plans:
      - parent.status = worst-of = NON_COMPLIANT
      - parent.narrative_q = composed "{scope_label}: {narrative}\\n\\n"
      - one AssessmentImplementation row per scope, each NC
    """
    a = Assessment(
        workbook_id=workbook_id,
        objective_id=objective_id,
        excel_row=42,
        status=ComplianceStatus.NON_COMPLIANT,
        tester="Noah Jaskolski",
        date_tested=datetime(2026, 6, 1, tzinfo=timezone.utc),
        narrative_q=(
            "AWS GovCloud: Compensating control for AC-2 not enforced.\n\n"
            "Azure Government: Conditional Access policy missing for "
            "privileged accounts."
        ),
        narrative_class=NarrativeClass.GAP_DESCRIBING,
        needs_review=False,
    )
    session.add(a)
    session.commit()
    session.refresh(a)

    session.add(
        AssessmentImplementation(
            assessment_id=a.id,
            scope_label="AWS GovCloud",
            source_baseline_id=None,
            responsibility="customer",
            status=ComplianceStatus.NON_COMPLIANT,
            narrative="Compensating control for AC-2 not enforced.",
            evidence_refs=None,
        )
    )
    session.add(
        AssessmentImplementation(
            assessment_id=a.id,
            scope_label="Azure Government",
            source_baseline_id=None,
            responsibility="customer",
            status=ComplianceStatus.NON_COMPLIANT,
            narrative="Conditional Access policy missing for privileged accounts.",
            evidence_refs=None,
        )
    )
    session.commit()
    session.refresh(a)
    return a


# ---------------------------------------------------------------------------
# The cascade
# ---------------------------------------------------------------------------


def test_multi_impl_cascade_through_sar_and_poam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One Assessment + 2 NC impl rows must surface in BOTH downstream paths.

    Pre-fix (any of: SAR drops the JOIN, POAM stops including scope_label
    in the cluster tuple, persistence helper appends instead of replacing)
    one of these assertions fails first; pinning both in the same test
    forces a regression author to confront the cascade as a unit rather
    than fix one half and silently break the other.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    wb_path = tmp_path / "ccis_multi_impl_cascade.xlsx"
    wb_path.touch()

    with Session(engine) as s:
        wb, obj = _seed(s, wb_path)
        assessment = _make_assessment_with_impls(
            s, workbook_id=wb.id, objective_id=obj.id
        )

        # ---- Hop 1: SAR _gather must see both impls on the AC-2 row. ----
        ccis_index = CcisIndex(
            workbook_path=wb_path,
            sheet_name="CCIS",
            rows=[
                _make_ccis_row(cci_id="CCI-000015", control_id="AC-2", excel_row=42),
            ],
        )
        monkeypatch.setattr(
            "cybersecurity_assessor.reports.sar.read_workbook_index",
            lambda path: ccis_index,
        )

        data = sar_module._gather(s, wb.id)

        # The CCI made it through (parent was NC, not needs_review).
        assert {r.cci_id for r in data.rows} == {"CCI-000015"}
        row = next(r for r in data.rows if r.cci_id == "CCI-000015")

        # Both impl rows attached to the SAR summary — this is the JOIN
        # that would silently break if AssessmentImplementation.assessment_id
        # were dropped from the .in_(...) filter, or the impl loader were
        # removed entirely.
        impl_scopes = sorted(i.scope_label for i in row.implementations)
        assert impl_scopes == ["AWS GovCloud", "Azure Government"]
        assert all(
            i.status == ComplianceStatus.NON_COMPLIANT for i in row.implementations
        )
        # Per-impl narratives survived round-trip — the SAR sub-table needs
        # this text to render Appendix D's 4-col layout (Scope/Resp/Status/Narr).
        narratives = {i.scope_label: i.narrative for i in row.implementations}
        assert "Compensating control" in narratives["AWS GovCloud"]
        assert "Conditional Access" in narratives["Azure Government"]

        # ---- Hop 2: POAM generator must split into two clusters. ----
        # Cluster key is (base_control_id, scope_label). Both impls are NC,
        # so the generator emits two distinct POAMs — one per scope — each
        # remediable on its own schedule by its own owner. Collapsing them
        # into a single AC-2 POAM would force a 3PAO to read evidence
        # across boundaries to figure out which finding closed when.
        created = generate_for_workbook(wb.id, s).created
        s.commit()

        assert len(created) == 2, (
            f"expected 2 scope-split POAMs, got {len(created)}: "
            f"{[p.control_cluster for p in created]}"
        )
        clusters = sorted(p.control_cluster for p in created)
        # Cluster id is encoded as ``"{base}|{scope_label}"`` by
        # poam.generator._encode_cluster_key — pin the literal form so a
        # change to the separator surfaces here too.
        assert clusters == ["AC-2|AWS GovCloud", "AC-2|Azure Government"]

        # Idempotence sanity: re-running the generator must NOT create
        # duplicate POAMs (the scope-split cluster keys must round-trip
        # through ``existing_poams_by_cluster``).
        second = generate_for_workbook(wb.id, s).created
        s.commit()
        assert second == []
        assert len(s.exec(select(Poam)).all()) == 2
