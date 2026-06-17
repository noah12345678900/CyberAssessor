"""Edge-case audit tests for the v0.2 multi-implementation backbone.

Created by the impl-persistence audit (night-shift/sharepoint-boundary-sweep).
Each test pins one silent-failure mode identified while reading
``engine/impl_persistence.py``, ``engine/assessor.py`` (rollup helpers),
``baselines/scope_labels.py``, ``models.py`` (UniqueConstraint), and the
consumer call sites in ``reports/sar.py``, ``poam/generator.py``,
``routes/controls.py``.

The contracts pinned here:

* :func:`compose_rolled_narrative` returns ``""`` on empty input — and on
  inputs whose narratives are all blank. The persistence helper must NOT
  overwrite ``Assessment.narrative_q`` with that empty string.
* :func:`compute_rollup_status` raises on empty input, and is
  deterministic / worst-of across NC/Compliant/NA combinations.
* :func:`persist_assessment_with_impls` replaces (not appends) impl rows
  on UPDATE — repeated calls do not violate the UniqueConstraint on
  ``(assessment_id, scope_label)``.
* The same helper, called with ``is_new=True`` against an assessment
  that already has impl rows, DOES raise IntegrityError — pinning the
  contract that callers must never lie about ``is_new``.
* Hard-abstain decisions (status=None) leave the parent
  ``status``/``narrative_q`` untouched even when deterministic impl
  rows are written from the CRM.
* :func:`normalize_scope_label` documents (and currently does NOT
  reject) ``"On-Premises"`` as user input — a documented silent gap
  flagged with FIXME in the source.

Backward compatibility: pre-v0.2 Assessment rows have zero impl
children and existing reader paths must keep reading parent
``status``/``narrative_q``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, SQLModel, create_engine, select
from sqlmodel.pool import StaticPool

# Ensure backend package is importable when pytest runs from any cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402 — register tables
from cybersecurity_assessor.baselines.scope_labels import (  # noqa: E402
    ON_PREM_LABEL,
    normalize_scope_label,
)
from cybersecurity_assessor.engine.assessor import (  # noqa: E402
    Decision,
    ImplementationPlan,
    compose_rolled_narrative,
    compute_rollup_status,
)
from cybersecurity_assessor.engine.crm_context import (  # noqa: E402
    CrmContext,
    ImplementationSlice,
)
from cybersecurity_assessor.engine.impl_persistence import (  # noqa: E402
    persist_assessment_with_impls,
)
from cybersecurity_assessor.excel.ccis_reader import (  # noqa: E402
    _ccis_to_oscal_control_id,
    _normalize_control,
)
from cybersecurity_assessor.models import (  # noqa: E402
    Assessment,
    AssessmentImplementation,
    ComplianceStatus,
    NarrativeClass,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _decision(status: ComplianceStatus | None = ComplianceStatus.COMPLIANT) -> Decision:
    return Decision(
        cci_id="CCI-000001",
        excel_row=10,
        accepted=status is not None,
        status=status,
        narrative="Examined the policy and confirmed it is in place." if status else None,
        narrative_class=NarrativeClass.COMPLIANCE_AFFIRMING,
        source="llm",
        rule=None,
    )


def _parent(
    *,
    status: ComplianceStatus = ComplianceStatus.COMPLIANT,
    narrative_q: str = "Parent narrative pre-rollup.",
    needs_review: bool = False,
) -> Assessment:
    # Minimal Assessment that satisfies NOT NULL columns; objective_id is
    # an unenforced FK in the unit DB so we can use a sentinel int.
    from datetime import datetime, timezone

    return Assessment(
        objective_id=1,
        status=status,
        tester="Noah Jaskolski",
        date_tested=datetime.now(timezone.utc),
        narrative_q=narrative_q,
        narrative_class=NarrativeClass.COMPLIANCE_AFFIRMING,
        needs_review=needs_review,
    )


# ---------------------------------------------------------------------------
# Display-form control_id resolves the OSCAL-keyed CRM slices
# ---------------------------------------------------------------------------
#
# Regression lock for the silent-keying bug: every REAL caller
# (routes/controls.py x5, engine/crm_backfill.py) passes
# ``control_id=row.control_id`` — the workbook DISPLAY form ("AC-2(1)",
# "PE-3"). But ``CrmContext.implementations`` keys ``by_control_impls`` on
# the OSCAL canonical form ("ac-2.1", "pe-3"), produced by
# ``build_crm_context`` joining the OSCAL-keyed ``Control`` table. Before the
# fix, ``persist_assessment_with_impls`` looked up the raw display id, the
# dict missed, ``slices`` came back ``[]``, NO AssessmentImplementation rows
# were ever written for any real call, and a fully-inherited multi-CRM
# control kept only the single latest-attach short-circuit narrative (one
# cloud). The whole existing suite missed it because it hardcodes the OSCAL
# form ``control_id="ac-2.1"`` — matching the key by accident.
#
# These tests call with the DISPLAY form and assert the impl rows DO land and
# the parent narrative_q composes BOTH scopes. If a future refactor drops the
# normalization in impl_persistence.py, these fail loudly.


@pytest.mark.parametrize(
    "display_id, oscal_key",
    [
        ("AC-2(1)", "ac-2.1"),
        ("PE-3", "pe-3"),
        ("ac-2.1", "ac-2.1"),  # already OSCAL — idempotent
        ("pe-3", "pe-3"),
    ],
)
def test_control_id_normalizer_maps_display_to_oscal(display_id, oscal_key):
    """The normalizer the persistence lookup depends on — fast unit guard.

    ``persist_assessment_with_impls`` resolves ``control_id`` via
    ``_ccis_to_oscal_control_id(_normalize_control(...))`` before the slice
    lookup. Pin that this maps display→OSCAL AND is idempotent on an already-
    OSCAL id (so the existing OSCAL-form tests stay green).
    """
    assert _ccis_to_oscal_control_id(_normalize_control(display_id)) == oscal_key


@pytest.mark.parametrize(
    "display_id, oscal_key",
    [
        ("AC-2(1)", "ac-2.1"),  # enhancement form
        ("PE-3", "pe-3"),       # base-control form
    ],
)
def test_display_form_control_id_resolves_oscal_keyed_crm(
    session, display_id, oscal_key
):
    """Display-form control_id must resolve OSCAL-keyed by_control_impls.

    Two scope-labeled CRM slices (AWS GovCloud + Azure Government), both
    ``inherited``. Calling with the workbook DISPLAY id must still hit the
    OSCAL-keyed slice group: 2 impl rows written, parent narrative_q composes
    both clouds. This is the end-to-end lock for the keying fix.
    """
    crm = CrmContext(
        by_control_impls={
            oscal_key: [
                ImplementationSlice(
                    scope_label="AWS GovCloud",
                    responsibility="inherited",
                    narrative="AWS GovCloud datacenters enforce physical access.",
                    source_baseline_id=1,
                ),
                ImplementationSlice(
                    scope_label="Azure Government",
                    responsibility="inherited",
                    narrative="Microsoft Azure Government enforces physical access.",
                    source_baseline_id=2,
                ),
            ]
        }
    )
    parent = _parent()
    pid = persist_assessment_with_impls(
        session,
        assessment=parent,
        decision=_decision(),
        crm_context=crm,
        control_id=display_id,  # DISPLAY form — what every real caller passes
        is_new=True,
    )
    session.commit()

    rows = session.exec(
        select(AssessmentImplementation).where(
            AssessmentImplementation.assessment_id == pid
        )
    ).all()
    # Both scopes landed — the lookup hit despite the display-form input.
    assert len(rows) == 2, (
        "display-form control_id failed to resolve OSCAL-keyed CRM slices — "
        "the keying bug regressed (slices came back empty)"
    )
    assert {r.scope_label for r in rows} == {"AWS GovCloud", "Azure Government"}
    # Parent narrative composes BOTH clouds — not just the latest attach.
    assert "AWS GovCloud:" in parent.narrative_q
    assert "Azure Government:" in parent.narrative_q


def test_display_form_na_both_scopes_composes_both(session):
    """NA+NA via display-form id: both scopes NOT_APPLICABLE, both narrated.

    The not_applicable branch had the same dependency on the slice lookup;
    pin it here so the N/A multi-CRM path can't silently regress to a single-
    scope parent narrative either.
    """
    crm = CrmContext(
        by_control_impls={
            "ac-18": [
                ImplementationSlice(
                    scope_label="AWS GovCloud",
                    responsibility="not_applicable",
                    narrative="Not applicable on AWS GovCloud — no such surface.",
                    source_baseline_id=1,
                ),
                ImplementationSlice(
                    scope_label="Azure Government",
                    responsibility="not_applicable",
                    narrative="Not applicable on Azure Government — no such surface.",
                    source_baseline_id=2,
                ),
            ]
        }
    )
    parent = _parent(status=ComplianceStatus.NOT_APPLICABLE)
    pid = persist_assessment_with_impls(
        session,
        assessment=parent,
        decision=_decision(status=ComplianceStatus.NOT_APPLICABLE),
        crm_context=crm,
        control_id="AC-18",  # DISPLAY form
        is_new=True,
    )
    session.commit()

    rows = session.exec(
        select(AssessmentImplementation).where(
            AssessmentImplementation.assessment_id == pid
        )
    ).all()
    assert len(rows) == 2
    assert all(r.status is ComplianceStatus.NOT_APPLICABLE for r in rows)
    assert parent.status is ComplianceStatus.NOT_APPLICABLE
    assert "AWS GovCloud:" in parent.narrative_q
    assert "Azure Government:" in parent.narrative_q


# ---------------------------------------------------------------------------
# compute_rollup_status — determinism + worst-of priority
# ---------------------------------------------------------------------------


def test_rollup_empty_raises_value_error():
    """Pre-v0.2 callers must never invoke rollup with zero impls."""
    with pytest.raises(ValueError):
        compute_rollup_status([])


def test_rollup_worst_of_nc_beats_compliant():
    """NC + Compliant → NC. Pins the worst-of priority."""
    got = compute_rollup_status(
        [ComplianceStatus.COMPLIANT, ComplianceStatus.NON_COMPLIANT]
    )
    assert got is ComplianceStatus.NON_COMPLIANT


def test_rollup_compliant_beats_na():
    """Compliant + NA → Compliant. NA is the weakest signal."""
    got = compute_rollup_status(
        [ComplianceStatus.NOT_APPLICABLE, ComplianceStatus.COMPLIANT]
    )
    assert got is ComplianceStatus.COMPLIANT


def test_rollup_all_none_returns_undetermined():
    """All-None input → None (undetermined / needs-review), NOT a confident NA.

    Pins the precision-over-recall contract: an all-abstain set of impl rows
    must not silently roll up to a clean NOT_APPLICABLE verdict. ``None`` is
    this codebase's representation of "undetermined"; the parent's
    ``needs_review`` flag carries the real signal. The persistence helper's
    ``decision.status is not None`` guard ensures this None is never written
    to ``Assessment.status``.
    """
    got = compute_rollup_status([None, None])
    assert got is None


# ---------------------------------------------------------------------------
# compose_rolled_narrative — silent-empty-string bug
# ---------------------------------------------------------------------------


def test_compose_rolled_narrative_all_blank_returns_empty_string():
    """BUG A: composing all-blank-narrative plans silently returns ``""``.

    The composer skips blank narratives (defensive against a validator
    miss), but if EVERY plan is blank it returns an empty string. The
    persistence helper at impl_persistence.py:111 then assigns that empty
    string to ``Assessment.narrative_q`` — silently destroying the parent
    narrative. This test pins the current behavior so the caller can be
    fixed to either (a) raise here, or (b) gate the assignment in the
    helper.
    """
    plans = [
        ImplementationPlan(
            scope_label="AWS GovCloud",
            responsibility="customer",
            status=ComplianceStatus.COMPLIANT,
            narrative="   ",  # whitespace-only
            evidence_refs=None,
            source_baseline_id=1,
        ),
        ImplementationPlan(
            scope_label=ON_PREM_LABEL,
            responsibility="customer",
            status=ComplianceStatus.COMPLIANT,
            narrative="",
            evidence_refs=None,
            source_baseline_id=None,
        ),
    ]
    assert compose_rolled_narrative(plans) == ""


def test_compose_rolled_narrative_prefixes_scope_label():
    """Affirms ``{scope_label}: {narrative}`` is the format the validator
    template-phrase table relies on. See
    ``feedback_validator_template_phrase_drift.md``.
    """
    plans = [
        ImplementationPlan(
            scope_label="AWS GovCloud",
            responsibility="customer",
            status=ComplianceStatus.COMPLIANT,
            narrative="Confirmed via attached policy.",
            evidence_refs=None,
            source_baseline_id=1,
        )
    ]
    out = compose_rolled_narrative(plans)
    assert out.startswith("AWS GovCloud: ")
    assert "Confirmed via attached policy." in out


# ---------------------------------------------------------------------------
# persist_assessment_with_impls — replace-don't-append semantics
# ---------------------------------------------------------------------------


def test_update_replaces_prior_impls_no_unique_violation(session):
    """UPDATE branch deletes prior impl rows; second write must not raise."""
    assessment = _parent()
    crm = CrmContext(
        by_control_impls={
            "ac-2.1": [
                ImplementationSlice(
                    scope_label="AWS GovCloud",
                    responsibility="customer",
                    narrative=None,
                    source_baseline_id=1,
                ),
            ]
        }
    )
    pid = persist_assessment_with_impls(
        session,
        assessment=assessment,
        decision=_decision(),
        crm_context=crm,
        control_id="ac-2.1",
        is_new=True,
    )
    session.commit()

    # Second call with is_new=False should DELETE-then-INSERT the same
    # (assessment_id, "AWS GovCloud") row instead of violating the
    # UniqueConstraint.
    pid2 = persist_assessment_with_impls(
        session,
        assessment=assessment,
        decision=_decision(),
        crm_context=crm,
        control_id="ac-2.1",
        is_new=False,
    )
    session.commit()
    assert pid == pid2

    rows = session.exec(
        select(AssessmentImplementation).where(
            AssessmentImplementation.assessment_id == pid
        )
    ).all()
    assert len(rows) == 1
    assert rows[0].scope_label == "AWS GovCloud"


def test_is_new_lie_against_existing_impls_raises_integrity_error(session):
    """Caller-contract pin: passing ``is_new=True`` for a parent that
    already has impl rows MUST raise IntegrityError. The helper takes
    ``is_new`` at face value; lying about it bypasses the replace branch
    and trips the UniqueConstraint. This pin documents the contract so a
    future caller doesn't silently corrupt the table.
    """
    assessment = _parent()
    crm = CrmContext(
        by_control_impls={
            "ac-2.1": [
                ImplementationSlice(
                    scope_label="AWS GovCloud",
                    responsibility="customer",
                    narrative=None,
                    source_baseline_id=1,
                ),
            ]
        }
    )
    persist_assessment_with_impls(
        session,
        assessment=assessment,
        decision=_decision(),
        crm_context=crm,
        control_id="ac-2.1",
        is_new=True,
    )
    session.commit()

    with pytest.raises(IntegrityError):
        persist_assessment_with_impls(
            session,
            assessment=assessment,
            decision=_decision(),
            crm_context=crm,
            control_id="ac-2.1",
            is_new=True,  # the lie
        )
        session.commit()
    session.rollback()


# ---------------------------------------------------------------------------
# Abstain preservation — parent fields untouched, deterministic impls written
# ---------------------------------------------------------------------------


def test_abstain_preserves_parent_status_and_narrative(session):
    """Decision.status=None ⇒ helper does NOT overwrite parent fields,
    EVEN when deterministic impl rows (provider/inherited/NA) exist.

    Pins ``feedback_precision_over_recall.md``: an abstain on the
    customer side must keep the reviewer flag visible at the parent. The
    deterministic impl rows still land in the DB as inheritance receipts.
    """
    coerced_narrative = "(abstain — pending human review)"
    parent = _parent(
        status=ComplianceStatus.NON_COMPLIANT,
        narrative_q=coerced_narrative,
        needs_review=True,
    )
    crm = CrmContext(
        by_control_impls={
            "ac-2.1": [
                ImplementationSlice(
                    scope_label="AWS GovCloud",
                    responsibility="inherited",
                    narrative="Customer inherits AWS GovCloud.",
                    source_baseline_id=1,
                ),
            ]
        }
    )
    persist_assessment_with_impls(
        session,
        assessment=parent,
        decision=_decision(status=None),  # hard abstain
        crm_context=crm,
        control_id="ac-2.1",
        is_new=True,
    )
    session.commit()

    # Parent untouched.
    assert parent.status is ComplianceStatus.NON_COMPLIANT
    assert parent.narrative_q == coerced_narrative
    assert parent.needs_review is True

    # Deterministic inheritance receipt persisted anyway.
    rows = session.exec(
        select(AssessmentImplementation).where(
            AssessmentImplementation.assessment_id == parent.id
        )
    ).all()
    assert len(rows) == 1
    assert rows[0].status is ComplianceStatus.COMPLIANT
    assert rows[0].responsibility == "inherited"


# ---------------------------------------------------------------------------
# Pre-v0.2 fallback — zero impls, no helper call, parent fields preserved
# ---------------------------------------------------------------------------


def test_no_crm_slices_preserves_parent_and_writes_zero_impls(session):
    """Empty CrmContext.implementations(...) → helper writes the parent
    and zero impl rows. Parent.status/narrative_q stay exactly as the
    caller set them (the legacy single-impl behavior).
    """
    parent = _parent(narrative_q="Single-scope verdict.")
    persist_assessment_with_impls(
        session,
        assessment=parent,
        decision=_decision(),
        crm_context=CrmContext.empty(),
        control_id="ac-2.1",
        is_new=True,
    )
    session.commit()

    assert parent.status is ComplianceStatus.COMPLIANT
    assert parent.narrative_q == "Single-scope verdict."

    rows = session.exec(
        select(AssessmentImplementation).where(
            AssessmentImplementation.assessment_id == parent.id
        )
    ).all()
    assert rows == []


# ---------------------------------------------------------------------------
# scope_labels — silent gap: ON_PREM_LABEL is NOT rejected at normalization
# ---------------------------------------------------------------------------


def test_normalize_scope_label_intentionally_roundtrips_on_prem():
    """``normalize_scope_label`` is a pure normalizer, not a validator. It
    canonicalizes ``ON_PREM_LABEL`` casings so ``is_on_prem()`` can do
    equality comparisons against label values pulled out of the DB. The
    "ON_PREM_LABEL is reserved at ingest" guarantee lives at the route
    layer (``POST /api/catalog/overlays/import`` raises 422 — see
    ``test_import_crm_with_on_premises_scope_label_returns_422``). This
    test pins the library contract so future refactors don't break
    ``is_on_prem`` by adding a reject path here.
    """
    assert normalize_scope_label("On-Premises") == ON_PREM_LABEL
    assert normalize_scope_label("on-premises") == ON_PREM_LABEL
    assert normalize_scope_label("  On-Premises  ") == ON_PREM_LABEL
