"""Route-layer regression tests for the abstain silent-drop fix.

History: see ``feedback_abstain_status_none_drops.md`` and the unit-level
sibling ``test_abstain_coercion.py``. The kernel's ``_abstain()`` returns
``Decision(accepted=True, status=<maybe None>, narrative=<maybe None>,
needs_review=True)`` on the explicit contract that the route persists the
row so the reviewer queue surfaces it. Before the fix, both
Assessment-write sites in ``routes/controls.py`` gated on
``status is not None and narrative`` and silently dropped any hard-abstain
row — CCI-002124 and CCI-002127 carried four ``EvidenceTag`` rows each and
zero ``Assessment`` rows because the LLM produced ``narrative=None`` and
the gate failed.

``test_abstain_coercion`` already pins the helper's contract in
isolation. This module exercises the *integration*: a real route call
through ``Assessor`` with a stub LLM that drives an abstain Decision,
followed by a direct DB read to prove the row landed with
``needs_review=True`` and a coerced ``status``. Both ``/api/controls/assess``
and ``/api/controls/assess-batch`` get coverage — the historical bug had
TWO write sites and a future refactor could re-break either independently.

How the abstain is forced: ``Assessor`` reads ``proposal.abstain`` and
routes through ``_abstain()`` with ``narrative=None`` (see
``assessor.py:763-780`` and ``_abstain`` at ``assessor.py:1277-1344``).
That yields ``Decision(accepted=True, narrative=None, needs_review=True,
review_reason="llm-abstain: forced abstain")`` — the exact silent-drop
shape the old gate rejected (the new gate persists it via
``_coerce_abstain_persistence_fields``).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

# Make the backend package importable from any pytest cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.db import get_session  # noqa: E402
from cybersecurity_assessor.baselines.scope_labels import ON_PREM_LABEL  # noqa: E402
from cybersecurity_assessor.engine.assessor import Decision, LlmProposal  # noqa: E402
from cybersecurity_assessor.routes.controls import (  # noqa: E402
    _coerce_abstain_persistence_fields,
)
from cybersecurity_assessor.engine.evidence_bundle import EvidenceBlock  # noqa: E402
from cybersecurity_assessor.engine.measurement import ValidatorRejection  # noqa: E402
from cybersecurity_assessor.excel.ccis_reader import CcisIndex, CcisRow  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Assessment,
    Baseline,
    BaselineControl,
    BaselineObjective,
    BaselineSourceType,
    ComplianceStatus,
    Control,
    Framework,
    NarrativeClass,
    Objective,
    Workbook,
)
from cybersecurity_assessor.server import create_app  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _AbstainOnlyClient:
    """LLM stub that returns one abstain proposal per ``propose_twice`` call.

    ``Assessor`` calls ``propose_twice`` on the dual-pass path; we return the
    same abstain-flagged proposal for both passes so they "agree" and the
    kernel routes straight to ``_abstain()`` with the proposal's status (we
    pin NON_COMPLIANT so we exercise the soft-abstain branch where status is
    populated but narrative drops to None — the exact write-site bug shape).
    """

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def _proposal(self) -> LlmProposal:
        # ``status`` is non-Optional on LlmProposal — pick NON_COMPLIANT so the
        # produced Decision has (status=NON_COMPLIANT, narrative=None,
        # needs_review=True). Old gate failed ``decision.narrative`` check
        # and dropped the row; new gate writes it via the coercion helper.
        return LlmProposal(
            status=ComplianceStatus.NON_COMPLIANT,
            narrative="forced abstain",
            abstain=True,
            confidence=0.10,
        )

    def propose(
        self,
        *,
        row,
        corrective_context=None,
        prior_attempts=None,
        tagged_evidence=None,
        crm_responsibility=None,
        boundary_brief=None,
    ):
        self.calls.append({"row": row, "crm_responsibility": crm_responsibility})
        return self._proposal()

    def propose_twice(
        self,
        *,
        row,
        corrective_context=None,
        prior_attempts=None,
        tagged_evidence=None,
        crm_responsibility=None,
        boundary_brief=None,
    ):
        self.calls.append({"row": row, "crm_responsibility": crm_responsibility})
        p = self._proposal()
        return (p, p)


def _make_ccis_row(*, cci_id: str, control_id: str = "AC-2", excel_row: int = 42) -> CcisRow:
    """Minimal CcisRow that the assessor can chew on without hitting the
    Step 1.65 short-circuit (we hand it a populated EvidenceBlock below)."""
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


def _patch_route_dependencies(
    monkeypatch: pytest.MonkeyPatch, *, ccis_row: CcisRow, wb_path: Path
) -> _AbstainOnlyClient:
    """Wire the route layer's three external dependencies to in-test stubs:

    - ``make_client`` → ``_AbstainOnlyClient`` (no real Anthropic key needed)
    - ``read_workbook_index`` → fake ``CcisIndex`` with one row matching the
      Objective.objective_id we seed below (so the route's by_cci lookup hits)
    - ``_build_evidence_block`` → a populated ``EvidenceBlock`` so Assessor's
      Step 1.65 no-evidence short-circuit does NOT fire (it would otherwise
      return Non-Compliant before the LLM is reached, which is a different
      code path than the one we're regressing).
    """
    stub_client = _AbstainOnlyClient()

    monkeypatch.setattr(
        "cybersecurity_assessor.routes.controls.make_client",
        lambda cfg: stub_client,
    )
    monkeypatch.setattr(
        "cybersecurity_assessor.routes.controls.read_workbook_index",
        lambda path: CcisIndex(
            workbook_path=wb_path, sheet_name="CCIS", rows=[ccis_row]
        ),
    )
    monkeypatch.setattr(
        "cybersecurity_assessor.routes.controls._build_evidence_block",
        lambda *, objective_pk, control_id, workbook_id, s: EvidenceBlock(
            text=(
                "## tagged_evidence\n"
                "- USD00050010 Example System Account Management Plan Rev - — covers account ops.\n"
            ),
            has_artifacts=True,
            has_coverage=False,
            has_findings=False,
            has_hosts=False,
            has_nonscan_artifact=True,
        ),
    )
    return stub_client


# ---------------------------------------------------------------------------
# Single-control endpoint — POST /api/controls/assess
# ---------------------------------------------------------------------------


def test_assess_control_persists_hard_abstain_with_needs_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for ``feedback_abstain_status_none_drops.md`` at the
    single-control write site (controls.py:837-925).

    The LLM emits an abstain proposal → ``_abstain()`` produces a Decision
    with ``narrative=None`` → the OLD gate ``status is not None and
    decision.narrative`` would have dropped it. The NEW gate routes
    through ``_coerce_abstain_persistence_fields`` and writes the row with
    a non-empty narrative + ``needs_review=True`` so the reviewer queue
    surfaces it.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    def _override_get_session():
        with Session(engine) as s:
            yield s

    app = create_app()
    app.dependency_overrides[get_session] = _override_get_session

    # Touch a placeholder workbook file so ``wb_path.exists()`` passes; the
    # actual XLSX read is monkeypatched to return our fake index.
    wb_path = tmp_path / "ccis_abstain.xlsx"
    wb_path.touch()

    with Session(engine) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5")
        s.add(fw)
        s.commit()
        s.refresh(fw)

        ctrl = Control(
            framework_id=fw.id,
            control_id="AC-2",
            title="Account Management",
            family="AC",
        )
        s.add(ctrl)
        s.commit()
        s.refresh(ctrl)

        obj = Objective(
            control_id_fk=ctrl.id,
            objective_id="CCI-002124",  # the CCI from the memory note
            source="CCI",
            text="Audit account creation, modification, enabling, disabling, and removal actions.",
        )
        s.add(obj)
        s.commit()
        s.refresh(obj)

        wb = Workbook(
            path=str(wb_path),
            filename="ccis_abstain.xlsx",
            framework_id=fw.id,
        )
        s.add(wb)
        s.commit()
        s.refresh(wb)

        wb_id = wb.id
        obj_id = obj.id

    ccis_row = _make_ccis_row(cci_id="CCI-002124", control_id="AC-2", excel_row=42)
    _patch_route_dependencies(monkeypatch, ccis_row=ccis_row, wb_path=wb_path)

    client = TestClient(app)
    resp = client.post(
        "/api/controls/assess",
        json={"workbook_id": wb_id, "objective_id": obj_id, "persist": True},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    # The route returns the kernel's raw Decision shape — coercion only
    # happens at the DB write boundary. The kernel accepted the abstain
    # (accepted=True) and flagged needs_review=True. The abstain now carries
    # the LLM's proposal narrative forward (AC-7 fix: ``_abstain`` is passed
    # ``narrative=proposal.narrative`` so column Q gets the FULL text rather
    # than a 300-char-truncated review_reason). The stub proposes
    # "forced abstain", so that's what rides on the payload narrative.
    assert body["accepted"] is True
    assert body["needs_review"] is True
    assert body["narrative"] == "forced abstain"
    assert body["assessment_id"] is not None  # row WAS written (this is the fix)

    # The row landed in the table — the silent drop is fixed. Coercion
    # filled the NOT NULL columns: status falls through from the proposal
    # (NON_COMPLIANT here — the helper preserves the proposal status when
    # set; only hard abstains with status=None get coerced to NON_COMPLIANT
    # from the placeholder branch). narrative_q falls through to
    # ``decision.review_reason`` (populated by ``_abstain`` with
    # ``"llm-abstain: forced abstain"``).
    with Session(engine) as s:
        row = s.exec(
            select(Assessment).where(Assessment.objective_id == obj_id)
        ).one()
        assert row.status is ComplianceStatus.NON_COMPLIANT
        assert row.narrative_q  # non-empty (review_reason or placeholder)
        assert row.needs_review is True
        assert row.review_reason  # populated for triage


# ---------------------------------------------------------------------------
# Bulk endpoint — POST /api/controls/assess-batch
# ---------------------------------------------------------------------------


def test_assess_batch_persists_hard_abstain_with_needs_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for the bulk-assess write site (controls.py:1327-1421).

    Same shape as the single-control test, but routed through the
    parallel-fanout batch endpoint. The batch site honors
    ``decision.needs_review`` (vs single-control which pins True), so this
    test additionally pins the response counters:
    ``accepted`` increments for the abstain-accepted Decision, ``persisted``
    increments because the row landed, and ``abstained`` increments because
    the row carries ``needs_review=True``. Pre-fix all three would be 0 for
    this CCI even though the kernel produced an accepted Decision — the
    silent drop hid it from every counter.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    def _override_get_session():
        with Session(engine) as s:
            yield s

    app = create_app()
    app.dependency_overrides[get_session] = _override_get_session

    wb_path = tmp_path / "ccis_abstain_batch.xlsx"
    wb_path.touch()

    with Session(engine) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5")
        s.add(fw)
        s.commit()
        s.refresh(fw)

        ctrl = Control(
            framework_id=fw.id,
            control_id="AC-2",
            title="Account Management",
            family="AC",
        )
        s.add(ctrl)
        s.commit()
        s.refresh(ctrl)

        obj = Objective(
            control_id_fk=ctrl.id,
            objective_id="CCI-002127",  # the OTHER CCI from the memory note
            source="CCI",
            text="Notify account managers of account modifications.",
        )
        s.add(obj)
        s.commit()
        s.refresh(obj)

        baseline = Baseline(
            framework_id=fw.id,
            name="In-scope baseline",
            source_type=BaselineSourceType.MANUAL,
        )
        s.add(baseline)
        s.commit()
        s.refresh(baseline)

        s.add(
            BaselineControl(
                baseline_id=baseline.id,
                control_id=ctrl.id,
                in_scope=True,
            )
        )
        s.add(
            BaselineObjective(
                baseline_id=baseline.id,
                objective_id=obj.id,
            )
        )
        s.commit()

        wb = Workbook(
            path=str(wb_path),
            filename="ccis_abstain_batch.xlsx",
            framework_id=fw.id,
            baseline_id=baseline.id,
        )
        s.add(wb)
        s.commit()
        s.refresh(wb)

        wb_id = wb.id
        obj_id = obj.id

    ccis_row = _make_ccis_row(cci_id="CCI-002127", control_id="AC-2", excel_row=43)
    _patch_route_dependencies(monkeypatch, ccis_row=ccis_row, wb_path=wb_path)

    client = TestClient(app)
    resp = client.post(
        "/api/controls/assess-batch",
        json={"workbook_id": wb_id, "persist": True, "skip_existing": True},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()

    # Response counters: pre-fix this row would silent-drop, so accepted
    # might still increment (the kernel returns accepted=True) but
    # persisted/abstained would stay at 0. Post-fix all three reflect the
    # row that actually landed.
    assert data["accepted"] >= 1
    assert data["persisted"] >= 1
    assert data["abstained"] >= 1

    # Direct DB read — same contract as the single-control test, but the
    # bulk site honors decision.needs_review (kernel-authoritative) so the
    # assertion shape is identical here only because the abstain path
    # always sets needs_review=True. status falls through from the
    # proposal (NON_COMPLIANT), narrative_q from the review_reason.
    with Session(engine) as s:
        row = s.exec(
            select(Assessment).where(Assessment.objective_id == obj_id)
        ).one()
        assert row.status is ComplianceStatus.NON_COMPLIANT
        assert row.narrative_q
        assert row.needs_review is True
        assert row.review_reason


# ---------------------------------------------------------------------------
# Unresolved-decision coverage — three paths the assess-batch summary modal
# surfaces. The Controls.tsx modal (see plan
# ``lucky-sleeping-parasol.md``) opens whenever the response carries any of
# these three buckets so the user knows which CCIs to re-run instead of
# silently losing them. The backend already emits the data; these tests pin
# the wire shape so future refactors of the route's unresolved-decision
# dict don't quietly break the UI consumer.
# ---------------------------------------------------------------------------


class _ExplodingClient:
    """LLM stub that raises on every propose call.

    Drives the Phase-3 worker-exception branch
    (``routes/controls.py:1395-1419``): ``_assess_one`` catches the
    exception, returns ``(item, None, exc)``, and Phase-3 surfaces it as an
    unresolved decision with ``error="RuntimeError: ..."``. Used to prove
    the wire shape the Controls modal's "Worker errored" section depends on.
    """

    def __init__(self) -> None:
        self.calls = 0

    def _raise(self) -> None:
        self.calls += 1
        raise RuntimeError("boom: simulated LLM failure for test")

    def propose(self, **_kwargs):
        self._raise()

    def propose_twice(self, **_kwargs):
        self._raise()


def _seed_batch_workbook(
    engine, *, tmp_path: Path, cci_id: str, filename: str
) -> tuple[int, int, Path]:
    """Set up the minimum Framework/Control/Objective/Baseline/Workbook
    rows that the batch endpoint needs to even resolve an in-scope pair.

    Returns ``(workbook_id, objective_id, wb_path)``. The wb_path is
    touched so the route's ``wb_path.exists()`` gate passes; the actual
    XLSX read is patched by ``_patch_route_dependencies``.
    """
    wb_path = tmp_path / filename
    wb_path.touch()

    with Session(engine) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5")
        s.add(fw)
        s.commit()
        s.refresh(fw)

        ctrl = Control(
            framework_id=fw.id,
            control_id="AC-2",
            title="Account Management",
            family="AC",
        )
        s.add(ctrl)
        s.commit()
        s.refresh(ctrl)

        obj = Objective(
            control_id_fk=ctrl.id,
            objective_id=cci_id,
            source="CCI",
            text="Test objective for unresolved-path regression.",
        )
        s.add(obj)
        s.commit()
        s.refresh(obj)

        baseline = Baseline(
            framework_id=fw.id,
            name="In-scope baseline",
            source_type=BaselineSourceType.MANUAL,
        )
        s.add(baseline)
        s.commit()
        s.refresh(baseline)

        s.add(BaselineControl(baseline_id=baseline.id, control_id=ctrl.id, in_scope=True))
        s.add(BaselineObjective(baseline_id=baseline.id, objective_id=obj.id))
        s.commit()

        wb = Workbook(
            path=str(wb_path),
            filename=filename,
            framework_id=fw.id,
            baseline_id=baseline.id,
        )
        s.add(wb)
        s.commit()
        s.refresh(wb)

        return wb.id, obj.id, wb_path


def _make_engine_and_app() -> tuple[object, object]:
    """In-memory SQLite + StaticPool engine and a FastAPI app whose
    ``get_session`` dependency yields a session bound to that engine.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    def _override_get_session():
        with Session(engine) as s:
            yield s

    app = create_app()
    app.dependency_overrides[get_session] = _override_get_session
    return engine, app


def test_assess_batch_worker_exception_surfaces_error_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Phase-2 worker raised → decisions[0].error is populated.

    Modal contract: ``Controls.tsx`` filters
    ``r.decisions.filter(d => !d.accepted && d.error)`` into the "Worker
    errored" section. The exception type + message must be a single
    ``"<ExceptionType>: <msg>"`` string the UI can render in a mono row.
    """
    engine, app = _make_engine_and_app()
    wb_id, obj_id, wb_path = _seed_batch_workbook(
        engine, tmp_path=tmp_path, cci_id="CCI-000048", filename="ccis_worker_err.xlsx"
    )

    ccis_row = _make_ccis_row(cci_id="CCI-000048", control_id="AC-2", excel_row=42)

    # Same wiring as the existing tests but swap make_client for the
    # exploding stub. The kernel's first LLM call (propose or
    # propose_twice depending on dual-pass mode) raises, _assess_one
    # catches, route returns the unresolved decision.
    exploding = _ExplodingClient()
    monkeypatch.setattr(
        "cybersecurity_assessor.routes.controls.make_client",
        lambda cfg: exploding,
    )
    monkeypatch.setattr(
        "cybersecurity_assessor.routes.controls.read_workbook_index",
        lambda path: CcisIndex(workbook_path=wb_path, sheet_name="CCIS", rows=[ccis_row]),
    )
    monkeypatch.setattr(
        "cybersecurity_assessor.routes.controls._build_evidence_block",
        lambda *, objective_pk, control_id, workbook_id, s: EvidenceBlock(
            text="## tagged_evidence\n- USD00050010 Example System Account Mgmt Plan.\n",
            has_artifacts=True,
            has_coverage=False,
            has_findings=False,
            has_hosts=False,
            has_nonscan_artifact=True,
        ),
    )

    client = TestClient(app)
    resp = client.post(
        "/api/controls/assess-batch",
        json={"workbook_id": wb_id, "persist": True, "skip_existing": True},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["unresolved"] >= 1
    # Find the decision for our seeded CCI — Phase-3 appends in workbook
    # order, but the test only seeds one objective so it's decisions[0].
    errored = [d for d in data["decisions"] if d["objective_id"] == "CCI-000048"]
    assert len(errored) == 1
    d = errored[0]
    assert d["accepted"] is False
    assert d["status"] is None
    assert d["narrative"] is None
    # The exact format the modal's "Worker errored" list renders.
    assert d["error"] is not None
    assert d["error"].startswith("RuntimeError: boom")
    # rejections[] is empty for the exception path (Phase-3 builds the
    # dict without a Decision object) — disjoint from the validator-
    # rejection path so the modal's filters cleanly separate them.
    assert d["rejections"] == []
    # No Assessment row was written — the modal's "re-run these" hint
    # depends on this: skip_existing=true on a re-run will pick them up.
    with Session(engine) as s:
        rows = s.exec(
            select(Assessment).where(Assessment.objective_id == obj_id)
        ).all()
        assert rows == []


def test_assess_batch_validator_rejection_populates_rejections_without_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Validator exhausted retries → ``rejections[]`` populated, no ``error``.

    Modal contract: this path lands in the "Validator rejected" section,
    which uses a disjoint filter
    ``!d.accepted && !d.error && d.rejections.length > 0`` so it doesn't
    overlap "Worker errored". The plan
    (``lucky-sleeping-parasol.md`` Step 4 extension) added this section
    because the prior modal trigger gated only on ``error``, so a batch
    with only validator-rejected CCIs would skip the modal entirely and
    silently lose feedback — same shape of bug as the abstain silent-drop
    in ``feedback_abstain_status_none_drops.md``.
    """
    engine, app = _make_engine_and_app()
    wb_id, obj_id, wb_path = _seed_batch_workbook(
        engine, tmp_path=tmp_path, cci_id="CCI-000049", filename="ccis_rejected.xlsx"
    )

    ccis_row = _make_ccis_row(cci_id="CCI-000049", control_id="AC-2", excel_row=44)
    stub_client = _patch_route_dependencies(
        monkeypatch, ccis_row=ccis_row, wb_path=wb_path
    )

    # Force the kernel to emit a validator-rejected Decision. Patch
    # Assessor.assess at the class so the route's
    # ``Assessor(llm=client, cache_session=s)`` instance picks it up.
    # The Decision shape mirrors what the kernel would produce after
    # exhausting rule #11 retries (see assessor.py around the retry
    # loop): accepted=False, status/narrative=None, rejection_log
    # populated with the last validator complaint.
    def _fake_assess(self, row, *, recorder=None, **_kw):
        return Decision(
            cci_id=row.cci_id,
            excel_row=row.excel_row,
            accepted=False,
            status=None,
            narrative=None,
            narrative_class=NarrativeClass.AMBIGUOUS,
            source="unresolved",
            rule=None,
            retries=2,
            rejection_log=[
                ValidatorRejection(
                    cci=row.cci_id,
                    rejection_class="requirement_restatement",
                    original_output="Compliant — the system implements account management.",
                    corrective_context="Narrative restates the requirement instead of citing "
                    "specific implementation evidence.",
                )
            ],
        )

    monkeypatch.setattr(
        "cybersecurity_assessor.routes.controls.Assessor.assess",
        _fake_assess,
    )

    client = TestClient(app)
    resp = client.post(
        "/api/controls/assess-batch",
        json={"workbook_id": wb_id, "persist": True, "skip_existing": True},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["unresolved"] >= 1
    rejected = [d for d in data["decisions"] if d["objective_id"] == "CCI-000049"]
    assert len(rejected) == 1
    d = rejected[0]
    assert d["accepted"] is False
    assert d["status"] is None
    assert d["narrative"] is None
    # Critical disjoint: no error field (or null) so the "Worker errored"
    # filter skips it and the "Validator rejected" filter catches it.
    assert d.get("error") is None
    assert len(d["rejections"]) == 1
    rj = d["rejections"][0]
    assert rj["reason"] == "requirement_restatement"
    assert "restates the requirement" in rj["context"]
    # No Assessment row — validator-rejected decisions are never
    # persisted (the route's plugin-hard-rule comment, controls.py:1120).
    with Session(engine) as s:
        rows = s.exec(
            select(Assessment).where(Assessment.objective_id == obj_id)
        ).all()
        assert rows == []
    # Stub client was wired but never reached — the assess monkeypatch
    # short-circuits before propose_twice. Sanity-check we didn't
    # accidentally invoke the real kernel path.
    assert stub_client.calls == []


def test_assess_batch_baseline_cci_missing_from_workbook_appears_in_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Baseline references a CCI the workbook doesn't list → ``skipped[]``.

    Modal contract: the "Not in workbook" section
    (``Controls.tsx``) lists each entry by ``objective_id`` and ``reason``
    so the user can either reload the workbook with the right framework
    or update the baseline. Today this is the silent-drop the user hit:
    the only signal was a "1 skipped" count in the toast.
    """
    engine, app = _make_engine_and_app()
    wb_id, obj_id, wb_path = _seed_batch_workbook(
        engine, tmp_path=tmp_path, cci_id="CCI-000050", filename="ccis_missing.xlsx"
    )

    # Critical: the workbook index is EMPTY (or carries a different CCI)
    # so the baseline's CCI-000050 has no matching row → the route's
    # cci_to_row.get() returns None → skipped[] gets one entry.
    monkeypatch.setattr(
        "cybersecurity_assessor.routes.controls.make_client",
        lambda cfg: _AbstainOnlyClient(),  # never called; safety stub
    )
    monkeypatch.setattr(
        "cybersecurity_assessor.routes.controls.read_workbook_index",
        lambda path: CcisIndex(workbook_path=wb_path, sheet_name="CCIS", rows=[]),
    )
    # Evidence block patch isn't strictly needed (the skip happens before
    # the evidence-build phase) but include it so an unrelated import
    # path doesn't accidentally exercise the real builder.
    monkeypatch.setattr(
        "cybersecurity_assessor.routes.controls._build_evidence_block",
        lambda *, objective_pk, control_id, workbook_id, s: EvidenceBlock(
            text=None,
            has_artifacts=False,
            has_coverage=False,
            has_findings=False,
            has_hosts=False,
            has_nonscan_artifact=False,
        ),
    )

    client = TestClient(app)
    resp = client.post(
        "/api/controls/assess-batch",
        json={"workbook_id": wb_id, "persist": True, "skip_existing": True},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert len(data["skipped"]) >= 1
    skipped = [s for s in data["skipped"] if s["objective_id"] == "CCI-000050"]
    assert len(skipped) == 1
    assert skipped[0]["reason"] == "not_in_workbook"
    # The CCI never entered Phase 2 — no decision dict, no Assessment row.
    assert not any(d["objective_id"] == "CCI-000050" for d in data["decisions"])
    with Session(engine) as s:
        rows = s.exec(
            select(Assessment).where(Assessment.objective_id == obj_id)
        ).all()
        assert rows == []


# ---------------------------------------------------------------------------
# Save-time stitch → column Q
# ---------------------------------------------------------------------------
#
# These lock the save boundary the user reminded us about: "even though i
# said it's visual/logical it should still be able to go in column Q when
# exported." ``_coerce_abstain_persistence_fields`` is the DRY chokepoint
# both Assessment-write sites call, and its returned narrative becomes
# ``Assessment.narrative_q`` → eMASS column Q (ccis_writer COL_RESULTS=17)
# and the working-copy exporter. So proving the stitch happens HERE proves
# the labeled multi-scope block reaches the exported cell, not just the GUI.


def _decision_with_scopes(narratives_by_scope: dict[str, str]) -> Decision:
    """A minimal accepted Decision carrying a per-scope narrative map.

    Mirrors the kernel's happy-path shape (accepted=True, a real status +
    canonical narrative) so the test exercises the soft pass-through branch,
    not the abstain coercion. ``narrative`` is the single canonical text the
    validator/classifier already ran on upstream; the stitch is layered on
    top at the write site.
    """
    return Decision(
        cci_id="CCI-000099",
        excel_row=42,
        accepted=True,
        status=ComplianceStatus.COMPLIANT,
        narrative="Canonical single-boundary narrative.",
        narrative_class=NarrativeClass.COMPLIANCE_AFFIRMING,
        source="llm",
        rule=None,
        narratives_by_scope=narratives_by_scope,
    )


def test_coerce_persistence_stitches_multi_scope_into_narrative_q() -> None:
    """≥2 populated scopes → narrative_q is the labeled stitched block.

    This is the value that lands in exported column Q. Cloud platforms
    render first (insertion order), synthesized On-Premises last.
    """
    status, narrative_q = _coerce_abstain_persistence_fields(
        _decision_with_scopes(
            {
                "AWS GovCloud": "Provider attests via CSP SSP.",
                ON_PREM_LABEL: "Verified via USD00050010 §3.2 on the Example System enclave.",
            }
        )
    )
    assert status == ComplianceStatus.COMPLIANT
    assert narrative_q == (
        "AWS GovCloud:\n\nProvider attests via CSP SSP."
        "\n\n"
        f"{ON_PREM_LABEL}:\n\nVerified via USD00050010 §3.2 on the Example System enclave."
    )


def test_coerce_persistence_single_scope_keeps_plain_narrative() -> None:
    """<2 populated scopes → no stitch; canonical narrative flows to col Q.

    The single-boundary path must collapse to the plain narrative so
    ordinary controls aren't decorated with a lone redundant label.
    """
    _, narrative_q = _coerce_abstain_persistence_fields(
        _decision_with_scopes({"AWS GovCloud": "Only the cloud side is in scope."})
    )
    assert narrative_q == "Canonical single-boundary narrative."


def test_coerce_persistence_empty_scope_map_keeps_plain_narrative() -> None:
    """The default (empty map) is the common single-boundary case."""
    _, narrative_q = _coerce_abstain_persistence_fields(
        _decision_with_scopes({})
    )
    assert narrative_q == "Canonical single-boundary narrative."
