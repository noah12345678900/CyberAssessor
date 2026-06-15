"""Regression coverage for Auditability v1 — citation pipeline.

Three failure modes have already bitten us once during the v1 build-out;
this file locks them in so they can't silently regress:

1. ``decision_cache.fingerprint`` must include the ``audit_citations``
   flag. Otherwise a flag-OFF cache hit silently satisfies a flag-ON
   re-run, the LLM is never called, no ``citations`` array comes back,
   and the audit trail stays empty even though Settings says the toggle
   is on. The fix lives in [decision_cache.py:224](../../cybersecurity_assessor/engine/decision_cache.py#L224)
   and the bump to ``KERNEL_VERSION = "0.5.0"`` invalidates any
   pre-fix entries.

2. The flag-gated prompt addendum must use the literal field name
   ``narrative_q`` (NOT bare ``narrative``). The persister in
   [routes/controls.py:_persist_audit_trail][routes/controls.py:387-397]
   keys citations against ``{narrative_q, narrative_on_prem,
   narrative_cloud, narrative_class}`` and silently drops anything else;
   the earlier draft of the addendum told the LLM to emit
   ``narrative_field="narrative"`` and every single citation was dropped
   at persist time. This file pins the literal "narrative_q" in the
   addendum so the prompt side of the contract can't drift again.

3. The persister must drop unknown ``narrative_field`` values without
   raising — a single bad citation can't poison the rest of a row's
   citations. This is the persistence-side mirror of #2: if some future
   prompt edit (or model hallucination) emits ``narrative_field="narrative"``
   again, the surviving citations still land in the DB and the audit
   trail is partially complete instead of partially missing.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import event
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

# Ensure the backend package is importable when pytest is launched from any cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- register tables
from cybersecurity_assessor.engine import decision_cache  # noqa: E402
from cybersecurity_assessor.engine.assessor import (  # noqa: E402
    Decision,
    EvidenceShownPayload,
    TracePayload,
)
from cybersecurity_assessor.excel.ccis_reader import CcisRow  # noqa: E402
from cybersecurity_assessor.llm.client import build_user_message  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Assessment,
    AssessmentCitation,
    AssessmentEvidenceShown,
    AssessmentTrace,
    ComplianceStatus,
    Control,
    Evidence,
    EvidenceKind,
    Framework,
    NarrativeClass,
    Objective,
    PromptSnapshot,
    Workbook,
)
from cybersecurity_assessor.routes.controls import _persist_audit_trail  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row(*, cci_id: str = "CCI-000001", control_id: str = "AC-2") -> CcisRow:
    """Minimal CcisRow — same shape as the e2e suite's _row helper."""
    return CcisRow(
        excel_row=10,
        required=True,
        control_id=control_id,
        ap_acronym=f"{control_id}.1",
        cci_id=cci_id,
        implementation_status=None,
        designation=None,
        narrative=None,
        definition="The information system manages information system accounts.",
        guidance=None,
        procedures=None,
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


@pytest.fixture
def session():
    """In-memory SQLite session — same fixture pattern as test_assessor_e2e."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


# ---------------------------------------------------------------------------
# 1. Cache fingerprint includes the audit_citations flag
# ---------------------------------------------------------------------------


def test_fingerprint_changes_when_audit_citations_flag_flipped():
    """Flag-OFF cache hits must NOT satisfy a flag-ON re-run.

    Without this, toggling ``audit_citations_enabled`` in Settings is a
    no-op until the cache is manually cleared — the assessor replays the
    citation-free Decision and the audit trail stays empty.
    """
    row = _row()
    tagged_evidence = (
        "## Tagged evidence\n"
        "- USD00050010 Example System Account Management Plan Rev - — covers account ops.\n"
    )

    fp_off = decision_cache.fingerprint(
        row=row,
        tagged_evidence=tagged_evidence,
        crm_context=None,
        audit_citations=False,
    )
    fp_on = decision_cache.fingerprint(
        row=row,
        tagged_evidence=tagged_evidence,
        crm_context=None,
        audit_citations=True,
    )

    assert fp_off != fp_on, (
        "audit_citations flag must participate in the cache fingerprint — "
        "otherwise flag-ON re-runs silently hit flag-OFF cached decisions "
        "and the citations[] array never gets requested from the LLM."
    )


def test_fingerprint_default_matches_explicit_false():
    """Default arg must equal explicit False — no silent contract drift."""
    row = _row()
    tagged_evidence = "## Tagged evidence\n- x"

    fp_default = decision_cache.fingerprint(
        row=row, tagged_evidence=tagged_evidence, crm_context=None
    )
    fp_explicit_false = decision_cache.fingerprint(
        row=row,
        tagged_evidence=tagged_evidence,
        crm_context=None,
        audit_citations=False,
    )

    assert fp_default == fp_explicit_false


# ---------------------------------------------------------------------------
# 2. Prompt addendum is flag-gated AND uses the literal "narrative_q"
# ---------------------------------------------------------------------------


def test_build_user_message_omits_citation_addendum_when_flag_off():
    """Flag-OFF prompt must be byte-clean of the audit-citation block.

    Two reasons: (a) prompt caching warmth — flag-OFF runs must keep the
    original byte-identical prompt prefix; (b) any leaked instruction
    would burn output tokens emitting an unrequested citations[] array.
    """
    body = build_user_message(
        row=_row(),
        corrective_context=None,
        prior_attempts=None,
        tagged_evidence="## Tagged evidence\n- USD00050010 — covers account ops.",
        audit_citations=False,
    )

    assert "Audit citations" not in body
    assert "citations" not in body  # no leaked instruction tokens at all


def test_build_user_message_emits_narrative_q_field_name_when_flag_on():
    """Flag-ON prompt MUST instruct the LLM to use ``narrative_q`` literally.

    The persister at routes/controls.py:_persist_audit_trail keys on
    {narrative_q, narrative_on_prem, narrative_cloud, narrative_class} —
    anything else (notably bare ``narrative``) is silently dropped. The
    prompt addendum has to mirror that exact vocabulary or every
    citation evaporates at persist time even though the LLM emitted them.
    """
    body = build_user_message(
        row=_row(),
        corrective_context=None,
        prior_attempts=None,
        tagged_evidence="## Tagged evidence\n- USD00050010 — covers account ops.",
        audit_citations=True,
    )

    assert "Audit citations (required this run)" in body, (
        "Flag-ON addendum header missing — the citation contract block "
        "didn't land in the user message."
    )
    assert '"narrative_q"' in body, (
        "Addendum must reference the literal Assessment column name "
        "'narrative_q'. Bare 'narrative' (the legacy draft text) gets "
        "dropped by the persister; this assertion locks the contract."
    )
    # Belt-and-suspenders: explicitly forbid the legacy bare name being
    # used as the field-name instruction. We allow incidental prose
    # containing "narrative" — only the JSON-key form is forbidden.
    assert '"narrative_field": "narrative"' not in body, (
        "Found the legacy 'narrative_field=narrative' example — the "
        "persister silently drops citations using that field name."
    )


# ---------------------------------------------------------------------------
# 3. _persist_audit_trail drops legacy "narrative" but keeps "narrative_q"
# ---------------------------------------------------------------------------


def _seed_persistence_fixtures(session: Session) -> tuple[int, int]:
    """Seed Framework + Control + Objective + Workbook + Evidence + Assessment.

    Returns (assessment_id, evidence_id) for the test to plug into the
    Decision payload. Every FK relationship the persister will traverse
    is satisfied so the staged citation rows can actually commit.
    """
    framework = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(framework)
    session.flush()

    control = Control(
        framework_id=framework.id,
        control_id="AC-2",
        title="Account Management",
        family="AC",
    )
    session.add(control)
    session.flush()

    objective = Objective(
        control_id_fk=control.id,
        objective_id="CCI-000001",
        text="The information system manages information system accounts.",
    )
    session.add(objective)
    session.flush()

    workbook = Workbook(path="C:/fake/workbook.xlsx", filename="workbook.xlsx")
    session.add(workbook)
    session.flush()

    evidence = Evidence(
        path="file:///fake/usd00050010.pdf",
        sha256="deadbeef" * 8,
        kind=EvidenceKind.PDF,
        size_bytes=1024,
        title="USD00050010 Example System Account Management Plan",
    )
    session.add(evidence)
    session.flush()

    assessment = Assessment(
        workbook_id=workbook.id,
        objective_id=objective.id,
        excel_row=10,
        status=ComplianceStatus.COMPLIANT,
        tester="Noah Jaskolski",
        date_tested=datetime.now(timezone.utc),
        narrative_q=(
            "Account management is documented in USD00050010 and validated "
            "by quarterly STIG scans showing no open AC-2 findings."
        ),
        narrative_class=NarrativeClass.COMPLIANCE_AFFIRMING,
    )
    session.add(assessment)
    session.flush()

    return assessment.id, evidence.id


def _decision_with_citations(
    *, evidence_id: int, citations: list[dict]
) -> Decision:
    """Build a minimal Decision carrying one TracePayload + one shown chunk."""
    chunk_text = (
        "USD00050010 Example System Account Management Plan establishes account "
        "creation, modification, and disabling procedures."
    )
    trace = TracePayload(
        system_prompt_sha="abc123" + "0" * 58,
        user_message="## Task\nProduce one (status, narrative) pair…",
        model="claude-opus-4-6",
        model_version="claude-opus-4-6-20260101",
        temperature=0.0,
        max_tokens=2048,
        request_id="req_test_1",
        raw_response_json='{"status":"Compliant"}',
        pass_index=0,
        citations=citations,
    )
    shown = EvidenceShownPayload(
        evidence_id=evidence_id,
        chunk_sha="cafe" * 16,
        chunk_text=chunk_text,
        order_index=0,
        relevance=0.92,
        tag_source="stig_mapper",
    )
    return Decision(
        cci_id="CCI-000001",
        excel_row=10,
        accepted=True,
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Account management is documented in USD00050010 and validated "
            "by quarterly STIG scans showing no open AC-2 findings."
        ),
        narrative_class=NarrativeClass.COMPLIANCE_AFFIRMING,
        source="llm",
        rule=None,
        trace_payload=[trace],
        evidence_shown=[shown],
    )


def test_persist_audit_trail_drops_legacy_narrative_field_name(session):
    """Citation with ``narrative_field="narrative"`` is silently dropped.

    Mirror of test_build_user_message_emits_narrative_q_field_name_when_flag_on
    on the persistence side. Two citations are emitted; only the one
    using the canonical ``narrative_q`` survives. This guarantees one
    bad citation (model hallucination, future prompt regression) can't
    poison the surviving citations on the same row.
    """
    assessment_id, evidence_id = _seed_persistence_fixtures(session)

    decision = _decision_with_citations(
        evidence_id=evidence_id,
        citations=[
            # GOOD — uses the canonical field name; must persist.
            {
                "narrative_field": "narrative_q",
                "claim": "Account management is documented in USD00050010",
                "evidence_id": evidence_id,
                "source_quote": "USD00050010 Example System Account Management Plan establishes account",
            },
            # BAD — legacy field name; must be silently dropped.
            {
                "narrative_field": "narrative",
                "claim": "validated by quarterly STIG scans",
                "evidence_id": evidence_id,
                "source_quote": "creation, modification, and disabling procedures",
            },
        ],
    )

    _persist_audit_trail(
        session, assessment_id=assessment_id, decision=decision
    )
    session.commit()

    citations = session.exec(select(AssessmentCitation)).all()
    assert len(citations) == 1, (
        f"Expected exactly 1 citation row (legacy 'narrative' field dropped), "
        f"got {len(citations)}"
    )
    surviving = citations[0]
    assert surviving.narrative_field == "narrative_q"
    assert surviving.assessment_id == assessment_id
    assert surviving.extraction_method == "llm_self_cite"
    # claim_start_char should be populated because the claim substring
    # appears verbatim in narrative_q — proves the offset math also ran.
    assert surviving.claim_start_char is not None
    assert surviving.claim_start_char >= 0

    # And the trace + evidence-shown plumbing must have landed too — the
    # citation row's FK depends on AssessmentEvidenceShown existing, and
    # AssessmentTrace existing is what makes any of this auditable.
    trace_rows = session.exec(select(AssessmentTrace)).all()
    assert len(trace_rows) == 1
    assert trace_rows[0].model == "claude-opus-4-6"
    assert trace_rows[0].anthropic_model_version == "claude-opus-4-6-20260101"

    shown_rows = session.exec(select(AssessmentEvidenceShown)).all()
    assert len(shown_rows) == 1
    assert shown_rows[0].evidence_id == evidence_id

    snapshots = session.exec(select(PromptSnapshot)).all()
    assert len(snapshots) == 1
    assert snapshots[0].sha256 == "abc123" + "0" * 58


# ---------------------------------------------------------------------------
# 4. _persist_audit_trail REPLACES prior child rows on re-assess
# ---------------------------------------------------------------------------


def test_persist_audit_trail_replaces_prior_rows_on_reassess(session):
    """Re-assessing the same Assessment.id must NOT accumulate audit rows.

    The single-CCI and batch routes UPDATE Assessment in place (same PK)
    when a CCI is re-assessed, then call _persist_audit_trail with the
    same assessment_id. Without REPLACE-on-id, the audit endpoint would
    return the union of every run's traces, evidence-shown chunks, and
    citations — N rows from N prior runs interleaved with the current
    one — which defeats the auditability goal (the auditor wants the
    LAST run's verdict→evidence path, not a chronologically-flattened
    soup of all prior attempts).

    PromptSnapshot rows survive across re-assesses because they're
    sha-keyed and shared across thousands of assessments; deleting one
    here would orphan unrelated trace rows.
    """
    assessment_id, evidence_id = _seed_persistence_fixtures(session)

    # First pass — write the audit trail.
    decision_v1 = _decision_with_citations(
        evidence_id=evidence_id,
        citations=[
            {
                "narrative_field": "narrative_q",
                "claim": "Account management is documented in USD00050010",
                "evidence_id": evidence_id,
                "source_quote": "USD00050010 Example System Account Management Plan establishes account",
            }
        ],
    )
    _persist_audit_trail(session, assessment_id=assessment_id, decision=decision_v1)
    session.commit()

    assert len(session.exec(select(AssessmentTrace)).all()) == 1
    assert len(session.exec(select(AssessmentEvidenceShown)).all()) == 1
    assert len(session.exec(select(AssessmentCitation)).all()) == 1
    assert len(session.exec(select(PromptSnapshot)).all()) == 1

    # Second pass — same assessment_id, different request_id (so we can
    # confirm the *new* trace landed and the *old* one is gone, not just
    # that the row count is right by coincidence).
    decision_v2 = _decision_with_citations(
        evidence_id=evidence_id,
        citations=[
            {
                "narrative_field": "narrative_q",
                "claim": "validated by quarterly STIG scans",
                "evidence_id": evidence_id,
                "source_quote": "creation, modification, and disabling procedures",
            }
        ],
    )
    # Mutate the trace payload so we can identify which run survived.
    decision_v2.trace_payload[0].request_id = "req_test_2_replaced"

    _persist_audit_trail(session, assessment_id=assessment_id, decision=decision_v2)
    session.commit()

    # Counts unchanged — prior rows replaced, not appended.
    trace_rows = session.exec(select(AssessmentTrace)).all()
    assert len(trace_rows) == 1, (
        f"Expected exactly 1 AssessmentTrace after re-assess (REPLACE-on-id), "
        f"got {len(trace_rows)} — duplicates accumulating across runs"
    )
    assert trace_rows[0].request_id == "req_test_2_replaced", (
        "Surviving trace must be the second-pass run, not the first — "
        "indicates DELETE order ran AFTER the new INSERT"
    )

    shown_rows = session.exec(select(AssessmentEvidenceShown)).all()
    assert len(shown_rows) == 1

    citation_rows = session.exec(select(AssessmentCitation)).all()
    assert len(citation_rows) == 1
    assert citation_rows[0].claim_text == "validated by quarterly STIG scans", (
        "Surviving citation must be from the second-pass run"
    )

    # PromptSnapshot is sha-keyed and shared across assessments — the cleanup
    # MUST NOT touch it. Same sha → same single row both runs.
    snapshots = session.exec(select(PromptSnapshot)).all()
    assert len(snapshots) == 1, (
        "PromptSnapshot is shared across all assessments via sha PK — "
        "REPLACE-on-id must not delete it (would orphan unrelated traces)"
    )


# ---------------------------------------------------------------------------
# 5. _persist_audit_trail re-creates a phantom PromptSnapshot FK parent
#    (regression lock for the recurring batch-assessment crash)
# ---------------------------------------------------------------------------


@pytest.fixture
def fk_session():
    """In-memory SQLite session with FOREIGN KEY enforcement ON.

    The default ``session`` fixture leaves PRAGMA foreign_keys at SQLite's
    OFF default, so an orphaned FK never raises there. The batch crash this
    file now locks in IS an FK violation, so we must mirror the runtime
    engine's ``PRAGMA foreign_keys=ON`` (db.py) to actually exercise it.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _record):  # noqa: ANN001
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def test_persist_audit_trail_inserts_prompt_snapshot_before_trace_under_fk_on(
    fk_session,
):
    """The PromptSnapshot FK parent must land BEFORE the AssessmentTrace flush.

    This is the regression lock for the recurring batch-assessment FK crash:

        sqlite3.IntegrityError: FOREIGN KEY constraint failed
        INSERT INTO assessmenttrace (assessment_id=…, system_prompt_sha=…) …
        → cascading PendingRollbackError at rec.finish()

    ROOT CAUSE: ``AssessmentTrace.system_prompt_sha`` is a bare
    ``Field(foreign_key="promptsnapshot.sha256")`` with NO ORM
    ``relationship()``. SQLAlchemy's unit-of-work therefore has no dependency
    edge between the two tables and flushes them in ALPHABETICAL order —
    ``assessmenttrace`` BEFORE ``promptsnapshot``. The legacy code added the
    PromptSnapshot as a merely *pending* ORM object (deferred to the SAME
    flush), so under ``PRAGMA foreign_keys=ON`` the trace INSERT fired before
    its parent existed and the whole batch transaction tore down.

    THE FIX: ``_persist_audit_trail`` now writes the parent with a
    connection-level idempotent ``INSERT OR IGNORE`` (sqlite_insert +
    on_conflict_do_nothing) which hits the connection IMMEDIATELY, before the
    trace flush — so the FK resolves regardless of ORM table ordering.

    This test enforces ``foreign_keys=ON`` (mirroring db.py) and seeds the
    real fixtures, so the *old* add-both-then-flush pattern fails here with
    IntegrityError and the *fixed* eager-insert pattern passes — a clean
    pass/fail discriminator with no identity-map phantom trickery.
    """
    sha = "abc123" + "0" * 58  # matches _decision_with_citations' trace sha
    assessment_id, evidence_id = _seed_persistence_fixtures(fk_session)

    # Precondition: no PromptSnapshot exists yet — the fix must create it.
    assert fk_session.exec(select(PromptSnapshot)).all() == [], (
        "Precondition: no PromptSnapshot should exist before persistence — "
        "_persist_audit_trail is solely responsible for creating the parent."
    )

    decision = _decision_with_citations(
        evidence_id=evidence_id,
        citations=[
            {
                "narrative_field": "narrative_q",
                "claim": "Account management is documented in USD00050010",
                "evidence_id": evidence_id,
                "source_quote": "USD00050010 Example System Account Management Plan establishes account",
            }
        ],
    )

    # Under FK ON, the OLD add-both-then-flush pattern raised IntegrityError
    # here (trace flushed alphabetically before its parent). The eager
    # INSERT OR IGNORE fix writes the parent to the connection first.
    _persist_audit_trail(
        fk_session, assessment_id=assessment_id, decision=decision
    )
    fk_session.commit()

    # Trace landed and its FK parent physically exists.
    trace_rows = fk_session.exec(select(AssessmentTrace)).all()
    assert len(trace_rows) == 1
    assert trace_rows[0].system_prompt_sha == sha

    snapshots = fk_session.exec(select(PromptSnapshot)).all()
    assert len(snapshots) == 1
    assert snapshots[0].sha256 == sha

    citations = fk_session.exec(select(AssessmentCitation)).all()
    assert len(citations) == 1
    assert citations[0].narrative_field == "narrative_q"
