"""Wire-shape pins for ``GET /api/controls/assessments/{id}/audit`` (Audit v1).

The UI's Audit trail card on ControlDetail.tsx is the consumer of this
endpoint — it expects a stable response envelope regardless of whether
the verdict was reached via LLM (full trace + evidence_shown + maybe
citations) or via a deterministic short-circuit (empty arrays, but
still 200 OK so the panel can render a "no LLM trace" banner instead of
exploding on a 404 / 500).

Four contract guarantees are pinned here:

1. **404 on missing assessment** — UI uses this to detect a stale link
   (e.g. assessment was hard-deleted between page-load and audit-expand).

2. **Deterministic verdict path returns 200 + empty arrays** — rule_8a /
   rule_8b / rule_8c / CRM short-circuits make no LLM call and render no
   per-objective evidence. The audit card must still mount so the user
   sees *why* there's no trace, not a "something went wrong" toast.

3. **Orphaned Evidence (hard-deleted file) renders with null title/path
   instead of dropping the AssessmentEvidenceShown row.** The audit card
   must show "the model saw this exact text" even if the source file is
   gone — that's the entire point of snapshotting ``chunk_text`` at
   capture time instead of resolving it on read.

4. **Dual-pass: 2 trace rows returned in ``pass_index`` order;
   ``system_prompts`` deduped by sha** so the UI doesn't render the
   identical 4-KB system prompt twice when both passes share it (which
   they always do in v1 — dual_pass uses the same system prompt for both
   passes by design).
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- register tables
from cybersecurity_assessor.db import get_session  # noqa: E402
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
from cybersecurity_assessor.server import create_app  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def env(tmp_path: Path) -> Iterator[dict]:
    """TestClient + a minimal Framework→Control→Objective→Workbook→Assessment
    graph the audit endpoint can resolve against. Per-test, the test seeds
    its own AssessmentTrace / AssessmentEvidenceShown / AssessmentCitation /
    PromptSnapshot rows so each test owns its scenario shape.
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

    wb_path = tmp_path / "wb.xlsx"
    wb_path.write_bytes(b"x")

    with Session(engine) as s:
        framework = Framework(name="NIST SP 800-53", version="Rev 5")
        s.add(framework)
        s.commit()
        s.refresh(framework)

        control = Control(
            framework_id=framework.id,
            control_id="AC-2",
            title="Account Management",
            family="AC",
        )
        s.add(control)
        s.commit()
        s.refresh(control)

        objective = Objective(
            control_id_fk=control.id,
            objective_id="CCI-000001",
            text="The information system manages information system accounts.",
        )
        s.add(objective)
        s.commit()
        s.refresh(objective)

        workbook = Workbook(
            path=str(wb_path), filename=wb_path.name, framework_id=framework.id
        )
        s.add(workbook)
        s.commit()
        s.refresh(workbook)

        evidence = Evidence(
            path="file:///fake/usd00050010.pdf",
            sha256="deadbeef" * 8,
            kind=EvidenceKind.PDF,
            size_bytes=1024,
            title="USD00050010 Example System Account Management Plan",
            workbook_id=workbook.id,
        )
        s.add(evidence)
        s.commit()
        s.refresh(evidence)

        assessment = Assessment(
            workbook_id=workbook.id,
            objective_id=objective.id,
            excel_row=10,
            status=ComplianceStatus.COMPLIANT,
            tester="Noah Jaskolski",
            date_tested=datetime.now(timezone.utc),
            narrative_q="Account management is documented in USD00050010.",
            narrative_class=NarrativeClass.COMPLIANCE_AFFIRMING,
        )
        s.add(assessment)
        s.commit()
        s.refresh(assessment)

        client = TestClient(app)
        yield {
            "client": client,
            "engine": engine,
            "session_factory": lambda: Session(engine),
            "assessment_id": assessment.id,
            "evidence_id": evidence.id,
        }


def _make_prompt_snapshot(s: Session, *, sha: str, text: str) -> None:
    """Insert-or-skip helper — mirrors the persister's dedup contract."""
    if s.get(PromptSnapshot, sha) is None:
        s.add(
            PromptSnapshot(
                sha256=sha, text=text, prompt_kind="assess_control"
            )
        )
        s.commit()


def _make_trace(
    s: Session,
    *,
    assessment_id: int,
    pass_index: int,
    sha: str,
    request_id: str,
) -> AssessmentTrace:
    tr = AssessmentTrace(
        assessment_id=assessment_id,
        system_prompt_sha=sha,
        user_message=f"## Task — pass {pass_index}",
        model="claude-opus-4-6",
        anthropic_model_version="claude-opus-4-6-20260101",
        temperature=0.0,
        max_tokens=2048,
        request_id=request_id,
        raw_response_json='{"status":"Compliant"}',
        pass_index=pass_index,
    )
    s.add(tr)
    s.commit()
    s.refresh(tr)
    return tr


# ---------------------------------------------------------------------------
# 1. 404 on missing assessment
# ---------------------------------------------------------------------------


def test_audit_endpoint_returns_404_for_missing_assessment(env):
    """Stale link from a deleted Assessment must surface as 404, not 500.

    The UI hook (useAssessmentAudit) treats 404 as a "this assessment is
    gone, navigate back to the workbook" signal. A 500 here would render
    a generic error toast and leave the user stranded.
    """
    resp = env["client"].get("/api/controls/assessments/999999/audit")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Assessment not found"


# ---------------------------------------------------------------------------
# 2. Deterministic verdict path — empty arrays, still 200 OK
# ---------------------------------------------------------------------------


def test_audit_endpoint_returns_empty_arrays_for_deterministic_verdict(env):
    """Rule-driven verdict (no LLM call) → 200 with empty trace arrays.

    rule_8a / rule_8b / rule_8c / CRM short-circuits write an Assessment
    row but skip every audit-trail child table because no LLM call was
    made and no per-objective evidence bundle was rendered. The UI Audit
    trail card must still mount and render its "no LLM trace —
    deterministic verdict" banner; a 404 here would mis-signal "stale
    link" and a 500 would render an error toast.
    """
    resp = env["client"].get(
        f"/api/controls/assessments/{env['assessment_id']}/audit"
    )
    assert resp.status_code == 200
    body = resp.json()

    assert body["assessment_id"] == env["assessment_id"]
    assert body["trace"] == []
    assert body["system_prompts"] == []
    assert body["evidence_shown"] == []
    assert body["citations"] == []
    # run_id is nullable on Assessment (single-CCI assess path doesn't
    # always set it); the endpoint must not crash when it's None.
    assert "run_id" in body


# ---------------------------------------------------------------------------
# 3. Orphaned Evidence — LEFT JOIN preserves the shown-chunk row
# ---------------------------------------------------------------------------


def test_audit_endpoint_renders_orphaned_evidence_with_null_metadata(env):
    """Hard-deleted Evidence row must NOT drop the AssessmentEvidenceShown.

    The auditability contract is "show the model what it saw", not
    "show the model what's still on disk". If the source PDF is moved or
    re-ingested under a different sha, the snapshot row (carrying the
    verbatim chunk_text and chunk_sha) must still render — with
    ``evidence_title`` and ``evidence_path`` set to null so the UI can
    badge it as "source file no longer available" instead of pretending
    the chunk came from nowhere.
    """
    assessment_id = env["assessment_id"]
    evidence_id = env["evidence_id"]

    with env["session_factory"]() as s:
        # Add a shown-chunk row, then hard-delete the parent Evidence.
        shown = AssessmentEvidenceShown(
            assessment_id=assessment_id,
            evidence_id=evidence_id,
            chunk_sha="cafe" * 16,
            chunk_text="Account creation, modification, and disabling procedures.",
            order_index=0,
            relevance=0.92,
            tag_source="stig_mapper",
        )
        s.add(shown)
        s.commit()

        # Hard-delete the Evidence row — simulates re-ingest / cleanup.
        ev = s.get(Evidence, evidence_id)
        assert ev is not None
        s.delete(ev)
        s.commit()

    resp = env["client"].get(
        f"/api/controls/assessments/{assessment_id}/audit"
    )
    assert resp.status_code == 200
    body = resp.json()

    # The shown-chunk row survived the LEFT JOIN.
    assert len(body["evidence_shown"]) == 1
    surviving = body["evidence_shown"][0]
    assert surviving["evidence_id"] == evidence_id
    assert surviving["chunk_sha"] == "cafe" * 16
    assert surviving["chunk_text"].startswith("Account creation")
    # …but the parent Evidence is gone, so title and path are null.
    assert surviving["evidence_title"] is None
    assert surviving["evidence_path"] is None


# ---------------------------------------------------------------------------
# 4. Dual-pass — 2 traces ordered by pass_index, system_prompts deduped
# ---------------------------------------------------------------------------


def test_audit_endpoint_returns_dual_pass_traces_ordered_with_deduped_prompts(env):
    """Two AssessmentTrace rows must come back in pass_index order.

    Dual-pass writes pass 0 (initial verdict) and pass 1 (challenger /
    rewrite). The UI renders them side-by-side under a "Pass 0 / Pass 1"
    tab, so a stable ordering is the entire contract — accidental
    reverse-order would mis-label the panels.

    Both passes use the SAME system prompt sha in v1; ``system_prompts``
    must be deduped to one entry so the UI doesn't render the same 4-KB
    prompt text twice. If a future v2 splits the system prompt per pass,
    this same loop will preserve both entries (it's sha-keyed, not
    pass-keyed) and the test will fail loudly, prompting an explicit
    schema-shape decision.
    """
    assessment_id = env["assessment_id"]
    shared_sha = "0" * 64

    with env["session_factory"]() as s:
        _make_prompt_snapshot(
            s, sha=shared_sha, text="You are a NIST SP 800-53 assessor…"
        )
        # Insert pass 1 first to prove the endpoint ORDERS BY pass_index
        # rather than insertion order — a bug here would mis-label the
        # UI's Pass 0 / Pass 1 tabs.
        _make_trace(
            s,
            assessment_id=assessment_id,
            pass_index=1,
            sha=shared_sha,
            request_id="req_pass_1_inserted_first",
        )
        _make_trace(
            s,
            assessment_id=assessment_id,
            pass_index=0,
            sha=shared_sha,
            request_id="req_pass_0_inserted_second",
        )

    resp = env["client"].get(
        f"/api/controls/assessments/{assessment_id}/audit"
    )
    assert resp.status_code == 200
    body = resp.json()

    # Trace ordering — pass_index ascending regardless of insert order.
    assert len(body["trace"]) == 2
    assert [tr["pass_index"] for tr in body["trace"]] == [0, 1]
    assert body["trace"][0]["request_id"] == "req_pass_0_inserted_second"
    assert body["trace"][1]["request_id"] == "req_pass_1_inserted_first"

    # System prompts deduped: both traces share the same sha → one entry.
    assert len(body["system_prompts"]) == 1
    assert body["system_prompts"][0]["sha256"] == shared_sha
    assert body["system_prompts"][0]["text"].startswith(
        "You are a NIST SP 800-53 assessor"
    )
    assert body["system_prompts"][0]["prompt_kind"] == "assess_control"


# ---------------------------------------------------------------------------
# 5. Citation envelope — full offset round-trip for UI click-to-jump
# ---------------------------------------------------------------------------


def test_audit_endpoint_returns_full_citation_envelope_for_ui_click_to_jump(env):
    """Every citation field the UI's click-to-jump highlighter reads must
    round-trip from DB to JSON. The plan calls out a click on a claim row
    that scrolls/highlights the source span inside the evidence chunk
    expander — that requires both (claim_start_char, claim_end_char) on
    the narrative side AND (source_start_char, source_end_char) plus
    evidence_shown_id on the evidence side. Drop any one of those and
    the highlighter silently degrades to a click-no-op.
    """
    assessment_id = env["assessment_id"]
    evidence_id = env["evidence_id"]
    shared_sha = "1" * 64

    with env["session_factory"]() as s:
        _make_prompt_snapshot(s, sha=shared_sha, text="prompt")
        _make_trace(
            s,
            assessment_id=assessment_id,
            pass_index=0,
            sha=shared_sha,
            request_id="req_citation_test",
        )
        shown = AssessmentEvidenceShown(
            assessment_id=assessment_id,
            evidence_id=evidence_id,
            chunk_sha="beef" * 16,
            chunk_text=(
                "USD00050010 Example System Account Management Plan establishes "
                "account creation, modification, and disabling procedures."
            ),
            order_index=0,
            relevance=0.95,
            tag_source="stig_mapper",
        )
        s.add(shown)
        s.commit()
        s.refresh(shown)

        cite = AssessmentCitation(
            assessment_id=assessment_id,
            narrative_field="narrative_q",
            claim_text="Account management is documented in USD00050010",
            claim_start_char=0,
            claim_end_char=49,
            evidence_shown_id=shown.id,
            source_quote="USD00050010 Example System Account Management Plan",
            source_start_char=0,
            source_end_char=39,
            extraction_method="llm_self_cite",
        )
        s.add(cite)
        s.commit()

    resp = env["client"].get(
        f"/api/controls/assessments/{assessment_id}/audit"
    )
    assert resp.status_code == 200
    body = resp.json()

    assert len(body["citations"]) == 1
    c = body["citations"][0]
    # Every field the UI's highlighter reads must be present and typed.
    for key in (
        "id",
        "narrative_field",
        "claim_text",
        "claim_start_char",
        "claim_end_char",
        "evidence_shown_id",
        "source_quote",
        "source_start_char",
        "source_end_char",
        "extraction_method",
    ):
        assert key in c, f"Citation envelope missing UI-required field: {key}"

    assert c["narrative_field"] == "narrative_q"
    assert c["claim_start_char"] == 0
    assert c["claim_end_char"] == 49
    assert c["source_start_char"] == 0
    assert c["source_end_char"] == 39
    assert c["extraction_method"] == "llm_self_cite"
    # The FK must point at the shown-chunk row so the UI can resolve
    # which evidence expander panel to scroll into view.
    assert c["evidence_shown_id"] == body["evidence_shown"][0]["id"]
