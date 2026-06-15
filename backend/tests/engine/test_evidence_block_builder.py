"""Tests for ``routes.controls._build_evidence_block`` structural output.

The builder is the *producer* half of the structural fix for Step 1.65.
Where ``test_assessor_no_evidence_short_circuit.py`` pins the consumer
(the assessor reads ``EvidenceBlock.is_only_context`` and decides),
this file pins the producer: for each shape of input, what envelope
does the builder hand back?

Three pinning cases, mirroring the plan:

  1. **No tags, non-coverage family** → ``EvidenceBlock(text=None,
     all booleans False)``. The baseline negative case — the assessor
     short-circuits, no LLM call wasted.
  2. **No tags, coverage-eligible family (CM-8)** → ``text is not None``
     (the coverage wrapper rendered), ``has_artifacts=False``,
     ``has_coverage=True``, ``is_only_context=True``. This is the
     production blind spot: the legacy string gate would have let this
     through; the structural flag stops it cold.
  3. **Tagged objective with findings + hosts** → all three artifact
     booleans True (``has_artifacts`` + ``has_findings`` + ``has_hosts``),
     ``is_only_context=False``. The rich-evidence path — the LLM IS
     consulted because real artifacts are present.

The fixtures lean on the patterns already established in
``test_evidence_bundle.py`` (in-memory SQLite + StaticPool, hand-built
Framework→Control→Objective→Evidence→EvidenceTag chain, extracted text
written to ``tmp_path``).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- register tables
from cybersecurity_assessor.engine.evidence_bundle import (  # noqa: E402
    AFFECTED_HOSTS_HEADER,
    CORROBORATING_FINDINGS_HEADER,
    TAGGED_EVIDENCE_HEADER,
    EvidenceBlock,
)
from cybersecurity_assessor.models import (  # noqa: E402
    Control,
    Evidence,
    EvidenceKind,
    EvidenceTag,
    FindingStatus,
    Framework,
    Objective,
    StigFinding,
    Workbook,
)
from cybersecurity_assessor.routes.controls import _build_evidence_block  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    """In-memory SQLite with StaticPool — matches test_evidence_bundle.py."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def framework(session: Session) -> Framework:
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)
    return fw


@pytest.fixture
def workbook(session: Session, framework: Framework) -> Workbook:
    wb = Workbook(
        path="/tmp/test_builder.xlsx",
        filename="test.xlsx",
        framework_id=framework.id,
    )
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb


def _make_objective(
    session: Session, framework: Framework, *, control_id: str, cci_id: str
) -> Objective:
    ctrl = Control(
        framework_id=framework.id,
        control_id=control_id,
        title=f"{control_id} title",
        family=control_id.split("-")[0],
    )
    session.add(ctrl)
    session.commit()
    session.refresh(ctrl)

    obj = Objective(
        control_id_fk=ctrl.id,
        objective_id=cci_id,
        source="CCI",
        text=f"Objective text for {cci_id}.",
    )
    session.add(obj)
    session.commit()
    session.refresh(obj)
    return obj


def _write_snippet(tmp_path: Path, name: str, body: str) -> str:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# Case 1: no tags, non-coverage family → empty envelope
# ---------------------------------------------------------------------------


def test_no_tags_non_coverage_family_returns_empty_envelope(
    session, workbook, framework
):
    """AC-2 with zero EvidenceTags → ``text=None``, every flag False.

    Baseline negative case. The producer asked for tagged evidence
    (got None), asked itself "is this coverage-eligible?" (no, AC-2),
    and short-circuited the coverage join. The envelope it returns
    is the canonical "nothing to assess" shape — the consumer's
    Step 1.65 fires on ``text is None``.
    """
    obj = _make_objective(session, framework, control_id="AC-2", cci_id="CCI-000015")

    block = _build_evidence_block(
        objective_pk=obj.id,
        control_id="AC-2",
        workbook_id=workbook.id,
        s=session,
    )

    assert isinstance(block, EvidenceBlock)
    assert block.text is None
    assert block.has_artifacts is False
    assert block.has_coverage is False
    assert block.has_findings is False
    assert block.has_hosts is False
    # is_only_context is False when text is None — the rule still fires,
    # but on the text=None branch, not the wrapper-only branch.
    assert block.is_only_context is False


# ---------------------------------------------------------------------------
# Case 2: no tags, coverage-eligible family → wrapper-only envelope
# ---------------------------------------------------------------------------


def test_no_tags_coverage_family_returns_wrapper_only_envelope(
    session, workbook, framework
):
    """CM-8 with zero EvidenceTags + at least one categorized artifact in
    the workbook → ``text is not None``, ``has_artifacts=False``,
    ``has_coverage=True``, ``is_only_context=True``.

    This is the production blind spot the structural fix targets: the
    asset coverage report is workbook-wide instructional context, NOT
    per-objective artifact evidence. The legacy string-emptiness gate
    let this string through (it's non-empty), and the LLM treated it
    as evidence. The new envelope carries the structural truth — the
    wrapper rendered, but no artifacts back it — and ``is_only_context``
    fires Step 1.65 deterministically.

    To make ``render_coverage_block`` actually emit content (it returns
    None if no source contributed), the workbook needs at least one
    categorized Evidence row with a ``host_inventory``. A STIG CKL with
    one host is the smallest valid fixture.
    """
    obj = _make_objective(session, framework, control_id="CM-8", cci_id="CCI-000018")

    # Categorized + host-bearing artifact so summarize_asset_coverage
    # returns a SourceSummary and render_coverage_block emits text.
    # NOT tagged to this objective — the test is "coverage wrapper alone
    # masquerading as per-CCI evidence." has_artifacts must stay False.
    ev = Evidence(
        path="/tmp/host1.ckl",
        sha256="cafef00d",
        kind=EvidenceKind.STIG_CKL,
        size_bytes=2048,
        title="Windows 2022 STIG",
        host_inventory=json.dumps(["host01.corp.local"]),
        # PR-2: summarize_asset_coverage is workbook-scoped; an Evidence row
        # without workbook_id is invisible to it, so render_coverage_block
        # would return None and block.text would be None. Scope it.
        workbook_id=workbook.id,
    )
    session.add(ev)
    session.commit()

    block = _build_evidence_block(
        objective_pk=obj.id,
        control_id="CM-8",
        workbook_id=workbook.id,
        s=session,
    )

    assert isinstance(block, EvidenceBlock)
    # The wrapper rendered — workbook-wide coverage report exists.
    assert block.text is not None
    assert "asset_inventory_coverage" in block.text
    # No per-objective tagged artifacts.
    assert block.has_artifacts is False
    assert block.has_coverage is True
    assert block.has_findings is False
    assert block.has_hosts is False
    # The whole point: text non-empty, but it's only context — Step 1.65
    # fires off this single flag.
    assert block.is_only_context is True


# ---------------------------------------------------------------------------
# Case 3: tagged objective with findings + hosts → rich envelope
# ---------------------------------------------------------------------------


def test_tagged_objective_with_findings_and_hosts_returns_rich_envelope(
    session, workbook, framework, tmp_path
):
    """Tagged objective on a CKL with findings + hosts → all three
    artifact booleans True, ``is_only_context=False``.

    The regression boundary on the producer side: when real evidence
    exists, the envelope must surface ``has_artifacts=True`` so the
    assessor stands aside and lets the LLM read the bundle. The
    findings + hosts sub-sections come along for the ride because the
    CKL has both an OPEN STIG finding citing the objective's CCI and
    a non-empty ``host_inventory``.
    """
    obj = _make_objective(session, framework, control_id="AC-2", cci_id="CCI-000015")

    snippet_path = _write_snippet(
        tmp_path,
        "ckl_snippet.txt",
        "Windows 2022 STIG — section 3.2 — privileged account review monthly.",
    )

    ev = Evidence(
        path="/tmp/host1.ckl",
        sha256="cafef00d",
        kind=EvidenceKind.STIG_CKL,
        size_bytes=2048,
        title="Windows 2022 STIG",
        doc_number=None,
        extracted_text_path=snippet_path,
        host_inventory=json.dumps(["host01.corp.local", "host02.corp.local"]),
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)

    # Tag the evidence to this objective so build_tagged_evidence picks
    # it up — has_artifacts hinges on this single join.
    tag = EvidenceTag(
        evidence_id=ev.id,
        objective_id=obj.id,
        relevance=0.9,
        confidence=0.8,
        source="manual",
    )
    session.add(tag)

    # OPEN STIG finding citing the same CCI as the objective →
    # corroborating_findings emits the sub-section.
    finding = StigFinding(
        evidence_id=ev.id,
        rule_id="SV-12345r1_rule",
        cci_refs="CCI-000015",
        severity="medium",
        status=FindingStatus.OPEN,
        finding_details="Account review cadence not enforced via GPO.",
    )
    session.add(finding)
    session.commit()

    block = _build_evidence_block(
        objective_pk=obj.id,
        control_id="AC-2",  # non-coverage family — no coverage wrapper
        workbook_id=workbook.id,
        s=session,
    )

    assert isinstance(block, EvidenceBlock)
    assert block.text is not None
    # All three artifact-evidence headers should be present in the text,
    # AND the structural flags should mirror them — the test pins both
    # so a drift between producer text and producer booleans is caught.
    assert TAGGED_EVIDENCE_HEADER in block.text
    assert CORROBORATING_FINDINGS_HEADER in block.text
    assert AFFECTED_HOSTS_HEADER in block.text
    assert block.has_artifacts is True
    assert block.has_findings is True
    assert block.has_hosts is True
    # AC-2 isn't a coverage family — the coverage join is skipped.
    assert block.has_coverage is False
    # Real evidence is present; the rule must stand aside.
    assert block.is_only_context is False
