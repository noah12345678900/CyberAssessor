"""Scale tests for IN-clause chunking and corroborating_findings / affected_hosts.

Tests:
  - chunked() unit: len 0, exactly 900, 901, 1801
  - corroborating_findings() with >900 tagged evidence ids — no SQLITE error
  - affected_hosts() with >900 tagged evidence ids — correct union
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

from cybersecurity_assessor import models  # noqa: F401 -- registers tables
from cybersecurity_assessor.db import IN_CLAUSE_CHUNK, chunked
from cybersecurity_assessor.engine.finding_corroboration import (
    affected_hosts,
    corroborating_findings,
)
from cybersecurity_assessor.models import (
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


@pytest.fixture
def objective(session) -> Objective:
    fw = Framework(name="NIST 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)
    ctrl = Control(framework_id=fw.id, control_id="SI-3", title="Malware Protection", family="SI")
    session.add(ctrl)
    session.commit()
    session.refresh(ctrl)
    obj = Objective(
        control_id_fk=ctrl.id,
        objective_id="CCI-001240",
        source="CCI",
        text="The system employs malware protection.",
    )
    session.add(obj)
    session.commit()
    session.refresh(obj)
    return obj


# ---------------------------------------------------------------------------
# chunked() unit tests
# ---------------------------------------------------------------------------


def test_chunked_empty():
    result = list(chunked([]))
    assert result == []


def test_chunked_exactly_one_batch():
    items = list(range(IN_CLAUSE_CHUNK))
    batches = list(chunked(items))
    assert len(batches) == 1
    assert batches[0] == items


def test_chunked_one_over_boundary():
    items = list(range(IN_CLAUSE_CHUNK + 1))
    batches = list(chunked(items))
    assert len(batches) == 2
    assert len(batches[0]) == IN_CLAUSE_CHUNK
    assert len(batches[1]) == 1
    # union of batches == original
    assert batches[0] + batches[1] == items


def test_chunked_two_full_plus_one():
    n = IN_CLAUSE_CHUNK * 2 + 1
    items = list(range(n))
    batches = list(chunked(items))
    assert len(batches) == 3
    all_items = [x for batch in batches for x in batch]
    assert all_items == items


def test_chunked_preserves_all_items():
    items = list(range(2000))
    batches = list(chunked(items))
    assert sum(len(b) for b in batches) == 2000
    assert sorted(x for b in batches for x in b) == items


# ---------------------------------------------------------------------------
# corroborating_findings with >900 evidence ids
# ---------------------------------------------------------------------------


def _bulk_evidence(
    session: Session, workbook_id: int, n: int, *, host_prefix: str = "host"
) -> list[Evidence]:
    rows = [
        Evidence(
            path=f"/scan/{i}.ckl",
            sha256=f"sha{i:08d}",
            kind=EvidenceKind.STIG_CKL,
            size_bytes=512,
            workbook_id=workbook_id,
            host_inventory=json.dumps([f"{host_prefix}{i}.corp.local"]),
        )
        for i in range(n)
    ]
    session.add_all(rows)
    session.commit()
    return rows


def test_corroborating_findings_over_900_ids(session, objective):
    """Chunked IN-clause: 2000 tagged evidence rows must not raise SQLITE error."""
    wb = Workbook(path="/tmp/wb.xlsx", filename="wb.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)

    n = 2_000
    evs = _bulk_evidence(session, wb.id, n)

    # Tag all of them to the objective
    tags = [
        EvidenceTag(evidence_id=ev.id, objective_id=objective.id, relevance=0.5, confidence=0.5)
        for ev in evs
    ]
    session.add_all(tags)
    session.commit()

    # Add a single OPEN StigFinding on the LAST evidence row, citing the cluster CCI
    finding = StigFinding(
        evidence_id=evs[-1].id,
        rule_id="V-12345",
        cci_refs="CCI-001240",
        severity="high",
        status=FindingStatus.OPEN,
        finding_details="Malware protection not enabled.",
    )
    session.add(finding)
    session.commit()

    results = corroborating_findings(
        objective_ids=[objective.id],
        cci_ids_in_cluster={"CCI-001240"},
        session=session,
    )

    # Must return exactly the one matching finding without raising
    assert len(results) == 1
    assert results[0][0].rule_id == "V-12345"


def test_corroborating_findings_empty_when_no_matching_cci(session, objective):
    """Findings that don't cite the cluster CCI are excluded even when tagged."""
    wb = Workbook(path="/tmp/wb2.xlsx", filename="wb2.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)

    ev = Evidence(
        path="/scan/other.ckl",
        sha256="abcd1234",
        kind=EvidenceKind.STIG_CKL,
        size_bytes=512,
        workbook_id=wb.id,
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    session.add(EvidenceTag(evidence_id=ev.id, objective_id=objective.id, relevance=0.5, confidence=0.5))
    session.add(
        StigFinding(
            evidence_id=ev.id,
            rule_id="V-99999",
            cci_refs="CCI-000001",  # different CCI
            severity="low",
            status=FindingStatus.OPEN,
            finding_details="Other finding.",
        )
    )
    session.commit()

    results = corroborating_findings(
        objective_ids=[objective.id],
        cci_ids_in_cluster={"CCI-001240"},
        session=session,
    )
    assert results == []


# ---------------------------------------------------------------------------
# affected_hosts with >900 evidence ids
# ---------------------------------------------------------------------------


def test_affected_hosts_over_900_ids(session, objective):
    """affected_hosts correctly unions hosts across a 2000-row evidence pool."""
    wb = Workbook(path="/tmp/wb3.xlsx", filename="wb3.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)

    n = 2_000
    evs = _bulk_evidence(session, wb.id, n, host_prefix="server")

    tags = [
        EvidenceTag(evidence_id=ev.id, objective_id=objective.id, relevance=0.5, confidence=0.5)
        for ev in evs
    ]
    session.add_all(tags)
    session.commit()

    hosts = affected_hosts(objective_ids=[objective.id], session=session)

    # Each evidence row has a unique hostname; we should see all 2000
    assert len(hosts) == n
    # Sorted
    assert hosts == sorted(hosts)
    # First and last hostnames present
    assert "server0.corp.local" in hosts
    assert f"server{n-1}.corp.local" in hosts


def test_affected_hosts_empty_when_no_tags(session, objective):
    results = affected_hosts(objective_ids=[objective.id], session=session)
    assert results == []


def test_affected_hosts_empty_objective_ids(session):
    results = affected_hosts(objective_ids=[], session=session)
    assert results == []
