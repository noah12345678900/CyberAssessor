"""Workbook isolation for ODP rendering and overwrite history."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from cybersecurity_assessor import models  # noqa: F401
from cybersecurity_assessor.controls.odp_render import fetch_odp_history, resolve_odps
from cybersecurity_assessor.models import OdpAssignment, OdpAuditLog, Workbook
from cybersecurity_assessor.routes.workbooks import delete_workbook

FW = "NIST-800-53r4"


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as value:
        yield value


def _workbook(session: Session, name: str) -> Workbook:
    workbook = Workbook(path=name, filename=name)
    session.add(workbook)
    session.commit()
    session.refresh(workbook)
    return workbook


def _assignment(
    session: Session,
    *,
    workbook_id: int | None,
    value: str,
    control_id: str = "ac-2",
) -> None:
    session.add(
        OdpAssignment(
            workbook_id=workbook_id,
            framework_version=FW,
            control_id=control_id,
            odp_id="{$37$}",
            assigned_from="DoW Enterprise",
            value=value,
            source_ingest="CCIS-workbook",
        )
    )
    session.commit()


def test_resolver_isolates_same_odp_between_workbooks(session: Session) -> None:
    workbook_a = _workbook(session, "a.xlsx")
    workbook_b = _workbook(session, "b.xlsx")
    _assignment(session, workbook_id=workbook_a.id, value="System A value")
    _assignment(session, workbook_id=workbook_b.id, value="System B value")

    rendered_a, _ = resolve_odps(session, FW, "ac-2", "Value: {$37$}", workbook_id=workbook_a.id)
    rendered_b, _ = resolve_odps(session, FW, "ac-2", "Value: {$37$}", workbook_id=workbook_b.id)
    assert rendered_a == "Value: System A value"
    assert rendered_b == "Value: System B value"


def test_legacy_global_row_is_fallback_only(session: Session) -> None:
    workbook = _workbook(session, "new.xlsx")
    _assignment(session, workbook_id=None, value="Legacy value")

    rendered, _ = resolve_odps(session, FW, "ac-2", "Value: {$37$}", workbook_id=workbook.id)
    assert rendered == "Value: Legacy value"

    _assignment(session, workbook_id=workbook.id, value="Scoped value", control_id="ac-3")
    rendered, unresolved = resolve_odps(
        session, FW, "ac-3", "Value: {$37$}", workbook_id=workbook.id
    )
    assert rendered == "Value: Scoped value"
    assert unresolved == []


def test_history_is_workbook_scoped(session: Session) -> None:
    workbook_a = _workbook(session, "a.xlsx")
    workbook_b = _workbook(session, "b.xlsx")
    for workbook, value in ((workbook_a, "A"), (workbook_b, "B")):
        session.add(
            OdpAuditLog(
                workbook_id=workbook.id,
                framework_version=FW,
                control_id="ac-2",
                odp_id="{$37$}",
                assigned_from="DoW Enterprise",
                prev_value="old",
                new_value=value,
                who=workbook.filename,
                when=datetime.now(UTC),
            )
        )
    session.commit()

    history_a = fetch_odp_history(session, FW, "ac-2", workbook_id=workbook_a.id)
    history_b = fetch_odp_history(session, FW, "ac-2", workbook_id=workbook_b.id)
    assert history_a[0]["events"][0]["new_value"] == "A"
    assert history_b[0]["events"][0]["new_value"] == "B"


def test_legacy_history_is_fallback_until_scoped_history_exists(session: Session) -> None:
    workbook = _workbook(session, "legacy-history.xlsx")
    session.add(
        OdpAuditLog(
            workbook_id=None,
            framework_version=FW,
            control_id="ac-2",
            odp_id="{$37$}",
            assigned_from="DoW Enterprise",
            prev_value="old",
            new_value="legacy",
            who="legacy",
            when=datetime.now(UTC),
        )
    )
    session.commit()

    history = fetch_odp_history(session, FW, "ac-2", workbook_id=workbook.id)
    assert history[0]["events"][0]["new_value"] == "legacy"


def test_deleting_workbook_removes_owned_odp_rows(session: Session) -> None:
    workbook = _workbook(session, "delete-me.xlsx")
    _assignment(session, workbook_id=workbook.id, value="owned")
    session.add(
        OdpAuditLog(
            workbook_id=workbook.id,
            framework_version=FW,
            control_id="ac-2",
            odp_id="{$37$}",
            assigned_from="DoW Enterprise",
            prev_value="old",
            new_value="owned",
            who=workbook.filename,
            when=datetime.now(UTC),
        )
    )
    session.commit()

    result = delete_workbook(workbook.id, s=session)
    assert result["cascade"]["odp_assignments"] == 1
    assert result["cascade"]["odp_audit_logs"] == 1
    assert session.get(Workbook, workbook.id) is None
