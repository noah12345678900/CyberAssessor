"""Unit tests for ``catalogs.iso27001_loader.load_iso27001_catalog``.

ISO/IEC 27001 Annex A is copyrighted, so this loader reads a user-supplied
licensed export instead of bundling/fabricating content. These tests use
SYNTHETIC, made-up control text only — never real ISO text — to honor that
defensibility requirement.

Pinned behaviors:
  1. No path (or offline) -> raises with a licensing/supply message.
  2. Loads from a synthetic CSV and a synthetic JSON list.
  3. Reload converges (one Framework, stable Control count).
  4. Missing the required text column -> ValueError naming the field.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.catalogs.iso27001_loader import (  # noqa: E402
    load_iso27001_catalog,
)
from cybersecurity_assessor.models import Control, Framework  # noqa: E402


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


# Synthetic Annex-A-shaped rows. Text is invented for testing — NOT real ISO.
_SYNTH_ROWS = [
    {
        "id": "A.5.1",
        "title": "Synthetic policy control",
        "text": "Synthetic ISO control text for testing one.",
        "category": "Organizational",
    },
    {
        "id": "A.6.1",
        "title": "Synthetic people control",
        "text": "Synthetic ISO control text for testing two.",
        "category": "People",
    },
    {
        "id": "A.8.1",
        "title": "Synthetic tech control",
        "text": "Synthetic ISO control text for testing three.",
        "category": "Technological",
    },
]


def _write_csv(tmp_path: Path, rows: list[dict], *, drop: str | None = None) -> Path:
    fieldnames = [k for k in rows[0].keys() if k != drop]
    path = tmp_path / "synthetic_iso27001.csv"
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: v for k, v in r.items() if k != drop})
    return path


def _write_json(tmp_path: Path, rows: list[dict]) -> Path:
    path = tmp_path / "synthetic_iso27001.json"
    path.write_text(json.dumps(rows), encoding="utf-8")
    return path


def test_requires_licensed_export(session):
    """No path AND offline mode both refuse, citing licensing/supply."""
    with pytest.raises((ValueError, RuntimeError)) as exc_none:
        load_iso27001_catalog(session, path=None)
    msg_none = str(exc_none.value).lower()
    assert "licens" in msg_none or "supply" in msg_none

    with pytest.raises((ValueError, RuntimeError)) as exc_off:
        load_iso27001_catalog(session, path="anything.csv", offline=True)
    msg_off = str(exc_off.value).lower()
    assert "licens" in msg_off or "supply" in msg_off


def test_loads_from_csv_fixture(session, tmp_path):
    path = _write_csv(tmp_path, _SYNTH_ROWS)
    fw = load_iso27001_catalog(session, path=path)

    assert fw.framework_id == "ISO-27001-2022"
    assert fw.version == "2022"
    assert fw.name == "ISO/IEC 27001"
    assert fw.enabled is True  # default untouched
    assert fw.parent_framework_id is None

    controls = session.exec(
        select(Control).where(Control.framework_id == fw.id)
    ).all()
    assert len(controls) == 3

    by_id = {c.control_id: c for c in controls}
    assert "A.5.1" in by_id
    assert by_id["A.5.1"].statement == "Synthetic ISO control text for testing one."
    assert by_id["A.5.1"].family == "Organizational"
    assert by_id["A.5.1"].family != ""


def test_loads_from_json_fixture(session, tmp_path):
    path = _write_json(tmp_path, _SYNTH_ROWS)
    fw = load_iso27001_catalog(session, path=path)

    assert fw.framework_id == "ISO-27001-2022"
    assert fw.version == "2022"

    controls = session.exec(
        select(Control).where(Control.framework_id == fw.id)
    ).all()
    assert len(controls) == 3
    by_id = {c.control_id: c for c in controls}
    assert by_id["A.8.1"].statement == "Synthetic ISO control text for testing three."
    assert by_id["A.8.1"].family == "Technological"


def test_idempotent_reload_converges(session, tmp_path):
    path = _write_csv(tmp_path, _SYNTH_ROWS)
    load_iso27001_catalog(session, path=path)
    load_iso27001_catalog(session, path=path)

    frameworks = session.exec(
        select(Framework).where(Framework.framework_id == "ISO-27001-2022")
    ).all()
    assert len(frameworks) == 1

    controls = session.exec(
        select(Control).where(Control.framework_id == frameworks[0].id)
    ).all()
    assert len(controls) == 3


def test_missing_required_column_raises(session, tmp_path):
    """Drop the text column -> ValueError naming the missing field."""
    path = _write_csv(tmp_path, _SYNTH_ROWS, drop="text")
    with pytest.raises(ValueError, match="text"):
        load_iso27001_catalog(session, path=path)
