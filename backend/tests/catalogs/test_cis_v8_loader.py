"""Unit tests for ``catalogs.cis_v8_loader.load_cis_v8_catalog``.

CIS Controls v8 are copyrighted, so this loader reads a user-supplied
licensed export instead of bundling/fabricating content. These tests use
SYNTHETIC, made-up safeguard text only — never real CIS text — to honor that
defensibility requirement.

Pinned behaviors:
  1. No path (or offline) -> raises with a licensing/supply message.
  2. Loads from a synthetic CSV and a synthetic JSON list.
  3. Family is derived from the Safeguard id (split on '.') when no family
     column is supplied; an explicit family column wins when present.
  4. Reload converges (one Framework, stable Control count).
  5. Missing the required text column -> ValueError naming the field.
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
from cybersecurity_assessor.catalogs.cis_v8_loader import (  # noqa: E402
    load_cis_v8_catalog,
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


# Synthetic Safeguard-shaped rows WITHOUT a family column so the loader must
# derive family from the id (split on '.'). Text is invented — NOT real CIS.
_SYNTH_ROWS = [
    {
        "id": "1.1",
        "title": "Synthetic inventory safeguard",
        "text": "Synthetic CIS safeguard text for testing one.",
    },
    {
        "id": "1.2",
        "title": "Synthetic inventory safeguard two",
        "text": "Synthetic CIS safeguard text for testing two.",
    },
    {
        "id": "18.5",
        "title": "Synthetic pentest safeguard",
        "text": "Synthetic CIS safeguard text for testing three.",
    },
]


def _write_csv(tmp_path: Path, rows: list[dict], *, drop: str | None = None) -> Path:
    fieldnames = [k for k in rows[0].keys() if k != drop]
    path = tmp_path / "synthetic_cis_v8.csv"
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: v for k, v in r.items() if k != drop})
    return path


def _write_json(tmp_path: Path, rows: list[dict]) -> Path:
    path = tmp_path / "synthetic_cis_v8.json"
    path.write_text(json.dumps(rows), encoding="utf-8")
    return path


def test_requires_licensed_export(session):
    """No path AND offline mode both refuse, citing licensing/supply."""
    with pytest.raises((ValueError, RuntimeError)) as exc_none:
        load_cis_v8_catalog(session, path=None)
    msg_none = str(exc_none.value).lower()
    assert "licens" in msg_none or "supply" in msg_none

    with pytest.raises((ValueError, RuntimeError)) as exc_off:
        load_cis_v8_catalog(session, path="anything.csv", offline=True)
    msg_off = str(exc_off.value).lower()
    assert "licens" in msg_off or "supply" in msg_off


def test_loads_from_csv_fixture(session, tmp_path):
    path = _write_csv(tmp_path, _SYNTH_ROWS)
    fw = load_cis_v8_catalog(session, path=path)

    assert fw.framework_id == "CIS-v8"
    assert fw.version == "v8"
    assert fw.name == "CIS Controls"
    assert fw.enabled is True  # default untouched
    assert fw.parent_framework_id is None

    controls = session.exec(
        select(Control).where(Control.framework_id == fw.id)
    ).all()
    assert len(controls) == 3

    by_id = {c.control_id: c for c in controls}
    assert "1.1" in by_id
    assert by_id["1.1"].statement == "Synthetic CIS safeguard text for testing one."
    # Family derived from id (no family column supplied): "1.1" -> "1".
    assert by_id["1.1"].family == "1"
    assert by_id["1.1"].family != ""
    assert by_id["18.5"].family == "18"


def test_loads_from_json_fixture(session, tmp_path):
    path = _write_json(tmp_path, _SYNTH_ROWS)
    fw = load_cis_v8_catalog(session, path=path)

    assert fw.framework_id == "CIS-v8"
    assert fw.version == "v8"

    controls = session.exec(
        select(Control).where(Control.framework_id == fw.id)
    ).all()
    assert len(controls) == 3
    by_id = {c.control_id: c for c in controls}
    assert by_id["18.5"].statement == "Synthetic CIS safeguard text for testing three."
    assert by_id["18.5"].family == "18"


def test_explicit_family_column_wins(session, tmp_path):
    """When a category column is present it overrides id-derived family."""
    rows = [
        {
            "id": "1.1",
            "name": "Synthetic safeguard",
            "requirement": "Synthetic CIS safeguard text for testing.",
            "category": "Inventory and Control of Enterprise Assets",
        }
    ]
    path = _write_json(tmp_path, rows)
    fw = load_cis_v8_catalog(session, path=path)
    ctrl = session.exec(
        select(Control).where(Control.framework_id == fw.id)
    ).first()
    assert ctrl is not None
    assert ctrl.family == "Inventory and Control of Enterprise Assets"
    # Liberal aliases: name->title, requirement->statement.
    assert ctrl.title == "Synthetic safeguard"
    assert ctrl.statement == "Synthetic CIS safeguard text for testing."


def test_idempotent_reload_converges(session, tmp_path):
    path = _write_csv(tmp_path, _SYNTH_ROWS)
    load_cis_v8_catalog(session, path=path)
    load_cis_v8_catalog(session, path=path)

    frameworks = session.exec(
        select(Framework).where(Framework.framework_id == "CIS-v8")
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
        load_cis_v8_catalog(session, path=path)
