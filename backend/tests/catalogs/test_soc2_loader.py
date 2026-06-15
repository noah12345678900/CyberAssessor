"""Unit tests for ``catalogs.soc2_loader.load_soc2_catalog``.

SOC 2 Trust Services Criteria text is copyrighted by the AICPA, so every
fixture here is SYNTHETIC — invented placeholder strings ("Synthetic SOC 2
criterion text."), never real TSC language. Pinned concerns:

1. The license guard fires for both ``path=None`` and ``offline=True``, with a
   message that mentions licensing / supplying the export.
2. A synthetic CSV and a synthetic JSON list both load into one Framework
   (correct framework_id + version, enabled defaulting True) and three
   Controls, with the alpha-prefix family derivation ("CC1.1" -> "CC").
3. Reloading the same export converges (one Framework, unchanged Control
   count).
4. A CSV missing the text column raises ValueError naming the field.
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
from cybersecurity_assessor.catalogs.soc2_loader import (  # noqa: E402
    FRAMEWORK_ID,
    FRAMEWORK_VERSION,
    load_soc2_catalog,
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


# Synthetic rows — fake ids/titles/text. NOT real SOC 2 TSC content.
_ROWS = [
    {
        "id": "CC1.1",
        "title": "Synthetic control environment criterion",
        "text": "Synthetic SOC 2 criterion text for CC1.1.",
        "tsc_category": "Common Criteria",
    },
    {
        "id": "A1.2",
        "title": "Synthetic availability criterion",
        # No tsc_category -> family derived from leading alpha prefix.
        "text": "Synthetic SOC 2 criterion text for A1.2.",
    },
    {
        "id": "PI1.1",
        "title": "Synthetic processing-integrity criterion",
        "text": "Synthetic SOC 2 criterion text for PI1.1.",
    },
]


def _write_csv(tmp_path: Path, rows: list[dict[str, str]]) -> Path:
    path = tmp_path / "synthetic_soc2.csv"
    fieldnames: list[str] = []
    for r in rows:
        for k in r:
            if k not in fieldnames:
                fieldnames.append(k)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return path


def _write_json(tmp_path: Path, rows: list[dict[str, str]]) -> Path:
    path = tmp_path / "synthetic_soc2.json"
    path.write_text(json.dumps(rows), encoding="utf-8")
    return path


def test_requires_licensed_export(session):
    """No path AND offline=True both raise with a licensing message."""
    with pytest.raises((RuntimeError, ValueError)) as none_exc:
        load_soc2_catalog(session, path=None)
    msg = str(none_exc.value).lower()
    assert "licens" in msg or "supply" in msg

    with pytest.raises((RuntimeError, ValueError)) as offline_exc:
        load_soc2_catalog(session, path="ignored.csv", offline=True)
    msg2 = str(offline_exc.value).lower()
    assert "licens" in msg2 or "supply" in msg2


def test_loads_from_csv_fixture(session, tmp_path):
    path = _write_csv(tmp_path, _ROWS)
    fw = load_soc2_catalog(session, path=path)

    assert fw.framework_id == FRAMEWORK_ID
    assert fw.version == FRAMEWORK_VERSION
    assert fw.enabled is True  # default untouched by loader

    controls = session.exec(
        select(Control).where(Control.framework_id == fw.id)
    ).all()
    assert len(controls) == 3

    by_id = {c.control_id: c for c in controls}
    assert "CC1.1" in by_id
    c = by_id["CC1.1"]
    assert c.statement == "Synthetic SOC 2 criterion text for CC1.1."
    # Explicit tsc_category honored.
    assert c.family == "Common Criteria"
    # No category column -> family from leading alpha prefix.
    assert by_id["A1.2"].family == "A"
    assert by_id["PI1.1"].family == "PI"


def test_loads_from_json_fixture(session, tmp_path):
    path = _write_json(tmp_path, _ROWS)
    fw = load_soc2_catalog(session, path=path)

    assert fw.framework_id == FRAMEWORK_ID
    assert fw.version == FRAMEWORK_VERSION
    assert fw.enabled is True

    controls = session.exec(
        select(Control).where(Control.framework_id == fw.id)
    ).all()
    assert len(controls) == 3
    by_id = {c.control_id: c for c in controls}
    assert by_id["A1.2"].family == "A"
    assert by_id["CC1.1"].statement == "Synthetic SOC 2 criterion text for CC1.1."


def test_idempotent_reload_converges(session, tmp_path):
    path = _write_csv(tmp_path, _ROWS)
    first = load_soc2_catalog(session, path=path)
    second = load_soc2_catalog(session, path=path)

    assert first.id == second.id
    frameworks = session.exec(
        select(Framework).where(Framework.framework_id == FRAMEWORK_ID)
    ).all()
    assert len(frameworks) == 1

    controls = session.exec(
        select(Control).where(Control.framework_id == first.id)
    ).all()
    assert len(controls) == 3


def test_missing_required_column_raises(session, tmp_path):
    """CSV with no text-equivalent column -> ValueError naming the field."""
    bad_rows = [
        {"id": "CC1.1", "title": "Synthetic control environment criterion"},
        {"id": "A1.2", "title": "Synthetic availability criterion"},
    ]
    path = _write_csv(tmp_path, bad_rows)
    with pytest.raises(ValueError, match="text"):
        load_soc2_catalog(session, path=path)
