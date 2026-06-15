"""Unit tests for ``catalogs.pci_dss_loader.load_pci_dss_catalog``.

PCI DSS requirement text is copyrighted by the PCI SSC, so every fixture here
is SYNTHETIC — invented placeholder strings ("Synthetic PCI requirement
text."), never real requirement language. Pinned concerns:

1. The license guard fires for both ``path=None`` and ``offline=True``, with a
   message that mentions licensing / supplying the export.
2. A synthetic CSV and a synthetic JSON list both load into one Framework
   (correct framework_id + version, enabled defaulting True) and three
   Controls, with the top-level-requirement family derivation ("8.3.6" -> "8").
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
from cybersecurity_assessor.catalogs.pci_dss_loader import (  # noqa: E402
    FRAMEWORK_ID,
    FRAMEWORK_VERSION,
    load_pci_dss_catalog,
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


# Synthetic rows — fake ids/titles/text. NOT real PCI DSS content.
_ROWS = [
    {
        "id": "1.1.1",
        "title": "Synthetic firewall requirement",
        "text": "Synthetic PCI requirement text for 1.1.1.",
        "category": "Network Security",
    },
    {
        "id": "8.3.6",
        "title": "Synthetic auth requirement",
        # No category -> family derived from leading requirement number.
        "text": "Synthetic PCI requirement text for 8.3.6.",
    },
    {
        "id": "10.2.1",
        "title": "Synthetic logging requirement",
        "text": "Synthetic PCI requirement text for 10.2.1.",
    },
]


def _write_csv(tmp_path: Path, rows: list[dict[str, str]]) -> Path:
    path = tmp_path / "synthetic_pci.csv"
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
    path = tmp_path / "synthetic_pci.json"
    path.write_text(json.dumps(rows), encoding="utf-8")
    return path


def test_requires_licensed_export(session):
    """No path AND offline=True both raise with a licensing message."""
    with pytest.raises((RuntimeError, ValueError)) as none_exc:
        load_pci_dss_catalog(session, path=None)
    msg = str(none_exc.value).lower()
    assert "licens" in msg or "supply" in msg

    with pytest.raises((RuntimeError, ValueError)) as offline_exc:
        load_pci_dss_catalog(session, path="ignored.csv", offline=True)
    msg2 = str(offline_exc.value).lower()
    assert "licens" in msg2 or "supply" in msg2


def test_loads_from_csv_fixture(session, tmp_path):
    path = _write_csv(tmp_path, _ROWS)
    fw = load_pci_dss_catalog(session, path=path)

    assert fw.framework_id == FRAMEWORK_ID
    assert fw.version == FRAMEWORK_VERSION
    assert fw.enabled is True  # default untouched by loader

    controls = session.exec(
        select(Control).where(Control.framework_id == fw.id)
    ).all()
    assert len(controls) == 3

    by_id = {c.control_id: c for c in controls}
    assert "8.3.6" in by_id
    c = by_id["8.3.6"]
    assert c.statement == "Synthetic PCI requirement text for 8.3.6."
    # No category column on that row -> family from top-level req number.
    assert c.family == "8"
    # Explicit category honored on the first row.
    assert by_id["1.1.1"].family == "Network Security"


def test_loads_from_json_fixture(session, tmp_path):
    path = _write_json(tmp_path, _ROWS)
    fw = load_pci_dss_catalog(session, path=path)

    assert fw.framework_id == FRAMEWORK_ID
    assert fw.version == FRAMEWORK_VERSION
    assert fw.enabled is True

    controls = session.exec(
        select(Control).where(Control.framework_id == fw.id)
    ).all()
    assert len(controls) == 3
    by_id = {c.control_id: c for c in controls}
    assert by_id["8.3.6"].family == "8"
    assert by_id["8.3.6"].statement == "Synthetic PCI requirement text for 8.3.6."


def test_idempotent_reload_converges(session, tmp_path):
    path = _write_csv(tmp_path, _ROWS)
    first = load_pci_dss_catalog(session, path=path)
    second = load_pci_dss_catalog(session, path=path)

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
        {"id": "1.1.1", "title": "Synthetic firewall requirement"},
        {"id": "8.3.6", "title": "Synthetic auth requirement"},
    ]
    path = _write_csv(tmp_path, bad_rows)
    with pytest.raises(ValueError, match="text"):
        load_pci_dss_catalog(session, path=path)
