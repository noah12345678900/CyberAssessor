"""Tests for GET /api/controls/{control_id}/program-controls.

The endpoint surfaces program-specific overlay rows (e.g. SDA Controls
"shall" statements) grouped by RequirementSource for one base control,
so the Control detail page can render them as a rollup without
expanding every objective.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

# Make the backend package importable from any pytest cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.db import get_session  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Control,
    Framework,
    Objective,
    RequirementMap,
    RequirementSource,
)
from cybersecurity_assessor.server import create_app  # noqa: E402


@pytest.fixture
def env(tmp_path: Path):
    """In-memory SQLite seeded with two frameworks, a control with two CCIs,
    and two overlays — one attached to each framework — both mapping to the
    same control's CCIs. Lets us exercise the framework filter without
    rebuilding the world per test.
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

    with Session(engine) as s:
        fw_r5 = Framework(name="NIST SP 800-53", version="Rev 5")
        fw_r4 = Framework(name="NIST SP 800-53", version="Rev 4")
        s.add_all([fw_r5, fw_r4])
        s.commit()
        s.refresh(fw_r5)
        s.refresh(fw_r4)

        ctrl = Control(
            framework_id=fw_r5.id,
            control_id="AC-2",
            title="Account Management",
            family="AC",
        )
        s.add(ctrl)
        s.commit()
        s.refresh(ctrl)

        cci_a = Objective(
            control_id_fk=ctrl.id,
            objective_id="CCI-000015",
            source="CCI",
            text="Account types defined.",
        )
        cci_b = Objective(
            control_id_fk=ctrl.id,
            objective_id="CCI-000007",
            source="CCI",
            text="Account approval recorded.",
        )
        s.add_all([cci_a, cci_b])
        s.commit()
        s.refresh(cci_a)
        s.refresh(cci_b)

        src_sda_r5 = RequirementSource(
            framework_id=fw_r5.id, name="SDA Enterprise Services Controls"
        )
        src_other_r5 = RequirementSource(framework_id=fw_r5.id, name="Other Overlay")
        src_sda_r4 = RequirementSource(framework_id=fw_r4.id, name="SDA Legacy r4")
        s.add_all([src_sda_r5, src_other_r5, src_sda_r4])
        s.commit()
        s.refresh(src_sda_r5)
        s.refresh(src_other_r5)
        s.refresh(src_sda_r4)

        # Two SDA shall statements onto AC-2's CCIs (intentionally out of
        # numeric order so we can verify the per-source sort).
        s.add_all(
            [
                RequirementMap(
                    requirement_source_id=src_sda_r5.id,
                    objective_id=cci_b.id,
                    requirement_number="SDA-127",
                    requirement_text="The system shall record account approvals.",
                ),
                RequirementMap(
                    requirement_source_id=src_sda_r5.id,
                    objective_id=cci_a.id,
                    requirement_number="SDA-014",
                    requirement_text="The system shall define account types.",
                ),
                # One Other Overlay shall onto cci_a — same control, different source.
                RequirementMap(
                    requirement_source_id=src_other_r5.id,
                    objective_id=cci_a.id,
                    requirement_number="OTH-001",
                    requirement_text="Other overlay requirement.",
                ),
                # An r4 overlay onto the same Objective rows — should NOT
                # appear when the framework filter is r5, since it's bound
                # to a different framework.
                RequirementMap(
                    requirement_source_id=src_sda_r4.id,
                    objective_id=cci_a.id,
                    requirement_number="SDA-R4-001",
                    requirement_text="Legacy r4 overlay requirement.",
                ),
            ]
        )
        s.commit()

        control_id = ctrl.id
        fw_r5_id = fw_r5.id
        fw_r4_id = fw_r4.id

    return {
        "client": TestClient(app),
        "engine": engine,
        "control_id": control_id,
        "fw_r5_id": fw_r5_id,
        "fw_r4_id": fw_r4_id,
    }


def test_program_controls_groups_by_source(env):
    """No framework filter → all three overlays attached to AC-2 appear,
    grouped by source name (alphabetic). Within each group, rows sort
    lexicographically by requirement_number.
    """
    resp = env["client"].get(f"/api/controls/{env['control_id']}/program-controls")
    assert resp.status_code == 200
    data = resp.json()

    # Three sources: Other Overlay, SDA Enterprise Services Controls, SDA Legacy r4.
    names = [g["source"]["name"] for g in data]
    assert names == sorted(names), "Sources must be sorted by name"
    assert {g["source"]["name"] for g in data} == {
        "Other Overlay",
        "SDA Enterprise Services Controls",
        "SDA Legacy r4",
    }

    # SDA group has SDA-014 before SDA-127 even though we inserted SDA-127 first.
    sda_group = next(
        g for g in data if g["source"]["name"] == "SDA Enterprise Services Controls"
    )
    nums = [r["requirement_number"] for r in sda_group["rows"]]
    assert nums == ["SDA-014", "SDA-127"], "Rows must be sorted by requirement_number"

    # The row carries the human CCI code so the UI can show a badge.
    sda127 = next(r for r in sda_group["rows"] if r["requirement_number"] == "SDA-127")
    assert sda127["objective_code"] == "CCI-000007"
    assert sda127["requirement_text"].startswith("The system shall record")


def test_program_controls_framework_filter(env):
    """framework_id=r5 → only the two r5 overlays come back; r4 overlay is hidden."""
    resp = env["client"].get(
        f"/api/controls/{env['control_id']}/program-controls",
        params={"framework_id": env["fw_r5_id"]},
    )
    assert resp.status_code == 200
    data = resp.json()
    names = {g["source"]["name"] for g in data}
    assert names == {"Other Overlay", "SDA Enterprise Services Controls"}
    assert "SDA Legacy r4" not in names


def test_program_controls_empty_when_no_overlays(env):
    """A control with no overlay coverage returns [] (not 404)."""
    with Session(env["engine"]) as s:
        ctrl2 = Control(
            framework_id=env["fw_r5_id"],
            control_id="PT-1",
            title="Privacy Authorization",
            family="PT",
        )
        s.add(ctrl2)
        s.commit()
        s.refresh(ctrl2)
        empty_control_id = ctrl2.id

    resp = env["client"].get(f"/api/controls/{empty_control_id}/program-controls")
    assert resp.status_code == 200
    assert resp.json() == []
