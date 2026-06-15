"""Unit tests for ``catalogs.fedramp_profile_loader.load_fedramp_profile``.

The loader projects an OSCAL FedRAMP profile onto a child Framework of a
loaded 800-53 r5 catalog. Three concerns pinned here:

1.  Membership rows are written for include-ids that exist on the parent;
    unknown ids are surfaced but not persisted.
2.  Shadow Controls carry merged FedRAMP-Additions prose
    (``FEDRAMP_ADDITIONS_HEADING`` marker) and FedRAMP-set ODP overrides
    on ``parameter_overrides_json``. A control with only set-parameters
    (no prose alter) still gets a shadow whose statement mirrors the
    parent's verbatim text.
3.  Re-running the loader on the same profile converges — counts match,
    no duplicate rows, no leftover params from a prior pass.

Synthetic OSCAL JSON is used (3 includes, 1 alter w/ prose, 1
set-parameter, 1 unknown id) so the test runs without touching the
bundled fixtures and is small enough to read top-to-bottom.
"""

from __future__ import annotations

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
from cybersecurity_assessor.baselines.oscal_adds import (  # noqa: E402
    FEDRAMP_ADDITIONS_HEADING,
)
from cybersecurity_assessor.catalogs.fedramp_profile_loader import (  # noqa: E402
    load_fedramp_profile,
)
from cybersecurity_assessor.models import (  # noqa: E402
    BaselineMembership,
    Control,
    Framework,
)


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


def _seed_parent_r5(s: Session) -> Framework:
    """Parent Framework standing in for NIST 800-53 r5 with 3 controls.

    Carries the canonical rev5 OSCAL URL so :func:`_resolve_rev5_framework`
    in the route layer would also find it (parity with bundled catalogs).
    """
    fw = Framework(
        name="NIST SP 800-53",
        version="Rev 5",
        oscal_uri="https://example.test/NIST_SP-800-53_rev5_catalog.json",
    )
    s.add(fw)
    s.commit()
    s.refresh(fw)

    for cid, title, family, stmt in [
        ("ac-1", "Access Control Policy", "AC", "Parent AC-1 statement."),
        ("ac-2", "Account Management", "AC", "Parent AC-2 statement."),
        ("au-3", "Content of Audit Records", "AU", "Parent AU-3 statement."),
    ]:
        s.add(
            Control(
                framework_id=fw.id,
                control_id=cid,
                title=title,
                family=family,
                statement=stmt,
            )
        )
    s.commit()
    return fw


def _write_profile_json(
    tmp_path: Path,
    *,
    include_ids: list[str],
    alters: list[dict] | None = None,
    set_parameters: list[dict] | None = None,
) -> Path:
    """Build a minimal but loader-valid OSCAL profile JSON at ``tmp_path``.

    The shape mirrors what GSA publishes: a single ``imports`` entry with
    ``include-controls.with-ids``, optional ``modify.alters`` for prose,
    and optional ``modify.set-parameters`` for ODP overrides.
    """
    doc = {
        "profile": {
            "metadata": {
                "title": "Synthetic FedRAMP Profile",
                "version": "Rev 5",
            },
            "imports": [
                {
                    "href": "#catalog",
                    "include-controls": [{"with-ids": include_ids}],
                }
            ],
            "modify": {
                "alters": alters or [],
                "set-parameters": set_parameters or [],
            },
        }
    }
    path = tmp_path / "synthetic_fedramp_profile.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_load_writes_membership_synth_and_params(session, tmp_path):
    """End-to-end happy path: membership, prose shadow, ODP shadow.

    Layout:
      - includes: ac-1, ac-2, au-3, xx-99 (xx-99 is unknown to parent)
      - alter on ac-1 with a ``parts`` block → shadow with FedRAMP
        Additions prose
      - set-parameter ``au-03_odp.01`` (FedRAMP zero-padded form) → shadow
        on au-3 (no alter, params-only) carrying parent's verbatim
        statement plus parameter_overrides_json
    """
    parent = _seed_parent_r5(session)
    profile_path = _write_profile_json(
        tmp_path,
        include_ids=["ac-1", "ac-2", "au-3", "xx-99"],
        alters=[
            {
                "control-id": "ac-1",
                "adds": [
                    {
                        "position": "after",
                        "by-id": "ac-1_smt",
                        "parts": [
                            {
                                "name": "item",
                                "prose": "FedRAMP-specific AC-1 requirement.",
                            }
                        ],
                    }
                ],
            }
        ],
        set_parameters=[
            {
                "param-id": "au-03_odp.01",
                "constraints": [{"description": "at least annually"}],
            }
        ],
    )

    result = load_fedramp_profile(
        session,
        level="HIGH",
        parent_framework_id=parent.id,
        path=profile_path,
    )

    # --- Child Framework created with parent FK set --------------------
    child = result.framework
    assert child.id != parent.id
    assert child.parent_framework_id == parent.id
    assert child.name == "FedRAMP Rev 5 HIGH"

    # --- Membership: 3 known ids written, 1 unknown surfaced -----------
    assert result.members_added == 3
    assert result.unknown_control_ids == ["xx-99"]
    members = {
        m.control_id
        for m in session.exec(
            select(BaselineMembership).where(
                BaselineMembership.framework_id == child.id
            )
        ).all()
    }
    assert members == {"ac-1", "ac-2", "au-3"}

    # --- Shadow Control for the prose alter ----------------------------
    assert result.controls_synthesized == 1
    ac1_shadow = session.exec(
        select(Control).where(
            Control.framework_id == child.id,
            Control.control_id == "ac-1",
        )
    ).first()
    assert ac1_shadow is not None
    assert ac1_shadow.statement is not None
    assert FEDRAMP_ADDITIONS_HEADING in ac1_shadow.statement
    assert "FedRAMP-specific AC-1 requirement." in ac1_shadow.statement
    # Parent prose is retained — the merged statement layers Additions on
    # top, doesn't replace.
    assert "Parent AC-1 statement." in ac1_shadow.statement

    # --- Shadow Control for the params-only entry ----------------------
    assert result.parameters_loaded == 1
    au3_shadow = session.exec(
        select(Control).where(
            Control.framework_id == child.id,
            Control.control_id == "au-3",
        )
    ).first()
    assert au3_shadow is not None
    assert au3_shadow.parameter_overrides_json is not None
    overrides = json.loads(au3_shadow.parameter_overrides_json)
    assert overrides == {"au-03_odp.01": "at least annually"}
    # Params-only shadow carries parent's verbatim statement (no Additions
    # marker — there was no prose alter for au-3).
    assert au3_shadow.statement == "Parent AU-3 statement."
    assert FEDRAMP_ADDITIONS_HEADING not in (au3_shadow.statement or "")


def test_idempotent_reload_converges(session, tmp_path):
    """Loading the same profile twice produces byte-equal state.

    Counts match; no duplicate Controls; no duplicate Memberships.
    """
    parent = _seed_parent_r5(session)
    profile_path = _write_profile_json(
        tmp_path,
        include_ids=["ac-1", "ac-2"],
        alters=[
            {
                "control-id": "ac-1",
                "adds": [
                    {
                        "position": "after",
                        "parts": [{"name": "item", "prose": "FedRAMP add."}],
                    }
                ],
            }
        ],
        set_parameters=[
            {
                "param-id": "ac-02_odp.01",
                "values": ["monthly"],
            }
        ],
    )

    first = load_fedramp_profile(
        session, level="HIGH", parent_framework_id=parent.id, path=profile_path
    )
    second = load_fedramp_profile(
        session, level="HIGH", parent_framework_id=parent.id, path=profile_path
    )

    assert first.framework.id == second.framework.id
    assert (
        first.members_added
        == second.members_added
        == 2
    )
    assert first.controls_synthesized == second.controls_synthesized == 1
    assert first.parameters_loaded == second.parameters_loaded == 1

    # Deeper check: no duplicate rows in the underlying tables.
    members = session.exec(
        select(BaselineMembership).where(
            BaselineMembership.framework_id == first.framework.id
        )
    ).all()
    assert len(members) == 2
    shadows = session.exec(
        select(Control).where(Control.framework_id == first.framework.id)
    ).all()
    # ac-1 (prose+nothing) and ac-2 (params-only) = 2 shadows total.
    assert len(shadows) == 2
    by_id = {c.control_id: c for c in shadows}
    assert "ac-1" in by_id and "ac-2" in by_id
    assert by_id["ac-2"].parameter_overrides_json is not None


def test_unknown_id_not_persisted_as_membership(session, tmp_path):
    """A profile referencing a control absent from the parent surfaces it
    in ``unknown_control_ids`` but never writes a phantom membership row.
    """
    parent = _seed_parent_r5(session)
    profile_path = _write_profile_json(
        tmp_path,
        include_ids=["zz-99"],
    )

    result = load_fedramp_profile(
        session, level="LOW", parent_framework_id=parent.id, path=profile_path
    )

    assert result.members_added == 0
    assert result.unknown_control_ids == ["zz-99"]
    members = session.exec(
        select(BaselineMembership).where(
            BaselineMembership.framework_id == result.framework.id
        )
    ).all()
    assert members == []


def test_stale_params_cleared_on_reload(session, tmp_path):
    """A control that loses its set-parameter between releases must lose
    its ``parameter_overrides_json`` on reload — otherwise a phantom JSON
    blob would survive and the LLM would render an obsolete ODP value.

    Variant: the control keeps its prose alter (so the shadow row stays)
    but the set-parameter entry is retracted. The clear-loop in the
    loader must null out ``parameter_overrides_json`` on that row.
    """
    parent = _seed_parent_r5(session)

    # First load: ac-1 has BOTH prose AND a set-parameter.
    first_path = _write_profile_json(
        tmp_path,
        include_ids=["ac-1"],
        alters=[
            {
                "control-id": "ac-1",
                "adds": [
                    {
                        "position": "after",
                        "parts": [{"name": "item", "prose": "First add."}],
                    }
                ],
            }
        ],
        set_parameters=[
            {"param-id": "ac-01_odp.01", "values": ["quarterly"]},
        ],
    )
    first = load_fedramp_profile(
        session, level="MODERATE", parent_framework_id=parent.id, path=first_path
    )
    ac1 = session.exec(
        select(Control).where(
            Control.framework_id == first.framework.id,
            Control.control_id == "ac-1",
        )
    ).first()
    assert ac1 is not None
    assert ac1.parameter_overrides_json is not None

    # Second load: same prose, set-parameter retracted. Shadow row must
    # remain (prose still present) but ``parameter_overrides_json`` must
    # be cleared.
    second_path = tmp_path / "synthetic_fedramp_profile_v2.json"
    second_path.write_text(first_path.read_text(encoding="utf-8"), encoding="utf-8")
    second_doc = json.loads(second_path.read_text(encoding="utf-8"))
    second_doc["profile"]["modify"]["set-parameters"] = []
    second_path.write_text(json.dumps(second_doc), encoding="utf-8")

    second = load_fedramp_profile(
        session, level="MODERATE", parent_framework_id=parent.id, path=second_path
    )
    assert second.parameters_loaded == 0
    session.expire_all()
    ac1_after = session.exec(
        select(Control).where(
            Control.framework_id == second.framework.id,
            Control.control_id == "ac-1",
        )
    ).first()
    assert ac1_after is not None, "shadow row dropped despite still-present prose"
    assert ac1_after.parameter_overrides_json is None


def test_missing_parent_framework_raises(session, tmp_path):
    """Bogus parent_framework_id surfaces as ValueError so the route can
    return a 400 ("Load NIST 800-53 Rev 5 first")."""
    profile_path = _write_profile_json(tmp_path, include_ids=["ac-1"])
    with pytest.raises(ValueError, match="Parent Framework"):
        load_fedramp_profile(
            session, level="HIGH", parent_framework_id=99999, path=profile_path
        )


def test_unknown_level_raises(session, tmp_path):
    """Level outside the canonical 4 is a typed validation error."""
    parent = _seed_parent_r5(session)
    profile_path = _write_profile_json(tmp_path, include_ids=["ac-1"])
    with pytest.raises(ValueError, match="Unsupported FedRAMP level"):
        load_fedramp_profile(
            session,
            level="ULTRA",
            parent_framework_id=parent.id,
            path=profile_path,
        )
