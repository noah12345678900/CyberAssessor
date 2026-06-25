"""Wire-shape pins for the v0.3-ready Evidence list + M2M endpoints.

Covers the new filter params on ``GET /api/evidence``:

- ``workbook_id`` / ``framework_id`` / ``control_id``
- ``component_id`` / ``asset_id`` / ``boundary_id``

and the three scope-link endpoint families:

- ``GET|POST|DELETE /api/evidence/{id}/components``
- ``GET|POST|DELETE /api/evidence/{id}/assets``
- ``GET|POST|DELETE /api/evidence/{id}/boundary-segments``

Both the success shapes and the short-circuit-to-empty behavior are
pinned so a future "treat empty filter as no-op" regression is caught.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.db import get_session  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Asset,
    AssetClass,
    AssetSource,
    BoundarySegment,
    Component,
    ComponentKind,
    Control,
    ControlCrosswalk,
    Crosswalk,
    Evidence,
    EvidenceAsset,
    EvidenceBoundary,
    EvidenceComponent,
    EvidenceKind,
    EvidenceTag,
    Framework,
    Objective,
    ScopeLinkSource,
    Workbook,
)
from cybersecurity_assessor.server import create_app  # noqa: E402


@pytest.fixture
def env(tmp_path: Path) -> Iterator[dict]:
    """TestClient + a fully-wired catalog/workbook/evidence graph.

    Two frameworks (fw_a, fw_b), one Control + one Objective in each,
    one Workbook under fw_a, two Evidence rows — ev_tagged is tagged
    against fw_a's objective, ev_untagged has no tags. This is enough
    to exercise the framework_id and control_id resolver paths and
    the scope-link endpoints without a per-test seeding ritual.
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
        fw_a = Framework(name="Framework A", version="r1")
        fw_b = Framework(name="Framework B", version="r1")
        s.add_all([fw_a, fw_b])
        s.commit()
        s.refresh(fw_a)
        s.refresh(fw_b)

        wb = Workbook(path=str(wb_path), filename=wb_path.name, framework_id=fw_a.id)
        s.add(wb)
        s.commit()
        s.refresh(wb)

        ctrl_a = Control(
            framework_id=fw_a.id, control_id="A-1", title="A control", family="A"
        )
        ctrl_b = Control(
            framework_id=fw_b.id, control_id="B-1", title="B control", family="B"
        )
        s.add_all([ctrl_a, ctrl_b])
        s.commit()
        s.refresh(ctrl_a)
        s.refresh(ctrl_b)

        obj_a = Objective(control_id_fk=ctrl_a.id, objective_id="A-1.1", text="A obj")
        obj_b = Objective(control_id_fk=ctrl_b.id, objective_id="B-1.1", text="B obj")
        s.add_all([obj_a, obj_b])
        s.commit()
        s.refresh(obj_a)
        s.refresh(obj_b)

        ev_tagged = Evidence(
            path="file:///fake/tagged.pdf",
            sha256="a" * 64,
            kind=EvidenceKind.PDF,
            size_bytes=10,
            workbook_id=wb.id,
        )
        ev_untagged = Evidence(
            path="file:///fake/untagged.pdf",
            sha256="b" * 64,
            kind=EvidenceKind.PDF,
            size_bytes=10,
            workbook_id=wb.id,
        )
        s.add_all([ev_tagged, ev_untagged])
        s.commit()
        s.refresh(ev_tagged)
        s.refresh(ev_untagged)

        s.add(EvidenceTag(evidence_id=ev_tagged.id, objective_id=obj_a.id))
        s.commit()

        # Capture ids while the session is still open — once the `with`
        # block exits, the ORM instances are detached and attribute
        # access raises DetachedInstanceError.
        ids = {
            "wb_id": wb.id,
            "fw_a": fw_a.id,
            "fw_b": fw_b.id,
            "ctrl_a": ctrl_a.id,
            "ctrl_b": ctrl_b.id,
            "obj_a": obj_a.id,
            "obj_b": obj_b.id,
            "ev_tagged": ev_tagged.id,
            "ev_untagged": ev_untagged.id,
        }

    yield {
        "tc": TestClient(app),
        "engine": engine,
        **ids,
    }

    app.dependency_overrides.clear()


def _new_session(env: dict) -> Session:
    """Open a fresh Session against the in-memory engine for test-side writes."""
    return Session(env["engine"])


# ---------------------------------------------------------------------------
# GET /api/evidence — filter params
# ---------------------------------------------------------------------------


def test_list_evidence_no_filter_returns_both_rows(env) -> None:
    rows = env["tc"].get("/api/evidence").json()
    paths = {r["path"] for r in rows}
    assert "file:///fake/tagged.pdf" in paths
    assert "file:///fake/untagged.pdf" in paths


def test_list_evidence_filters_by_workbook_id(env) -> None:
    # Both seeded rows belong to wb_id; an unknown workbook should yield [].
    rows = env["tc"].get(f"/api/evidence?workbook_id={env['wb_id']}").json()
    assert len(rows) == 2

    rows_other = env["tc"].get("/api/evidence?workbook_id=9999").json()
    assert rows_other == []


def test_list_evidence_workbook_filter_excludes_null_workbook_rows(env) -> None:
    """workbook_id filter is STRICT — rows with workbook_id IS NULL never leak.

    Evidence is hard-bound at ingest to the workbook that is open at the time,
    and a workbook view shows ONLY that workbook's artifacts. Legacy rows with
    ``workbook_id = NULL`` (pre-binding ingests, or rows orphaned when a
    workbook was deleted and its FK nulled) belong to no system under
    assessment and MUST NOT bleed into any workbook's view. This pins the
    strict-equality contract so the old NULL-leak can't come back.
    """
    with _new_session(env) as s:
        ev_global = Evidence(
            path="file:///fake/global.pdf",
            sha256="c" * 64,
            kind=EvidenceKind.PDF,
            size_bytes=10,
            workbook_id=None,
        )
        s.add(ev_global)
        s.commit()
        s.refresh(ev_global)
        global_id = ev_global.id

    rows = env["tc"].get(f"/api/evidence?workbook_id={env['wb_id']}").json()
    ids = {r["id"] for r in rows}
    assert global_id not in ids, "NULL workbook_id row must NOT appear in a scoped view"
    assert env["ev_tagged"] in ids
    assert env["ev_untagged"] in ids
    assert len(rows) == 2

    # The NULL row is invisible under every workbook scope, including unknown ids.
    rows_other = env["tc"].get("/api/evidence?workbook_id=9999").json()
    assert rows_other == []


def test_list_evidence_framework_filter_includes_directly_tagged(env) -> None:
    """fw_a directly owns obj_a; ev_tagged is tagged on obj_a → visible."""
    rows = env["tc"].get(f"/api/evidence?framework_id={env['fw_a']}").json()
    ids = {r["id"] for r in rows}
    assert env["ev_tagged"] in ids
    assert env["ev_untagged"] not in ids


def test_list_evidence_framework_filter_short_circuits_to_empty(env) -> None:
    """fw_b has its own objective but no Evidence tagged against it.

    Resolver returns a non-empty visible set (obj_b) but the EvidenceTag
    lookup is empty → endpoint returns [], NOT the full evidence list.
    """
    rows = env["tc"].get(f"/api/evidence?framework_id={env['fw_b']}").json()
    assert rows == []


def test_list_evidence_framework_filter_walks_objective_crosswalk(env) -> None:
    """An A→B objective crosswalk lights up A-tagged evidence under the B lens.

    obj_a is tagged on ev_tagged. Add Crosswalk(obj_a → obj_b) and ask
    "what's visible under fw_b?" — ev_tagged should now appear because
    obj_a is in the visible set for fw_b.
    """
    with _new_session(env) as s:
        s.add(Crosswalk(from_objective_id=env["obj_a"], to_objective_id=env["obj_b"]))
        s.commit()

    rows = env["tc"].get(f"/api/evidence?framework_id={env['fw_b']}").json()
    ids = {r["id"] for r in rows}
    assert env["ev_tagged"] in ids


def test_list_evidence_filters_by_control_id(env) -> None:
    """Tagged evidence appears when filtering by its objective's control."""
    rows = env["tc"].get(f"/api/evidence?control_id={env['ctrl_a']}").json()
    ids = {r["id"] for r in rows}
    assert env["ev_tagged"] in ids
    assert env["ev_untagged"] not in ids


def test_list_evidence_control_filter_short_circuits_on_unknown_control(env) -> None:
    """control_id pointing at a nonexistent Control row → []."""
    rows = env["tc"].get("/api/evidence?control_id=9999").json()
    assert rows == []


def test_list_evidence_control_filter_short_circuits_when_no_tags(env) -> None:
    """ctrl_b owns obj_b, but no Evidence is tagged against obj_b → []."""
    rows = env["tc"].get(f"/api/evidence?control_id={env['ctrl_b']}").json()
    assert rows == []


def test_list_evidence_filters_by_component_id(env) -> None:
    with _new_session(env) as s:
        comp = Component(
            workbook_id=env["wb_id"], name="Web Tier", kind=ComponentKind.TIER
        )
        s.add(comp)
        s.commit()
        s.refresh(comp)
        s.add(
            EvidenceComponent(
                evidence_id=env["ev_tagged"],
                component_id=comp.id,
                source=ScopeLinkSource.MANUAL,
            )
        )
        s.commit()
        comp_id = comp.id

    rows = env["tc"].get(f"/api/evidence?component_id={comp_id}").json()
    ids = {r["id"] for r in rows}
    assert ids == {env["ev_tagged"]}

    # Unknown component → []. Pins short-circuit; a "no filter applied" bug
    # would return all rows.
    rows_other = env["tc"].get("/api/evidence?component_id=9999").json()
    assert rows_other == []


def test_list_evidence_filters_by_asset_id(env) -> None:
    with _new_session(env) as s:
        a = Asset(
            workbook_id=env["wb_id"],
            hostname="server01",
            asset_class=AssetClass.SERVER,
            source=AssetSource.MANUAL,
        )
        s.add(a)
        s.commit()
        s.refresh(a)
        s.add(
            EvidenceAsset(
                evidence_id=env["ev_untagged"],
                asset_id=a.id,
                source=ScopeLinkSource.MANUAL,
            )
        )
        s.commit()
        a_id = a.id

    rows = env["tc"].get(f"/api/evidence?asset_id={a_id}").json()
    ids = {r["id"] for r in rows}
    assert ids == {env["ev_untagged"]}


def test_list_evidence_filters_by_boundary_id(env) -> None:
    with _new_session(env) as s:
        seg = BoundarySegment(workbook_id=env["wb_id"], name="DMZ", kind="dmz")
        s.add(seg)
        s.commit()
        s.refresh(seg)
        s.add(
            EvidenceBoundary(
                evidence_id=env["ev_tagged"],
                boundary_segment_id=seg.id,
                source=ScopeLinkSource.MANUAL,
            )
        )
        s.commit()
        seg_id = seg.id

    rows = env["tc"].get(f"/api/evidence?boundary_id={seg_id}").json()
    ids = {r["id"] for r in rows}
    assert ids == {env["ev_tagged"]}


# ---------------------------------------------------------------------------
# Component link endpoints
# ---------------------------------------------------------------------------


def test_attach_components_returns_created_and_is_idempotent(env) -> None:
    with _new_session(env) as s:
        comp = Component(workbook_id=env["wb_id"], name="C1", kind=ComponentKind.TIER)
        s.add(comp)
        s.commit()
        s.refresh(comp)
        comp_id = comp.id

    r1 = env["tc"].post(
        f"/api/evidence/{env['ev_tagged']}/components",
        json={"ids": [comp_id]},
    )
    assert r1.status_code == 200, r1.text
    assert r1.json() == {"ok": True, "created": [comp_id]}

    # Re-attach: created list is empty because the row already exists.
    r2 = env["tc"].post(
        f"/api/evidence/{env['ev_tagged']}/components",
        json={"ids": [comp_id]},
    )
    assert r2.json() == {"ok": True, "created": []}


def test_attach_components_404_on_unknown_evidence(env) -> None:
    r = env["tc"].post("/api/evidence/9999/components", json={"ids": [1]})
    assert r.status_code == 404


def test_list_evidence_components_enriched_shape(env) -> None:
    with _new_session(env) as s:
        comp = Component(
            workbook_id=env["wb_id"], name="Web Tier", kind=ComponentKind.TIER
        )
        s.add(comp)
        s.commit()
        s.refresh(comp)
        s.add(
            EvidenceComponent(
                evidence_id=env["ev_tagged"],
                component_id=comp.id,
                confidence=0.9,
                source=ScopeLinkSource.AUTO,
            )
        )
        s.commit()
        comp_id = comp.id

    rows = env["tc"].get(f"/api/evidence/{env['ev_tagged']}/components").json()
    assert len(rows) == 1
    row = rows[0]
    # Pins the joined shape — chip label fields + link metadata together.
    assert row["component_id"] == comp_id
    assert row["name"] == "Web Tier"
    assert row["kind"] == ComponentKind.TIER.value
    assert row["confidence"] == 0.9
    assert row["source"] == ScopeLinkSource.AUTO.value


def test_detach_component_is_ok_even_if_link_absent(env) -> None:
    """No-op DELETE returns ok=True so a chip-remove race doesn't 404."""
    r = env["tc"].delete(f"/api/evidence/{env['ev_tagged']}/components/9999")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


# ---------------------------------------------------------------------------
# Asset link endpoints
# ---------------------------------------------------------------------------


def test_attach_assets_returns_created_and_is_idempotent(env) -> None:
    with _new_session(env) as s:
        a = Asset(
            workbook_id=env["wb_id"],
            hostname="server01",
            asset_class=AssetClass.SERVER,
            source=AssetSource.MANUAL,
        )
        s.add(a)
        s.commit()
        s.refresh(a)
        a_id = a.id

    r1 = env["tc"].post(
        f"/api/evidence/{env['ev_tagged']}/assets", json={"ids": [a_id]}
    )
    assert r1.json() == {"ok": True, "created": [a_id]}

    r2 = env["tc"].post(
        f"/api/evidence/{env['ev_tagged']}/assets", json={"ids": [a_id]}
    )
    assert r2.json() == {"ok": True, "created": []}


def test_list_evidence_assets_enriched_shape(env) -> None:
    with _new_session(env) as s:
        a = Asset(
            workbook_id=env["wb_id"],
            hostname="server01",
            fqdn="server01.example",
            ip_address="10.0.0.1",
            asset_class=AssetClass.SERVER,
            source=AssetSource.SCAN,
        )
        s.add(a)
        s.commit()
        s.refresh(a)
        s.add(
            EvidenceAsset(
                evidence_id=env["ev_tagged"],
                asset_id=a.id,
                confidence=0.75,
                source=ScopeLinkSource.BACKFILL,
            )
        )
        s.commit()
        a_id = a.id

    rows = env["tc"].get(f"/api/evidence/{env['ev_tagged']}/assets").json()
    assert len(rows) == 1
    row = rows[0]
    assert row["asset_id"] == a_id
    assert row["hostname"] == "server01"
    assert row["fqdn"] == "server01.example"
    assert row["ip_address"] == "10.0.0.1"
    assert row["asset_class"] == AssetClass.SERVER.value
    # Note: asset's *source* serializes as `asset_source`; link's source as
    # `link_source`. The shape is deliberately disambiguated.
    assert row["asset_source"] == AssetSource.SCAN.value
    assert row["link_source"] == ScopeLinkSource.BACKFILL.value
    assert row["confidence"] == 0.75


def test_detach_asset_is_ok_even_if_link_absent(env) -> None:
    r = env["tc"].delete(f"/api/evidence/{env['ev_tagged']}/assets/9999")
    assert r.json() == {"ok": True}


# ---------------------------------------------------------------------------
# Boundary segment link endpoints
# ---------------------------------------------------------------------------


def test_attach_boundary_segments_returns_created_and_is_idempotent(env) -> None:
    with _new_session(env) as s:
        seg = BoundarySegment(workbook_id=env["wb_id"], name="DMZ", kind="dmz")
        s.add(seg)
        s.commit()
        s.refresh(seg)
        seg_id = seg.id

    r1 = env["tc"].post(
        f"/api/evidence/{env['ev_tagged']}/boundary-segments",
        json={"ids": [seg_id]},
    )
    assert r1.json() == {"ok": True, "created": [seg_id]}

    r2 = env["tc"].post(
        f"/api/evidence/{env['ev_tagged']}/boundary-segments",
        json={"ids": [seg_id]},
    )
    assert r2.json() == {"ok": True, "created": []}


def test_list_evidence_boundary_segments_enriched_shape(env) -> None:
    with _new_session(env) as s:
        seg = BoundarySegment(workbook_id=env["wb_id"], name="DMZ", kind="dmz")
        s.add(seg)
        s.commit()
        s.refresh(seg)
        s.add(
            EvidenceBoundary(
                evidence_id=env["ev_tagged"],
                boundary_segment_id=seg.id,
                confidence=1.0,
                source=ScopeLinkSource.MANUAL,
            )
        )
        s.commit()
        seg_id = seg.id

    rows = env["tc"].get(f"/api/evidence/{env['ev_tagged']}/boundary-segments").json()
    assert len(rows) == 1
    row = rows[0]
    assert row["boundary_segment_id"] == seg_id
    assert row["name"] == "DMZ"
    assert row["kind"] == "dmz"
    assert row["source"] == ScopeLinkSource.MANUAL.value


def test_detach_boundary_segment_is_ok_even_if_link_absent(env) -> None:
    r = env["tc"].delete(
        f"/api/evidence/{env['ev_tagged']}/boundary-segments/9999"
    )
    assert r.json() == {"ok": True}


# ---------------------------------------------------------------------------
# Retag endpoints
#
# Seeded evidence paths are ``file:///fake/...`` (don't exist) and have no
# extracted_text_path, so re-extraction never fires in-fixture and the retag
# falls back to empty text → 0 fresh tags. These tests therefore pin the
# *delete / preserve / invalidate / shape* contract, NOT re-extracted counts:
#   * auto + auto_review tags are dropped and regenerated
#   * manual / llm tags survive untouched
#   * unknown id → 404
#   * bulk shape + optional workbook_id filter
# ---------------------------------------------------------------------------


def _tags_for(env, evidence_id: int) -> list[EvidenceTag]:
    with _new_session(env) as s:
        from sqlmodel import select as _select

        return list(
            s.exec(
                _select(EvidenceTag).where(EvidenceTag.evidence_id == evidence_id)
            ).all()
        )


def test_retag_one_404_on_unknown_evidence(env) -> None:
    r = env["tc"].post("/api/evidence/9999/retag")
    assert r.status_code == 404


def test_retag_one_drops_auto_tag_and_returns_shape(env) -> None:
    """The seeded auto tag on ev_tagged is dropped; fallback re-tag adds none."""
    before = _tags_for(env, env["ev_tagged"])
    assert len(before) == 1
    assert before[0].source == "auto"

    r = env["tc"].post(f"/api/evidence/{env['ev_tagged']}/retag")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["evidence_id"] == env["ev_tagged"]
    assert body["reextracted"] is False  # file:///fake/... doesn't exist
    assert body["objectives_invalidated"] == 1  # obj_a lost its auto tag
    assert body["tags_created"] == 0  # empty-text fallback tags nothing

    after = _tags_for(env, env["ev_tagged"])
    assert after == []


def test_retag_one_preserves_manual_tags(env) -> None:
    """Manual / llm tags survive a retag; only auto + auto_review are dropped."""
    with _new_session(env) as s:
        s.add(
            EvidenceTag(
                evidence_id=env["ev_tagged"],
                objective_id=env["obj_b"],
                source="manual",
            )
        )
        s.add(
            EvidenceTag(
                evidence_id=env["ev_tagged"],
                objective_id=env["obj_a"],
                source="auto_review",
            )
        )
        s.commit()

    # ev_tagged now has: auto(obj_a) + auto_review(obj_a) + manual(obj_b).
    r = env["tc"].post(f"/api/evidence/{env['ev_tagged']}/retag")
    assert r.status_code == 200, r.text

    after = _tags_for(env, env["ev_tagged"])
    # Only the manual tag remains.
    assert len(after) == 1
    assert after[0].source == "manual"
    assert after[0].objective_id == env["obj_b"]


def test_retag_all_returns_bulk_shape(env) -> None:
    r = env["tc"].post("/api/evidence/retag")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["evidence_retagged"] == 2  # both seeded rows
    assert body["reextracted"] == 0  # neither fake path exists
    assert body["tags_created"] == 0
    assert isinstance(body["per_file"], list)
    assert len(body["per_file"]) == 2
    for entry in body["per_file"]:
        assert {"evidence_id", "reextracted", "tags_created", "objectives_invalidated"} <= entry.keys()


def test_retag_all_honors_workbook_filter(env) -> None:
    """An unknown workbook_id retags nothing; the seeded workbook retags both."""
    r_none = env["tc"].post("/api/evidence/retag", json={"workbook_id": 9999})
    assert r_none.json()["evidence_retagged"] == 0

    r_wb = env["tc"].post("/api/evidence/retag", json={"workbook_id": env["wb_id"]})
    assert r_wb.json()["evidence_retagged"] == 2


def test_retag_all_does_not_collide_with_id_path(env) -> None:
    """POST /retag matches the literal route, not /{evidence_id} with id='retag'."""
    r = env["tc"].post("/api/evidence/retag")
    # If the int-path route had captured "retag", FastAPI would 422 on int
    # coercion. A 200 proves the literal route wins.
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Manual evidence→CCI tagging (source="manual")
# ---------------------------------------------------------------------------


def test_add_manual_tag_creates_manual_source_tag(env) -> None:
    """POST manual-tag attaches the untagged artifact to a CCI as source=manual."""
    tc = env["tc"]
    r = tc.post(
        f"/api/evidence/{env['ev_untagged']}/manual-tag",
        json={"objective_id": env["obj_b"], "rationale": "reviewer says relevant"},
    )
    assert r.status_code == 200, r.text
    with _new_session(env) as s:
        tags = s.exec(
            select(EvidenceTag)
            .where(EvidenceTag.evidence_id == env["ev_untagged"])
            .where(EvidenceTag.objective_id == env["obj_b"])
        ).all()
        assert len(tags) == 1
        assert tags[0].source == "manual"
        assert tags[0].relevance == 1.0  # human assertion = maximal trust
        assert "reviewer says relevant" in (tags[0].rationale or "")


def test_add_manual_tag_is_idempotent(env) -> None:
    """Re-posting the same (evidence, CCI) updates rationale, no duplicate row."""
    tc = env["tc"]
    base = f"/api/evidence/{env['ev_untagged']}/manual-tag"
    assert tc.post(base, json={"objective_id": env["obj_b"], "rationale": "v1"}).status_code == 200
    assert tc.post(base, json={"objective_id": env["obj_b"], "rationale": "v2"}).status_code == 200
    with _new_session(env) as s:
        tags = s.exec(
            select(EvidenceTag)
            .where(EvidenceTag.evidence_id == env["ev_untagged"])
            .where(EvidenceTag.objective_id == env["obj_b"])
            .where(EvidenceTag.source == "manual")
        ).all()
        assert len(tags) == 1  # idempotent — one row
        assert "v2" in (tags[0].rationale or "")


def test_remove_manual_tag_deletes_only_manual(env) -> None:
    """DELETE removes the manual tag but leaves any auto tag on the same pair."""
    tc = env["tc"]
    # Seed an AUTO tag on (ev_untagged, obj_b) alongside a manual one.
    with _new_session(env) as s:
        s.add(EvidenceTag(evidence_id=env["ev_untagged"], objective_id=env["obj_b"], source="auto"))
        s.commit()
    tc.post(
        f"/api/evidence/{env['ev_untagged']}/manual-tag",
        json={"objective_id": env["obj_b"]},
    )
    r = tc.delete(f"/api/evidence/{env['ev_untagged']}/manual-tag/{env['obj_b']}")
    assert r.status_code == 200, r.text
    assert r.json()["removed"] == 1
    with _new_session(env) as s:
        remaining = s.exec(
            select(EvidenceTag)
            .where(EvidenceTag.evidence_id == env["ev_untagged"])
            .where(EvidenceTag.objective_id == env["obj_b"])
        ).all()
        # The auto tag survives; only the manual one was removed.
        assert [t.source for t in remaining] == ["auto"]


def test_add_manual_tag_404_on_unknown_evidence(env) -> None:
    tc = env["tc"]
    r = tc.post("/api/evidence/999999/manual-tag", json={"objective_id": env["obj_b"]})
    assert r.status_code == 404


def test_add_manual_tag_404_on_unknown_objective(env) -> None:
    tc = env["tc"]
    r = tc.post(
        f"/api/evidence/{env['ev_untagged']}/manual-tag",
        json={"objective_id": 999999},
    )
    assert r.status_code == 404
