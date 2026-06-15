"""Scope-entity CRUD: Component, Asset, BoundarySegment.

Backs the v0.3-ready Evidence model. The Evidence tab needs filter
chips driven by per-workbook lists of Components, Assets, and
BoundarySegments; this module is the read/write API behind those
chips and behind any future direct-management UI.

Scope is intentionally narrow for v0.1:

- All three resources are **per-workbook** — the GET endpoints require
  ``workbook_id``, and POST refuses to create rows without one. The
  Evidence tab is always workbook-scoped, so a global list would be
  confusing and would let two workbooks accidentally share entities.
- CRUD is minimal — list, create, delete. Update lands in v0.2 when
  the dedicated management UIs ship; right now the Evidence-tab
  filter chips only need to know "what exists" and "remove this one".
- Delete is hard-delete with cascading link removal. SQLite FKs are
  enabled per :mod:`db`, but link tables (EvidenceComponent etc.)
  carry composite PKs without ON DELETE CASCADE, so we explicitly
  ``DELETE FROM`` them first to keep referential integrity in the
  ORM layer.

The shape mirrors :mod:`routes.evidence` — APIRouter with prefix,
``get_session`` dependency, Pydantic request bodies, plain dict
responses (no response_model decorations so the UI can evolve fields
freely during v0.1).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session, delete, select

from ..db import get_session
from ..models import (
    Asset,
    AssetClass,
    AssetSource,
    BoundarySegment,
    Component,
    ComponentAsset,
    ComponentKind,
    EvidenceAsset,
    EvidenceBoundary,
    EvidenceComponent,
    Workbook,
)

router = APIRouter(prefix="/api", tags=["scope"])


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------


class ComponentCreate(BaseModel):
    workbook_id: int
    name: str = Field(min_length=1)
    kind: ComponentKind = ComponentKind.OTHER
    parent_component_id: int | None = None
    description: str | None = None


class AssetCreate(BaseModel):
    workbook_id: int
    hostname: str = Field(min_length=1)
    fqdn: str | None = None
    ip_address: str | None = None
    cpe: str | None = None
    os_family: str | None = None
    asset_class: AssetClass = AssetClass.OTHER
    # Default to MANUAL — POST-from-UI is by definition assessor-entered.
    # Scan-ingested and asset-list-ingested rows take a different code
    # path through the backfill / extractor pipelines.
    source: AssetSource = AssetSource.MANUAL


class BoundarySegmentCreate(BaseModel):
    workbook_id: int
    name: str = Field(min_length=1)
    kind: str | None = None
    description: str | None = None


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _serialize_component(c: Component) -> dict[str, Any]:
    return {
        "id": c.id,
        "workbook_id": c.workbook_id,
        "name": c.name,
        "kind": c.kind.value if hasattr(c.kind, "value") else c.kind,
        "parent_component_id": c.parent_component_id,
        "description": c.description,
        "created_at": c.created_at.isoformat() if c.created_at else None,
    }


def _serialize_asset(a: Asset) -> dict[str, Any]:
    return {
        "id": a.id,
        "workbook_id": a.workbook_id,
        "hostname": a.hostname,
        "fqdn": a.fqdn,
        "ip_address": a.ip_address,
        "cpe": a.cpe,
        "os_family": a.os_family,
        "asset_class": a.asset_class.value if hasattr(a.asset_class, "value") else a.asset_class,
        "source": a.source.value if hasattr(a.source, "value") else a.source,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


def _serialize_boundary(b: BoundarySegment) -> dict[str, Any]:
    return {
        "id": b.id,
        "workbook_id": b.workbook_id,
        "name": b.name,
        "kind": b.kind,
        "description": b.description,
        "created_at": b.created_at.isoformat() if b.created_at else None,
    }


def _require_workbook(s: Session, workbook_id: int) -> None:
    """Reject creates against a workbook id that doesn't exist.

    Without this guard a typo on the UI side would leave dangling rows
    that the Evidence tab filter would never surface (filter is always
    ``WHERE workbook_id = ?``). FK enforcement at the DB layer would
    catch it on COMMIT, but a 4xx with a clear message is friendlier.
    """
    if s.get(Workbook, workbook_id) is None:
        raise HTTPException(status_code=404, detail=f"Workbook {workbook_id} not found")


# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------


@router.get("/components")
def list_components(
    workbook_id: int,
    s: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rows = s.exec(
        select(Component)
        .where(Component.workbook_id == workbook_id)
        .order_by(Component.name)  # type: ignore[arg-type]
    ).all()
    return [_serialize_component(c) for c in rows]


@router.post("/components")
def create_component(
    body: ComponentCreate,
    s: Session = Depends(get_session),
) -> dict[str, Any]:
    _require_workbook(s, body.workbook_id)
    if body.parent_component_id is not None:
        parent = s.get(Component, body.parent_component_id)
        if parent is None or parent.workbook_id != body.workbook_id:
            # Parent must exist AND live in the same workbook — a cross-
            # workbook parent would let the tree escape its boundary.
            raise HTTPException(
                status_code=400,
                detail="parent_component_id must reference a component in the same workbook",
            )
    comp = Component(
        workbook_id=body.workbook_id,
        name=body.name.strip(),
        kind=body.kind,
        parent_component_id=body.parent_component_id,
        description=body.description,
    )
    s.add(comp)
    s.commit()
    s.refresh(comp)
    return _serialize_component(comp)


@router.delete("/components/{component_id}")
def delete_component(
    component_id: int,
    s: Session = Depends(get_session),
) -> dict[str, Any]:
    comp = s.get(Component, component_id)
    if comp is None:
        # Idempotent — repeated DELETE is a 204-shaped 200 with deleted=False.
        return {"deleted": False, "component_id": component_id}
    # Cascade link rows before the FK-bearing row goes away. Composite PKs
    # mean ON DELETE CASCADE isn't reliable on SQLite via SQLModel; explicit
    # statements keep the cleanup obvious in the audit log.
    s.exec(delete(EvidenceComponent).where(EvidenceComponent.component_id == component_id))  # type: ignore[call-overload]
    s.exec(delete(ComponentAsset).where(ComponentAsset.component_id == component_id))  # type: ignore[call-overload]
    s.delete(comp)
    s.commit()
    return {"deleted": True, "component_id": component_id}


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


@router.get("/assets")
def list_assets(
    workbook_id: int,
    s: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rows = s.exec(
        select(Asset)
        .where(Asset.workbook_id == workbook_id)
        .order_by(Asset.hostname)  # type: ignore[arg-type]
    ).all()
    return [_serialize_asset(a) for a in rows]


@router.post("/assets")
def create_asset(
    body: AssetCreate,
    s: Session = Depends(get_session),
) -> dict[str, Any]:
    _require_workbook(s, body.workbook_id)
    hostname = body.hostname.strip().lower()
    # Dedupe on (workbook_id, hostname) — same key the backfill uses.
    # Lets the UI POST blindly without first checking "does this asset
    # already exist?"; the API returns the existing row instead of 4xx.
    existing = s.exec(
        select(Asset)
        .where(Asset.workbook_id == body.workbook_id)
        .where(Asset.hostname == hostname)
    ).first()
    if existing is not None:
        return _serialize_asset(existing)
    asset = Asset(
        workbook_id=body.workbook_id,
        hostname=hostname,
        fqdn=body.fqdn,
        ip_address=body.ip_address,
        cpe=body.cpe,
        os_family=body.os_family,
        asset_class=body.asset_class,
        source=body.source,
    )
    s.add(asset)
    s.commit()
    s.refresh(asset)
    return _serialize_asset(asset)


@router.delete("/assets/{asset_id}")
def delete_asset(
    asset_id: int,
    s: Session = Depends(get_session),
) -> dict[str, Any]:
    asset = s.get(Asset, asset_id)
    if asset is None:
        return {"deleted": False, "asset_id": asset_id}
    s.exec(delete(EvidenceAsset).where(EvidenceAsset.asset_id == asset_id))  # type: ignore[call-overload]
    s.exec(delete(ComponentAsset).where(ComponentAsset.asset_id == asset_id))  # type: ignore[call-overload]
    s.delete(asset)
    s.commit()
    return {"deleted": True, "asset_id": asset_id}


# ---------------------------------------------------------------------------
# Boundary segments
# ---------------------------------------------------------------------------


@router.get("/boundary-segments")
def list_boundary_segments(
    workbook_id: int,
    s: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rows = s.exec(
        select(BoundarySegment)
        .where(BoundarySegment.workbook_id == workbook_id)
        .order_by(BoundarySegment.name)  # type: ignore[arg-type]
    ).all()
    return [_serialize_boundary(b) for b in rows]


@router.post("/boundary-segments")
def create_boundary_segment(
    body: BoundarySegmentCreate,
    s: Session = Depends(get_session),
) -> dict[str, Any]:
    _require_workbook(s, body.workbook_id)
    name = body.name.strip()
    # Dedupe on (workbook_id, name) — boundary segments are named by
    # the program (DMZ, mgmt, etc.) and re-POSTing the same name should
    # be idempotent, matching Asset semantics.
    existing = s.exec(
        select(BoundarySegment)
        .where(BoundarySegment.workbook_id == body.workbook_id)
        .where(BoundarySegment.name == name)
    ).first()
    if existing is not None:
        return _serialize_boundary(existing)
    seg = BoundarySegment(
        workbook_id=body.workbook_id,
        name=name,
        kind=body.kind,
        description=body.description,
    )
    s.add(seg)
    s.commit()
    s.refresh(seg)
    return _serialize_boundary(seg)


@router.delete("/boundary-segments/{segment_id}")
def delete_boundary_segment(
    segment_id: int,
    s: Session = Depends(get_session),
) -> dict[str, Any]:
    seg = s.get(BoundarySegment, segment_id)
    if seg is None:
        return {"deleted": False, "segment_id": segment_id}
    s.exec(
        delete(EvidenceBoundary).where(EvidenceBoundary.boundary_segment_id == segment_id)  # type: ignore[call-overload]
    )
    s.delete(seg)
    s.commit()
    return {"deleted": True, "segment_id": segment_id}
