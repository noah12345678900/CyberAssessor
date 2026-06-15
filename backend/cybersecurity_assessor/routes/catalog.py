"""Framework + control catalog endpoints."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, delete, select

from ..baselines.crm_xlsx import CrmXlsxBaselineSource
from ..baselines.other_xlsx import OtherXlsxBaselineSource
from ..baselines.overlay_classifier import (
    OverlayKind,
    OverlaySheetCandidate,
    classify_overlay,
    classify_overlay_sheets,
)
from ..baselines.scope_labels import ON_PREM_LABEL, normalize_scope_label
from ..catalogs.cis_v8_loader import load_cis_v8_catalog
from ..catalogs.crosswalk_loader import load_id_match_crosswalk
from ..catalogs.csf_loader import load_csf_catalog
from ..catalogs.disa_cci_loader import load_disa_cci_catalog
from ..catalogs.fedramp_profile_loader import (
    FEDRAMP_PROFILE_URLS,
    load_fedramp_profile,
)
from ..catalogs.iso27001_loader import load_iso27001_catalog
from ..catalogs.oscal_loader import load_oscal_catalog
from ..catalogs.pci_dss_loader import load_pci_dss_catalog
from ..catalogs.program_controls_loader import load_program_controls
from ..catalogs.soc2_loader import load_soc2_catalog
from ..catalogs.sp800_171_loader import load_sp800_171_catalog
from ..db import get_session
from ..models import (
    Baseline,
    BaselineControl,
    BaselineMembership,
    BaselineObjective,
    BaselineSourceType,
    Control,
    Framework,
    Objective,
    RequirementMap,
    RequirementSource,
    Workbook,
    WorkbookOverlay,
    iso_utc,
)

router = APIRouter(prefix="/api/catalog", tags=["catalog"])

# OSCAL control ids look like "ac-1", "ac-2", "ac-2.1", "ac-2.10".
# String-sorting them puts ac-10 before ac-2 and ac-2.10 before ac-2.2.
# This regex lets us natural-sort by (family, base int, enhancement int).
_CTRL_ID_RE = re.compile(r"^([a-z]+)-(\d+)(?:\.(\d+))?$")


def _control_sort_key(control_id: str) -> tuple:
    m = _CTRL_ID_RE.match(control_id)
    if not m:
        # Unknown shape — sort to the end, alphabetic
        return ("zzz", 9999, 9999, control_id)
    family, base, enh = m.groups()
    return (family, int(base), int(enh) if enh is not None else 0, "")


# Matches "Rev 5" / "Rev. 5" / "Revision 5" in a framework name or version.
# Case-insensitive; the explicit "Rev"/"Revision" prefix is what
# distinguishes a real revision marker from a year ("2015") or a build
# string ("3.0.0rc1") that happens to contain digits.
_REV_RE = re.compile(r"Rev(?:ision|\.)?\s*(\d+)", re.IGNORECASE)


def _derive_target_revision(fw: Framework | None) -> int | None:
    """Extract the 800-53 revision integer from a Framework row, or None.

    Lookup order:

    1. ``Framework.name`` for an explicit ``Revision N`` / ``Rev N`` /
       ``Rev. N`` marker — the most reliable signal because import code
       sets it deliberately (e.g. ``"NIST Special Publication 800-53
       Revision 4: ..."`` or ``"FedRAMP Rev 5 HIGH"``).
    2. Same regex against ``Framework.version`` (covers users who type
       ``"Rev 5"`` into the version column).
    3. Bare integer 1–9 in ``version`` (covers the canonical ``"5"`` /
       ``"4"`` shorthand the app's own NIST loader writes).

    Returns ``None`` (no filter) when nothing matches — important for OSCAL
    build strings (``"fedramp-3.0.0rc1-oscal-1.1.2"``) and date-shaped
    versions (``"2015-01-22"``) where a naive ``\\d+`` match would pick the
    wrong digit. Earlier code parsed ``"2015-01-22"`` as ``2015`` and
    filtered EVERY CCI as below-revision (no ref has rev=2015).
    """
    if fw is None:
        return None
    for field in (fw.name, fw.version):
        if not field:
            continue
        m = _REV_RE.search(field)
        if m:
            return int(m.group(1))
    if fw.version:
        v = fw.version.strip()
        if v.isdigit() and 1 <= int(v) <= 9:
            return int(v)
    return None


@router.get("/frameworks")
def list_frameworks(s: Session = Depends(get_session)) -> list[dict]:
    rows = s.exec(select(Framework)).all()
    return [
        {
            "id": f.id,
            "name": f.name,
            "version": f.version,
            "oscal_uri": f.oscal_uri,
            # v0.2 catalog refactor — non-null when this framework extends
            # another (FedRAMP → 800-53 r5). UI picker indents children
            # under their parent in the Catalogs group.
            "parent_framework_id": f.parent_framework_id,
            # Display/selection gate (migration 0012). UI shows the toggle row
            # for every framework but filters the *active* catalog list and
            # the assess/baseline pickers to enabled-only.
            "enabled": bool(f.enabled),
        }
        for f in rows
    ]


class FrameworkEnabledRequest(BaseModel):
    enabled: bool


@router.post("/frameworks/{framework_id}/enabled")
def set_framework_enabled(
    framework_id: int,
    body: FrameworkEnabledRequest,
    s: Session = Depends(get_session),
) -> dict:
    """Toggle a framework's display/selection gate.

    Presentation-only: flipping ``enabled`` hides the framework from the
    active Catalog list and the assess/baseline pickers but never touches
    Control/Objective rows or the parent→child inheritance merge. A disabled
    parent's rows still merge into an enabled child (``list_controls`` reads
    parent rows by id, not by ``enabled``), so toggling a parent off does not
    corrupt a child framework's effective catalog.

    Idempotent: setting the same value twice is a no-op that still returns
    the current state. 404 only when the id truly doesn't exist.
    """
    fw = s.get(Framework, framework_id)
    if fw is None:
        raise HTTPException(
            status_code=404, detail=f"framework {framework_id} not found"
        )
    fw.enabled = bool(body.enabled)
    s.add(fw)
    s.commit()
    s.refresh(fw)
    return {
        "id": fw.id,
        "name": fw.name,
        "version": fw.version,
        "enabled": bool(fw.enabled),
    }


@router.get("/status")
def catalog_status(s: Session = Depends(get_session)) -> dict:
    """One-shot summary of what's loaded — drives the Workbooks status card.

    Returns per-framework control counts, total Objective rows (DISA CCIs once
    the overlay has been loaded), and the list of RequirementSource rows
    (e.g. Program-specific controls).

    For child frameworks (FedRAMP → 800-53 rev5), the reported counts mirror
    the inherited+membership-merged view that ``list_controls`` returns — i.e.
    a FedRAMP HIGH child reports ~410 (its baseline membership applied to the
    parent rev5 catalog plus any FedRAMP-only synthesised rows), not the ~97
    bare shadow rows that live on the child framework itself. Without this,
    the Workbooks status card mis-labels FedRAMP children with a tiny
    "97 controls" badge that looks like a broken catalog load.
    """
    framework_rows = s.exec(select(Framework)).all()

    # Raw per-framework counts — what the framework actually owns in the
    # Control table. We start from these and merge inheritance below for
    # child frameworks.
    raw_control_counts = dict(
        s.exec(
            select(Control.framework_id, func.count(Control.id)).group_by(Control.framework_id)
        ).all()
    )

    # Objective rows are CCIs (for 800-53) — joined back through Control to
    # split totals per framework so the UI can flag "CCIs missing for rev5".
    raw_objective_counts = dict(
        s.exec(
            select(Control.framework_id, func.count(Objective.id))
            .join(Objective, Objective.control_id_fk == Control.id)
            .group_by(Control.framework_id)
        ).all()
    )

    # Index Controls per framework once so we can merge cheaply for any
    # child. Each list is the framework's own Control rows; we do NOT
    # pre-merge parents here because the merge depends on per-framework
    # membership.
    controls_by_framework: dict[int, list[Control]] = {}
    for c in s.exec(select(Control)).all():
        controls_by_framework.setdefault(c.framework_id, []).append(c)

    # Objective counts by Control.id — drives the merged CCI total.
    objective_count_by_control: dict[int, int] = dict(
        s.exec(
            select(Objective.control_id_fk, func.count(Objective.id)).group_by(
                Objective.control_id_fk
            )
        ).all()
    )

    # Membership rows by framework — empty set means "permissive" (no
    # filter on the parent), same convention as list_controls.
    membership_by_framework: dict[int, set[str]] = {}
    for row in s.exec(select(BaselineMembership)).all():
        membership_by_framework.setdefault(row.framework_id, set()).add(row.control_id)

    def merged_counts(fw: Framework) -> tuple[int, int]:
        """Return (control_count, objective_count) for fw's effective view."""
        own = controls_by_framework.get(fw.id, [])
        if fw.parent_framework_id is None:
            ctrl_count = len(own)
            obj_count = sum(objective_count_by_control.get(c.id, 0) for c in own)
            return ctrl_count, obj_count

        # Child framework — merge parent + own, child wins on collision,
        # parent rows filtered by membership when present.
        parent_rows = controls_by_framework.get(fw.parent_framework_id, [])
        membership = membership_by_framework.get(fw.id, set())
        if membership:
            parent_rows = [c for c in parent_rows if c.control_id in membership]
        merged: dict[str, Control] = {c.control_id: c for c in parent_rows}
        for c in own:
            merged[c.control_id] = c  # child shadow wins
        merged_controls = list(merged.values())
        ctrl_count = len(merged_controls)
        obj_count = sum(objective_count_by_control.get(c.id, 0) for c in merged_controls)
        return ctrl_count, obj_count

    frameworks: list[dict] = []
    for f in framework_rows:
        ctrl_count, obj_count = merged_counts(f)
        frameworks.append(
            {
                "id": f.id,
                "name": f.name,
                "version": f.version,
                "parent_framework_id": f.parent_framework_id,
                "enabled": bool(f.enabled),
                "control_count": int(ctrl_count),
                "objective_count": int(obj_count),
            }
        )

    # Total still reflects raw Objective rows (sum across the underlying
    # table) — that's the storage-level count the UI uses to detect
    # "DISA CCI overlay loaded" and shouldn't double-count via inheritance.
    objectives_total = int(sum(raw_objective_counts.values()))
    # Silence unused-variable warning while keeping the raw_control_counts
    # query visible for future per-framework "own rows only" debugging.
    _ = raw_control_counts

    req_sources = s.exec(select(RequirementSource)).all()
    return {
        "frameworks": frameworks,
        "objectives_total": objectives_total,
        "requirement_sources": [
            {
                "id": r.id,
                "name": r.name,
                "framework_id": r.framework_id,
                # Surfaced in the Catalogs overlay list so PSC rows render
                # a refreshed-at date parallel to CRM Baseline rows. Same
                # value the dedicated /requirement-sources endpoint returns.
                "loaded_at": iso_utc(r.loaded_at),
            }
            for r in req_sources
        ],
    }


@router.get("/frameworks/{framework_id}/controls")
def list_controls(
    framework_id: int,
    include_inherited: bool = True,
    s: Session = Depends(get_session),
) -> list[dict]:
    """List controls for a framework, merging inherited rows from the parent.

    Child frameworks (e.g. FedRAMP → 800-53 rev5) shadow inherited rows on
    the same ``control_id`` — the OSCAL ``add`` directive parser writes
    these as Control rows on the child framework carrying FedRAMP-specific
    Requirement / Guidance prose. The default ``include_inherited=true``
    surface is the inherited + shadowed view (child wins on collision) so
    that picking "FedRAMP HIGH" in the Controls grid actually returns the
    rev5 catalog enriched with FedRAMP overlay prose. Pass
    ``include_inherited=false`` for the raw child-only view (debugging
    the overlay itself).

    When the child Framework has ``BaselineMembership`` rows recorded
    (populated from OSCAL ``profile.imports[].include-controls[].with-ids[]``),
    the inherited view is filtered to ONLY those membership ids — so
    FedRAMP HIGH returns its 410-control baseline rather than all 1014
    rev5 rows. Child-defined shadow rows (FedRAMP-only synthesised
    controls, e.g. an ``xx-99`` carrying overlay-only prose) are always
    surfaced regardless of membership, since the child opted them in by
    writing them. When membership is empty (non-baseline overlays), every
    inherited row passes through — keeps the behaviour permissive for
    pure-renaming overlays.
    """
    fw = s.get(Framework, framework_id)
    if fw is None:
        raise HTTPException(
            status_code=404, detail=f"framework {framework_id} not found"
        )

    if fw.parent_framework_id is None or not include_inherited:
        rows = s.exec(
            select(Control).where(Control.framework_id == framework_id)
        ).all()
        rows = sorted(rows, key=lambda c: _control_sort_key(c.control_id))
        return [
            {"id": c.id, "control_id": c.control_id, "title": c.title, "family": c.family}
            for c in rows
        ]

    # Membership-aware inherited filter. Empty set ⇒ permissive (no
    # filter), so non-baseline child overlays (e.g. a pure renaming
    # overlay) still return every parent row.
    membership_ids: set[str] = {
        row.control_id
        for row in s.exec(
            select(BaselineMembership).where(
                BaselineMembership.framework_id == framework_id
            )
        ).all()
    }

    # Parent first so the child can shadow on collision.
    parent_rows = s.exec(
        select(Control).where(Control.framework_id == fw.parent_framework_id)
    ).all()
    if membership_ids:
        parent_rows = [c for c in parent_rows if c.control_id in membership_ids]
    merged: dict[str, Control] = {c.control_id: c for c in parent_rows}

    # Child rows always win on collision; FedRAMP-only synthesised rows
    # (e.g. xx-99) are surfaced even when not in membership — the child
    # opted them in by writing them.
    for c in s.exec(
        select(Control).where(Control.framework_id == framework_id)
    ).all():
        merged[c.control_id] = c

    rows = sorted(merged.values(), key=lambda c: _control_sort_key(c.control_id))
    return [
        {"id": c.id, "control_id": c.control_id, "title": c.title, "family": c.family}
        for c in rows
    ]


@router.get("/controls/{control_id}/objectives")
def list_objectives(
    control_id: int,
    include_mappings: bool = False,
    workbook_id: int | None = None,
    s: Session = Depends(get_session),
) -> list[dict]:
    """List CCIs (objectives) for a control.

    With ``include_mappings=true``, each objective also carries the
    program-specific requirements that crosswalk to it (RequirementMap rows,
    e.g. SDA Controls' "shall" statements). This is opt-in so existing
    callers (the drill-down view) keep the lighter payload, but the CSV
    export can pull both objectives and mappings in one round-trip per
    control.

    When ``workbook_id`` is provided and the workbook is tied to a baseline,
    each objective also carries ``in_workbook`` — True if the workbook's
    source surfaced this CCI (via BaselineObjective), False if it's a
    catalog-only stub for the same control. The UI uses this to sort
    workbook CCIs first and visually mark stubs. When ``workbook_id`` is
    omitted or the workbook has no baseline, ``in_workbook`` is True for
    every row (backwards-compat default — show everything as if scoped).
    """
    rows = s.exec(select(Objective).where(Objective.control_id_fk == control_id)).all()

    # Resolve the in-workbook CCI set. Default to "all in" when we can't
    # narrow it — keeps existing callers (drill-down, CSV export) unchanged.
    in_workbook_ids: set[int] | None = None
    if workbook_id is not None:
        wb = s.get(Workbook, workbook_id)
        if wb is not None and wb.baseline_id is not None:
            objective_ids = [o.id for o in rows if o.id is not None]
            if objective_ids:
                # Exclude soft-deleted rows so the in-workbook badge
                # reflects the current workbook roster — a CCI the user
                # dropped from col A should display as catalog-only,
                # not "in workbook". See models.py BaselineObjective.is_deprecated.
                bo_rows = s.exec(
                    select(BaselineObjective.objective_id).where(
                        BaselineObjective.baseline_id == wb.baseline_id,
                        BaselineObjective.is_deprecated.is_(False),  # type: ignore[union-attr]
                        BaselineObjective.objective_id.in_(objective_ids),  # type: ignore[attr-defined]
                    )
                ).all()
                in_workbook_ids = set(bo_rows)
            else:
                in_workbook_ids = set()

    mappings_by_objective: dict[int, list[dict]] = {}
    if include_mappings and rows:
        objective_ids = [o.id for o in rows if o.id is not None]
        if objective_ids:
            # Single join query — name the source so the CSV can distinguish
            # multiple overlays if more than one is loaded against the same
            # framework (e.g. SDA Controls + a future CDS overlay).
            map_rows = s.exec(
                select(RequirementMap, RequirementSource.name)
                .join(
                    RequirementSource,
                    RequirementSource.id == RequirementMap.requirement_source_id,
                )
                .where(RequirementMap.objective_id.in_(objective_ids))  # type: ignore[attr-defined]
            ).all()
            for m, source_name in map_rows:
                mappings_by_objective.setdefault(m.objective_id, []).append(
                    {
                        "source_name": source_name,
                        "requirement_number": m.requirement_number,
                        "requirement_text": m.requirement_text,
                    }
                )

    return [
        {
            "id": o.id,
            "objective_id": o.objective_id,
            "source": o.source,
            "text": o.text,
            "implementation_guidance": o.implementation_guidance,
            "assessment_procedures": o.assessment_procedures,
            "in_workbook": (
                True if in_workbook_ids is None else o.id in in_workbook_ids
            ),
            **(
                {"mappings": mappings_by_objective.get(o.id, [])}
                if include_mappings
                else {}
            ),
        }
        for o in rows
    ]


@router.post("/load/nist-800-53r5")
def load_nist_800_53r5(path: str | None = None, s: Session = Depends(get_session)) -> dict:
    """Load the NIST 800-53r5 OSCAL JSON catalog.

    If ``path`` is omitted, downloads the official NIST catalog into the local
    cache (~/.cybersecurity-assessor/catalogs/).
    """
    try:
        framework = load_oscal_catalog(s, path=path, rev="5")
    except FileNotFoundError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    # ``id`` matches the UI's Framework type (so the Workbooks page can
    # auto-select the just-loaded catalog); ``framework_id`` kept as a
    # backwards-compat alias for older callers.
    return {
        "id": framework.id,
        "framework_id": framework.id,
        "name": framework.name,
        "version": framework.version,
        "oscal_uri": framework.oscal_uri,
    }


@router.post("/load/nist-800-53r4")
def load_nist_800_53r4(path: str | None = None, s: Session = Depends(get_session)) -> dict:
    """Load the NIST 800-53r4 OSCAL JSON catalog.

    Rev 4 is the prior baseline still referenced by some legacy DoD systems
    and FedRAMP packages mid-transition. If ``path`` is omitted, downloads
    the official NIST catalog into the local cache.
    """
    try:
        framework = load_oscal_catalog(s, path=path, rev="4")
    except FileNotFoundError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {
        "id": framework.id,
        "framework_id": framework.id,
        "name": framework.name,
        "version": framework.version,
        "oscal_uri": framework.oscal_uri,
    }


class FedrampLoadRequest(BaseModel):
    """Body for ``POST /api/catalog/load/fedramp``.

    ``level`` is case-insensitive — ``"HIGH"``, ``"high"``, and
    ``"High"`` all resolve to the same profile. ``path`` overrides the
    resolution chain when an operator has a profile JSON on disk (e.g.
    a pre-release FedRAMP draft); ``offline`` skips the network entirely
    and goes straight to the wheel-bundled copy.
    """

    level: str
    path: str | None = None
    offline: bool = False


def _resolve_rev5_framework(s: Session) -> Framework:
    """Find the loaded 800-53 Rev 5 Framework, or raise 400.

    Detection matches :func:`oscal_loader.load_oscal_catalog` — the
    canonical rev5 row carries the NIST rev5 OSCAL URL. Using the URL
    rather than the name/version pair keeps the check robust against
    metadata edits and matches how the UI's ``pickRev5`` helper detects
    the same framework on the picker side.
    """
    rows = s.exec(select(Framework)).all()
    for f in rows:
        if f.oscal_uri and "rev5" in f.oscal_uri.lower():
            return f
    raise HTTPException(
        status_code=400,
        detail="NIST 800-53 Rev 5 is not loaded. Load it first via /api/catalog/load/nist-800-53r5.",
    )


@router.post("/load/fedramp")
def load_fedramp(
    req: FedrampLoadRequest, s: Session = Depends(get_session)
) -> dict:
    """Load a FedRAMP Rev 5 baseline profile as a child of 800-53 r5.

    The profile is projected as a *child Framework* (``parent_framework_id``
    set to the rev5 row's id). Membership is recorded in
    ``BaselineMembership``; controls with FedRAMP-Additions prose get
    shadow Control rows on the child carrying the merged statement.

    Response shape is intentionally flat (Framework fields + load
    counts) so the UI can render a single toast and re-query the
    Frameworks list without a second round-trip.
    """
    parent = _resolve_rev5_framework(s)
    try:
        result = load_fedramp_profile(
            s,
            level=req.level,
            parent_framework_id=parent.id,  # type: ignore[arg-type]
            path=req.path,
            offline=req.offline,
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except RuntimeError as e:
        # Network failed AND no bundled fallback — surfaces as 502 so the
        # UI can show a "couldn't reach upstream" toast distinct from a
        # validation error.
        raise HTTPException(status_code=502, detail=str(e)) from e

    fw = result.framework
    return {
        "id": fw.id,
        "framework_id": fw.id,
        "name": fw.name,
        "version": fw.version,
        "oscal_uri": fw.oscal_uri,
        "parent_framework_id": fw.parent_framework_id,
        "members_added": result.members_added,
        "controls_synthesized": result.controls_synthesized,
        "parameters_loaded": result.parameters_loaded,
        "unknown_control_ids": result.unknown_control_ids,
    }


# ---------------------------------------------------------------------------
# NIST Cybersecurity Framework (CSF) 2.0 — public-domain root catalog
# ---------------------------------------------------------------------------
@router.post("/load/nist-csf")
def load_nist_csf(path: str | None = None, s: Session = Depends(get_session)) -> dict:
    """Load the NIST CSF 2.0 OSCAL JSON catalog.

    Public-domain content (like 800-53), so this is a download-style endpoint:
    if ``path`` is omitted the official NIST catalog is fetched into the local
    cache, falling back to the wheel-bundled copy when the network is down.
    """
    try:
        framework = load_csf_catalog(s, path=path)
    except FileNotFoundError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except RuntimeError as e:
        # Network failed AND no bundled fallback present.
        raise HTTPException(status_code=502, detail=str(e)) from e
    return {
        "id": framework.id,
        "framework_id": framework.id,
        "name": framework.name,
        "version": framework.version,
        "oscal_uri": framework.oscal_uri,
    }


# ---------------------------------------------------------------------------
# NIST SP 800-171 Rev 3 — public-domain root catalog
# ---------------------------------------------------------------------------
@router.post("/load/nist-800-171")
def load_nist_800_171(path: str | None = None, s: Session = Depends(get_session)) -> dict:
    """Load the NIST SP 800-171 Rev 3 OSCAL JSON catalog.

    Public-domain; download-style with bundled fallback.
    """
    try:
        framework = load_sp800_171_catalog(s, path=path)
    except FileNotFoundError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    return {
        "id": framework.id,
        "framework_id": framework.id,
        "name": framework.name,
        "version": framework.version,
        "oscal_uri": framework.oscal_uri,
    }


class LicensedCatalogLoadRequest(BaseModel):
    """Body for the license-aware catalog loaders (ISO / CIS / PCI / SOC 2).

    These frameworks carry copyrighted control text that this app may not
    bundle or download. ``path`` is REQUIRED — it points at the
    organization's own licensed export (a ``.csv`` or ``.json`` file). With
    no path (or ``offline=True``) the underlying loader raises the
    supply-your-licensed-export error, which we surface as a 400.
    """

    path: str | None = None
    offline: bool = False


def _license_aware_load(loader, req: LicensedCatalogLoadRequest, s: Session) -> dict:
    """Shared driver for the four license-aware catalog endpoints.

    The loaders disagree on guard exception type — CIS/ISO raise
    ``ValueError`` while PCI/SOC 2 raise ``RuntimeError`` — but for these
    frameworks there is NO network source, so a ``RuntimeError`` here is the
    licensing guard, not an upstream failure. We therefore map
    ValueError, RuntimeError, and FileNotFoundError all to HTTP 400.
    """
    try:
        framework = loader(s, path=req.path, offline=req.offline)
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {
        "id": framework.id,
        "framework_id": framework.id,
        "name": framework.name,
        "version": framework.version,
        "oscal_uri": framework.oscal_uri,
    }


@router.post("/load/iso-27001")
def load_iso_27001(
    req: LicensedCatalogLoadRequest, s: Session = Depends(get_session)
) -> dict:
    """Load ISO/IEC 27001:2022 from a user-supplied licensed export."""
    return _license_aware_load(load_iso27001_catalog, req, s)


@router.post("/load/cis-v8")
def load_cis_v8(
    req: LicensedCatalogLoadRequest, s: Session = Depends(get_session)
) -> dict:
    """Load CIS Controls v8 Safeguards from a user-supplied licensed export."""
    return _license_aware_load(load_cis_v8_catalog, req, s)


@router.post("/load/pci-dss")
def load_pci_dss(
    req: LicensedCatalogLoadRequest, s: Session = Depends(get_session)
) -> dict:
    """Load PCI DSS 4.0 requirements from a user-supplied licensed export."""
    return _license_aware_load(load_pci_dss_catalog, req, s)


@router.post("/load/soc2")
def load_soc2(
    req: LicensedCatalogLoadRequest, s: Session = Depends(get_session)
) -> dict:
    """Load the SOC 2 Trust Services Criteria from a user-supplied export."""
    return _license_aware_load(load_soc2_catalog, req, s)


class ProgramControlsLoadRequest(BaseModel):
    source_name: str
    workbook_path: str
    framework_id: int
    sheet_name: str


@router.post("/load/program-controls", deprecated=True)
def load_program_controls_endpoint(
    req: ProgramControlsLoadRequest, s: Session = Depends(get_session)
) -> dict:
    """Load a program-specific controls overlay and crosswalk it to a framework.

    DEPRECATED — prefer ``POST /api/catalog/overlays/import`` which
    auto-classifies the file and dispatches to this loader. Kept so any
    existing callers that already know the file is a PSC overlay and
    have an explicit ``sheet_name`` keep working until the UI fully
    migrates.

    Overlays map program-numbered requirements (e.g. "SDA-AC-01") to one or
    more NIST 800-53 CCIs. The ``source_name`` is the label that distinguishes
    one overlay from another for the same framework.

    If DISA CCIs haven't been loaded yet, requirements that reference unknown
    CCIs are reported in ``unmapped_ccis`` instead of erroring. Rerunning this
    endpoint after the CCI list is loaded fills them in.
    """
    try:
        src = load_program_controls(
            s,
            source_name=req.source_name,
            workbook_path=req.workbook_path,
            framework_id=req.framework_id,
            sheet_name=req.sheet_name,
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {
        "requirement_source_id": src.id,
        "name": src.name,
        "rows_seen": src.__dict__.get("_rows_seen", 0),
        "maps_written": src.__dict__.get("_maps_written", 0),
        # Audit counters from IngestReport (alembic 0005). rows_forward_filled
        # counts continuation rows of unmerged tall col-A cell blocks that
        # inherited their parent's req_number; rows_unnumbered counts blank
        # col-A rows that kept the "(unnumbered)" sentinel because a top
        # border signalled a genuine workbook gap.
        "rows_forward_filled": src.__dict__.get("_rows_forward_filled", 0),
        "rows_unnumbered": src.__dict__.get("_rows_unnumbered", 0),
        "ingest_report_id": src.__dict__.get("_ingest_report_id"),
        "loader_version": src.__dict__.get("_loader_version"),
        "unmapped_ccis": src.__dict__.get("_unmapped_ccis", []),
        # Populated when the overlay is control-grain (T1TL-style) and the
        # shall-text references controls not present in the target framework.
        "unmapped_control_ids": src.__dict__.get("_unmapped_control_ids", []),
    }


@router.get("/overlays/sheets")
def list_overlay_sheets(path: str) -> dict:
    """Preview an overlay xlsx — list every sheet + the classifier's pick.

    Feeds the Settings → Import overlay sheet-picker dropdown. The user
    sets the xlsx path, the UI calls this endpoint, and the dropdown is
    populated with "Auto-pick ({classifier's choice})" plus one option per
    sheet labeled with its candidate kind. The user can then explicitly
    target Ground vs SV (the T1TL workbook ships with both PSC-shaped
    tabs and the classifier always picks Ground — first match wins).

    Read-only — never mutates the file.
    """
    p = Path(path)
    if not p.exists():
        raise HTTPException(
            status_code=400, detail=f"overlay file not found: {path}"
        )
    try:
        auto = classify_overlay(p)
        candidates = classify_overlay_sheets(p)
    except FileNotFoundError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {
        "auto_pick": {
            "kind": auto.kind.value,
            "sheet_name": auto.sheet_name,
        },
        "sheets": [
            {
                "name": c.name,
                "candidate_kind": c.kind.value if c.kind is not None else None,
            }
            for c in candidates
        ],
    }


class OverlayImportRequest(BaseModel):
    """Single front-door for any overlay xlsx the user drops in.

    Auto-classifies via :func:`baselines.overlay_classifier.classify_overlay`
    unless ``kind_hint`` pins a specific loader. ``name`` overrides the
    auto-derived label (defaults to the file stem); ``system_id`` is
    threaded through to the CRM/OTHER loaders so per-system overlays are
    attributable.
    """

    framework_id: int
    path: str
    name: str | None = None
    # Optional escape hatch — bypass the classifier when the user knows
    # which loader to run (e.g. a PSC file with hand-edited headers the
    # classifier doesn't recognize yet).
    kind_hint: OverlayKind | None = None
    # Optional explicit PSC sheet selector. The T1TL workbook ships with
    # both "Ground Security Controls" and "SV Security Controls" — the
    # classifier picks the first PSC-shaped sheet (Ground), so without
    # this field the user has no way to target SV. When provided AND the
    # dispatched loader is PSC, this overrides the classifier's choice.
    # Ignored (with a warning) for CRM/OTHER dispatch; the PSC loader
    # validates that the sheet exists in the workbook and 400s otherwise.
    #
    # Pydantic constraints front-run obvious garbage so the user gets a
    # 422 with a specific field error instead of a confusing loader-side
    # 400. Excel caps sheet names at 31 chars and disallows the
    # characters in the regex below; min_length=1 rejects empty strings
    # (which would otherwise pass the falsy override check and silently
    # fall back to auto-detection).
    sheet_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=31,
        pattern=r"^[^:\\/?*\[\]]+$",
    )
    system_id: int | None = None
    # v0.2 multi-implementation: each CRM upload tags a single
    # implementation slice (e.g. "AWS GovCloud", "Azure Government").
    # Required when this dispatch routes to the CRM loader; ignored
    # (with a warning) for PSC / OTHER dispatch. The canonical vocabulary
    # lives in baselines.scope_labels; the special "On-Premises" label is
    # reserved and rejected here — on-prem implementations are synthesized
    # by the assessor at assess-time, not stored as a CRM Baseline.
    # Free-text values are allowed (the "Other..." UI path); they are
    # passed through normalize_scope_label() which canonical-matches
    # known labels and otherwise trims whitespace.
    scope_label: str | None = None


@router.post("/overlays/import")
def import_overlay(
    req: OverlayImportRequest, s: Session = Depends(get_session)
) -> dict:
    """Unified overlay import — auto-classify CRM / PSC / OTHER and dispatch.

    Replaces the two-button affordance ("Load CRM" + "Load Program
    Controls") with a single endpoint that sniffs the xlsx headers and
    routes to the right loader. Unrecognized files import as ``OTHER`` —
    a Baseline row is created so the file is visible in the Workbooks
    attach UI, but no resolver runs against it during assessment until
    one is programmed for the file's shape.

    Response shape is intentionally flat so the UI can render a single
    toast regardless of which loader actually ran:

    ``kind`` — what was detected (or forced via ``kind_hint``).
    ``baseline_id`` — present for CRM and OTHER (Baseline rows).
    ``requirement_source_id`` — present for PSC (RequirementSource row).
    ``warnings`` — human-readable strings; OTHER always includes a
      "no resolver registered" line so the user understands the file is
      inert until programmed.
    """
    path = Path(req.path)
    if not path.exists():
        raise HTTPException(
            status_code=400, detail=f"overlay file not found: {req.path}"
        )
    if not s.get(Framework, req.framework_id):
        raise HTTPException(
            status_code=400, detail=f"Framework id={req.framework_id} not loaded"
        )

    # Classify once. When ``kind_hint`` is given we still need the
    # matched sheet name for PSC dispatch (the PSC loader requires an
    # explicit sheet_name and intentionally won't fuzzy-match), so we
    # run the classifier anyway and only override the kind field.
    auto = classify_overlay(path)
    warnings: list[str] = []
    if req.kind_hint is not None and req.kind_hint is not auto.kind:
        warnings.append(
            f"kind_hint={req.kind_hint.value} overrides auto-classified "
            f"kind={auto.kind.value}; downstream loader may reject the "
            "file if its headers don't match."
        )
    classification_kind = req.kind_hint or auto.kind
    # Explicit sheet_name takes precedence over the classifier's pick so
    # a user uploading T1TL can target "SV Security Controls" instead of
    # the auto-selected "Ground Security Controls" (first PSC-shaped
    # sheet wins). Surface a warning when the override differs from the
    # auto pick so the toast reflects which tab actually got parsed.
    if req.sheet_name and classification_kind is OverlayKind.PSC:
        if auto.sheet_name and req.sheet_name != auto.sheet_name:
            warnings.append(
                f"sheet_name={req.sheet_name!r} overrides auto-classified "
                f"sheet={auto.sheet_name!r}."
            )
        classification_sheet = req.sheet_name
    else:
        classification_sheet = auto.sheet_name
        if req.sheet_name and classification_kind is not OverlayKind.PSC:
            warnings.append(
                f"sheet_name={req.sheet_name!r} ignored — only used for "
                "PSC dispatch."
            )

    if classification_kind is OverlayKind.PSC:
        # PSC loader needs an explicit sheet name. classify_overlay
        # returns the first sheet whose headers matched the PSC
        # vocabulary; that's the same sheet the PSC loader would parse.
        # Realistic path to this branch: caller passed kind_hint=psc
        # against a file the classifier didn't see PSC headers in, and
        # didn't also pass sheet_name to nominate a tab.
        if not classification_sheet:
            hint_clause = (
                "kind_hint=psc was supplied but "
                if req.kind_hint is OverlayKind.PSC
                else ""
            )
            raise HTTPException(
                status_code=400,
                detail=(
                    f"{hint_clause}no PSC-shaped sheet was detected in the "
                    "workbook; can't dispatch to the PSC loader without a "
                    "sheet name. Pass sheet_name explicitly to target a "
                    "specific tab."
                ),
            )
        try:
            src = load_program_controls(
                s,
                source_name=req.name or path.stem,
                workbook_path=str(path),
                framework_id=req.framework_id,
                sheet_name=classification_sheet,
            )
        except FileNotFoundError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return {
            "kind": OverlayKind.PSC.value,
            "requirement_source_id": src.id,
            # Surface the synthetic Baseline id so the frontend can invalidate
            # per-baseline caches (qk.baseline(id)) on PSC import the same
            # way it does for CRM/OTHER. Without this the Overlays surface
            # for the just-imported baseline stays stale.
            "baseline_id": src.__dict__.get("_baseline_id"),
            "name": src.name,
            "sheet_name": classification_sheet,
            "rows_seen": src.__dict__.get("_rows_seen", 0),
            "maps_written": src.__dict__.get("_maps_written", 0),
            # Audit counters from IngestReport (alembic 0005). See the
            # deprecated /load/program-controls endpoint above for the
            # field semantics — same row, same source attrs.
            "rows_forward_filled": src.__dict__.get("_rows_forward_filled", 0),
            "rows_unnumbered": src.__dict__.get("_rows_unnumbered", 0),
            "ingest_report_id": src.__dict__.get("_ingest_report_id"),
            "loader_version": src.__dict__.get("_loader_version"),
            "unmapped_ccis": src.__dict__.get("_unmapped_ccis", []),
            "unmapped_control_ids": src.__dict__.get("_unmapped_control_ids", []),
            "warnings": warnings,
        }

    if classification_kind is OverlayKind.CRM:
        # scope_label is required for CRM dispatch — each CRM upload
        # represents one implementation slice (AWS GovCloud / Azure Gov /
        # etc.). Surface a 422-equivalent so the UI can show a field-level
        # error instead of a generic 400.
        if not req.scope_label or not req.scope_label.strip():
            raise HTTPException(
                status_code=422,
                detail=(
                    "scope_label is required for CRM imports — pick one of "
                    "the canonical implementation labels (e.g. "
                    "'AWS GovCloud', 'Azure Government') or type a custom "
                    "label in the 'Other...' field."
                ),
            )
        try:
            normalized_label = normalize_scope_label(req.scope_label)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e)) from e
        # "On-Premises" is reserved — the assessor synthesizes an on-prem
        # implementation row when no CRM covers a customer-responsibility
        # CCI. Storing an "On-Premises" CRM would double-count.
        if normalized_label == ON_PREM_LABEL:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"scope_label={ON_PREM_LABEL!r} is reserved — on-prem "
                    "implementations are synthesized by the assessor and "
                    "should not be uploaded as a CRM. Use the cloud-platform "
                    "label that this CRM actually covers."
                ),
            )

        # Replace-by-label: same (framework, CRM, scope_label) under a
        # different file path = the user is replacing the prior upload for
        # this implementation slice. Cascade-delete the prior Baseline
        # (mirrors routes/baselines.py:delete_baseline) so re-attach is
        # idempotent and the overlays UI doesn't accumulate stale rows.
        existing = s.exec(
            select(Baseline).where(
                Baseline.framework_id == req.framework_id,
                Baseline.source_type == BaselineSourceType.CRM,
                Baseline.scope_label == normalized_label,
            )
        ).all()
        replaced_baseline_ids: list[int] = []
        for prior in existing:
            if prior.source_ref == str(path):
                # Same path + same label → the in-place upsert in
                # CrmXlsxBaselineSource handles it; nothing to delete.
                continue
            prior_id = prior.id
            if prior_id is None:
                continue
            s.exec(delete(BaselineControl).where(BaselineControl.baseline_id == prior_id))
            s.exec(delete(BaselineObjective).where(BaselineObjective.baseline_id == prior_id))
            s.exec(delete(WorkbookOverlay).where(WorkbookOverlay.baseline_id == prior_id))
            s.delete(prior)
            replaced_baseline_ids.append(prior_id)
        if replaced_baseline_ids:
            s.commit()
            warnings.append(
                f"Replaced prior {normalized_label!r} CRM "
                f"(baseline_id={replaced_baseline_ids[0]}) — the previous "
                "file is no longer attached."
            )

        crm = CrmXlsxBaselineSource(
            workbook_path=str(path),
            name=req.name,
            system_id=req.system_id,
            scope_label=normalized_label,
        )
        try:
            result = crm.apply(s, framework_id=req.framework_id)
        except (FileNotFoundError, ValueError) as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except RuntimeError as e:
            raise HTTPException(status_code=502, detail=str(e)) from e
        notes = result.notes or {}
        return {
            "kind": OverlayKind.CRM.value,
            "baseline_id": result.baseline.id,
            "name": result.baseline.name,
            "scope_label": normalized_label,
            "replaced_baseline_ids": replaced_baseline_ids,
            "controls_in_scope": result.controls_in_scope,
            "controls_unknown": result.controls_unknown,
            "unknown_control_ids": notes.get("unknown_control_ids", []) or [],
            "unknown_responsibility_rows": int(
                notes.get("unknown_responsibility_rows", 0) or 0
            ),
            "warnings": warnings,
        }

    # OTHER — register an inert Baseline so the file shows up in the
    # attach UI, but no resolver runs against it. Always emit the
    # "no resolver" warning so the user doesn't expect the file to bias
    # assessment.
    other = OtherXlsxBaselineSource(
        workbook_path=str(path),
        name=req.name,
        system_id=req.system_id,
    )
    try:
        result = other.apply(s, framework_id=req.framework_id)
    except (FileNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    warnings.append(
        "Imported as OTHER — no resolver is registered for this file's "
        "shape, so it will not influence assessment until one is "
        "programmed."
    )
    return {
        "kind": OverlayKind.OTHER.value,
        "baseline_id": result.baseline.id,
        "name": result.baseline.name,
        "warnings": warnings,
    }


class DisaCciLoadRequest(BaseModel):
    # New name -- accepts either the NIST CSRC xlsx (preferred, since DISA
    # stopped publishing the standalone XML) or an archived U_CCI_List.xml.
    source_path: str | None = None
    # Legacy alias kept so existing UI callers (Settings.tsx) keep working
    # without a coordinated front+back deploy. Either field is accepted.
    xml_path: str | None = None
    framework_id: int


@router.post("/load/disa-cci")
def load_disa_cci_endpoint(
    req: DisaCciLoadRequest, s: Session = Depends(get_session)
) -> dict:
    """Load the CCI catalog and upsert ~3500 Objective rows into the given framework.

    Accepts either:
      * the **NIST CSRC** ``stig-mapping-to-nist-800-53.xlsx`` (recommended;
        public, no CAC, no zip step), or
      * an **archived DISA** ``U_CCI_List.xml`` (the older source -- DISA
        no longer publishes it standalone, but old downloads still parse).

    Enriches NIST 800-53 objectives with CCI definitions, NIST references,
    and deprecation status. The UI exposes this as Settings -> "DISA CCI List".
    """
    chosen = req.source_path or req.xml_path
    if not chosen:
        raise HTTPException(
            status_code=400,
            detail="source_path is required (path to NIST CSRC xlsx or archived U_CCI_List.xml).",
        )
    # Derive the target 800-53 revision from the framework being loaded so
    # legacy Rev3-only CCIs don't get attached to a Rev4 framework as
    # catalog-only stubs. Both ``Framework.name`` ("...Revision 4...") and
    # ``Framework.version`` ("5", "Rev 5") can carry the revision; prefer
    # an explicit "Revision/Rev N" in the name first because version fields
    # often hold dates ("2015-01-22") or opaque OSCAL build strings
    # ("fedramp-3.0.0rc1-oscal-1.1.2") that don't say revision at all.
    # A bare-integer version (1-9) is the secondary signal. Anything else
    # falls through to ``None`` = no filter (legacy import-everything).
    fw_for_rev = s.get(Framework, req.framework_id)
    target_revision = _derive_target_revision(fw_for_rev)
    try:
        result = load_disa_cci_catalog(
            s,
            source_path=chosen,
            framework_id=req.framework_id,
            target_revision=target_revision,
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ET.ParseError as e:
        # Bare 500s from XML parse errors lose CORS headers (Starlette
        # middleware ordering), so the browser console reads them as a
        # misleading CORS error instead of the real "wrong file" problem.
        raise HTTPException(
            status_code=400,
            detail=(
                f"Not a valid XML document: {e}. "
                "Expected NIST CSRC stig-mapping-to-nist-800-53.xlsx (preferred) "
                "or archived DISA U_CCI_List.xml. If you downloaded a DISA zip, "
                "extract the XML first."
            ),
        ) from e
    except OSError as e:
        raise HTTPException(status_code=400, detail=f"Cannot read file: {e}") from e
    except IntegrityError as e:
        # The loader's subtractive cleanup hit a foreign-key constraint while
        # deleting an objective that is still referenced (baseline / assessment
        # / evidence / POA&M). The loader now guards against the empty-match
        # case that caused this, but surface a clean 409 rather than a bare 500
        # (which also drops CORS headers and shows up as a misleading CORS
        # error in the browser console).
        s.rollback()
        raise HTTPException(
            status_code=409,
            detail=(
                "CCI load aborted to protect referenced objectives "
                "(in-flight assessments/baselines depend on them). "
                f"Database integrity error: {e.orig}"
            ),
        ) from e
    return {
        "total_ccis": result.cci_items_in_xml,
        "inserted": result.objectives_created,
        "updated": result.objectives_updated,
        "skipped": result.cci_items_unmatched + result.cci_items_no_nist_ref,
        "deprecated": result.cci_items_deprecated,
    }


class CrosswalkRequest(BaseModel):
    from_framework_id: int
    to_framework_id: int
    source_label: str = "auto-id-match"


@router.post("/crosswalk/auto")
def build_auto_crosswalk(
    req: CrosswalkRequest, s: Session = Depends(get_session)
) -> dict:
    """Auto-build a control-level crosswalk by matching ``control_id``.

    Most NIST 800-53 rev4 controls map 1:1 to rev5 by identifier. Controls
    only present in one revision (e.g. rev5's PT/SR families) come back in
    ``unmapped_from`` or ``unmapped_to`` for manual review.
    """
    try:
        result = load_id_match_crosswalk(
            s,
            from_framework_id=req.from_framework_id,
            to_framework_id=req.to_framework_id,
            source_label=req.source_label,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {
        "from_framework_id": result.from_framework_id,
        "to_framework_id": result.to_framework_id,
        "pairs_created": result.pairs_created,
        "pairs_already_present": result.pairs_already_present,
        "unmapped_from_count": len(result.unmapped_from),
        "unmapped_to_count": len(result.unmapped_to),
        "unmapped_from_sample": result.unmapped_from[:20],
        "unmapped_to_sample": result.unmapped_to[:20],
    }


@router.get("/requirement-sources")
def list_requirement_sources(s: Session = Depends(get_session)) -> list[dict]:
    rows = s.exec(select(RequirementSource)).all()
    out: list[dict] = []
    for r in rows:
        map_count = s.exec(
            select(func.count(RequirementMap.id)).where(
                RequirementMap.requirement_source_id == r.id  # type: ignore[arg-type]
            )
        ).one()
        out.append(
            {
                "id": r.id,
                "name": r.name,
                "path": r.path,
                "framework_id": r.framework_id,
                "loaded_at": iso_utc(r.loaded_at),
                "map_count": int(map_count or 0),
            }
        )
    return out


@router.delete("/requirement-sources/{source_id}")
def delete_requirement_source(
    source_id: int, s: Session = Depends(get_session)
) -> dict:
    """Remove a program-controls overlay and all of its requirement maps.

    Destructive: every ``RequirementMap`` pointing at this source is deleted
    too (the cascade is manual because we don't declare ON DELETE CASCADE in
    SQLModel). The 800-53 Objective rows the maps pointed at stay put —
    those are framework-owned, not overlay-owned. Workbook status writes are
    unaffected; this only removes the "which program requirements drive
    this CCI" join data.

    Idempotent on the missing-id path: 404 only if the row truly doesn't
    exist; deleting twice in a row from a stale UI returns 404 cleanly.
    """
    source = s.get(RequirementSource, source_id)
    if source is None:
        raise HTTPException(
            status_code=404, detail=f"requirement source {source_id} not found"
        )

    # Cascade — the loader does the same on upsert, mirror that pattern.
    existing_maps = s.exec(
        select(RequirementMap).where(
            RequirementMap.requirement_source_id == source_id  # type: ignore[arg-type]
        )
    ).all()
    for m in existing_maps:
        s.delete(m)
    s.delete(source)
    s.commit()
    return {
        "deleted_source_id": source_id,
        "name": source.name,
        "maps_removed": len(existing_maps),
    }
