"""FedRAMP Rev 5 OSCAL profile loader.

Sister of :mod:`oscal_loader`. Where the OSCAL *catalog* loader writes the
flat NIST 800-53 control set onto a root Framework, this loader reads an
OSCAL *profile* — FedRAMP HIGH / MODERATE / LOW / LI-SaaS — and projects
it as a **child Framework** of an already-loaded 800-53 r5 Framework.

What "projecting a profile" means here
--------------------------------------
1. Create (or refresh) a child Framework row with
   ``parent_framework_id = <r5 id>``. The child carries no Control rows
   of its own except shadow rows for controls the profile alters with
   FedRAMP-specific prose.
2. Walk ``profile.imports[].include-controls[].with-ids[]`` and write a
   ``BaselineMembership(framework_id=child.id, control_id=...)`` row per
   selected control. The catalog endpoint's membership-aware merge
   already filters inherited parent rows through this table, so the
   ~410 HIGH / 323 MOD / 156 LOW / ~125 LI-SaaS subsets fall out for
   free.
3. Walk ``profile.modify.alters[].adds[]`` via :mod:`baselines.oscal_adds`
   and, for every alter that carries ``parts[]`` (prose), upsert a
   *shadow* Control row on the child Framework whose statement is the
   parent's statement plus a "### FedRAMP Additions" block. The
   ``synthesize_statement`` output is fully derived from the source, so
   reloading the profile produces a byte-equal statement — idempotency
   without needing a UNIQUE constraint.

Why this is **not** a :class:`BaselineSource`
---------------------------------------------
That Protocol is for ingesting a program workbook (CCIS / CRM / Other
xlsx) into a Baseline + BaselineObjective set. A FedRAMP profile is
upstream of that — it's catalog data published by the framework owner,
slotting alongside ``load_oscal_catalog``. Keeping the two layers
separate means a user can load FedRAMP HIGH without owning a workbook,
and a workbook can be bound to either the raw 800-53 r5 Framework or a
FedRAMP child without the catalog layer caring which is picked.

Why bundled + online with the same resolution order as oscal_loader
-------------------------------------------------------------------
First-launch UX should work offline (a fresh install on a disconnected
workstation must still be able to load FedRAMP HIGH), but the bundled
copies will lag the upstream GSA publication, so when a network is
available we prefer the cached/downloaded copy. The resolution order
(explicit path → cache → download → bundled) mirrors
:func:`oscal_loader._load_json` exactly — same reasoning, same failure
modes.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlmodel import Session, select

from .. import config as cfg
from ..baselines.oscal_adds import (
    extract_alters,
    partition_alter,
    synthesize_statement,
)
from ..models import BaselineMembership, Control, Framework

# Canonical FedRAMP Rev 5 profiles. The original GSA/fedramp-automation
# repo was retired; OSCAL-Foundation/fedramp-resources is now the
# upstream mirror that GSA points at. The filename convention uses
# underscore-separated tokens for the trailing ``baseline_profile``
# suffix; the level token preserves its original casing (LI-SaaS keeps
# the lowercase 'a').
_FEDRAMP_PROFILE_FILENAMES: dict[str, str] = {
    "HIGH": "FedRAMP_rev5_HIGH-baseline_profile.json",
    "MODERATE": "FedRAMP_rev5_MODERATE-baseline_profile.json",
    "LOW": "FedRAMP_rev5_LOW-baseline_profile.json",
    "LI-SAAS": "FedRAMP_rev5_LI-SaaS-baseline_profile.json",
}

_FEDRAMP_BASE_URL = (
    "https://raw.githubusercontent.com/OSCAL-Foundation/"
    "fedramp-resources/main/baselines/rev5/json/"
)

FEDRAMP_PROFILE_URLS: dict[str, str] = {
    level: _FEDRAMP_BASE_URL + fname
    for level, fname in _FEDRAMP_PROFILE_FILENAMES.items()
}

# Human-readable Framework.name for each level — used both for the
# upsert lookup and the picker label. Kept in one place so renames stay
# consistent.
_FRAMEWORK_NAMES: dict[str, str] = {
    "HIGH": "FedRAMP Rev 5 HIGH",
    "MODERATE": "FedRAMP Rev 5 MODERATE",
    "LOW": "FedRAMP Rev 5 LOW",
    "LI-SAAS": "FedRAMP Rev 5 LI-SaaS",
}

# Canonical short Framework.framework_id for each level — the framework-scope
# key on OdpAssignment / FrameworkEquivalence. Stable, hyphenated, mirrors the
# pattern used for base catalogs ("NIST-800-53r5"). See models.Framework
# docstring for the full contract.
_FRAMEWORK_IDS: dict[str, str] = {
    "HIGH": "FedRAMP-r5-HIGH",
    "MODERATE": "FedRAMP-r5-MODERATE",
    "LOW": "FedRAMP-r5-LOW",
    "LI-SAAS": "FedRAMP-r5-LI-SAAS",
}

# Fallback version string when the profile metadata omits ``version``.
# FedRAMP publishes profiles under the same Rev 5 umbrella so the value
# is stable enough to hard-code as a floor.
_DEFAULT_VERSION = "Rev 5"


def _normalize_level(level: str) -> str:
    """Accept ``high``, ``High``, ``LI-SaaS``, ``li-saas`` and canonicalize.

    The route layer accepts user-typed casing; the loader's internal
    dicts key on the upper-case form. ``LI-SAAS`` collapses the FedRAMP
    convention "LI-SaaS" so callers don't have to remember the unusual
    casing.
    """
    up = level.strip().upper()
    if up not in _FEDRAMP_PROFILE_FILENAMES:
        raise ValueError(
            f"Unsupported FedRAMP level: {level!r} "
            f"(expected one of {sorted(_FEDRAMP_PROFILE_FILENAMES)})"
        )
    return up


def _cache_path(level: str) -> Path:
    """Local cache path under the user's config dir.

    Co-located with the parent OSCAL catalogs so a single cleanup of
    ``~/.cybersecurity-assessor/catalogs/`` resets everything.
    """
    return cfg.config_dir() / "catalogs" / _FEDRAMP_PROFILE_FILENAMES[level]


def _bundled_path(level: str) -> Path:
    """Wheel-bundled fallback path.

    The bundled copy is the floor (offline-first install must work);
    upstream updates land via the cache/download path on the next online
    launch. Refreshing the bundled copy is a release-engineering step.
    """
    return Path(__file__).parent / "_bundled" / _FEDRAMP_PROFILE_FILENAMES[level]


def _download_profile(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310
        data = resp.read()
    dest.write_bytes(data)


def _load_profile_json(
    path: Path | None, level: str, *, offline: bool = False
) -> dict[str, Any]:
    """Resolve and parse a FedRAMP profile JSON.

    Resolution order — mirrors :func:`oscal_loader._load_json`:

      1. Explicit ``path`` — caller-supplied file (errors if missing).
      2. Local cache under ``~/.cybersecurity-assessor/catalogs/``.
      3. ``offline=True`` → bundled copy (errors if missing); otherwise
         try the GSA download and fall back to the bundled copy on
         network failure. A network-failure fallback does NOT write the
         bundled copy into the cache, so the next launch retries the
         download and picks up upstream fixes once connectivity returns.
    """
    if path is not None:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"FedRAMP profile not found: {p}")
        return json.loads(p.read_text(encoding="utf-8"))

    cached = _cache_path(level)
    if cached.exists():
        return json.loads(cached.read_text(encoding="utf-8"))

    bundled = _bundled_path(level)
    if offline:
        if not bundled.exists():
            raise FileNotFoundError(
                f"Offline mode requested but no bundled FedRAMP {level} "
                f"profile at {bundled}"
            )
        return json.loads(bundled.read_text(encoding="utf-8"))

    try:
        _download_profile(FEDRAMP_PROFILE_URLS[level], cached)
        return json.loads(cached.read_text(encoding="utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        if bundled.exists():
            return json.loads(bundled.read_text(encoding="utf-8"))
        raise RuntimeError(
            f"Could not download FedRAMP {level} profile ({exc}) and no "
            f"bundled copy at {bundled}"
        ) from exc


def _control_id_from_param(param_id: str) -> str | None:
    """Pull the owning control id out of an OSCAL ``param-id``.

    OSCAL parameter ids carry their parent control id as a prefix:

      ``ac-01_odp.05`` → ``ac-1``    (FedRAMP zero-padded family number)
      ``ac-2.3_prm_1`` → ``ac-2.3``  (enhancement)
      ``au-3_prm_1``   → ``au-3``

    FedRAMP profiles zero-pad the family-number segment (``ac-01``) while
    the NIST 800-53 catalog stores plain ``ac-1``; we strip the padding
    here so the projected ``param_id`` lookup against ``Control`` rows
    hits a real row. Returns ``None`` for ids that don't look
    control-scoped (very rare — well-formed FedRAMP profiles never emit
    these).
    """
    head, sep, _ = param_id.partition("_")
    if not sep or not head:
        return None
    fam, dash, rest = head.partition("-")
    if not dash or not fam:
        return None
    # rest may be "01" (base) or "01.03" (enhancement). Strip leading
    # zeros segment-by-segment so we converge on the catalog convention.
    normalized_segs: list[str] = []
    for seg in rest.split("."):
        normalized_segs.append(str(int(seg)) if seg.isdigit() else seg)
    return f"{fam.lower()}-{'.'.join(normalized_segs)}"


def _extract_param_value(param: dict[str, Any]) -> str | None:
    """Pull a human-readable value out of an OSCAL ``set-parameters[]`` entry.

    Two shapes exist in the wild:

    - ``values: ["at least annually"]`` — older / direct override form.
    - ``constraints: [{"description": "at least annually"}]`` — FedRAMP
      Rev 5's preferred shape (the override is phrased as a constraint
      so downstream tools can render it as guidance, not a hard literal).

    We prefer ``values`` when present (it's the more literal answer); fall
    back to joining all ``constraints[].description`` strings. Returns
    ``None`` when neither shape carries usable text.
    """
    vals = param.get("values")
    if isinstance(vals, list) and vals:
        return "; ".join(str(v) for v in vals if v)
    constraints = param.get("constraints")
    if isinstance(constraints, list):
        descs = [
            c["description"]
            for c in constraints
            if isinstance(c, dict) and isinstance(c.get("description"), str)
        ]
        if descs:
            return "; ".join(descs)
    return None


def _collect_set_parameters(
    profile_doc: dict[str, Any],
) -> dict[str, dict[str, str]]:
    """Group ``profile.modify.set-parameters[]`` by owning control id.

    Returns ``{control_id: {param_id: value}}`` with normalized lowercase
    control ids. Params whose value can't be extracted are silently
    dropped (no useful override to project). Params whose owning control
    id can't be inferred are dropped likewise — they'd have no Control
    row to attach to.
    """
    out: dict[str, dict[str, str]] = {}
    profile = profile_doc.get("profile", {}) or {}
    modify = profile.get("modify", {}) or {}
    for sp in modify.get("set-parameters", []) or []:
        if not isinstance(sp, dict):
            continue
        param_id = sp.get("param-id")
        if not isinstance(param_id, str) or not param_id:
            continue
        cid = _control_id_from_param(param_id)
        if cid is None:
            continue
        value = _extract_param_value(sp)
        if value is None:
            continue
        out.setdefault(cid, {})[param_id] = value
    return out


def _collect_include_ids(profile_doc: dict[str, Any]) -> list[str]:
    """Pull all ``with-ids`` strings out of every ``include-controls`` block.

    OSCAL profiles can have multiple ``imports[]`` (each pointing at a
    different catalog) and multiple ``include-controls[]`` inside each.
    We flatten across all of them — the lookup against the parent
    catalog filters out anything that isn't a real Control.
    """
    out: list[str] = []
    profile = profile_doc.get("profile", {}) or {}
    for imp in profile.get("imports", []) or []:
        if not isinstance(imp, dict):
            continue
        for inc in imp.get("include-controls", []) or []:
            if not isinstance(inc, dict):
                continue
            for cid in inc.get("with-ids", []) or []:
                if isinstance(cid, str) and cid:
                    out.append(cid.lower())
    return out


@dataclass
class FedrampLoadResult:
    """What :func:`load_fedramp_profile` produced.

    Counts are returned alongside the Framework so the route layer can
    show a toast like "FedRAMP HIGH loaded — 410 controls, 97 with
    FedRAMP additions, 0 unknown" without re-querying the DB.
    """

    framework: Framework
    members_added: int = 0
    """Number of ``BaselineMembership`` rows persisted for the child."""
    controls_synthesized: int = 0
    """Number of shadow Control rows on the child carrying merged
    FedRAMP-Additions prose."""
    parameters_loaded: int = 0
    """Number of shadow Control rows whose ``parameter_overrides_json``
    column was populated from ``profile.modify.set-parameters[]``. May
    overlap with ``controls_synthesized`` (a single shadow can carry both
    Additions prose AND ODP overrides) or stand alone (a control with
    only set-parameters gets a shadow whose statement is the parent's
    verbatim text)."""
    unknown_control_ids: list[str] = field(default_factory=list)
    """Control ids the profile referenced that the parent catalog does
    not have (e.g. a profile referencing a withdrawn or unloaded
    control). Surfaced but never persisted as membership."""


def load_fedramp_profile(
    session: Session,
    *,
    level: str,
    parent_framework_id: int,
    path: str | Path | None = None,
    offline: bool = False,
) -> FedrampLoadResult:
    """Idempotently load a FedRAMP Rev 5 baseline profile.

    Args:
        session: active SQLModel session.
        level: ``"HIGH"``, ``"MODERATE"``, ``"LOW"``, or ``"LI-SAAS"``
            (case-insensitive).
        parent_framework_id: the loaded 800-53 r5 Framework id. Profiles
            are projected as child Frameworks of this row.
        path: optional override pointing at a local profile JSON file.
        offline: if True, never attempt the network — go straight to the
            bundled copy.

    Returns:
        :class:`FedrampLoadResult` with the upserted Framework plus
        load counts.

    Raises:
        ValueError: unknown ``level`` or missing/invalid parent.
        FileNotFoundError: explicit path doesn't exist, or offline=True
            and no bundled copy.
        RuntimeError: network failed and no bundled fallback.
    """
    canonical = _normalize_level(level)

    parent = session.get(Framework, parent_framework_id)
    if parent is None:
        raise ValueError(
            f"Parent Framework id={parent_framework_id} not found — load "
            f"NIST 800-53 Rev 5 before loading a FedRAMP profile."
        )

    doc = _load_profile_json(Path(path) if path else None, canonical, offline=offline)
    profile = doc.get("profile")
    if profile is None:
        raise ValueError(
            "Document is not an OSCAL profile (missing 'profile' key)"
        )

    metadata = profile.get("metadata", {}) or {}
    framework_name = _FRAMEWORK_NAMES[canonical]
    framework_version = metadata.get("version") or _DEFAULT_VERSION

    # --- Child Framework upsert --------------------------------------------
    child = session.exec(
        select(Framework).where(
            Framework.name == framework_name,
            Framework.parent_framework_id == parent_framework_id,
        )
    ).first()
    if child is None:
        child = Framework(
            name=framework_name,
            version=framework_version,
            # Canonical framework_id keyed off the level (e.g. "FedRAMP-r5-HIGH")
            # for the OdpAssignment / FrameworkEquivalence framework-scope key.
            framework_id=_FRAMEWORK_IDS[canonical],
            oscal_uri=FEDRAMP_PROFILE_URLS[canonical],
            parent_framework_id=parent_framework_id,
        )
        session.add(child)
        session.commit()
        session.refresh(child)
    elif child.framework_id is None:
        # Idempotent self-heal for pre-framework_id installs whose FedRAMP
        # rows the NIST-only additive backfill couldn't reach.
        child.framework_id = _FRAMEWORK_IDS[canonical]
        session.add(child)
        session.commit()
        session.refresh(child)
    else:
        # Refresh metadata in case the upstream profile was republished
        # with a bumped version or moved its canonical URL.
        child.version = framework_version
        child.oscal_uri = FEDRAMP_PROFILE_URLS[canonical]
        session.add(child)
        session.commit()
        session.refresh(child)

    # --- Membership upsert -------------------------------------------------
    desired_ids = set(_collect_include_ids(doc))

    # Filter out ids the parent catalog doesn't carry — typically a
    # withdrawn enhancement or a profile published against a catalog
    # revision newer than what's loaded. We track these so the route
    # can surface them but never write them as membership (lookups would
    # 404 against an absent Control row).
    known_parent_ids: set[str] = set(
        session.exec(
            select(Control.control_id).where(Control.framework_id == parent_framework_id)
        ).all()
    )
    valid_ids = desired_ids & known_parent_ids
    unknown_ids = sorted(desired_ids - known_parent_ids)

    existing_members = {
        m.control_id: m
        for m in session.exec(
            select(BaselineMembership).where(
                BaselineMembership.framework_id == child.id
            )
        ).all()
    }

    # Add new memberships.
    for cid in valid_ids:
        if cid not in existing_members:
            session.add(
                BaselineMembership(framework_id=child.id, control_id=cid)  # type: ignore[arg-type]
            )

    # Remove memberships no longer in the profile (re-runs converge).
    for cid, row in existing_members.items():
        if cid not in valid_ids:
            session.delete(row)

    session.commit()

    # --- Shadow Controls from modify.alters[] ------------------------------
    # Build a parent statement lookup once so the alters walk doesn't
    # re-query for every altered control.
    #
    # ARCHITECTURE INVARIANT — do NOT call ``str.replace`` (or any other
    # mutation) on the parent ``Control.statement`` text on its way into
    # the shadow row. ODP placeholders ({$37$}, ac-XX_odp.NN) MUST reach
    # the shadow Control verbatim so the render layer can resolve them
    # per (framework_version, control_id) at read time. See
    # ``memory/project_odp_architecture.md`` — principle 1, "Templates
    # stay templates". Profile-level overrides belong in the
    # ``odp_assignment`` table, not baked into the catalog statement.
    parent_statements: dict[str, str | None] = {
        cid: stmt
        for (cid, stmt) in session.exec(
            select(Control.control_id, Control.statement).where(
                Control.framework_id == parent_framework_id
            )
        ).all()
    }

    existing_shadows = {
        c.control_id: c
        for c in session.exec(
            select(Control).where(Control.framework_id == child.id)
        ).all()
    }

    desired_shadow_ids: set[str] = set()
    for alter in extract_alters(doc):
        target_id = alter.get("control-id")
        if not isinstance(target_id, str) or not target_id:
            continue
        target_id = target_id.lower()
        part_adds, _prop_only = partition_alter(alter)
        if not part_adds:
            # prop-only adds carry method/responsibility metadata only;
            # nothing to render as a shadow Control statement.
            continue
        if target_id not in known_parent_ids:
            # Profile alters a control the parent doesn't carry — silently
            # skip; it'll show up in unknown_control_ids if the same id
            # was also in the include set, which is the user-visible
            # signal that the profile references something missing.
            continue

        inherited = parent_statements.get(target_id)
        statement = synthesize_statement(target_id, part_adds, inherited)

        # Carry over the parent's title/family so the shadow row renders
        # with sensible labels even when the consumer hits it directly
        # (not via the parent-walk merge).
        parent_row = session.exec(
            select(Control).where(
                Control.framework_id == parent_framework_id,
                Control.control_id == target_id,
            )
        ).first()
        title = parent_row.title if parent_row else target_id.upper()
        family = parent_row.family if parent_row else target_id.split("-", 1)[0].upper()

        shadow = existing_shadows.get(target_id)
        if shadow is None:
            shadow = Control(
                framework_id=child.id,  # type: ignore[arg-type]
                control_id=target_id,
                title=title,
                family=family,
                statement=statement,
            )
            session.add(shadow)
            existing_shadows[target_id] = shadow
        else:
            shadow.title = title
            shadow.family = family
            shadow.statement = statement
            session.add(shadow)
        desired_shadow_ids.add(target_id)

    # Flush so any newly-created shadow rows above are visible to the
    # set-parameters pass (which may need to update the same row, not
    # spawn a duplicate).
    session.flush()

    # --- Shadow Controls from modify.set-parameters[] ----------------------
    # FedRAMP's primary contribution at HIGH is parameter values, not
    # prose alters (HIGH has 309 set-params, 0 alters). Project them onto
    # ``Control.parameter_overrides_json`` on the child Framework. A
    # control with set-parameters but no prose alter gets a shadow whose
    # statement is the parent's verbatim text — needed because
    # ``parameter_overrides_json`` lives on the Control row and the
    # parent-walk merge will surface the child row when present.
    params_by_control = _collect_set_parameters(doc)
    desired_param_ids: set[str] = set()
    for cid, params_dict in params_by_control.items():
        if cid not in known_parent_ids:
            # Parameter targets a control the parent catalog doesn't
            # carry — drop silently; consistent with the alters walk.
            continue
        if not params_dict:
            continue
        overrides_json = json.dumps(params_dict, sort_keys=True)
        shadow = existing_shadows.get(cid)
        if shadow is None:
            parent_row = session.exec(
                select(Control).where(
                    Control.framework_id == parent_framework_id,
                    Control.control_id == cid,
                )
            ).first()
            statement = parent_row.statement if parent_row else None
            title = parent_row.title if parent_row else cid.upper()
            family = (
                parent_row.family
                if parent_row
                else cid.split("-", 1)[0].upper()
            )
            shadow = Control(
                framework_id=child.id,  # type: ignore[arg-type]
                control_id=cid,
                title=title,
                family=family,
                statement=statement,
                parameter_overrides_json=overrides_json,
            )
            session.add(shadow)
            existing_shadows[cid] = shadow
        else:
            shadow.parameter_overrides_json = overrides_json
            session.add(shadow)
        desired_param_ids.add(cid)

    # Clear stale overrides from shadows that still exist for prose
    # reasons but no longer carry params (e.g. FedRAMP retracted an ODP
    # between releases). Without this, a re-load would leave a phantom
    # JSON blob attached to the row.
    for cid, row in existing_shadows.items():
        if cid in desired_shadow_ids and cid not in desired_param_ids:
            if row.parameter_overrides_json is not None:
                row.parameter_overrides_json = None
                session.add(row)

    # Drop shadow rows that are no longer altered AND no longer carry
    # parameter overrides (e.g. GSA dropped both an alter and its
    # set-parameter entry between releases). Memberships are unaffected.
    keep_shadow_ids = desired_shadow_ids | desired_param_ids
    for cid, row in list(existing_shadows.items()):
        if cid not in keep_shadow_ids:
            session.delete(row)

    session.commit()
    session.refresh(child)

    return FedrampLoadResult(
        framework=child,
        members_added=len(valid_ids),
        controls_synthesized=len(desired_shadow_ids),
        parameters_loaded=len(desired_param_ids),
        unknown_control_ids=unknown_ids,
    )
