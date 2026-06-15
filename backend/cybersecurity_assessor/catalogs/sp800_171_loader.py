"""NIST SP 800-171 Revision 3 OSCAL JSON catalog loader.

Loads the official NIST SP 800-171 r3 OSCAL JSON catalog and writes a root
``Framework`` row plus one ``Control`` row per security requirement.

Mirrors :mod:`catalogs.oscal_loader` (the 800-53 root loader) exactly:
identical resolution order (explicit path -> cache -> download/bundled ->
network-fail fallback) and the same recursive statement-prose flattening.

A note on Objectives
--------------------
The NIST 800-171 OSCAL catalog does NOT publish CCIs -- those are a DoD
construct. 800-171 r3 expresses each requirement's sub-items as OSCAL
"item" parts under the "statement" part; we flatten those into the
Control.statement prose rather than minting Objective rows. This loader
intentionally creates zero Objective rows.

Structure of the catalog
-------------------------
``catalog.groups[]`` -- 17 families (class="family", id like
"SP_800_171_03.01", title like "Access Control"). Each family carries
``controls[]`` -- the security requirements (class="requirement", id like
"SP_800_171_03.01.01", title like "Account Management"). Withdrawn
requirements (status=withdrawn, e.g. 03.01.13) are skipped — they're empty
shells whose title is just the bare control id and aren't assessable.
Requirements are flat (no nested requirement groups). Each requirement's
``parts[]`` includes a "statement" part whose prose lives in nested "item"
sub-parts.

control_id convention
---------------------
The verbose OSCAL id "SP_800_171_03.01.01" is normalized to the canonical
dotted requirement number "03.01.01" -- that's how assessors cite 800-171
requirements.

family convention
-----------------
``Control.family`` stores the family TITLE verbatim (e.g. "Access Control").
This is the simplest defensible choice: it needs no abbreviation table and
matches the human-readable family names in the catalog.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from sqlmodel import Session, select

from .. import config as cfg
from ..models import Control, Framework

# Stable raw GitHub URL maintained by NIST (download branch).
OSCAL_800_171R3_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json"
)

# Catalog filename -- shared by cache + bundled copy.
_CATALOG_FILENAME = "NIST_SP800-171_rev3_catalog.json"

# Verbose OSCAL id prefix stripped to reach the canonical requirement number.
_OSCAL_ID_PREFIX = "SP_800_171_"

# Framework metadata. ``framework_id`` is the canonical scope key (matches the
# convention used by oscal_loader's "NIST-800-53r5" etc.).
_FRAMEWORK_NAME = "NIST SP 800-171"
_FRAMEWORK_VERSION = "Rev 3"
_FRAMEWORK_ID = "NIST-800-171r3"


def _cache_path() -> Path:
    return cfg.config_dir() / "catalogs" / _CATALOG_FILENAME


def _bundled_path() -> Path:
    """Path to the catalog JSON shipped inside the wheel/source tree.

    Used as the offline fallback when the network is unreachable on a fresh
    install. Refreshing the bundled copy is a release-engineering step -- at
    runtime we only read it.
    """
    return Path(__file__).parent / "_bundled" / _CATALOG_FILENAME


def _download_catalog(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310
        data = resp.read()
    dest.write_bytes(data)


def _load_json(path: Path | None, *, offline: bool = False) -> dict[str, Any]:
    """Load the OSCAL catalog JSON.

    Resolution order (identical to oscal_loader._load_json):
      1. Explicit ``path`` -- caller-supplied file (errors if missing).
      2. Local cache under ``~/.cybersecurity-assessor/catalogs/`` -- written
         on first successful download.
      3. If ``offline`` is True: go straight to the wheel-bundled copy.
      4. Otherwise download into the cache; on network failure fall back to the
         bundled copy WITHOUT caching it (so the next launch retries the
         download once connectivity returns).

    Read with encoding="utf-8" explicitly -- the Windows cp1252 default
    crashes on byte 0x9d present in this catalog's prose.
    """
    if path is not None:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"OSCAL catalog not found: {p}")
        return json.loads(p.read_text(encoding="utf-8"))

    cached = _cache_path()
    if cached.exists():
        return json.loads(cached.read_text(encoding="utf-8"))

    bundled = _bundled_path()
    if offline:
        if not bundled.exists():
            raise FileNotFoundError(
                f"Offline mode requested but no bundled catalog at {bundled}"
            )
        return json.loads(bundled.read_text(encoding="utf-8"))

    try:
        _download_catalog(OSCAL_800_171R3_URL, cached)
        return json.loads(cached.read_text(encoding="utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        if bundled.exists():
            # Network unreachable on a fresh install -- use the bundled copy
            # but do NOT write it into the cache, so the next launch retries
            # the download and picks up upstream fixes once connectivity
            # returns.
            return json.loads(bundled.read_text(encoding="utf-8"))
        raise RuntimeError(
            f"Could not download SP 800-171 r3 catalog ({exc}) and no bundled "
            f"copy at {bundled}"
        ) from exc


def _statement_text(requirement: dict[str, Any]) -> str | None:
    """Pull the human-readable 'statement' part out of an OSCAL requirement."""
    for part in requirement.get("parts", []) or []:
        if part.get("name") == "statement":
            return _flatten_part_prose(part) or None
    return None


def _flatten_part_prose(part: dict[str, Any]) -> str:
    """Recursively concatenate prose from a part and its sub-parts.

    800-171 r3 puts the requirement text in nested "item" sub-parts under the
    "statement" part (the statement part itself often has no direct prose), so
    the recursion is what actually pulls the requirement body.
    """
    chunks: list[str] = []
    if prose := part.get("prose"):
        chunks.append(prose)
    for child in part.get("parts", []) or []:
        chunks.append(_flatten_part_prose(child))
    return "\n".join(c for c in chunks if c)


def _normalize_control_id(oscal_id: str) -> str:
    """'SP_800_171_03.01.01' -> '03.01.01' (canonical requirement number)."""
    if oscal_id.startswith(_OSCAL_ID_PREFIX):
        return oscal_id[len(_OSCAL_ID_PREFIX):]
    return oscal_id


def _is_withdrawn(requirement: dict[str, Any]) -> bool:
    """True if NIST has withdrawn this requirement.

    Withdrawn r3 requirements (e.g. 03.01.13, incorporated into 03.13.08)
    are published as empty shells: a ``status=withdrawn`` prop, the bare
    requirement number as their ``title`` (no descriptive name), no
    ``parts``. Loading them inflated the catalog count and surfaced bogus
    rows whose title was just the control id. They are not assessable, so
    we skip them entirely.
    """
    for prop in requirement.get("props", []) or []:
        if prop.get("name") == "status" and prop.get("value") == "withdrawn":
            return True
    return False


def load_sp800_171_catalog(
    session: Session,
    *,
    path: str | Path | None = None,
    offline: bool = False,
) -> Framework:
    """Idempotently load NIST SP 800-171 Rev 3 from OSCAL JSON.

    Args:
        session: an active SQLModel Session.
        path: optional override -- a local OSCAL JSON file. If omitted,
            resolves cache -> download (or bundled if offline) just like
            :func:`oscal_loader.load_oscal_catalog`.
        offline: if True, never attempt the network -- go straight to the
            wheel-bundled catalog. Default False.

    Returns:
        The Framework row (created or updated). 130 Control rows are written;
        no Objective rows.
    """
    doc = _load_json(Path(path) if path else None, offline=offline)
    catalog = doc.get("catalog")
    if catalog is None:
        raise ValueError("Document is not an OSCAL catalog (missing 'catalog' key)")

    # --- Framework upsert (idempotent by name + version) --------------------
    framework = session.exec(
        select(Framework).where(
            Framework.name == _FRAMEWORK_NAME,
            Framework.version == _FRAMEWORK_VERSION,
        )
    ).first()
    if framework is None:
        framework = Framework(
            name=_FRAMEWORK_NAME,
            version=_FRAMEWORK_VERSION,
            framework_id=_FRAMEWORK_ID,
            oscal_uri=OSCAL_800_171R3_URL,
            parent_framework_id=None,
        )
        session.add(framework)
        session.commit()
        session.refresh(framework)
    elif framework.framework_id is None:
        # Idempotent self-heal for a pre-framework_id row.
        framework.framework_id = _FRAMEWORK_ID
        session.add(framework)
        session.commit()
        session.refresh(framework)

    # --- Walk families -> requirements (idempotent by control_id) -----------
    existing_controls = {
        c.control_id: c
        for c in session.exec(
            select(Control).where(Control.framework_id == framework.id)
        ).all()
    }

    # Track withdrawn control_ids so a re-run prunes any shells a prior
    # (pre-filter) load left behind in the DB.
    withdrawn_ids: set[str] = set()

    for family in catalog.get("groups", []) or []:
        if family.get("class") != "family":
            continue
        family_title = family.get("title", "")
        for req in family.get("controls", []) or []:
            if req.get("class") != "requirement":
                continue
            control_id = _normalize_control_id(req["id"])
            # Skip withdrawn requirements — they're empty shells whose title
            # is just the bare control id and aren't assessable (see helper).
            if _is_withdrawn(req):
                withdrawn_ids.add(control_id)
                continue
            title_text = req.get("title", "")
            statement = _statement_text(req)

            row = existing_controls.get(control_id)
            if row is None:
                row = Control(
                    framework_id=framework.id,  # type: ignore[arg-type]
                    control_id=control_id,
                    title=title_text,
                    family=family_title,
                    statement=statement,
                )
                session.add(row)
            else:
                row.title = title_text
                row.family = family_title
                row.statement = statement
                session.add(row)

    # Prune withdrawn shells inserted by an earlier load.
    for control_id in withdrawn_ids:
        stale = existing_controls.get(control_id)
        if stale is not None:
            session.delete(stale)

    session.commit()
    session.refresh(framework)
    return framework
