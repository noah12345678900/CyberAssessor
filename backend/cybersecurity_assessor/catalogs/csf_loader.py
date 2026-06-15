"""NIST Cybersecurity Framework (CSF) 2.0 root-catalog loader.

Loads the official NIST CSF 2.0 OSCAL JSON catalog and writes ``Framework`` +
``Control`` rows. This is a *root* catalog (``parent_framework_id`` stays
``None``), mirroring :mod:`oscal_loader` for NIST 800-53.

CSF 2.0 structure
-----------------
The OSCAL catalog nests three levels of ``groups``/``controls``:

    catalog.groups[]            -> 6 Functions   (class="function", id "GV"...)
      .controls[]               -> Categories     (class="category",   id "GV.OC")
        .controls[]             -> Subcategories  (class="subcategory", id "GV.OC-01")

The **subcategory** is the assessable unit (185 of them). For each subcategory
we write one ``Control`` row:

    control_id = subcategory id     ("GV.OC-01")
    title      = subcategory title  (often just the id repeated -- stored as-is)
    family     = the FUNCTION id    ("GV") -- groups the grid by function
    statement  = flattened prose of the part with name=="statement"

A note on Objectives (CCIs)
---------------------------
CSF 2.0 has no CCIs or assessment objectives -- the subcategory *is* the leaf.
So this loader never creates ``Objective`` rows (parity with how the 800-53
OSCAL catalog leaves CCIs to the DISA-sourced workbook).
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

# Stable raw GitHub URL maintained by NIST.
CSF_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/CSF/v2.0/json/NIST_CSF_v2.0_catalog.json"
)

# Catalog-row metadata. ``framework_id`` is the canonical framework-scope key
# (see models.Framework docstring); kept stable like "NIST-800-53r5".
_FRAMEWORK_NAME = "NIST Cybersecurity Framework"
_FRAMEWORK_VERSION = "2.0"
_FRAMEWORK_ID = "NIST-CSF-2.0"

_CATALOG_FILENAME = "NIST_CSF_v2.0_catalog.json"


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
    """Load the CSF OSCAL catalog JSON.

    Resolution order (identical to :func:`oscal_loader._load_json`):
      1. Explicit ``path`` -- caller-supplied file (errors if missing).
      2. Local cache under ``~/.cybersecurity-assessor/catalogs/`` -- written
         on first successful download.
      3. If ``offline`` or the download fails: fall back to the wheel-bundled
         copy under ``catalogs/_bundled/``. On network failure the bundled
         copy is read but NOT written to the cache, so the next launch retries
         the download.

    Files are read with explicit ``encoding="utf-8"`` -- the CSF catalog
    contains bytes (e.g. 0x9d) that crash the Windows default cp1252 codec.
    """
    if path is not None:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"CSF catalog not found: {p}")
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
        _download_catalog(CSF_URL, cached)
        return json.loads(cached.read_text(encoding="utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        if bundled.exists():
            # Network unreachable on a fresh install -- use the bundled copy
            # but do NOT write it into the cache, so the next launch retries
            # the download and picks up upstream fixes once connectivity
            # returns.
            return json.loads(bundled.read_text(encoding="utf-8"))
        raise RuntimeError(
            f"Could not download CSF catalog ({exc}) and no bundled copy at {bundled}"
        ) from exc


def _statement_text(node: dict[str, Any]) -> str | None:
    """Pull the human-readable 'statement' part out of an OSCAL node."""
    for part in node.get("parts", []) or []:
        if part.get("name") == "statement":
            return _flatten_part_prose(part)
    return None


def _flatten_part_prose(part: dict[str, Any]) -> str:
    """Recursively concatenate prose from a part and its sub-parts."""
    chunks: list[str] = []
    if prose := part.get("prose"):
        chunks.append(prose)
    for child in part.get("parts", []) or []:
        chunks.append(_flatten_part_prose(child))
    return "\n".join(c for c in chunks if c)


def _iter_subcategories(catalog: dict[str, Any]):
    """Yield (function_id, subcategory_node) for every CSF subcategory.

    Walks functions -> categories -> subcategories. Only nodes explicitly
    classed ``subcategory`` are yielded; function and category nodes are
    structural and never become Control rows.
    """
    for function in catalog.get("groups", []) or []:
        function_id = function.get("id")
        for category in function.get("controls", []) or []:
            for sub in category.get("controls", []) or []:
                if sub.get("class") != "subcategory":
                    continue
                if "id" not in sub:
                    continue
                yield function_id, sub


def load_csf_catalog(
    session: Session,
    *,
    path: str | Path | None = None,
    offline: bool = False,
) -> Framework:
    """Idempotently load NIST CSF 2.0 from the OSCAL JSON catalog.

    Args:
        session: an active SQLModel Session.
        path: optional override -- a local CSF OSCAL JSON file. If omitted,
            resolves via cache -> download -> bundled (see :func:`_load_json`).
        offline: if True, never attempt the network -- go straight to the
            wheel-bundled catalog. Default False.

    Returns:
        The Framework row (created or updated). This is a root catalog;
        ``parent_framework_id`` is left ``None`` and ``enabled`` uses the
        model default (True).
    """
    doc = _load_json(Path(path) if path else None, offline=offline)
    catalog = doc.get("catalog")
    if catalog is None:
        raise ValueError("Document is not an OSCAL catalog (missing 'catalog' key)")

    # --- Framework upsert by (name, version) -------------------------------
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
            oscal_uri=CSF_URL,
            # parent_framework_id stays None -- CSF 2.0 is a root catalog.
            # enabled is left at the model default (True).
        )
        session.add(framework)
        session.commit()
        session.refresh(framework)
    else:
        # Idempotent self-heal of the canonical identifier / uri in case an
        # older row was created before these were set.
        changed = False
        if framework.framework_id != _FRAMEWORK_ID:
            framework.framework_id = _FRAMEWORK_ID
            changed = True
        if framework.oscal_uri != CSF_URL:
            framework.oscal_uri = CSF_URL
            changed = True
        if changed:
            session.add(framework)
            session.commit()
            session.refresh(framework)

    # --- Walk functions -> categories -> subcategories ---------------------
    existing_controls = {
        c.control_id: c
        for c in session.exec(
            select(Control).where(Control.framework_id == framework.id)
        ).all()
    }

    for function_id, sub in _iter_subcategories(catalog):
        control_id = sub["id"]
        title_text = sub.get("title", control_id)
        family = (function_id or "").upper()
        statement = _statement_text(sub)

        row = existing_controls.get(control_id)
        if row is None:
            row = Control(
                framework_id=framework.id,  # type: ignore[arg-type]
                control_id=control_id,
                title=title_text,
                family=family,
                statement=statement,
            )
            session.add(row)
        else:
            row.title = title_text
            row.family = family
            row.statement = statement
            session.add(row)

    session.commit()
    session.refresh(framework)
    return framework
