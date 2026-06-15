"""NIST OSCAL JSON catalog loader.

Loads the official NIST SP 800-53 OSCAL JSON catalog (rev4 or rev5) and
writes ``Framework`` + ``Control`` rows.

A note on Objectives (CCIs)
---------------------------
The NIST OSCAL catalog does NOT publish CCIs -- those are a DoD construct
maintained separately by DISA. For 800-53 work the per-CCI assessment
objectives are sourced from the CCIS workbook itself (cols I/J), so the
workbook reader is what populates ``Objective`` rows for this framework.

The OSCAL 800-53A *assessment* catalog (separate file from NIST) does contain
generic assessment objectives keyed like ``ac-1_obj.a``; loading that file
into Objective rows is deferred to a later version once we need framework-
neutral objectives for 800-171.
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

# Stable raw GitHub URLs maintained by NIST.
OSCAL_URLS: dict[str, str] = {
    "5": (
        "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
        "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
    ),
    "4": (
        "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
        "nist.gov/SP800-53/rev4/json/NIST_SP-800-53_rev4_catalog.json"
    ),
}

# Fallback metadata when the catalog's own metadata is missing fields.
_DEFAULT_TITLES = {
    "5": "NIST SP 800-53 Rev 5",
    "4": "NIST SP 800-53 Rev 4",
}
_DEFAULT_VERSIONS = {"5": "5.1.1", "4": "4"}

# Back-compat alias — earlier code imported this constant directly.
OSCAL_800_53R5_URL = OSCAL_URLS["5"]


def _cache_path(rev: str) -> Path:
    return cfg.config_dir() / "catalogs" / f"NIST_SP-800-53_rev{rev}_catalog.json"


def _bundled_path(rev: str) -> Path:
    """Path to the catalog JSON shipped inside the wheel/source tree.

    Used as the offline fallback when the network is unreachable on a
    fresh install. Refreshing the bundled copy is a release-engineering
    step — at runtime we only read it.
    """
    return Path(__file__).parent / "_bundled" / f"NIST_SP-800-53_rev{rev}_catalog.json"


def _download_catalog(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310
        data = resp.read()
    dest.write_bytes(data)


def _load_json(path: Path | None, rev: str, *, offline: bool = False) -> dict[str, Any]:
    """Load the OSCAL catalog JSON.

    Resolution order:
      1. Explicit ``path`` — caller-supplied file (errors if missing).
      2. Local cache under ``~/.cybersecurity-assessor/catalogs/`` — written
         on first successful download.
      3. If ``offline`` or the download fails: fall back to the wheel-bundled
         copy under ``catalogs/_bundled/``. The bundled copy may lag the
         upstream NIST publication; that's intentional — it's a floor, not
         the source of truth.
    """
    if path is not None:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"OSCAL catalog not found: {p}")
        return json.loads(p.read_text(encoding="utf-8"))

    cached = _cache_path(rev)
    if cached.exists():
        return json.loads(cached.read_text(encoding="utf-8"))

    bundled = _bundled_path(rev)
    if offline:
        if not bundled.exists():
            raise FileNotFoundError(
                f"Offline mode requested but no bundled catalog at {bundled}"
            )
        return json.loads(bundled.read_text(encoding="utf-8"))

    try:
        _download_catalog(OSCAL_URLS[rev], cached)
        return json.loads(cached.read_text(encoding="utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        if bundled.exists():
            # Network unreachable on a fresh install — use the bundled copy
            # but do NOT write it into the cache, so the next launch retries
            # the download and picks up upstream fixes once connectivity
            # returns.
            return json.loads(bundled.read_text(encoding="utf-8"))
        raise RuntimeError(
            f"Could not download OSCAL rev{rev} ({exc}) and no bundled copy at {bundled}"
        ) from exc


def _statement_text(control: dict[str, Any]) -> str | None:
    """Pull the human-readable 'statement' part out of an OSCAL control."""
    for part in control.get("parts", []):
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


def _family_from_control_id(control_id: str) -> str:
    """'ac-2.1' -> 'AC'."""
    head = control_id.split("-", 1)[0]
    return head.upper()


def _normalize_control_id(oscal_id: str) -> str:
    """OSCAL uses lowercase 'ac-2.1'; CCIS workbooks use 'AC-2(1)'.

    We store the OSCAL-style id (lowercase, dot-separated) as Control.control_id
    and let the workbook reader translate when matching. Translation is
    deterministic so storing one canonical form is enough.
    """
    return oscal_id


def _is_withdrawn(node: dict[str, Any]) -> bool:
    """OSCAL marks withdrawn controls with props[name=status, value=withdrawn].

    NIST 800-53r5 catalog includes 182 withdrawn enhancements (e.g. AC-2(10))
    that have no statement and no assessment objectives — we don't want them
    polluting the Control table.
    """
    for p in node.get("props", []) or []:
        if p.get("name") == "status" and p.get("value") == "withdrawn":
            return True
    return False


def _walk_controls(group_or_control: dict[str, Any]) -> list[dict[str, Any]]:
    """Yield this control plus all enhancement controls (recursive).

    Filters:
      - SP800-53-enhancement-only sentinel rows (no real content)
      - Withdrawn controls (status=withdrawn in props)
      - Family group headers (no 'id' or no 'title')
    """
    out: list[dict[str, Any]] = []
    if (
        "id" in group_or_control
        and "title" in group_or_control
        and group_or_control.get("class") != "SP800-53-enhancement-only"
        and not _is_withdrawn(group_or_control)
    ):
        out.append(group_or_control)
    for child in group_or_control.get("controls", []) or []:
        out.extend(_walk_controls(child))
    return out


def load_oscal_catalog(
    session: Session,
    *,
    path: str | Path | None = None,
    rev: str = "5",
    offline: bool = False,
) -> Framework:
    """Idempotently load NIST 800-53 from OSCAL JSON (rev4 or rev5).

    Args:
        session: an active SQLModel Session.
        path: optional override -- a local OSCAL JSON file. If omitted,
            downloads from the official NIST GitHub mirror into the local
            cache (~/.cybersecurity-assessor/catalogs/).
        rev: ``"5"`` (default) or ``"4"``. Picks which catalog URL + cache
            file + fallback metadata to use.
        offline: if True, never attempt the network — go straight to the
            wheel-bundled catalog. Default False (try cache → download →
            bundled). Set True from the Settings page when the user has
            explicitly opted out of outbound traffic.

    Returns:
        The Framework row (created or updated).
    """
    if rev not in OSCAL_URLS:
        raise ValueError(
            f"Unsupported NIST 800-53 revision: {rev!r} (expected '4' or '5')"
        )

    doc = _load_json(Path(path) if path else None, rev, offline=offline)
    catalog = doc.get("catalog")
    if catalog is None:
        raise ValueError("Document is not an OSCAL catalog (missing 'catalog' key)")

    metadata = catalog.get("metadata", {})
    title = metadata.get("title", _DEFAULT_TITLES[rev])
    version = metadata.get("version", _DEFAULT_VERSIONS[rev])

    # --- Framework upsert ---------------------------------------------------
    framework = session.exec(
        select(Framework).where(Framework.name == title, Framework.version == version)
    ).first()
    if framework is None:
        framework = Framework(
            name=title,
            version=version,
            # Canonical framework_id used as the framework-scope key on
            # OdpAssignment / FrameworkEquivalence. Stable across versions
            # (workbook col C "Control Set" matches "NIST-800-53r4" /
            # "NIST-800-53r5"). See models.Framework docstring.
            framework_id=f"NIST-800-53r{rev}",
            oscal_uri=OSCAL_URLS[rev],
        )
        session.add(framework)
        session.commit()
        session.refresh(framework)
    elif framework.framework_id is None:
        # Pre-framework_id rows backfilled by additive migration in the
        # common case, but the migration only knows about NIST rows by
        # name/version. Idempotent self-heal in case the migration path
        # missed a one-off catalog row.
        framework.framework_id = f"NIST-800-53r{rev}"
        session.add(framework)
        session.commit()
        session.refresh(framework)

    # --- Walk groups -> controls -------------------------------------------
    existing_controls = {
        c.control_id: c
        for c in session.exec(select(Control).where(Control.framework_id == framework.id)).all()
    }

    for group in catalog.get("groups", []) or []:
        # Iterate the group's controls — the group itself is a family header,
        # not a control, even though it carries id/title (e.g. id="ac",
        # title="Access Control"). Passing the group into _walk_controls
        # would otherwise yield a spurious "ac" control row.
        for top_ctrl in group.get("controls", []) or []:
            for ctrl in _walk_controls(top_ctrl):
                control_id = _normalize_control_id(ctrl["id"])
                family = _family_from_control_id(control_id)
                title_text = ctrl.get("title", "")
                statement = _statement_text(ctrl)

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
