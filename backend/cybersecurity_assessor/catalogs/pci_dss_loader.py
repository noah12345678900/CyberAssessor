"""PCI DSS catalog loader (license-aware).

PCI DSS is copyrighted by the PCI Security Standards Council (PCI SSC). The
control text MUST NOT be bundled with this application, downloaded from an
unlicensed mirror, or fabricated. Instead this loader reads a **user-supplied
licensed export** that the organization already owns (the PCI SSC distributes
the requirements as part of the licensed standard; an org can export them to
CSV/JSON). With no path (or ``offline=True``) the loader raises a clear,
actionable error telling the user to supply that export.

Licensed-import contract
------------------------
Accepts a user-supplied path to either ``.csv`` (header row) or ``.json``
(a list of objects). Headers are matched **case-insensitively**; the loader is
liberal in the names it accepts and strict in what it writes.

REQUIRED columns (first matching name wins):
  - id    : ``id`` | ``control_id`` | ``ref`` | ``requirement_id``
  - title : ``title`` | ``name``
  - text  : ``text`` | ``requirement`` | ``statement`` | ``criteria``

OPTIONAL columns:
  - family/category : ``family`` | ``category`` | ``requirement_group``
                      | ``tsc_category`` | ``area``

A missing REQUIRED column raises ``ValueError`` naming the absent field.
Files are read with ``encoding="utf-8"``.

PCI rows are sub-requirements (ids like ``"1.1.1"``, ``"8.3.6"``). Each row
becomes a ``Control`` whose ``control_id`` is the id, ``statement`` is the
text, and ``family`` is the explicit category if present, otherwise the
top-level requirement number (``control_id`` split on ``"."``, first segment —
``"8.3.6"`` -> ``"8"``).

The loader mirrors ``oscal_loader``'s session/commit/upsert discipline:
idempotent Framework-by-(name, version) and Control-by-(framework_id,
control_id) upserts, so reloading converges.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from sqlmodel import Session, select

from ..models import Control, Framework

FRAMEWORK_NAME = "PCI DSS"
FRAMEWORK_VERSION = "4.0"
FRAMEWORK_ID = "PCI-DSS-4.0"

# Case-insensitive accepted header names, in priority order.
_ID_KEYS = ("id", "control_id", "ref", "requirement_id")
_TITLE_KEYS = ("title", "name")
_TEXT_KEYS = ("text", "requirement", "statement", "criteria")
_FAMILY_KEYS = ("family", "category", "requirement_group", "tsc_category", "area")

_LICENSE_ERROR = (
    "PCI DSS requirement text is copyrighted by the PCI Security Standards "
    "Council (PCI SSC) and cannot be bundled or downloaded by this "
    "application. To load the PCI DSS catalog you must supply a path to your "
    "organization's own licensed export of the requirements (a .csv or .json "
    "file you already own). Re-run with path=<your licensed export> and "
    "offline=False."
)


def _pick(row: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    """Return the first present, non-empty value for any accepted key.

    Matching is case-insensitive on the row's own keys; surrounding
    whitespace on values is stripped. Returns ``None`` if no accepted key
    is present at all (caller decides whether that is fatal).
    """
    lowered = {str(k).strip().lower(): v for k, v in row.items()}
    for key in keys:
        if key in lowered:
            val = lowered[key]
            if val is None:
                continue
            text = str(val).strip()
            if text:
                return text
    return None


def _has_any_key(headers: set[str], keys: tuple[str, ...]) -> bool:
    return any(k in headers for k in keys)


def _read_rows(path: Path) -> list[dict[str, Any]]:
    """Read a CSV or JSON licensed export into a list of plain dicts."""
    suffix = path.suffix.lower()
    if suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError(
                "PCI DSS JSON export must be a list of objects (got "
                f"{type(data).__name__})."
            )
        return [dict(r) for r in data]
    if suffix == ".csv":
        with path.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            return [dict(r) for r in reader]
    raise ValueError(
        f"Unsupported PCI DSS export type {suffix!r}; expected .csv or .json."
    )


def _validate_headers(rows: list[dict[str, Any]]) -> None:
    """Ensure every REQUIRED logical column is satisfiable from the headers.

    Raises ValueError naming the first missing required field so the route
    layer / user gets an actionable message.
    """
    if not rows:
        raise ValueError("PCI DSS export is empty (no rows found).")
    headers: set[str] = set()
    for row in rows:
        headers.update(str(k).strip().lower() for k in row.keys())
    if not _has_any_key(headers, _ID_KEYS):
        raise ValueError(
            "PCI DSS export is missing the required 'id' column "
            f"(accepted: {', '.join(_ID_KEYS)})."
        )
    if not _has_any_key(headers, _TITLE_KEYS):
        raise ValueError(
            "PCI DSS export is missing the required 'title' column "
            f"(accepted: {', '.join(_TITLE_KEYS)})."
        )
    if not _has_any_key(headers, _TEXT_KEYS):
        raise ValueError(
            "PCI DSS export is missing the required 'text' column "
            f"(accepted: {', '.join(_TEXT_KEYS)})."
        )


def _family_for(control_id: str, explicit: str | None) -> str:
    """Explicit category wins; else top-level requirement number.

    ``"8.3.6"`` -> ``"8"``. Falls back to the whole id if it contains no dot.
    """
    if explicit:
        return explicit
    return control_id.split(".", 1)[0]


def load_pci_dss_catalog(
    session: Session,
    *,
    path: str | Path | None = None,
    offline: bool = False,
) -> Framework:
    """Idempotently load the PCI DSS catalog from a user-supplied export.

    Args:
        session: an active SQLModel Session.
        path: REQUIRED path to the organization's licensed PCI DSS export
            (.csv or .json). There is no download fallback — the text is
            copyrighted.
        offline: kept for signature parity with the other catalog loaders.
            Because there is no network path here, ``offline=True`` (like
            ``path=None``) raises the supply-your-licensed-export error.

    Returns:
        The Framework row (created or updated).

    Raises:
        RuntimeError: if ``path`` is None or ``offline`` is True.
        ValueError: if a required column is missing or the file is malformed.
        FileNotFoundError: if ``path`` does not exist.
    """
    if path is None or offline:
        raise RuntimeError(_LICENSE_ERROR)

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(
            f"PCI DSS licensed export not found: {p}. {_LICENSE_ERROR}"
        )

    rows = _read_rows(p)
    _validate_headers(rows)

    # --- Framework upsert ---------------------------------------------------
    framework = session.exec(
        select(Framework).where(
            Framework.name == FRAMEWORK_NAME,
            Framework.version == FRAMEWORK_VERSION,
        )
    ).first()
    if framework is None:
        framework = Framework(
            name=FRAMEWORK_NAME,
            version=FRAMEWORK_VERSION,
            framework_id=FRAMEWORK_ID,
        )
        session.add(framework)
        session.commit()
        session.refresh(framework)
    elif framework.framework_id is None:
        framework.framework_id = FRAMEWORK_ID
        session.add(framework)
        session.commit()
        session.refresh(framework)

    # --- Control upserts ----------------------------------------------------
    existing = {
        c.control_id: c
        for c in session.exec(
            select(Control).where(Control.framework_id == framework.id)
        ).all()
    }

    for row in rows:
        control_id = _pick(row, _ID_KEYS)
        if not control_id:
            # A row with no id at all can't be addressed; skip rather than
            # write an unkeyed Control. Header validation already proved the
            # column exists; this guards a blank cell.
            continue
        title = _pick(row, _TITLE_KEYS) or ""
        statement = _pick(row, _TEXT_KEYS)
        family = _family_for(control_id, _pick(row, _FAMILY_KEYS))

        existing_row = existing.get(control_id)
        if existing_row is None:
            existing_row = Control(
                framework_id=framework.id,  # type: ignore[arg-type]
                control_id=control_id,
                title=title,
                family=family,
                statement=statement,
            )
            session.add(existing_row)
            existing[control_id] = existing_row
        else:
            existing_row.title = title
            existing_row.family = family
            existing_row.statement = statement
            session.add(existing_row)

    session.commit()
    session.refresh(framework)
    return framework
