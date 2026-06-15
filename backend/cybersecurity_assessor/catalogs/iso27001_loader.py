"""ISO/IEC 27001 Annex A catalog loader (license-aware).

WHY THIS LOADER IS DIFFERENT FROM THE NIST LOADERS
--------------------------------------------------
The NIST OSCAL catalogs are U.S. Government public-domain content, so
``oscal_loader.py`` is free to download and bundle the real control text.

ISO/IEC 27001 (and its Annex A control set) is **copyrighted by ISO/IEC**.
We may NOT bundle, fabricate, paraphrase, or otherwise ship the real
Annex A control text. Instead, an organization that has lawfully licensed
ISO/IEC 27001 supplies its own export of the Annex A controls, and this
loader reads that user-supplied file. With no path (or in offline mode)
the loader refuses to run and tells the user to supply their licensed
export — it never invents content to fill the gap.

THE LICENSED-IMPORT CONTRACT
----------------------------
``load_iso27001_catalog`` accepts a user-supplied file ``path`` pointing at
either:

  * a ``.csv`` file (Excel-friendly — what assessors usually have), or
  * a ``.json`` file (a list of objects).

Accepted column / field names are matched case-insensitively and are liberal
on input, strict on output:

  REQUIRED
    - id    : one of ``id`` | ``control_id`` | ``ref``
              (ISO Annex A ids look like ``A.5.1`` or ``5.1`` — stored as given)
    - title : one of ``title`` | ``name``
    - text  : one of ``text`` | ``requirement`` | ``statement``
  OPTIONAL
    - family/category : one of ``family`` | ``category`` | ``theme`` | ``function``
                        (ISO 27001:2022 themes: Organizational / People /
                        Physical / Technological). Stored on ``Control.family``;
                        defaults to ``""`` when absent.

A missing REQUIRED column raises a clear ``ValueError`` naming the field.

Reloads are idempotent: the Framework is upserted by ``(name, version)`` and
each Control by ``(framework_id, control_id)``.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from sqlmodel import Session, select

from ..models import Control, Framework

# --- Framework identity (NOT copyrighted — these are bibliographic facts) ---
FRAMEWORK_NAME = "ISO/IEC 27001"
FRAMEWORK_VERSION = "2022"
FRAMEWORK_ID = "ISO-27001-2022"

# Header aliases — lower-cased on lookup. Order = preference.
_ID_KEYS = ("id", "control_id", "ref")
_TITLE_KEYS = ("title", "name")
_TEXT_KEYS = ("text", "requirement", "statement")
_FAMILY_KEYS = ("family", "category", "theme", "function")

_LICENSE_MSG = (
    "ISO/IEC 27001 Annex A control text is copyrighted by ISO/IEC and cannot "
    "be bundled or downloaded by this application. To load this framework you "
    "must supply a licensed export your organization already owns: pass "
    "path=<file> pointing at a CSV or JSON file of the Annex A controls "
    "(columns: id/control_id/ref, title/name, text/requirement/statement, and "
    "optionally family/category/theme/function). Offline mode cannot satisfy "
    "this requirement — there is no public copy to fall back on."
)


def _pick(row: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    """Return the first present, non-empty value among ``keys`` (case-insensitive)."""
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


def _present_header(headers: set[str], keys: tuple[str, ...]) -> bool:
    """True if any alias in ``keys`` appears among ``headers`` (case-insensitive)."""
    lowered = {h.strip().lower() for h in headers}
    return any(k in lowered for k in keys)


def _read_rows(path: Path) -> list[dict[str, Any]]:
    """Read a user-supplied CSV or JSON file into a list of row dicts.

    CSV: first line is the header. JSON: a list of objects (each object is a
    row). Both are read as UTF-8. Required-column validation happens against
    the union of headers so an empty data file still names the missing field.
    """
    if not path.exists():
        raise FileNotFoundError(f"Licensed ISO/IEC 27001 export not found: {path}")

    suffix = path.suffix.lower()
    if suffix == ".json":
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError(
                "ISO/IEC 27001 JSON export must be a list of control objects."
            )
        rows = [dict(r) for r in raw if isinstance(r, dict)]
        headers: set[str] = set()
        for r in rows:
            headers.update(str(k) for k in r.keys())
    elif suffix == ".csv":
        with path.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            headers = set(reader.fieldnames or [])
            rows = [dict(r) for r in reader]
    else:
        raise ValueError(
            f"Unsupported licensed-export format {suffix!r}; supply a .csv or .json file."
        )

    # Strict required-column validation, liberal alias matching.
    if not _present_header(headers, _ID_KEYS):
        raise ValueError(
            "Licensed ISO/IEC 27001 export is missing the required 'id' column "
            f"(accepted: {', '.join(_ID_KEYS)})."
        )
    if not _present_header(headers, _TITLE_KEYS):
        raise ValueError(
            "Licensed ISO/IEC 27001 export is missing the required 'title' column "
            f"(accepted: {', '.join(_TITLE_KEYS)})."
        )
    if not _present_header(headers, _TEXT_KEYS):
        raise ValueError(
            "Licensed ISO/IEC 27001 export is missing the required 'text' column "
            f"(accepted: {', '.join(_TEXT_KEYS)})."
        )
    return rows


def load_iso27001_catalog(
    session: Session,
    *,
    path: str | Path | None = None,
    offline: bool = False,
) -> Framework:
    """Idempotently load ISO/IEC 27001 Annex A from a user-supplied export.

    Args:
        session: an active SQLModel Session.
        path: REQUIRED — a local CSV or JSON file containing the licensed
            Annex A control set the organization already owns. There is no
            download fallback because the content is copyrighted.
        offline: accepted for signature parity with the NIST loaders. Because
            there is never a network source for this framework, ``offline=True``
            is treated the same as ``path=None``: it raises with the licensing
            guidance.

    Returns:
        The Framework row (created or updated).

    Raises:
        ValueError: if ``path`` is None or ``offline`` is True (licensing
            guard), or if a required column is missing.
        FileNotFoundError: if the supplied path does not exist.
    """
    if path is None or offline:
        raise ValueError(_LICENSE_MSG)

    file_path = Path(path)
    rows = _read_rows(file_path)

    # --- Framework upsert by (name, version) -------------------------------
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
            oscal_uri=None,
            parent_framework_id=None,
            # enabled left untouched — defaults True.
        )
        session.add(framework)
        session.commit()
        session.refresh(framework)
    elif framework.framework_id is None:
        framework.framework_id = FRAMEWORK_ID
        session.add(framework)
        session.commit()
        session.refresh(framework)

    # --- Control upsert by (framework_id, control_id) ----------------------
    existing = {
        c.control_id: c
        for c in session.exec(
            select(Control).where(Control.framework_id == framework.id)
        ).all()
    }

    for row in rows:
        control_id = _pick(row, _ID_KEYS)
        if not control_id:
            # Row with no id — skip rather than persist an unkeyed control.
            continue
        title = _pick(row, _TITLE_KEYS) or ""
        statement = _pick(row, _TEXT_KEYS)
        family = _pick(row, _FAMILY_KEYS) or ""

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
