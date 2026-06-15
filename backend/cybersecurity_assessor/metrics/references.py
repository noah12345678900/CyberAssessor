"""Loader for the static reference benchmarks bundled with the wheel.

The reference table is intentionally a hand-curated JSON file (see
``_bundled/references.json``) rather than a runtime fetch — manual A&A
benchmarks don't change weekly, and an offline / GovCloud-only run must
never silently render zero. When the user sources a value, they edit the
JSON and re-bundle.

Mirrors the load pattern in ``catalogs/oscal_loader.py:88-104`` —
``json.loads(Path.read_text(encoding="utf-8"))`` against a sibling
``_bundled/`` directory.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_BUNDLED = Path(__file__).resolve().parent / "_bundled" / "references.json"


@lru_cache(maxsize=1)
def _load_raw() -> dict[str, Any]:
    if not _BUNDLED.exists():
        # An empty payload is safer than raising — Metrics still renders,
        # just with every Reference column showing "Awaiting source".
        return {"rates_revised": None, "references": []}
    return json.loads(_BUNDLED.read_text(encoding="utf-8"))


def load_references() -> dict[str, list[dict[str, Any]]]:
    """Return references grouped by family.

    Shape: ``{"accuracy": [...], "cost": [...], "time": [...]}``. Families
    with no entries get an empty list, never a missing key — the frontend
    can iterate the three families unconditionally.
    """
    raw = _load_raw()
    out: dict[str, list[dict[str, Any]]] = {"accuracy": [], "cost": [], "time": []}
    for ref in raw.get("references", []):
        fam = ref.get("family")
        if fam in out:
            out[fam].append(ref)
    return out


def rates_revised() -> str | None:
    """Date the bundled reference card was last revised (UI footer)."""
    return _load_raw().get("rates_revised")
