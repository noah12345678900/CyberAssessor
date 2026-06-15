"""Canonical scope-label vocabulary for multi-implementation CCI splits.

Why this exists
---------------
A single federal system legitimately runs on multiple cloud platforms
(AWS GovCloud + Azure Government + Oracle Gov Cloud) AND retains an
on-prem footprint. Each CRM upload represents one implementation slice;
on-prem is the implicit residual (no CRM upload).

A single source of truth for the scope-label vocabulary keeps:
* the Baseline.scope_label column,
* the OverlayImportRequest validator,
* the UI picker (via GET /api/baselines/scope-labels),
* the assessor engine's per-impl grouping,
* the SAR/POAM/CCIS exporters

all in lock-step. Adding or renaming a label is a one-file change.

Conventions
-----------
* ``ON_PREM_LABEL`` is reserved. It is NEVER passed in via a CRM upload —
  the assessor synthesizes an on-prem implementation row whenever any CCI
  responsibility on the workbook is not fully provider-covered by an
  attached CRM.
* ``OTHER_LABEL`` is the sentinel for free-text labels. The UI shows an
  "Other..." option that swaps to a text input; the server stores the
  user-typed value verbatim (after :func:`normalize_scope_label`).
"""

from __future__ import annotations

ON_PREM_LABEL = "On-Premises"
OTHER_LABEL = "Other"

# Order here is the order shown in the UI picker. Keep the most common
# choices at the top.
CANONICAL_SCOPE_LABELS: list[str] = [
    "AWS GovCloud",
    "Azure Government",
    "Oracle Government Cloud",
    "Google Cloud Assured Workloads",
    "IBM Cloud for Government",
]


def _canonical_index() -> dict[str, str]:
    """Build a case/whitespace-insensitive lookup into the canonical list."""
    index: dict[str, str] = {}
    for label in CANONICAL_SCOPE_LABELS:
        index[label.casefold().strip()] = label
    index[ON_PREM_LABEL.casefold().strip()] = ON_PREM_LABEL
    return index


_CANONICAL_INDEX = _canonical_index()


def normalize_scope_label(raw: str) -> str:
    """Return the canonical form of *raw* if it matches a known label.

    Matching is case- and whitespace-insensitive. If *raw* doesn't match
    any canonical entry, the user's input is returned with surrounding
    whitespace trimmed (this is the "Other → free text" path).

    Raises :class:`ValueError` if *raw* is empty after trimming.
    """
    # NB: this normalizer intentionally accepts ON_PREM_LABEL and round-trips
    # it. ``is_on_prem()`` below relies on that to do equality checks. The
    # "reserved at ingest" guarantee lives in routes/catalog.py — the CRM
    # dispatch path raises 422 when normalized_label == ON_PREM_LABEL (see
    # ``import_overlay``, covered by
    # ``test_import_crm_with_on_premises_scope_label_returns_422``). Any new
    # endpoint that accepts a user-supplied scope_label must replicate that
    # check or call a future ``validate_user_scope_label`` helper.
    if raw is None:
        raise ValueError("scope_label must not be None")
    trimmed = raw.strip()
    if not trimmed:
        raise ValueError("scope_label must not be empty")
    return _CANONICAL_INDEX.get(trimmed.casefold(), trimmed)


def is_on_prem(label: str) -> bool:
    """True if *label* refers to the implicit on-prem implementation."""
    return normalize_scope_label(label) == ON_PREM_LABEL


__all__ = [
    "CANONICAL_SCOPE_LABELS",
    "ON_PREM_LABEL",
    "OTHER_LABEL",
    "is_on_prem",
    "normalize_scope_label",
]
