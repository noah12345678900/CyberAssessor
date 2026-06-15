"""Tagger precision/recall eval — parametrized runner.

Mirrors ``tests/eval/boundary/test_boundary_extraction.py`` for the
deterministic 4-tier ``tag_evidence`` adapter
(``backend/cybersecurity_assessor/evidence/tagger.py``). Each JSON file
under ``cases/`` freezes one
``(catalog, evidence, stig_findings) → (tier_hits, tag_count,
must_include, must_not_include)`` tuple. Adding a new case is a
one-file diff; the test ID matches the filename stem so
``pytest -k <case_name>`` selects exactly one.

Why this exists
---------------
There is no ``test_tagger.py`` today. The tagger has 4 tiers and 5
documented failure modes (see ``cases/README.md`` and the plan at
``.claude/plans/dreamy-wobbling-chipmunk.md``):

  1. **Tier 3 spray** — one body mention of "AC-2" tags every
     ac-2 child objective at the same relevance/confidence.
  2. **Tier 4 spray** — ``evidence_type="sw_inventory"`` fans out to
     four controls via ``EVIDENCE_TYPE_TO_CONTROLS``.
  3. **STIG CCI_RE false positives** — ``re.compile(r"CCI-\\d{6}")``
     scrapes every CCI mention, no finding-vs-quote anchor.
  4. **No framework filter on Objective lookups** — multi-framework
     catalogs leak: one CCI tag spreads across every framework's
     matching objective row.
  5. **Tier 3 control-ID-in-path** — filename ``AC-2_policy.pdf``
     tags AC-2 children regardless of body content.

This harness pins CURRENT behavior, including those five failure modes
(filename prefix ``pin_``). Each fix slice that addresses a failure
mode re-records the matching pin from "documents current behavior" to
"asserts correct behavior" — that re-record is the gate that proves
the fix landed without unintended widening or narrowing.

The tagger is fully deterministic (no LLM, no embeddings, no network)
so this harness needs no stub queue and no live-LLM marker. Every case
runs every time, fast.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from sqlmodel import Session

# Make the backend package importable from any pytest cwd. The repo-root
# conftest already does this for ``tests/eval/``, but mirror it so the
# file runs in isolation (e.g. ``pytest tests/eval/tagger/test_tagger_precision.py``).
_BACKEND = Path(__file__).resolve().parents[3] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

# Sibling-module import — tests/eval/tagger/ is a package (has
# __init__.py) but pytest's rootdir discovery doesn't put it on
# sys.path automatically. Add it so the flat ``_fixtures`` import below
# resolves without dragging in the boundary/_fixtures or assessor
# helpers one directory up.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from cybersecurity_assessor import models  # noqa: F401,E402 -- register tables
from cybersecurity_assessor.evidence.tagger import tag_evidence  # noqa: E402

from _fixtures import (  # noqa: E402
    _assert_tag_count,
    _assert_tags_absent,
    _assert_tags_present,
    _assert_tier_hits,
    _build_stig_findings,
    _load_catalog,
    _load_evidence,
    _make_session,
)

CASES_DIR = Path(__file__).parent / "cases"
CASE_FILES = sorted(CASES_DIR.glob("*.json"))


# ---------------------------------------------------------------------------
# Sanity guard
# ---------------------------------------------------------------------------


def test_cases_directory_is_not_empty() -> None:
    """Fail loudly if the cases dir is missing or empty.

    Without this, an accidentally-deleted ``cases/`` would collect zero
    parametrize IDs and report a green test run — masking total harness
    failure. Same shape as
    ``tests/eval/boundary/test_boundary_extraction.py::test_cases_directory_is_not_empty``.
    """
    assert CASES_DIR.exists(), f"cases directory missing: {CASES_DIR}"
    assert CASE_FILES, (
        f"no case files found under {CASES_DIR}; "
        "expected at least the ~20 seed cases from the Phase 1 plan"
    )


# ---------------------------------------------------------------------------
# Parametrized eval
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case_path", CASE_FILES, ids=lambda p: p.stem)
def test_tagger_case(case_path: Path, tmp_path: Path) -> None:
    """Run one tagger case end-to-end.

    Steps:
      1. Load case JSON; require an ``expected`` block.
      2. Build in-memory session, seed catalog (Framework + Controls +
         Objectives), seed Evidence row + on-disk text, build any STIG
         findings as ``StigFindingRow`` dataclasses (not persisted —
         passed by value to ``tag_evidence``).
      3. Resolve ``case["framework_id"]`` (a string identifier like
         ``"NIST-800-53r4"``) to the int PK via the catalog id_map.
         A case can also pass ``framework_id: null`` to test the
         framework-agnostic ingest path.
      4. Call ``tag_evidence`` — commit the session so any new tag rows
         show up in the assertion queries.
      5. Assert tier hits, total tag count, presence, and absence.
    """
    case = json.loads(case_path.read_text(encoding="utf-8"))

    expected = case.get("expected")
    if expected is None:
        pytest.fail(
            f"{case_path.name}: case file missing ``expected`` block; "
            "every case must declare at least tier_hits or "
            "tags_must_include / tags_must_not_include"
        )

    session: Session
    session, engine = _make_session()
    try:
        id_map = _load_catalog(case, session)
        ev_block = case["evidence"]
        ev = _load_evidence(case, session, tmp_path)
        stig_findings = _build_stig_findings(
            ev_block.get("stig_findings") or []
        )

        # ``framework_id`` resolution:
        #   * key absent       → framework-agnostic ingest (None PK)
        #   * value is null    → framework-agnostic ingest (None PK)
        #   * value is string  → look up that framework's int PK in id_map
        #   * value is int     → already a PK, pass through (test escape hatch)
        framework_pk: int | None
        if "framework_id" not in case or case["framework_id"] is None:
            framework_pk = None
        elif isinstance(case["framework_id"], int):
            framework_pk = case["framework_id"]
        else:
            # String like "NIST-800-53r4" → PK from catalog seeding.
            framework_pk = id_map[case["framework_id"]]

        result = tag_evidence(
            session,
            ev,
            text=ev_block.get("text", ""),
            stig_findings=stig_findings,
            cci_refs=ev_block.get("cci_refs"),
            evidence_type=ev_block.get("evidence_type"),
            evidence_type_signals=ev_block.get("evidence_type_signals"),
            framework_id=framework_pk,
        )
        # tag_evidence accumulates rows but leaves the commit to the
        # caller (production runs one txn per folder ingest). Commit so
        # the assertion queries see the new rows.
        session.commit()

        assert ev.id is not None  # post-_load_evidence invariant

        _assert_tier_hits(result, expected.get("tier_hits") or {})
        _assert_tag_count(session, ev.id, expected.get("tag_count"))
        _assert_tags_present(
            session, ev.id, expected.get("tags_must_include") or []
        )
        _assert_tags_absent(
            session, ev.id, expected.get("tags_must_not_include") or []
        )

        # Optional: re-invocation idempotency check. Cases declaring
        # ``rerun_must_not_duplicate: true`` call ``tag_evidence`` a
        # second time with identical inputs and assert the row count
        # didn't change — pins the ``_existing_pairs`` dedup invariant.
        if case.get("rerun_must_not_duplicate"):
            from sqlmodel import select

            from cybersecurity_assessor.models import EvidenceTag

            rows_before = session.exec(
                select(EvidenceTag).where(EvidenceTag.evidence_id == ev.id)
            ).all()
            tag_evidence(
                session,
                ev,
                text=ev_block.get("text", ""),
                stig_findings=stig_findings,
                cci_refs=ev_block.get("cci_refs"),
                evidence_type=ev_block.get("evidence_type"),
                evidence_type_signals=ev_block.get("evidence_type_signals"),
                framework_id=framework_pk,
            )
            session.commit()
            rows_after = session.exec(
                select(EvidenceTag).where(EvidenceTag.evidence_id == ev.id)
            ).all()
            assert len(rows_before) == len(rows_after), (
                f"rerun-idempotency broken: tag count went from "
                f"{len(rows_before)} to {len(rows_after)} on identical "
                "second call; ``_existing_pairs`` dedup regressed"
            )

    finally:
        session.close()
        engine.dispose()
