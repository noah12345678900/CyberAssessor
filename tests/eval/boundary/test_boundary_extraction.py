"""Boundary-doc extraction eval harness — stub-mode entry point.

Mirrors ``tests/eval/test_eval_harness.py`` for the boundary-docs adapter
(``system_context/boundary_docs.py``). Each JSON file under ``cases/``
freezes one ``(fixture_docs, stub_extractor envelope) → expected (tokens
kernel, snapshot, confidence floor)`` tuple. Adding a new case is a
one-file diff; the test ID matches the filename stem so
``pytest -k <case_name>`` selects exactly one.

Why this exists
---------------
The boundary-docs adapter has three failure surfaces that aren't visible
to ``backend/tests/`` unit tests:

  1. **Prompt drift** — silent change to ``_EXTRACTION_PROMPT`` shifts
     which tokens the LLM emits. Phase 3 of the plan rewrites this
     prompt; without a regression rig the swap is unauditable.
  2. **Normalization drift** — ``_normalize_token`` is currently
     lowercase + strip-punctuation. Tightening it (e.g. dropping
     ``.local`` suffix) silently changes downstream sweep matches.
  3. **Empty / partial / exception paths** — the adapter has three
     degrade-gracefully paths (empty docs, no extracted text,
     extractor exception) that all write a SystemContext row. A
     regression that flips one path's confidence or token set would go
     unnoticed without a case-level assertion.

The cases pin CURRENT kernel behavior. A flip means deliberate work:
either intended (update the case + ``description``) or a regression
(revert).

Hybrid recording strategy (decision D1)
---------------------------------------
Two assertions per case:

  * **Curated kernel** (``expected_tokens`` + ``banned_tokens``) — the
    legible 3PAO contract. A case file reads as "this prompt MUST emit
    server01 and MUST NOT emit example.com." Set arithmetic, fails loud.
  * **Snapshot drift** (``snapshot_tokens``) — the full captured token
    set. Loose check: if the snapshot drifts the test still passes the
    kernel, but a warning surfaces so the author re-records
    intentionally. Snapshot diffs catch token additions/removals the
    kernel doesn't name.

Phase 2 will add ``max_unattributed_ratio`` here (token-to-source
attribution ceiling). Phase 3 swaps the prompt and re-records snapshots.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

# Make the backend package importable from any pytest cwd. The repo-root
# conftest already does this for ``tests/eval/``, but mirror it so the
# file runs in isolation (e.g. ``pytest tests/eval/boundary/test_boundary_extraction.py``).
_BACKEND = Path(__file__).resolve().parents[3] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

# Sibling-module import — tests/eval/boundary/ is a package (has
# __init__.py) but pytest's rootdir discovery doesn't put it on sys.path
# automatically. Add it so the flat ``_stubs`` / ``_fixtures`` imports
# below resolve without dragging in the unrelated ``tests/eval/_stubs``
# module that lives one directory up.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from cybersecurity_assessor import models  # noqa: F401,E402  -- register tables
from cybersecurity_assessor.models import BoundaryTokenSource  # noqa: E402
from cybersecurity_assessor.system_context.boundary_docs import (  # noqa: E402
    BoundaryDocsContextSource,
)
from sqlmodel import select  # noqa: E402

from _boundary_fixtures import _assert_token_kernel, _load_doc_evidence  # noqa: E402
from _extractor_stubs import StubExtractorClient  # noqa: E402

CASES_DIR = Path(__file__).parent / "cases"
CASE_FILES = sorted(CASES_DIR.glob("*.json"))


# ---------------------------------------------------------------------------
# Sanity guard
# ---------------------------------------------------------------------------


def test_cases_directory_is_not_empty() -> None:
    """Fail loudly if the cases dir is missing or empty.

    Without this, an accidentally-deleted ``cases/`` would collect zero
    parametrize IDs and report a green test run — masking a total
    harness failure. Pattern from
    ``tests/eval/test_eval_harness.py::test_cases_directory_is_not_empty``.
    """
    assert CASES_DIR.exists(), f"cases directory missing: {CASES_DIR}"
    assert CASE_FILES, (
        f"no case files found under {CASES_DIR}; "
        "expected at least the 8 seed cases from the Phase 1 plan"
    )


# ---------------------------------------------------------------------------
# In-memory DB
# ---------------------------------------------------------------------------


def _make_session() -> tuple[Session, Any]:
    """Spin up an in-memory SQLite with the assessor schema realized.

    StaticPool keeps the single connection alive across the test so the
    in-memory DB (which dies on connection close) persists for the
    duration of one case. Pattern from
    ``backend/tests/routes/test_system_context_pending.py`` and
    ``backend/tests/conftest.py``.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    return Session(engine), engine


# ---------------------------------------------------------------------------
# Stub-mode parameterized eval
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case_path", CASE_FILES, ids=lambda p: p.stem)
def test_boundary_extraction_case(case_path: Path, tmp_path: Path) -> None:
    """Run one boundary-doc extraction case through a stub extractor.

    Steps:
      1. Load case JSON; skip if it's a live-only case (no
         ``stub_extractor`` block).
      2. Seed fixture docs onto disk + Evidence rows via
         ``_load_doc_evidence``.
      3. Build ``StubExtractorClient`` from ``stub_extractor`` envelope.
      4. Run ``BoundaryDocsContextSource.apply`` against the pending
         scope (``workbook_id=None``), which is the same scope the
         Sweep Context UI hits before a workbook is attached and the
         simplest one to seed.
      5. Assert kernel (``expected_tokens`` present, ``banned_tokens``
         absent), confidence floor, and snapshot drift (loose check).
    """
    case = json.loads(case_path.read_text(encoding="utf-8"))

    if "stub_extractor" not in case:
        pytest.skip(
            f"{case_path.name}: live-only case (no ``stub_extractor`` block); "
            "run via test_boundary_extraction_live_llm.py with "
            "``-m live_llm_boundary``"
        )

    expected = case.get("expected") or {}
    if not expected:
        pytest.fail(
            f"{case_path.name}: case file missing ``expected`` block; "
            "every case must declare at least expected_tokens/banned_tokens"
        )

    session, engine = _make_session()
    try:
        # Seed boundary-doc Evidence rows (writes inline text to tmp_path
        # as .txt and points extracted_text_path at it — the adapter
        # never opens the original artifact, only the extracted text).
        _load_doc_evidence(case, session, tmp_path, workbook_id=None)

        # Build the stub from the declared envelope. The adapter calls
        # the extractor at most once per apply() (single concatenated
        # prompt), so a single-item queue is the common case — but the
        # FIFO supports multi-envelope cases if a future adapter
        # iteration adds per-section calls.
        envelope = case["stub_extractor"]
        stub = StubExtractorClient([envelope])

        source = BoundaryDocsContextSource()
        result = source.apply(session, workbook_id=None, extractor=stub)

        ctx = result.context
        actual_tokens = list(ctx.extracted_tokens or [])

        # Curated kernel — the legible 3PAO contract. Failure here means
        # the adapter either dropped a required token or leaked a banned
        # one; both are precision regressions.
        _assert_token_kernel(
            actual=actual_tokens,
            expected=list(expected.get("expected_tokens", [])),
            banned=list(expected.get("banned_tokens", [])),
        )

        # Confidence floor — catches the degrade-gracefully paths
        # silently overwriting a real extraction with the 0.2 exception
        # fallback or the 0.0 empty-docs path.
        min_conf = float(expected.get("min_confidence", 0.0))
        assert result.confidence >= min_conf, (
            f"confidence {result.confidence:.3f} below floor {min_conf:.3f}; "
            f"notes={result.notes}"
        )

        # Snapshot drift — loose check. If the case declares
        # ``snapshot_tokens``, the actual full set must match exactly.
        # The kernel above is the load-bearing assertion; the snapshot
        # catches additions/removals the kernel doesn't name. Re-record
        # the snapshot deliberately when intent changes (see
        # cases/README.md).
        snapshot = expected.get("snapshot_tokens")
        if snapshot is not None:
            assert sorted(actual_tokens) == sorted(snapshot), (
                f"snapshot drift in {case_path.name}:\n"
                f"  expected ({len(snapshot)}): {sorted(snapshot)}\n"
                f"  actual   ({len(actual_tokens)}): {sorted(actual_tokens)}\n"
                "If intentional, re-record snapshot_tokens; "
                "otherwise the prompt or normalizer regressed."
            )

        # Provenance ceiling — Phase 2 gate on the riskiest assumption
        # of this slice: that token strings round-trip cleanly between
        # the LLM and the section concatenation we attribute from. The
        # stacked match in ``_attribute_token`` (substring → normalized
        # → bail) writes ``source_kind="unattributed"`` when it can't
        # trace a token back to a doc; ``max_unattributed_ratio`` caps
        # the fraction allowed before the build fails. Skip when there
        # are no tokens (empty-docs / all-skipped paths) since the ratio
        # is undefined and the upstream confidence-floor check already
        # gates those cases.
        max_unattr = expected.get("max_unattributed_ratio")
        if max_unattr is not None and actual_tokens and ctx.id is not None:
            bts_rows = session.exec(
                select(BoundaryTokenSource).where(
                    BoundaryTokenSource.system_context_id == ctx.id
                )
            ).all()
            # One BoundaryTokenSource row per token in
            # ``extracted_tokens`` (enforced by the adapter's
            # delete-then-insert in ``apply``); if that invariant ever
            # breaks the assertion below would silently misreport, so
            # pin it explicitly.
            assert len(bts_rows) == len(actual_tokens), (
                f"BoundaryTokenSource row count {len(bts_rows)} "
                f"!= extracted_tokens count {len(actual_tokens)}; "
                "adapter upsert/cleanup invariant broken"
            )
            unattributed = sum(
                1 for r in bts_rows if r.source_kind == "unattributed"
            )
            ratio = unattributed / len(bts_rows)
            assert ratio <= float(max_unattr) + 1e-9, (
                f"unattributed ratio {ratio:.3f} exceeds ceiling "
                f"{float(max_unattr):.3f} in {case_path.name}; "
                f"{unattributed}/{len(bts_rows)} tokens fell through "
                "the stacked match. Either the LLM is rewriting tokens "
                "away from the source text, or the section concatenation "
                "is too narrow."
            )

        # Sanity: empty-docs path SHOULD NOT call the extractor; every
        # other path should call it exactly once. Catches accidental
        # re-entry or skipped invocations.
        fixture_docs = case.get("fixture_docs") or []
        if not fixture_docs:
            assert stub.calls == [], (
                "extractor called on empty-docs case; the adapter should "
                "short-circuit with confidence=0.0 before issuing a prompt"
            )
        else:
            # Allow 0 calls only when every doc was skipped (no extracted
            # text). Case files don't currently exercise that path, but
            # leave the door open by gating on ``docs_used``.
            docs_used = result.notes.get("docs_used", 0)
            if docs_used > 0:
                assert len(stub.calls) == 1, (
                    f"expected exactly 1 extractor call when docs_used={docs_used}, "
                    f"got {len(stub.calls)}"
                )

    finally:
        session.close()
        engine.dispose()
