"""Boundary-doc extraction eval harness — live-LLM twin.

Companion to ``test_boundary_extraction.py``. The stub-mode runner pins
"given THIS canned envelope, the adapter produces THIS token set" —
useful for catching adapter-side regressions (normalization, dedup,
empty-path handling, exception path) but blind to "did the LLM itself
drift in response to a prompt change."

This runner closes that gap by driving the SAME case files through the
SAME ``BoundaryDocsContextSource.apply`` contract, but with a real
``AnthropicClient`` (which structurally satisfies the
``LlmExtractorClient`` Protocol) on the wire.

Gated three ways so default CI stays free / offline / fast:

1. ``@pytest.mark.live_llm_boundary`` — registered in
   ``tests/eval/boundary/conftest.py``. Default invocation excludes live
   mode unless the user opts in with ``pytest -m live_llm_boundary``.
   The marker is SEPARATE from ``live_llm`` so a CCI-eval live run
   doesn't accidentally fire boundary-doc extraction requests (different
   prompts, different fixture corpus, different cost profile).
2. **Per-case opt-in** — only cases that declare a top-level
   ``"live_llm_boundary": {...}`` block run in live mode. Stub-only
   cases (engineered placeholder rejection, unicode-survival, empty-doc
   confidence floor) skip cleanly — running them against a real LLM
   would waste tokens and give noisy failures because the engineered
   stub envelope is the whole point of the case.
3. **API-key availability** — missing ``ANTHROPIC_API_KEY`` (or keyring
   equivalent) → ``pytest.skip``, not fail. Live mode is opt-in even
   when the marker is selected.

Assertions are loosened vs. the stub runner
-------------------------------------------
A real LLM rephrases tokens, adds or drops marginal hits, and produces a
different ``confidence`` value per request. So:

- ``snapshot_tokens`` is NOT asserted — a real model's full set drifts;
  the kernel is what matters.
- The kernel uses the ``live_llm_boundary`` block's ``expected_tokens``
  + ``banned_tokens``, which are typically a STRICTER subset of the
  stub block (just the must-have hits and must-not-leak strings).
- ``min_confidence`` is asserted using the live block's floor (often
  lower than the stub block's, since the real model is less certain
  than a hand-tuned stub envelope).

A-B evaluation through this harness (Phase 3 of the plan)
---------------------------------------------------------
1. Record stub-mode ``snapshot_tokens`` under the OLD
   ``_EXTRACTION_PROMPT``; commit as baseline.
2. Swap the prompt in ``boundary_docs.py``.
3. Re-run ``pytest tests/eval/boundary/ -m live_llm_boundary``.
4. Per case, recall MUST NOT regress; banned-leakage MUST drop or stay
   zero; snapshot drift is expected and gets re-recorded once (1) + (2)
   pass.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

# sys.path bootstrap — same two-stage pattern as the stub runner so this
# file works in isolation (``pytest tests/eval/boundary/test_boundary_extraction_live_llm.py``).
_BACKEND = Path(__file__).resolve().parents[3] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from cybersecurity_assessor import models  # noqa: F401,E402  -- register tables
from cybersecurity_assessor.system_context.boundary_docs import (  # noqa: E402
    BoundaryDocsContextSource,
)

from _boundary_fixtures import _assert_token_kernel, _load_doc_evidence  # noqa: E402

CASES_DIR = Path(__file__).parent / "cases"
CASE_FILES = sorted(CASES_DIR.glob("*.json"))


# ---------------------------------------------------------------------------
# Client construction — fail-soft on missing key/SDK
# ---------------------------------------------------------------------------


def _build_live_client():
    """Construct a real LLM client or skip cleanly.

    Mirrors ``test_eval_harness_live_llm._build_live_client`` exactly so
    the two harnesses behave identically on a developer box without an
    API key configured. The Anthropic client structurally satisfies the
    ``LlmExtractorClient`` Protocol via its generic completion plumbing —
    no boundary-specific client subclass needed.
    """
    try:
        from cybersecurity_assessor.llm.client import (
            AnthropicClient,
            MissingApiKeyError,
        )
    except ImportError as exc:
        pytest.skip(f"cybersecurity_assessor.llm.client unavailable: {exc}")

    try:
        return AnthropicClient()
    except MissingApiKeyError as exc:
        pytest.skip(
            f"No Anthropic API key available for live-LLM boundary eval: {exc}"
        )
    except RuntimeError as exc:
        if "anthropic" in str(exc).lower():
            pytest.skip(f"anthropic SDK unavailable: {exc}")
        raise


@pytest.fixture(scope="session")
def live_llm_client() -> Any:
    """Session-scoped — re-resolving the key per case dominates runtime."""
    return _build_live_client()


def _make_session() -> tuple[Session, Any]:
    """In-memory SQLite with assessor schema; mirrors the stub runner."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    return Session(engine), engine


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


@pytest.mark.live_llm_boundary
@pytest.mark.parametrize("case_path", CASE_FILES, ids=lambda p: p.stem)
def test_boundary_extraction_case_live(
    case_path: Path, tmp_path: Path, live_llm_client: Any
) -> None:
    """Drive one boundary-doc case through ``apply`` with a real LLM.

    Only cases that declare a top-level ``"live_llm_boundary"`` block
    are exercised; the rest skip cleanly. The block schema is::

        "live_llm_boundary": {
            "expected_tokens": ["..."],   // must be present (kernel)
            "banned_tokens":   ["..."],   // must NOT be present (kernel)
            "min_confidence":  0.6        // floor from the real model
        }

    All three fields are required when the block is present — partial
    blocks raise KeyError so a misconfigured case fails as a test bug.
    """
    case = json.loads(case_path.read_text(encoding="utf-8"))
    live_spec = case.get("live_llm_boundary")
    if live_spec is None:
        pytest.skip(
            f"Case {case_path.stem!r} has no top-level 'live_llm_boundary' "
            "block — stub-only by design (engineered placeholder rejection, "
            "unicode-survival, empty-doc confidence floor, or other scenario "
            "that wouldn't add signal against a real model)."
        )

    expected_tokens = list(live_spec["expected_tokens"])
    banned_tokens = list(live_spec["banned_tokens"])
    min_conf = float(live_spec["min_confidence"])

    session, engine = _make_session()
    try:
        _load_doc_evidence(case, session, tmp_path, workbook_id=None)

        source = BoundaryDocsContextSource()
        result = source.apply(
            session, workbook_id=None, extractor=live_llm_client
        )

        ctx = result.context
        actual_tokens = list(ctx.extracted_tokens or [])

        # Kernel — same set arithmetic as stub mode but typically a
        # STRICTER subset (just the must-have/must-not strings the
        # assessor cares about for 3PAO defensibility).
        _assert_token_kernel(
            actual=actual_tokens,
            expected=expected_tokens,
            banned=banned_tokens,
        )

        # Confidence floor — looser than stub mode because the real
        # model is less certain than a hand-tuned envelope.
        assert result.confidence >= min_conf, (
            f"Live LLM confidence {result.confidence:.3f} below floor "
            f"{min_conf:.3f}; tokens={actual_tokens}; notes={result.notes}"
        )

        # Deliberately NOT asserted: ``snapshot_tokens`` — real-model
        # drift is expected and gets re-recorded as part of the Phase 3
        # A-B evaluation workflow (see module docstring).

    finally:
        session.close()
        engine.dispose()
