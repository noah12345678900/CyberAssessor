"""Live-LLM eval harness — same JSON cases, real Claude on the wire.

Companion to ``test_eval_harness.py``. The deterministic runner pins
"given THIS stub output, the kernel produces THIS verdict" — useful for
catching kernel regressions but blind to "did the model itself drift."
This runner closes that gap by driving the same ``Assessor.assess(...)``
contract against a real ``AnthropicClient`` (or whatever ``make_client``
returns based on local config).

Gated three ways so default CI stays free / offline / fast:

1. ``@pytest.mark.live_llm`` — the marker is registered in
   ``backend/pyproject.toml``. Default invocation excludes live mode
   unless the user opts in with ``pytest -m live_llm`` or
   ``-m "live_llm or not live_llm"``.
2. **Per-case opt-in** — only cases that declare a top-level
   ``"live_llm": {...}`` block run in live mode. Cases that exist purely
   to pin engineered stub behavior (e.g. ``future_tense_rejection``
   forces a contradiction a real model would not emit, or
   ``rule_8a_structural_l`` short-circuits before the model is ever
   called) are skipped — running them against a real LLM would waste
   tokens and give noisy failures.
3. **API-key availability** — missing ``ANTHROPIC_API_KEY`` (or
   keyring equivalent) → ``pytest.skip``, not fail. Live mode is opt-in
   even when the marker is selected.

Assertions are loosened vs. the deterministic runner:

- ``llm_calls`` is NOT asserted — a real model may succeed on attempt 0
  where the stub had to retry, or vice versa.
- ``narrative_contains_regex`` is NOT asserted — real models phrase
  things differently per request; pinning a regex would flake.
- ``review_reason_contains_regex`` is NOT asserted — same reason.

The high-signal contract is ``(status, needs_review, source_in)`` — what
the user actually sees in the workbook. The per-case ``live_llm`` block
declares only those three fields.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Mirror the sys.path bootstrap from the deterministic runner so this file
# also works in isolation (e.g. ``pytest tests/eval/test_eval_harness_live_llm.py``).
_BACKEND = Path(__file__).resolve().parents[2] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from cybersecurity_assessor import models  # noqa: F401,E402  -- register tables
from cybersecurity_assessor.engine.assessor import Assessor  # noqa: E402
from cybersecurity_assessor.models import ComplianceStatus  # noqa: E402

# Reuse helpers from the deterministic runner so the row-construction +
# proposal-coercion logic stays in one place. The deterministic runner is
# the source of truth for case-file parsing; this file only diverges in
# the LLM client and the loosened assertion set.
from test_eval_harness import _build_row  # noqa: E402

CASES_DIR = Path(__file__).parent / "cases"
CASE_FILES = sorted(CASES_DIR.glob("*.json"))


# ---------------------------------------------------------------------------
# Client construction — fail-soft on missing key/SDK
# ---------------------------------------------------------------------------


def _build_live_client():
    """Construct a real LLM client or skip the test cleanly.

    Resolution order matches production: explicit env var → keyring →
    config-resolved endpoint token. We don't try ``make_client(cfg)``
    here because that would require booting the FastAPI config layer
    just to satisfy a test; the direct ``AnthropicClient()`` call hits
    the same key-resolution helpers and is the path 99% of users will
    exercise.
    """
    # Cheap pre-flight: if neither env nor keyring has a key, skip
    # before we import anything heavy. The ``MissingApiKeyError`` raised
    # by ``AnthropicClient.__init__`` would also skip cleanly, but
    # importing ``anthropic`` first is wasted work on a dev box without
    # a key configured.
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
        pytest.skip(f"No Anthropic API key available for live-LLM eval: {exc}")
    except RuntimeError as exc:
        # ``anthropic`` SDK not installed — surfaced as RuntimeError from
        # the client constructor. Treat as "live mode unavailable" not
        # as a failure.
        if "anthropic" in str(exc).lower():
            pytest.skip(f"anthropic SDK unavailable: {exc}")
        raise


# Build the client once per session — re-resolving the key and re-importing
# the SDK on every case would dominate the runtime budget.
@pytest.fixture(scope="session")
def live_llm_client():
    return _build_live_client()


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


@pytest.mark.live_llm
@pytest.mark.parametrize("case_path", CASE_FILES, ids=lambda p: p.stem)
def test_eval_case_live(case_path: Path, live_llm_client) -> None:
    """Drive one case through ``Assessor.assess`` with a real LLM.

    Only cases that declare a top-level ``"live_llm"`` block are
    exercised; the rest skip cleanly. The block schema is::

        "live_llm": {
            "expected_status": "Compliant" | "Non-Compliant" | "Not Applicable" | null,
            "expected_needs_review": true | false,
            "expected_source_in": ["llm", "llm_after_retry"]
        }

    All three fields are required when the block is present — partial
    blocks raise a clear KeyError. Cases with no block at all skip
    silently (most cases are deliberate stub-only scenarios).
    """
    case = json.loads(case_path.read_text(encoding="utf-8"))
    live_spec = case.get("live_llm")
    if live_spec is None:
        pytest.skip(
            f"Case {case_path.stem!r} has no top-level 'live_llm' block — "
            "deterministic-stub-only by design (engineered abstain, rule "
            "short-circuit, or low-signal-for-real-model scenario)."
        )

    row = _build_row(case["ccis_row"])
    assessor = Assessor(llm=live_llm_client)
    decision = assessor.assess(row, tagged_evidence=case.get("tagged_evidence"))

    # status — same coercion as deterministic runner, but pulled from the
    # live_llm block so a case can have a different status expectation
    # for stub vs real (rare but possible — e.g. if the stub forces a
    # retry path the real model would skip).
    expected_status = live_spec["expected_status"]
    if expected_status is None:
        assert decision.status is None, (
            f"Live LLM: expected hard abstain (status=None) but got "
            f"{decision.status!r}; review_reason={decision.review_reason!r}; "
            f"narrative={decision.narrative!r}"
        )
    else:
        assert decision.status == ComplianceStatus(expected_status), (
            f"Live LLM: expected status={expected_status!r} but got "
            f"{decision.status!r}; review_reason={decision.review_reason!r}; "
            f"narrative={decision.narrative!r}"
        )

    expected_needs_review = live_spec["expected_needs_review"]
    assert decision.needs_review is expected_needs_review, (
        f"Live LLM: expected needs_review={expected_needs_review!r} but got "
        f"{decision.needs_review!r}; review_reason={decision.review_reason!r}; "
        f"narrative={decision.narrative!r}"
    )

    expected_source_in = live_spec["expected_source_in"]
    assert decision.source in expected_source_in, (
        f"Live LLM: expected source in {expected_source_in!r} but got "
        f"{decision.source!r}; notes={decision.notes!r}"
    )
