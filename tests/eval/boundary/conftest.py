"""Boundary-doc eval harness conftest — opt-in gate for live-LLM tests.

Mirrors ``tests/eval/conftest.py`` exactly, but registers a *separate*
``live_llm_boundary`` marker so the two eval suites can be gated
independently. A developer running the CCI eval against a real Claude
endpoint (``-m live_llm``) should NOT also fire boundary-doc extraction
requests against the LLM, and vice versa — different prompts, different
fixture corpus, different cost profile.

The skip-gate hook (not ``addopts``) is the same pattern: it inspects
``config.getoption("-m")`` for the literal substring ``live_llm_boundary``
and only runs marked tests when that substring is present. Hook over
addopts because addopts prepends to argv and collides with user-supplied
``-m`` flags.

Boundary-doc cases live under ``tests/eval/boundary/cases/*.json`` and
are picked up by ``test_boundary_extraction.py`` (stub LLM) and
``test_boundary_extraction_live_llm.py`` (live LLM, opt-in only).
"""

from __future__ import annotations

import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "live_llm_boundary: runs boundary-doc extraction cases against a "
        "real LLM endpoint (requires API key; opt-in via "
        "`pytest -m live_llm_boundary`; skipped in default CI)",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    markexpr = config.getoption("-m", default="") or ""
    if "live_llm_boundary" in markexpr:
        return

    skip_marker = pytest.mark.skip(
        reason=(
            "live_llm_boundary tests are opt-in; "
            "run `pytest -m live_llm_boundary` to enable"
        )
    )
    for item in items:
        if "live_llm_boundary" in item.keywords:
            item.add_marker(skip_marker)
