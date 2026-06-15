"""Eval-harness local conftest — opt-in gate for live-LLM tests.

By default, ``pytest`` runs every collected test regardless of markers.
For an expensive / network-bound suite like ``test_eval_harness_live_llm``,
that's the wrong default: developers running ``pytest tests/eval/``
should get the fast deterministic suite, not have their dev box quietly
fire a real Claude request per case.

This hook skips any test carrying ``@pytest.mark.live_llm`` unless the
``-m`` expression explicitly mentions ``live_llm`` (e.g.
``pytest -m live_llm``, ``-m "live_llm or whatever"``). The marker
itself is registered in ``backend/pyproject.toml`` so ``pytest --markers``
documents it and ``--strict-markers`` won't complain.

Why a hook and not ``addopts = ["-m", "not live_llm"]`` in pyproject:
the addopts approach prepends to argv and collides with user-supplied
``-m`` flags (``-m live_llm`` becomes ``-m "not live_llm" -m live_llm``,
which pytest resolves to the LAST -m wins — workable but fragile).
The hook is explicit, local to the eval suite, and doesn't surprise
callers of the broader top-level ``pytest`` invocation.
"""

from __future__ import annotations

import pytest


def pytest_configure(config: pytest.Config) -> None:
    """Register the ``live_llm`` marker locally.

    The marker is also declared in ``backend/pyproject.toml``, but
    pytest's config-discovery + rootdir resolution can land in a state
    where the eval-suite test files load before the pyproject markers
    list is consulted, producing a ``PytestUnknownMarkWarning`` even
    though ``pytest --markers`` shows the marker correctly. Registering
    here too is harmless and silences that warning.
    """
    config.addinivalue_line(
        "markers",
        "live_llm: runs eval cases against a real LLM endpoint "
        "(requires API key; opt-in via `pytest -m live_llm`; skipped in default CI)",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip ``live_llm`` tests unless the marker is explicitly requested."""
    markexpr = config.getoption("-m", default="") or ""
    if "live_llm" in markexpr:
        # Caller asked for live_llm explicitly — let them run.
        return

    skip_marker = pytest.mark.skip(
        reason="live_llm tests are opt-in; run `pytest -m live_llm` to enable"
    )
    for item in items:
        if "live_llm" in item.keywords:
            item.add_marker(skip_marker)
