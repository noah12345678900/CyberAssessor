"""Integration tests for ``Assessor`` ↔ supersession-index wiring.

The :func:`build_evidence_chain_index` / ``EvidenceChainIndex`` /
``rewrite_evidence_chain(index=...)`` triple is exercised end-to-end in
``test_evidence_chain_index_equivalence.py``. THIS file pins the
Assessor-level glue:

* ``Assessor.prime_evidence_chain_index(workbook_id)`` actually stashes
  an index, and a subsequent ``_locked_rewrite_evidence_chain(...)`` call
  hands it to the supersession kernel (fast path: ``session=None``,
  ``index=<non-None>``).

* Without a prime call, ``_locked_rewrite_evidence_chain`` falls back to
  the legacy per-call path (``session=<cache session>``, no ``index``
  kwarg or ``index=None``) — backward compatibility for non-batched
  callers (``/assess`` single-shot, CLI tools, future test paths).

Spy via ``unittest.mock.patch`` on
``cybersecurity_assessor.engine.supersession.rewrite_evidence_chain``;
``assessor.py`` imports the module (``from . import supersession``) and
calls through ``supersession.rewrite_evidence_chain``, so patching the
attribute on the module catches both call paths.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

# Make the backend package importable from any pytest cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402 -- registers tables
from cybersecurity_assessor.engine import supersession  # noqa: E402
from cybersecurity_assessor.engine.assessor import Assessor  # noqa: E402
from cybersecurity_assessor.engine.supersession import (  # noqa: E402
    EvidenceChainIndex,
    EvidenceChainResult,
)
from cybersecurity_assessor.models import Evidence, EvidenceKind  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _seed_one_chain(session: Session) -> None:
    """Seed one superseded chain so the index has at least one candidate."""
    new = Evidence(
        path="file:///docs/new.pdf",
        sha256="sha-new",
        kind=EvidenceKind.PDF,
        size_bytes=1,
        title="Account Mgmt Plan Rev B",
        doc_number="USD00099999",
    )
    session.add(new)
    session.flush()
    old = Evidence(
        path="file:///docs/old.pdf",
        sha256="sha-old",
        kind=EvidenceKind.PDF,
        size_bytes=1,
        title="Account Mgmt Plan Rev A",
        doc_number="USD00088888",
        superseded_by_id=new.id,
    )
    session.add(old)
    session.flush()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_prime_then_assess_uses_cached_index(session):
    """After ``prime_evidence_chain_index``, the chokepoint takes the
    indexed fast path.

    Pins the wiring contract: priming actually stashes the index AND
    ``_locked_rewrite_evidence_chain`` consults it. If priming silently
    no-op'd, or the chokepoint forgot to check the index attribute, the
    spy would see the legacy ``session=<session>`` shape on every call
    — which is the perf-regression we built this slice to prevent.
    """
    _seed_one_chain(session)
    assessor = Assessor(llm=None, cache_session=session)

    # Build the index. After this call, _evidence_chain_index is populated.
    assessor.prime_evidence_chain_index(workbook_id=None)
    assert isinstance(assessor._evidence_chain_index, EvidenceChainIndex)
    assert assessor._evidence_chain_index.candidates  # at least one candidate

    text = "Per USD00088888 reviews happen quarterly."
    with patch.object(
        supersession,
        "rewrite_evidence_chain",
        return_value=EvidenceChainResult(rewritten_text=text, hits=[]),
    ) as spy:
        assessor._locked_rewrite_evidence_chain(text, workbook_id=None)

    assert spy.call_count == 1
    call = spy.call_args
    # First positional arg is the session — fast path passes None.
    assert call.args[0] is None
    # Second positional arg is the narrative text — passed verbatim.
    assert call.args[1] == text
    # The cached index must be handed through as the ``index`` kwarg.
    assert call.kwargs.get("index") is assessor._evidence_chain_index
    # And the legacy ``workbook_id`` kwarg must NOT be set on the fast
    # path (the index carries its own scope; passing both would muddy
    # the contract).
    assert "workbook_id" not in call.kwargs


def test_unprimed_assessor_falls_back_to_legacy_path(session):
    """Without priming, the chokepoint stays on the legacy session-bound
    path — same call shape it had before this slice landed.

    Backward-compatibility pin: ``/assess`` single-shot, CLI tools, and
    any future caller that constructs an ``Assessor(cache_session=...)``
    without bothering to prime must still get a correct rewrite. If the
    chokepoint regressed to "no index → no rewrite" the spy would see
    ``session=None`` and the live behavior would silently lose the
    patent-supporting catch-net.
    """
    _seed_one_chain(session)
    assessor = Assessor(llm=None, cache_session=session)
    # Explicit: never call prime_evidence_chain_index. The cached index
    # must still be None at the chokepoint.
    assert assessor._evidence_chain_index is None

    text = "Per USD00088888 reviews happen quarterly."
    with patch.object(
        supersession,
        "rewrite_evidence_chain",
        return_value=EvidenceChainResult(rewritten_text=text, hits=[]),
    ) as spy:
        assessor._locked_rewrite_evidence_chain(text, workbook_id=42)

    assert spy.call_count == 1
    call = spy.call_args
    # Legacy path passes the actual session object.
    assert call.args[0] is session
    assert call.args[1] == text
    # Legacy path forwards workbook_id and does NOT pass an index.
    assert call.kwargs.get("workbook_id") == 42
    assert call.kwargs.get("index") is None
