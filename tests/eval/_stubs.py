"""Stubs used by the eval harness — self-contained so the eval doesn't
import from ``backend/tests/engine/``.

The kernel's ``Assessor`` only requires its ``llm`` client to expose
``propose`` and ``propose_twice``; this stub is the minimum surface.
Same shape as ``StubLlmClient`` in
``backend/tests/engine/test_assessor_e2e.py:71`` — kept independently so
a refactor of that file can't break the eval, and so callers can read
the eval harness without chasing imports across test trees.

``LlmProposal`` itself is re-exported from the kernel so case files
declare proposals using exactly the kernel dataclass (no schema drift).
"""

from __future__ import annotations

from cybersecurity_assessor.engine.assessor import LlmProposal
from cybersecurity_assessor.excel.ccis_reader import CcisRow

__all__ = ["AssertNoCallStub", "LlmProposal", "StubLlmClient"]


class StubLlmClient:
    """Returns canned proposals in FIFO order; records every call.

    Construct with a list of ``LlmProposal`` objects — each ``.propose``
    call pops one off the front. ``.propose_twice`` returns the same
    proposal twice (matches the kernel's dual-pass contract when both
    passes agree); to exercise the dual-pass disagreement path, supply
    two different proposals back-to-back and call ``propose_twice``
    directly.

    If the queue runs empty mid-test, raises ``AssertionError`` rather
    than returning a placeholder — that surfaces a case file declaring
    too few proposals for the path it expects to take.
    """

    def __init__(self, proposals: list[LlmProposal]) -> None:
        self._queue: list[LlmProposal] = list(proposals)
        self.calls: list[dict] = []

    def propose(
        self,
        *,
        row: CcisRow,
        corrective_context: str | None = None,
        prior_attempts: list[LlmProposal] | None = None,
        tagged_evidence: str | None = None,
        crm_responsibility: str | None = None,
        boundary_brief: str | None = None,
    ) -> LlmProposal:
        self.calls.append(
            {
                "row": row,
                "corrective_context": corrective_context,
                "prior_attempts": list(prior_attempts) if prior_attempts else None,
                "tagged_evidence": tagged_evidence,
                "crm_responsibility": crm_responsibility,
                "boundary_brief": boundary_brief,
            }
        )
        if not self._queue:
            raise AssertionError(
                "StubLlmClient queue exhausted — case file declared fewer "
                "proposals than the orchestrator asked for. Inspect "
                "stub.calls to see what was being requested."
            )
        return self._queue.pop(0)

    def propose_twice(
        self,
        *,
        row: CcisRow,
        corrective_context: str | None = None,
        prior_attempts: list[LlmProposal] | None = None,
        tagged_evidence: str | None = None,
        crm_responsibility: str | None = None,
        boundary_brief: str | None = None,
    ) -> tuple[LlmProposal, LlmProposal]:
        """Single-pass parity surface — emits the same proposal twice.

        Matches ``test_assessor_e2e.StubLlmClient.propose_twice``: pop one
        proposal and return ``(p, p)`` so single-proposal cases pass the
        dual-pass agreement check without queuing duplicates in every
        case file. Disagreement cases queue two distinct proposals and
        rely on the orchestrator's dual-pass branch.
        """
        p = self.propose(
            row=row,
            corrective_context=corrective_context,
            prior_attempts=prior_attempts,
            tagged_evidence=tagged_evidence,
            crm_responsibility=crm_responsibility,
            boundary_brief=boundary_brief,
        )
        return (p, p)


class AssertNoCallStub:
    """LLM client that raises if any propose call is attempted.

    Used by the eval harness's ``engine-only`` mode: the engine should
    short-circuit on every row before reaching gate 7. If the orchestrator
    falls through to the LLM call, we want the run to fail loudly with the
    row that escaped — not silently degrade to abstain.

    Both ``propose`` and ``propose_twice`` raise ``AssertionError`` with a
    message that includes the ``CcisRow.cci_id`` so the operator can see
    exactly which CCI the engine couldn't resolve deterministically.

    The kernel's ``Assessor`` only requires the client to expose those two
    methods — same minimum surface as ``StubLlmClient`` — so this works as
    a drop-in replacement.
    """

    def __init__(self) -> None:
        # No queue; calls are recorded only for post-run diagnostics if
        # the run somehow swallows the AssertionError.
        self.calls: list[dict] = []

    def propose(
        self,
        *,
        row: CcisRow,
        corrective_context: str | None = None,
        prior_attempts: list[LlmProposal] | None = None,
        tagged_evidence: str | None = None,
        crm_responsibility: str | None = None,
        boundary_brief: str | None = None,
    ) -> LlmProposal:
        self.calls.append(
            {
                "row": row,
                "corrective_context": corrective_context,
                "prior_attempts": list(prior_attempts) if prior_attempts else None,
                "tagged_evidence": tagged_evidence,
                "crm_responsibility": crm_responsibility,
                "boundary_brief": boundary_brief,
            }
        )
        raise AssertionError(
            f"engine-only mode reached the LLM for CCI {row.cci_id!r} — "
            "the engine should have short-circuited via Rule_8a/8b/CRM/"
            "Rule_8c/NoEvidence/Cache. Inspect stub.calls for context."
        )

    def propose_twice(
        self,
        *,
        row: CcisRow,
        corrective_context: str | None = None,
        prior_attempts: list[LlmProposal] | None = None,
        tagged_evidence: str | None = None,
        crm_responsibility: str | None = None,
        boundary_brief: str | None = None,
    ) -> tuple[LlmProposal, LlmProposal]:
        # propose() raises before returning, so this never produces a tuple;
        # the call is forwarded so the AssertionError carries the same CCI
        # context and the call is still recorded.
        self.propose(
            row=row,
            corrective_context=corrective_context,
            prior_attempts=prior_attempts,
            tagged_evidence=tagged_evidence,
            crm_responsibility=crm_responsibility,
            boundary_brief=boundary_brief,
        )
        raise AssertionError("unreachable")  # pragma: no cover
