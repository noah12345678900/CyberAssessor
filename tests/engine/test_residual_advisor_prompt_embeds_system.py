"""Guard: the residual advisor MUST embed its system prompt in the message.

Regression for the "residual risk advisor is genuinely broken" bug. The
client method the advisor calls, ``extract_system_context``, deliberately
sends NO ``system=`` parameter (its contract: "the caller embeds the full
instructions in ``prompt``"). The advisor used to emit only the structured
data — relying on a stale comment that claimed the client loads
``residual_advisor.md``. The model therefore received a bare data dump with
no output contract, produced free-form prose, ``_parse_extraction_json``
found no JSON, and EVERY POAM hard-abstained with ``[parse_error]``.

No existing test caught this because the unit suite stubs
``extract_system_context`` to return clean JSON, never exercising the
prompt-content path. This test asserts the rendered message actually carries
the instruction set, so the advisor can never silently regress to a
data-only prompt again.
"""

from __future__ import annotations

# tests/conftest.py puts the backend package on sys.path.
from cybersecurity_assessor.models import Poam
from cybersecurity_assessor.poam.residual_advisor import (
    ADVISOR_SYSTEM_PROMPT,
    build_advisor_prompt,
)


def test_system_prompt_is_loaded_and_nonempty():
    """The .md instruction set loads at import (not an empty sentinel)."""
    assert ADVISOR_SYSTEM_PROMPT, "residual_advisor.md must load at import"
    # Sanity: it's the real contract, not a stub.
    assert "suggested_residual" in ADVISOR_SYSTEM_PROMPT
    assert "json" in ADVISOR_SYSTEM_PROMPT.lower()


def test_build_advisor_prompt_embeds_system_instructions():
    """The rendered message prepends the system prompt ahead of the data.

    Without this, the model gets `## POAM ...` with no instructions and
    every call parse-errors.
    """
    poam = Poam(
        vulnerability_description="Test finding.",
        raw_severity=None,
        likelihood=None,
        impact=None,
    )
    msg = build_advisor_prompt(poam, findings=[], narratives=[])

    # The instruction set must be present...
    assert "suggested_residual" in msg, (
        "rendered advisor message must embed the system prompt (output "
        "contract) — otherwise the model has no JSON instructions and every "
        "POAM hard-abstains with [parse_error]"
    )
    # ...and it must come BEFORE the data section.
    assert msg.index("suggested_residual") < msg.index("## POAM"), (
        "instructions must be prepended ahead of the ## POAM data block"
    )
    # The data section is still present.
    assert "## POAM" in msg
    assert "## Contributing findings" in msg
    assert "## Linked control narratives" in msg
