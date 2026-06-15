"""Unit tests for ``stitch_scope_narrative`` — the visual / save-only
multi-boundary column-Q renderer.

Contract under test (set by the user's clarification "it just needs to be
added visually and for when you save not logically"):

  * PRESENTATION-ONLY. The function turns a ``{scope_label: narrative}`` map
    into one labeled block (``<label>:\\n\\n<text>``) joined by blank lines.
  * Returns ``None`` for 0 or 1 populated scope so callers fall back with
    ``stitch_scope_narrative(...) or narrative`` and keep the plain canonical
    narrative — nothing to stitch.
  * Cloud platforms render first (insertion order), the synthesized
    ``On-Premises`` slice last, mirroring the impl-slice ordering the rest of
    the app uses.

There is NO validation / classification behavior here by design — the verdict
is classified on the single ``Decision.narrative`` upstream, never on this
stitched form.
"""

from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor.baselines.scope_labels import (  # noqa: E402
    ON_PREM_LABEL,
)
from cybersecurity_assessor.engine.assessor import (  # noqa: E402
    stitch_scope_narrative,
)


def test_none_input_returns_none():
    assert stitch_scope_narrative(None) is None


def test_empty_map_returns_none():
    assert stitch_scope_narrative({}) is None


def test_single_scope_returns_none():
    """One scope = nothing to stitch; caller keeps the plain narrative."""
    assert (
        stitch_scope_narrative({"AWS GovCloud": "Provider attests via CSP SSP."})
        is None
    )


def test_single_scope_with_blank_sibling_returns_none():
    """A second scope whose text is whitespace-only doesn't count."""
    out = stitch_scope_narrative(
        {"AWS GovCloud": "Real cloud text.", ON_PREM_LABEL: "   "}
    )
    assert out is None


def test_two_scopes_stitch_with_labels_and_blank_lines():
    out = stitch_scope_narrative(
        {
            "AWS GovCloud": "Provider attests via CSP SSP.",
            ON_PREM_LABEL: "Verified via USD00050010 §3.2 on the Example System enclave.",
        }
    )
    assert out == (
        "AWS GovCloud:\n\nProvider attests via CSP SSP."
        "\n\n"
        f"{ON_PREM_LABEL}:\n\nVerified via USD00050010 §3.2 on the Example System enclave."
    )


def test_on_prem_always_rendered_last():
    """Even when On-Premises is inserted first, it sorts to the bottom."""
    out = stitch_scope_narrative(
        {
            ON_PREM_LABEL: "On-prem residual finding; POA&M opened.",
            "Azure Gov": "Azure provider side.",
        }
    )
    lines = out.splitlines()
    assert lines[0] == "Azure Gov:"
    # On-Premises header must come AFTER the cloud header in the block.
    assert lines.index(f"{ON_PREM_LABEL}:") > lines.index("Azure Gov:")
    # ...and it's the last labeled section (its text is the final line).
    assert lines[-1] == "On-prem residual finding; POA&M opened."


def test_multiple_clouds_preserve_insertion_order_then_on_prem():
    """>2 scopes: clouds first in insertion order, On-Premises last."""
    out = stitch_scope_narrative(
        {
            "AWS GovCloud": "AWS side.",
            "Azure Gov": "Azure side.",
            ON_PREM_LABEL: "On-prem side.",
        }
    )
    assert out == (
        "AWS GovCloud:\n\nAWS side."
        "\n\n"
        "Azure Gov:\n\nAzure side."
        "\n\n"
        f"{ON_PREM_LABEL}:\n\nOn-prem side."
    )


def test_text_is_stripped_before_stitching():
    out = stitch_scope_narrative(
        {"AWS GovCloud": "  padded cloud  ", ON_PREM_LABEL: "\npadded onprem\n"}
    )
    assert out == (
        "AWS GovCloud:\n\npadded cloud"
        "\n\n"
        f"{ON_PREM_LABEL}:\n\npadded onprem"
    )
