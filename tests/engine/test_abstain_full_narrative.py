"""Regression: a hard-abstain persists the FULL narrative, not a truncated reason.

AC-7 bug: the self-abstain path called ``_abstain(row, cci,
f"{reason_prefix}: {proposal.narrative[:300]}")`` with NO ``narrative=``
kwarg. ``_coerce_abstain_persistence_fields`` then fell back to the
300-char-truncated ``review_reason`` as the column-Q narrative, so the cell
ended mid-word ("...shows GPO Example-System-Har"). The fix passes the full
proposal narrative as ``narrative=`` and makes the coercion prefix use only
the reason's short CATEGORY ("llm-abstain") instead of echoing the whole
300-char reason (which had duplicated the narrative head).
"""

from __future__ import annotations

from cybersecurity_assessor.engine.assessor import Decision
from cybersecurity_assessor.models import ComplianceStatus, NarrativeClass
from cybersecurity_assessor.routes.controls import (
    _coerce_abstain_persistence_fields,
)

# A conflicting-evidence narrative longer than the 300-char telemetry slice.
_FULL = (
    "Conflicting evidence on the on-prem Example System enclave for the "
    "AC-7(a) lockout threshold: GPO export USD20240218 (Password Policy, "
    "dated 2026-04-21) shows threshold = 5 attempts / 15-min reset, while "
    "the Windows Server 2022 STIG CKL (chunk 0, SV-254244r877393_rule) shows "
    "GPO Example-System-Hardening sets the lockout threshold to 3 attempts. "
    "The two artifacts disagree; a reviewer must reconcile which GPO is "
    "authoritative before a defensible verdict can be issued for this CCI."
)


def _hard_abstain_decision() -> Decision:
    # Mirrors the kernel's self-abstain shape AFTER the fix: full narrative on
    # ``narrative``, the truncated telemetry label on ``review_reason``.
    return Decision(
        cci_id="CCI-000044",
        excel_row=8,
        accepted=True,
        status=None,  # hard abstain
        narrative=_FULL,
        narrative_class=NarrativeClass.AMBIGUOUS,
        source="abstain",
        rule=None,
        needs_review=True,
        review_reason=f"llm-abstain: {_FULL[:300]}",
    )


def test_column_q_carries_full_narrative_not_truncated():
    status, narrative = _coerce_abstain_persistence_fields(_hard_abstain_decision())
    assert status is ComplianceStatus.NON_COMPLIANT
    # The full narrative survives — including the tail that used to be cut off.
    assert _FULL in narrative
    assert narrative.rstrip().endswith("for this CCI.")
    assert "Example-System-Hardening sets the lockout threshold to 3" in narrative


def test_column_q_prefix_is_short_category_not_300_char_echo():
    _, narrative = _coerce_abstain_persistence_fields(_hard_abstain_decision())
    # Prefix is the short category label, applied once.
    assert narrative.startswith("[Needs review — llm-abstain]")
    # The 300-char reason head must NOT be echoed into the prefix (the old
    # double-up). The narrative body appears exactly once.
    assert narrative.count("Conflicting evidence on the on-prem") == 1


def test_hard_abstain_without_narrative_still_falls_back_to_reason():
    """No narrative at all → cell falls back to the review_reason (unchanged)."""
    d = Decision(
        cci_id="X",
        excel_row=1,
        accepted=True,
        status=None,
        narrative=None,
        narrative_class=NarrativeClass.AMBIGUOUS,
        source="abstain",
        rule=None,
        needs_review=True,
        review_reason="no-evidence: nothing tagged for this CCI",
    )
    status, narrative = _coerce_abstain_persistence_fields(d)
    assert status is ComplianceStatus.NON_COMPLIANT
    assert narrative == "no-evidence: nothing tagged for this CCI"
