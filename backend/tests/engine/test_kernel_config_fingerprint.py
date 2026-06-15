"""Pin the v0.3 patent-defensibility contract for the kernel-config snapshot.

The kernel's runtime tuning knobs (``CONFIDENCE_THRESHOLD`` and
``DUAL_PASS_ENABLED``) used to be silent inputs to every decision — a
reviewer who lowered the confidence floor would leave high-confidence
needs_review verdicts cached against the *old* threshold, masking the
precision-over-recall change they just made.

Audit item #4 closes that hole: ``active_kernel_config()`` snapshots the
current module values, ``kernel_config_signature()`` hashes the snapshot,
and ``decision_cache.fingerprint()`` bakes the hash into every cache key.
A knob flip therefore changes the fingerprint, the next ``lookup()``
cleanly misses, and the LLM re-evaluates under the new contract — same
mechanism KERNEL_VERSION uses, but auto-derived so engineers can't
forget to bump it.

The four tests below pin both ends of the contract:

  1. Snapshot reads the *live* module values (monkeypatch-observable),
     not an import-time freeze.
  2. The signature is byte-stable for unchanged inputs.
  3. Flipping ``DUAL_PASS_ENABLED`` changes the signature.
  4. Flipping ``CONFIDENCE_THRESHOLD`` changes the decision fingerprint
     end-to-end — the regression boundary the audit item targets.
"""

from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor.engine import assessor, decision_cache  # noqa: E402
from cybersecurity_assessor.engine.assessor import (  # noqa: E402
    KernelConfig,
    active_kernel_config,
    kernel_config_signature,
)
from cybersecurity_assessor.excel.ccis_reader import CcisRow  # noqa: E402


def _row() -> CcisRow:
    """Minimal CcisRow — every field None/blank so only the config knob
    moves between fingerprint calls in test 4.
    """
    return CcisRow(
        excel_row=7,
        required=True,
        control_id="AC-2",
        ap_acronym="AC-2.1",
        cci_id="CCI-000015",
        implementation_status=None,
        designation=None,
        narrative=None,
        definition=None,
        guidance=None,
        procedures=None,
        inherited=None,
        remote_inheritance=None,
        status=None,
        date_tested=None,
        tester=None,
        results=None,
        previous_status=None,
        previous_date=None,
        previous_tester=None,
        previous_results=None,
    )


def test_active_kernel_config_reads_live_module_values(monkeypatch):
    """``active_kernel_config()`` must observe a monkeypatched constant.

    If this returned a frozen import-time snapshot the v0.2-gates test
    suite (which monkeypatches ``DUAL_PASS_ENABLED`` to True) would
    silently run against the default-False config — masking real
    behavioral drift. Read-on-every-call is the contract.
    """
    monkeypatch.setattr(assessor, "DUAL_PASS_ENABLED", True)
    monkeypatch.setattr(assessor, "CONFIDENCE_THRESHOLD", 0.99)

    cfg = active_kernel_config()
    assert isinstance(cfg, KernelConfig)
    assert cfg.dual_pass_enabled is True
    assert cfg.confidence_threshold == 0.99


def test_kernel_config_signature_stable_for_unchanged_inputs():
    """Two calls without any knob change must return byte-identical hashes.

    The cache invariant rests on this — if the signature drifted between
    a store() and the next lookup() with the same config, every entry
    would silently miss and the LLM would re-evaluate every run.
    """
    sig1 = kernel_config_signature()
    sig2 = kernel_config_signature()
    assert sig1 == sig2
    # 12-char truncation contract — keeps log lines compact.
    assert len(sig1) == 12


def test_kernel_config_signature_changes_when_dual_pass_flipped(monkeypatch):
    """Flipping ``DUAL_PASS_ENABLED`` must produce a different signature.

    The defensible claim: any tuning change automatically invalidates
    cached decisions made under the old value. Pinned at the signature
    layer so a refactor that breaks this surfaces here, not via a
    silently-stale prod cache.
    """
    baseline = kernel_config_signature()
    monkeypatch.setattr(assessor, "DUAL_PASS_ENABLED", not assessor.DUAL_PASS_ENABLED)
    flipped = kernel_config_signature()
    assert baseline != flipped


def test_decision_fingerprint_changes_when_confidence_threshold_changes(monkeypatch):
    """End-to-end: ``fingerprint()`` output diverges when the threshold moves.

    This is the regression boundary the audit item targets. Same row,
    same evidence, same CRM context — only the confidence floor moves.
    The cache key MUST change so the next lookup misses cleanly and the
    LLM re-evaluates under the new precision-over-recall posture.
    """
    row = _row()
    fp_before = decision_cache.fingerprint(
        row=row, tagged_evidence=None, crm_context=None
    )

    monkeypatch.setattr(assessor, "CONFIDENCE_THRESHOLD", 0.99)
    fp_after = decision_cache.fingerprint(
        row=row, tagged_evidence=None, crm_context=None
    )

    assert fp_before != fp_after
