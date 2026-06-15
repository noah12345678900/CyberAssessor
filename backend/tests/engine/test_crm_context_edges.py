"""CRM audit edge-case tests — pins risks turned up by the crm-audit pass.

Goals (each test pins one finding so a future change can't silently
regress):

1. **Multi-scope_label precision** (`crm_context.build_crm_context`):
   when two CRMs targeting different cloud scopes (e.g. AWS GovCloud
   vs Azure) cover the same control_id with different verdicts, the
   legacy ``by_control`` map keeps only the latest-attached entry —
   the deterministic short-circuit path in ``assessor._run`` reads
   ``by_control`` (via ``_lookup_crm``) and will silently drop the
   more-restrictive earlier verdict. Per the precision-over-recall
   rule, the kernel should never let "inherited" win over "customer"
   for the same control just because of attach order.

2. **validate_dual_narratives leak detection** is phrase-list-based —
   pin its true positives, then mark its known blind spot for
   paraphrased provider language so we don't pretend it's robust.

3. **Empty CRM context safety**: lookup() and implementations() must
   both be call-safe on an empty/unbuilt context (defends the
   overlay-default-local rule from a future NoneType refactor).

4. **CRM backfill on hybrid/customer**: backfill must NOT write
   Assessment rows for hybrid/customer verdicts — those need the LLM,
   and a deterministic write here would silently set the status
   without evidence.

Uses the same in-memory SQLite + StaticPool fixture pattern as
``test_crm_context.py``.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.engine.crm_context import (  # noqa: E402
    CrmContext,
    build_crm_context,
)
from cybersecurity_assessor.engine.validator import (  # noqa: E402
    validate_dual_narratives,
)
from cybersecurity_assessor.models import (  # noqa: E402
    Baseline,
    BaselineControl,
    BaselineSourceType,
    Control,
    Framework,
    Workbook,
    WorkbookOverlay,
)


# ---------------------------------------------------------------------------
# Fixtures (mirror test_crm_context.py — same shapes, same helpers)
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


@pytest.fixture
def framework(session) -> Framework:
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)
    return fw


@pytest.fixture
def controls(session, framework) -> dict[str, Control]:
    out: dict[str, Control] = {}
    for cid, title, family in (
        ("ac-2", "Account Management", "AC"),
        ("ac-2.1", "Automated Account Management", "AC"),
    ):
        c = Control(
            framework_id=framework.id, control_id=cid, title=title, family=family
        )
        session.add(c)
        session.commit()
        session.refresh(c)
        out[cid] = c
    return out


@pytest.fixture
def workbook(session) -> Workbook:
    wb = Workbook(path="C:/wb/edges.xlsx", filename="edges.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb


def _add_crm_baseline(
    session: Session,
    *,
    framework_id: int,
    name: str,
    scope_label: str | None = None,
) -> Baseline:
    b = Baseline(
        framework_id=framework_id,
        name=name,
        source_type=BaselineSourceType.CRM,
        scope_label=scope_label,
    )
    session.add(b)
    session.commit()
    session.refresh(b)
    return b


def _add_bc(
    session: Session,
    *,
    baseline_id: int,
    control_id_int: int,
    responsibility: str | None,
    narrative: str | None = None,
) -> BaselineControl:
    bc = BaselineControl(
        baseline_id=baseline_id,
        control_id=control_id_int,
        responsibility=responsibility,
        responsibility_narrative=narrative,
    )
    session.add(bc)
    session.commit()
    session.refresh(bc)
    return bc


def _attach(
    session: Session,
    *,
    workbook_id: int,
    baseline_id: int,
    attached_at: datetime,
) -> WorkbookOverlay:
    ov = WorkbookOverlay(
        workbook_id=workbook_id,
        baseline_id=baseline_id,
        attached_at=attached_at,
    )
    session.add(ov)
    session.commit()
    session.refresh(ov)
    return ov


_T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# RISK 1 — Multi-scope_label CRM conflict (PRECISION-LOSS)
# ---------------------------------------------------------------------------


def test_multi_scope_label_latest_wins_in_by_control_can_drop_customer_verdict(
    session, workbook, framework, controls
):
    """Pins a precision risk: latest attach silently overrides earlier.

    Two CRMs targeting the same control under different scope_labels:
      - AWS GovCloud  -> "customer"  (older attach)
      - Azure         -> "inherited" (newer attach)

    The legacy ``by_control`` map keeps only the Azure "inherited" entry,
    so ``ctx.lookup("ac-2").responsibility == "inherited"``. The
    assessor's deterministic short-circuit reads exactly this field and
    would mark the control COMPLIANT-by-inheritance — losing the AWS
    half's customer-side work.

    The per-scope ``by_control_impls`` map DOES preserve both slices,
    so the multi-impl persistence path still sees the customer work.
    This test documents the asymmetry so a future refactor either
      (a) folds the per-scope view into the short-circuit decision, or
      (b) explicitly downgrades the legacy lookup() to "the most
          restrictive responsibility across attached scopes".
    """
    aws = _add_crm_baseline(
        session, framework_id=framework.id, name="AWS-Gov CRM",
        scope_label="AWS GovCloud",
    )
    azure = _add_crm_baseline(
        session, framework_id=framework.id, name="Azure CRM",
        scope_label="Azure",
    )
    _add_bc(
        session, baseline_id=aws.id,
        control_id_int=controls["ac-2"].id,
        responsibility="customer",
        narrative="Customer manages IAM in AWS GovCloud",
    )
    _add_bc(
        session, baseline_id=azure.id,
        control_id_int=controls["ac-2"].id,
        responsibility="inherited",
        narrative="Inherited from Azure Active Directory baseline",
    )
    # Azure attached AFTER AWS — latest-wins ordering.
    _attach(session, workbook_id=workbook.id, baseline_id=aws.id, attached_at=_T0)
    _attach(
        session, workbook_id=workbook.id, baseline_id=azure.id,
        attached_at=_T0 + timedelta(hours=1),
    )

    ctx = build_crm_context(workbook.id, session)

    # The legacy lookup() reflects only the newest attach — the
    # short-circuit path will short-circuit on "inherited" and drop
    # the AWS-side customer work. FIXME(crm-audit): see file header.
    entry = ctx.lookup("ac-2")
    assert entry is not None
    assert entry.responsibility == "inherited", (
        "Latest-wins is in effect; if this assertion ever flips, the "
        "short-circuit logic in assessor._run also needs to change."
    )

    # Per-scope view DOES carry both — the persistence path is fine.
    slices = ctx.implementations("ac-2")
    scopes = {s.scope_label: s.responsibility for s in slices}
    assert "AWS GovCloud" in scopes
    assert "Azure" in scopes
    assert scopes["AWS GovCloud"] == "customer"
    assert scopes["Azure"] == "inherited"
    # Customer-owned cloud slice -> synth On-Prem slice appended.
    assert any(s.scope_label.lower().startswith("on-prem") for s in slices)


def test_multi_scope_label_customer_wins_over_inherited_when_attached_last(
    session, workbook, framework, controls
):
    """Symmetric to the prior test — flip the attach order, "customer" wins.

    Demonstrates the bug is order-dependent (not value-dependent): the
    SAME pair of CRMs produces a different short-circuit decision based
    only on which one happened to be uploaded second. A precision-first
    kernel should pick the most-restrictive verdict deterministically,
    not the freshest attach.
    """
    aws = _add_crm_baseline(
        session, framework_id=framework.id, name="AWS-Gov CRM",
        scope_label="AWS GovCloud",
    )
    azure = _add_crm_baseline(
        session, framework_id=framework.id, name="Azure CRM",
        scope_label="Azure",
    )
    _add_bc(
        session, baseline_id=aws.id,
        control_id_int=controls["ac-2"].id,
        responsibility="customer",
    )
    _add_bc(
        session, baseline_id=azure.id,
        control_id_int=controls["ac-2"].id,
        responsibility="inherited",
    )
    # Azure FIRST, AWS second — opposite of prior test.
    _attach(session, workbook_id=workbook.id, baseline_id=azure.id, attached_at=_T0)
    _attach(
        session, workbook_id=workbook.id, baseline_id=aws.id,
        attached_at=_T0 + timedelta(hours=1),
    )

    entry = build_crm_context(workbook.id, session).lookup("ac-2")
    assert entry is not None
    assert entry.responsibility == "customer", (
        "Flipping attach order flips the short-circuit verdict — "
        "precision-over-recall says the kernel should pick the more "
        "restrictive value, not the most recent."
    )


# ---------------------------------------------------------------------------
# RISK 2 — validate_dual_narratives is phrase-list based (FN-prone)
# ---------------------------------------------------------------------------


def test_validate_dual_narratives_catches_canonical_provider_leak():
    """True-positive: 'inherited from AWS' in on-prem half → flagged."""
    res = validate_dual_narratives(
        narrative_on_prem="Inherited from AWS GovCloud baseline.",
        narrative_cloud="Customer manages IAM roles.",
        crm_responsibility=None,
    )
    assert res.flagged, "canonical provider phrase should produce a note"
    assert any("provider-only language" in n for n in res.notes)


def test_validate_dual_narratives_misses_paraphrased_provider_attribution():
    """Documented blind spot: paraphrased provider language is NOT caught.

    The leak detector is a small literal-phrase table. Common paraphrases
    that mean exactly "the CSP handles this" sail through with zero
    notes. The result is advisory (NOTE-level) and assessment still
    proceeds, so this is a *fidelity* gap, not a correctness gap —
    pinned here so any move toward enforcement notices the blind spot.

    FIXME(crm-audit): if validate_dual_narratives ever becomes
    rejection-grade rather than advisory, replace the phrase table
    with the narrative-embedding classifier already used in crm_sanity.
    """
    paraphrases = [
        "AWS handles this control for us at the platform layer.",
        "The cloud provider is responsible for this requirement.",
        "Managed entirely by the CSP under the shared responsibility model.",
    ]
    for paraphrase in paraphrases:
        res = validate_dual_narratives(
            narrative_on_prem=paraphrase,
            narrative_cloud="Mirrors on-prem implementation.",
            crm_responsibility=None,
        )
        assert not res.flagged, (
            f"phrase-list miss documented for: {paraphrase!r}"
        )


def test_validate_dual_narratives_crm_mismatch_cross_check():
    """CRM=customer + non-empty cloud half → mismatch note (true positive)."""
    res = validate_dual_narratives(
        narrative_on_prem="Customer-owned IAM controls on the bastion hosts.",
        narrative_cloud="Customer-owned IAM also configured in cloud console.",
        crm_responsibility="customer",
    )
    assert res.flagged
    assert any("customer-owned" in n.lower() for n in res.notes)


# ---------------------------------------------------------------------------
# RISK 3 — Empty / missing CRM safety (overlay-default-local rule)
# ---------------------------------------------------------------------------


def test_empty_context_implementations_returns_empty_list_not_none():
    """``implementations()`` on a fresh empty context never raises.

    Defends the overlay-default-local rule: the kernel must be able to
    call ``ctx.implementations(any_control_id)`` without checking the
    map first. Returns ``[]`` so the caller falls through to the
    legacy single-result path.
    """
    ctx = CrmContext.empty()
    assert ctx.implementations("ac-2") == []
    assert ctx.implementations("nonexistent") == []
    assert ctx.lookup("ac-2") is None


def test_workbook_with_only_responsibility_null_crm_produces_empty_context(
    session, workbook, framework, controls
):
    """A CRM whose only row has responsibility=NULL must NOT contribute.

    Reinforces the overlay-default-local rule at the build_crm_context
    layer: if every row in the CRM is silent, the workbook's effective
    state is identical to "no CRM attached" and the assessor must run
    the full LLM path.
    """
    crm = _add_crm_baseline(session, framework_id=framework.id, name="silent")
    _add_bc(
        session, baseline_id=crm.id,
        control_id_int=controls["ac-2"].id,
        responsibility=None,
        narrative="will be filled in later",
    )
    _attach(session, workbook_id=workbook.id, baseline_id=crm.id, attached_at=_T0)

    ctx = build_crm_context(workbook.id, session)
    assert ctx.by_control == {}
    assert ctx.by_control_impls == {}
    assert ctx.lookup("ac-2") is None
    assert ctx.implementations("ac-2") == []


# ---------------------------------------------------------------------------
# RISK 4 — Backfill must never write hybrid/customer rows
# ---------------------------------------------------------------------------


def test_backfill_deterministic_set_excludes_hybrid_and_customer():
    """The deterministic backfill set must be exactly the 3 short-circuit values.

    Hybrid prepends a scoping block to the LLM prompt; customer is a
    no-op short-circuit on the LLM path. Writing either at attach time
    would silently set an Assessment status without ever calling the
    LLM — a precision violation.
    """
    from cybersecurity_assessor.engine.crm_backfill import _DETERMINISTIC

    assert _DETERMINISTIC == {"provider", "inherited", "not_applicable"}
    assert "customer" not in _DETERMINISTIC
    assert "hybrid" not in _DETERMINISTIC
