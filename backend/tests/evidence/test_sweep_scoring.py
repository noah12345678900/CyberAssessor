"""Unit tests for the boundary-aware sweep scorer.

Covers the three things that have to stay stable across refactors:

1. :func:`build_boundary_fingerprint` constructs the right set of
   tokens from a workbook + CRM, and the CRM skip-family veto follows
   the conservative "every in-scope control in the family must be
   provider/inherited/not_applicable" rule (per
   ``SHAREPOINT_SWEEP_DESIGN.md`` and the overlay-default-local memo).
2. :func:`score_candidate` applies the documented weight table
   exactly — drift here silently changes which files surface in the
   triage dialog.
3. Files matching ONLY a skip-list family are dropped (veto path),
   while files that *also* hit a non-skip family still surface.

All tests use the in-memory SQLite + StaticPool pattern shared by the
other evidence tests, with no cross-suite fixture imports.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.evidence.sources.sweep import (  # noqa: E402
    BoundaryFingerprint,
    SCORE_PRECHECK_THRESHOLD,
    SCORE_SURFACE_THRESHOLD,
    build_boundary_fingerprint,
    score_candidate,
    _W_CONTROL_ID,
    _W_CRM_KEYWORD,
    _W_DOC_PREFIX,
    _W_FAMILY,
    _W_HOST,
)
from cybersecurity_assessor.models import (  # noqa: E402
    Baseline,
    BaselineControl,
    BaselineObjective,
    BaselineSourceType,
    Control,
    Evidence,
    EvidenceKind,
    Framework,
    Objective,
    Workbook,
    WorkbookOverlay,
)


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


@pytest.fixture
def seeded(session, tmp_path):
    """Workbook + primary baseline + CRM overlay covering AC and AU.

    - AC-2 + AC-2(1)  ->  in-scope, customer (full assessment)
    - AU-2 + AU-3      ->  in-scope, CRM marks BOTH as provider (skip family)
    - SC-7             ->  in-scope, no CRM entry (silence = customer)

    Plus one Evidence row with host_inventory + a USD-numbered doc so the
    fingerprint picks up host tokens and the doc-prefix fallback isn't the
    only contributor.
    """
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)

    # Control IDs are stored in OSCAL canonical lowercase ("ac-2", "ac-2.1")
    # because that's what _normalize_control_id and _ccis_to_oscal_control_id
    # produce when the catalog is loaded — and what the production CRM lookup
    # path expects (see crm_context.CrmContext.by_control keying).
    ctrls: dict[str, Control] = {}
    for cid, family in [
        ("ac-2", "AC"),
        ("ac-2.1", "AC"),
        ("au-2", "AU"),
        ("au-3", "AU"),
        ("sc-7", "SC"),
    ]:
        c = Control(
            framework_id=fw.id,
            control_id=cid,
            title=f"{cid} title",
            family=family,
        )
        session.add(c)
        ctrls[cid] = c
    session.commit()
    for c in ctrls.values():
        session.refresh(c)

    # One CCI per control so proposed_ccis has something to surface.
    objs_by_ctrl: dict[str, Objective] = {}
    for cid, c in ctrls.items():
        o = Objective(
            control_id_fk=c.id,
            objective_id=f"CCI-{cid.replace('-', '').replace('(', '').replace(')', '')}",
            source="CCI",
            text=f"objective for {cid}",
        )
        session.add(o)
        objs_by_ctrl[cid] = o
    session.commit()
    for o in objs_by_ctrl.values():
        session.refresh(o)

    # Primary baseline + in-scope rows for every control.
    primary = Baseline(
        framework_id=fw.id,
        name="primary",
        source_type=BaselineSourceType.CCIS_WORKBOOK,
    )
    session.add(primary)
    session.commit()
    session.refresh(primary)
    for c in ctrls.values():
        session.add(BaselineControl(baseline_id=primary.id, control_id=c.id, in_scope=True))
    for o in objs_by_ctrl.values():
        session.add(BaselineObjective(baseline_id=primary.id, objective_id=o.id))
    session.commit()

    # CRM overlay baseline — provider for both AU-2 and AU-3 (skip the
    # whole AU family), customer for AC-2 + narrative full of distinctive
    # keywords so we can assert crm_keywords tokenization.
    crm = Baseline(
        framework_id=fw.id,
        name="crm",
        source_type=BaselineSourceType.CRM,
    )
    session.add(crm)
    session.commit()
    session.refresh(crm)
    session.add(
        BaselineControl(
            baseline_id=crm.id,
            control_id=ctrls["ac-2"].id,
            in_scope=True,
            responsibility="customer",
            responsibility_narrative="GitLab role assignments enforce account management via Okta.",
        )
    )
    session.add(
        BaselineControl(
            baseline_id=crm.id,
            control_id=ctrls["au-2"].id,
            in_scope=True,
            responsibility="provider",
        )
    )
    session.add(
        BaselineControl(
            baseline_id=crm.id,
            control_id=ctrls["au-3"].id,
            in_scope=True,
            responsibility="provider",
        )
    )
    session.commit()

    # Workbook backed by a real file, pointed at primary baseline.
    p = tmp_path / "seeded.xlsx"
    p.write_bytes(b"x")
    wb = Workbook(
        path=str(p),
        filename=p.name,
        framework_id=fw.id,
        baseline_id=primary.id,
    )
    session.add(wb)
    session.commit()
    session.refresh(wb)
    session.add(WorkbookOverlay(workbook_id=wb.id, baseline_id=crm.id))

    # One Evidence row contributes hosts + a USD doc number.
    ev = Evidence(
        path="file:///x/y/USD00012345-policy.pdf",
        sha256="deadbeef",
        kind=EvidenceKind.PDF,
        size_bytes=10,
        doc_number="USD00012345",
        host_inventory='["server01", "db-prod-01"]',
    )
    session.add(ev)
    session.commit()

    return {"workbook": wb, "controls": ctrls, "primary": primary, "crm": crm}


# ---------------------------------------------------------------------------
# build_boundary_fingerprint
# ---------------------------------------------------------------------------


def test_fingerprint_captures_in_scope_controls_and_families(seeded, session):
    fp = build_boundary_fingerprint(workbook_id=seeded["workbook"].id, session=session)

    assert fp.workbook_id == seeded["workbook"].id
    assert fp.control_families == frozenset({"AC", "AU", "SC"})
    assert fp.in_scope_control_ids == frozenset(
        {"ac-2", "ac-2.1", "au-2", "au-3", "sc-7"}
    )


def test_fingerprint_lifts_host_tokens_from_evidence(seeded, session):
    fp = build_boundary_fingerprint(workbook_id=seeded["workbook"].id, session=session)
    # Hosts are lowercased and trimmed.
    assert "server01" in fp.host_tokens
    assert "db-prod-01" in fp.host_tokens


def test_fingerprint_picks_up_usd_doc_prefix(seeded, session):
    fp = build_boundary_fingerprint(workbook_id=seeded["workbook"].id, session=session)
    assert "USD" in fp.doc_number_prefixes


def test_fingerprint_skips_family_when_all_controls_provider(seeded, session):
    """AU-2 + AU-3 both provider -> whole AU family vetoed."""
    fp = build_boundary_fingerprint(workbook_id=seeded["workbook"].id, session=session)
    assert "AU" in fp.crm_skip_families
    # AC still in (CRM has it as customer) and SC still in (silence = customer).
    assert "AC" not in fp.crm_skip_families
    assert "SC" not in fp.crm_skip_families


def test_fingerprint_keeps_family_with_one_customer_control(session, tmp_path):
    """A single customer/hybrid control keeps the whole family in scope —
    even if every other control in the family is provider. This is the
    overlay-default-local rule applied at the family level."""
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)

    au2 = Control(framework_id=fw.id, control_id="au-2", title="t", family="AU")
    au3 = Control(framework_id=fw.id, control_id="au-3", title="t", family="AU")
    session.add_all([au2, au3])
    session.commit()
    session.refresh(au2)
    session.refresh(au3)

    primary = Baseline(framework_id=fw.id, name="p", source_type=BaselineSourceType.CCIS_WORKBOOK)
    session.add(primary)
    session.commit()
    session.refresh(primary)
    session.add(BaselineControl(baseline_id=primary.id, control_id=au2.id, in_scope=True))
    session.add(BaselineControl(baseline_id=primary.id, control_id=au3.id, in_scope=True))
    session.commit()

    crm = Baseline(framework_id=fw.id, name="crm", source_type=BaselineSourceType.CRM)
    session.add(crm)
    session.commit()
    session.refresh(crm)
    # AU-2 customer (decisive non-skip) → keep AU.
    session.add(BaselineControl(baseline_id=crm.id, control_id=au2.id, responsibility="customer"))
    session.add(BaselineControl(baseline_id=crm.id, control_id=au3.id, responsibility="provider"))
    session.commit()

    p = tmp_path / "wb.xlsx"
    p.write_bytes(b"x")
    wb = Workbook(path=str(p), filename=p.name, framework_id=fw.id, baseline_id=primary.id)
    session.add(wb)
    session.commit()
    session.refresh(wb)
    session.add(WorkbookOverlay(workbook_id=wb.id, baseline_id=crm.id))
    session.commit()

    fp = build_boundary_fingerprint(workbook_id=wb.id, session=session)
    assert "AU" not in fp.crm_skip_families


def test_fingerprint_missing_crm_entry_keeps_family(seeded, session):
    """SC-7 has no CRM row at all → silence = customer → SC stays in."""
    fp = build_boundary_fingerprint(workbook_id=seeded["workbook"].id, session=session)
    assert "SC" not in fp.crm_skip_families


def test_fingerprint_extracts_crm_keywords(seeded, session):
    fp = build_boundary_fingerprint(workbook_id=seeded["workbook"].id, session=session)
    ac2_kws = fp.crm_keywords.get("ac-2", frozenset())
    assert "gitlab" in ac2_kws
    assert "okta" in ac2_kws
    # Stopwords stripped.
    assert "the" not in ac2_kws


def test_fingerprint_does_not_emit_crm_keywords_for_skip_family(seeded, session):
    """No point tokenizing AU narrative when the whole family is vetoed."""
    fp = build_boundary_fingerprint(workbook_id=seeded["workbook"].id, session=session)
    assert "au-2" not in fp.crm_keywords
    assert "au-3" not in fp.crm_keywords


def test_fingerprint_proposes_ccis_per_control(seeded, session):
    fp = build_boundary_fingerprint(workbook_id=seeded["workbook"].id, session=session)
    # Each in-scope control got one CCI in seed data.
    assert "ac-2" in fp.control_ccis
    assert "ac-2.1" in fp.control_ccis
    assert "sc-7" in fp.control_ccis
    # AU still resolves CCIs even though the family is skip — the veto
    # is enforced at scoring time, not at fingerprint construction.
    assert "au-2" in fp.control_ccis


def test_fingerprint_unknown_workbook_returns_empty(session):
    fp = build_boundary_fingerprint(workbook_id=9999, session=session)
    assert fp.workbook_id == 9999
    assert fp.in_scope_control_ids == frozenset()
    assert fp.crm_skip_families == frozenset()


# ---------------------------------------------------------------------------
# score_candidate weight table
# ---------------------------------------------------------------------------


def _fp(
    *,
    hosts=(),
    families=(),
    controls=(),
    skip=(),
    crm_kw=None,
    doc_prefixes=(),
    control_ccis=None,
) -> BoundaryFingerprint:
    return BoundaryFingerprint(
        workbook_id=1,
        host_tokens=frozenset(hosts),
        control_families=frozenset(families),
        in_scope_control_ids=frozenset(controls),
        crm_skip_families=frozenset(skip),
        crm_keywords=dict(crm_kw or {}),
        doc_number_prefixes=frozenset(doc_prefixes),
        control_ccis=dict(control_ccis or {}),
    )


def test_score_host_token_weight():
    fp = _fp(hosts={"server01"})
    score, signals, _ = score_candidate("notes.txt", "/x/server01-config.txt", None, fp)
    assert score == pytest.approx(_W_HOST)
    assert "host:server01" in signals


def test_score_control_id_weight():
    fp = _fp(controls={"ac-2"}, families={"AC"}, control_ccis={"ac-2": ("ac-2.1",)})
    score, signals, ccis = score_candidate("AC-2 SOP.pdf", "/x/AC-2 SOP.pdf", None, fp)
    assert score == pytest.approx(_W_CONTROL_ID)
    # Signal carries OSCAL canonical form because that's what in_scope_control_ids stores.
    assert "control:ac-2" in signals
    assert ccis == ["ac-2.1"]


def test_score_family_keyword_weight():
    """A family keyword (e.g. 'firewall' for SC) fires only if the family
    is in scope — gives +0.20 and nothing else."""
    fp = _fp(families={"SC"})
    score, signals, _ = score_candidate("firewall ruleset.pdf", "/x/firewall.pdf", None, fp)
    assert score == pytest.approx(_W_FAMILY)
    assert "family:SC" in signals


def test_score_family_keyword_requires_family_in_scope():
    """If the family isn't in scope, the keyword does NOT fire."""
    fp = _fp(families={"AC"})  # SC NOT in scope
    score, signals, _ = score_candidate("firewall ruleset.pdf", "/x/firewall.pdf", None, fp)
    assert score == 0.0
    assert signals == []


def test_score_crm_keyword_weight():
    fp = _fp(
        families={"AC"},
        controls={"ac-2"},
        crm_kw={"ac-2": frozenset({"gitlab"})},
    )
    score, signals, _ = score_candidate(
        "gitlab access review.pdf", "/x/gitlab.pdf", None, fp
    )
    assert score == pytest.approx(_W_CRM_KEYWORD)
    assert any(s.startswith("crm-kw:gitlab") for s in signals)


def test_score_doc_prefix_weight():
    fp = _fp(doc_prefixes={"USD"})
    # No family/control hits — only the prefix fires.
    score, signals, _ = score_candidate("USD00012345-policy.pdf", "/x/usd.pdf", None, fp)
    assert score == pytest.approx(_W_DOC_PREFIX)
    assert "doc-prefix:USD" in signals


def test_score_additive_across_signals():
    """Multiple signals stack additively up to the 1.0 cap."""
    fp = _fp(
        hosts={"server01"},
        families={"AC"},
        controls={"ac-2"},
        crm_kw={"ac-2": frozenset({"okta"})},
        doc_prefixes={"USD"},
        control_ccis={"ac-2": ("ac-2.1",)},
    )
    score, _, _ = score_candidate(
        "USD00012345 AC-2 access control on server01 via okta.pdf",
        "/x/AC-2.pdf",
        None,
        fp,
    )
    raw = _W_HOST + _W_CONTROL_ID + _W_FAMILY + _W_CRM_KEYWORD + _W_DOC_PREFIX
    assert score == pytest.approx(min(1.0, raw))


def test_score_caps_at_one():
    """Raw weights sum to >1.0 — bar must cap visually-honest values."""
    raw = _W_HOST + _W_CONTROL_ID + _W_FAMILY + _W_CRM_KEYWORD + _W_DOC_PREFIX
    assert raw > 1.0, "test premise: weights must sum past 1.0"


def test_score_unrelated_file_is_zero():
    fp = _fp(hosts={"server01"}, families={"AC"}, controls={"ac-2"})
    score, signals, ccis = score_candidate("vacation_photos.jpg", "/x/photo.jpg", None, fp)
    assert score == 0.0
    assert signals == []
    assert ccis == []


def test_score_control_id_normalizes_enhancement_paren_to_dot():
    """Filename "AC-2(1)" must match fingerprint key "ac-2.1" — the regex
    matches the eMASS-style paren form, _normalize_control_id rewrites it
    to OSCAL dot form before the in-scope lookup."""
    fp = _fp(controls={"ac-2.1"}, families={"AC"}, control_ccis={"ac-2.1": ("ac-2.1.a",)})
    score, signals, ccis = score_candidate(
        "AC-2(1) enhancement matrix.pdf", "/x/AC-2(1).pdf", None, fp
    )
    assert score == pytest.approx(_W_CONTROL_ID)
    assert "control:ac-2.1" in signals
    assert ccis == ["ac-2.1.a"]


def test_score_control_id_normalizes_uppercase_filename_to_lowercase_fingerprint():
    """Regression: production stores Control.control_id in lowercase OSCAL
    form, filenames almost always use uppercase. Pre-fix, the +0.30 signal
    NEVER fired in production because the uppercase regex match was being
    looked up directly against the lowercase set."""
    fp = _fp(controls={"sc-7"}, families={"SC"})
    score, signals, _ = score_candidate(
        "SC-7 boundary protection.pdf", "/x/SC-7.pdf", None, fp
    )
    assert score >= _W_CONTROL_ID, "control-id signal must fire on uppercase filename"
    assert "control:sc-7" in signals


def test_score_host_match_requires_whole_word():
    """Substring 'ac' inside 'track' must not fire as host 'ac'."""
    fp = _fp(hosts={"ac"})
    score, signals, _ = score_candidate(
        "tracker.pdf", "/x/tracker-changes.pdf", None, fp
    )
    assert score == 0.0
    assert signals == []


# ---------------------------------------------------------------------------
# Skip-family veto
# ---------------------------------------------------------------------------


def test_skip_family_only_match_returns_zero():
    """A file that hits ONLY a skip-family keyword is dropped entirely."""
    fp = _fp(families={"AU"}, skip={"AU"})
    score, signals, ccis = score_candidate(
        "audit log policy.pdf", "/x/audit.pdf", None, fp
    )
    assert score == 0.0
    assert signals == []
    assert ccis == []


def test_skip_family_with_other_match_still_surfaces():
    """If the file also hits a non-skip family, the veto doesn't apply
    (the file probably touches both and should still be visible)."""
    fp = _fp(families={"AU", "SC"}, skip={"AU"})
    score, signals, _ = score_candidate(
        "audit log via firewall.pdf", "/x/audit-firewall.pdf", None, fp
    )
    # Two family hits, but family weight caps once per call.
    assert score == pytest.approx(_W_FAMILY)
    assert "family:SC" in signals
    # AU is in matched signals (we surface what we found) but the veto
    # does not fire because SC is also matched.
    assert "family:AU" in signals


def test_skip_family_crm_keywords_pruned_at_fingerprint():
    """The fingerprint never emits crm_keywords for a skip family, so
    score_candidate has nothing to match against for that family."""
    fp = _fp(
        families={"AU"},
        skip={"AU"},
        crm_kw={},  # explicitly empty — mirrors fingerprint behavior
    )
    score, signals, _ = score_candidate(
        "splunk audit pipeline.pdf", "/x/splunk.pdf", None, fp
    )
    # Falls through to family keyword (audit) — only family is AU (skip),
    # so the veto strips everything.
    assert score == 0.0
    assert signals == []


# ---------------------------------------------------------------------------
# Threshold constants
# ---------------------------------------------------------------------------


def test_thresholds_have_expected_relationship():
    """Pre-check must be strictly higher than surface — otherwise the UI
    pre-checks everything it shows."""
    assert SCORE_PRECHECK_THRESHOLD > SCORE_SURFACE_THRESHOLD
    assert 0.0 < SCORE_SURFACE_THRESHOLD < 1.0
    assert 0.0 < SCORE_PRECHECK_THRESHOLD <= 1.0
