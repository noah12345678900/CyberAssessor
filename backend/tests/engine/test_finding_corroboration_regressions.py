"""Regression tests for ``engine/finding_corroboration.py`` edge cases.

Pins bugs that the exploratory probe in ``test_edge_cases_probe.py`` first
surfaced. Three were real and now fixed; one is a regression guard for
NULL ``cci_refs`` (the function already handled it, but the join is so
central to both assessor narratives and POAM clusters that an explicit
guard test is cheaper than re-debugging a future regression).

Bugs pinned here:

  1. **Semicolon-delimited cci_refs**. DISA tooling emits cci_refs joined
     with EITHER "," OR ";" depending on the scanner. A semicolon-only
     payload like ``"CCI-000015;CCI-001735"`` was previously treated as
     one token by ``.split(",")``, silently producing zero matches.

  2. **Case-sensitive CCI compare**. Some upstream parsers lowercase CCI
     ids ("cci-000015"). The set-intersect was case-sensitive, so the
     lowercased finding never matched the canonical upper-case cluster set.

  3. **Windows backslash in label fallback**. ``path.rsplit("/", 1)[-1]``
     left full Windows paths (no forward slashes) intact, exposing the
     user's local filesystem in narrative + POAM output.

Importing ``models`` is required to register the SQLModel tables before
``SQLModel.metadata.create_all`` runs (canonical pattern in this repo).
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

import json  # noqa: E402

from cybersecurity_assessor import models  # noqa: F401,E402
from cybersecurity_assessor.engine.finding_corroboration import (  # noqa: E402
    _basename,
    affected_hosts,
    corroborating_findings,
)
from cybersecurity_assessor.models import (  # noqa: E402
    Control,
    Evidence,
    EvidenceKind,
    EvidenceTag,
    FindingStatus,
    Framework,
    Objective,
    StigFinding,
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
def objective(session) -> Objective:
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)
    ctrl = Control(
        framework_id=fw.id, control_id="AC-2", title="Account Management", family="AC"
    )
    session.add(ctrl)
    session.commit()
    session.refresh(ctrl)
    obj = Objective(
        control_id_fk=ctrl.id,
        objective_id="CCI-000015",
        source="CCI",
        text="Account management automation",
    )
    session.add(obj)
    session.commit()
    session.refresh(obj)
    return obj


def _add_ev(session, *, path: str, sha: str, title: str | None = None) -> Evidence:
    ev = Evidence(
        path=path, sha256=sha, kind=EvidenceKind.PDF, size_bytes=1024, title=title
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    return ev


def _tag(session, *, evidence_id: int, objective_id: int) -> None:
    session.add(
        EvidenceTag(
            evidence_id=evidence_id,
            objective_id=objective_id,
            relevance=0.5,
            confidence=0.5,
            source="auto",
        )
    )
    session.commit()


def _add_finding(session, *, evidence_id: int, rule_id: str, cci_refs: str | None):
    f = StigFinding(
        evidence_id=evidence_id,
        rule_id=rule_id,
        cci_refs=cci_refs,
        severity="high",
        status=FindingStatus.OPEN,
        finding_details="...",
    )
    session.add(f)
    session.commit()
    session.refresh(f)
    return f


# ---------------------------------------------------------------------------
# Bug #1 — semicolon delimiter
# ---------------------------------------------------------------------------


def test_cci_refs_semicolon_delimiter_matches(session, objective):
    ev = _add_ev(session, path="file:///a.ckl", sha="a")
    _tag(session, evidence_id=ev.id, objective_id=objective.id)
    _add_finding(
        session, evidence_id=ev.id, rule_id="SV-1", cci_refs="CCI-000015;CCI-999999"
    )
    out = corroborating_findings([objective.id], {"CCI-000015"}, session)
    assert len(out) == 1, "semicolon-delimited cci_refs must match"


def test_cci_refs_mixed_comma_and_semicolon(session, objective):
    """Real-world payloads sometimes mix both delimiters."""
    ev = _add_ev(session, path="file:///mixed.ckl", sha="m")
    _tag(session, evidence_id=ev.id, objective_id=objective.id)
    _add_finding(
        session,
        evidence_id=ev.id,
        rule_id="SV-MIX",
        cci_refs="CCI-999999, CCI-000015; CCI-888888",
    )
    out = corroborating_findings([objective.id], {"CCI-000015"}, session)
    assert len(out) == 1


# ---------------------------------------------------------------------------
# Bug #2 — case sensitivity
# ---------------------------------------------------------------------------


def test_cci_refs_lowercase_matches_uppercase_cluster(session, objective):
    ev = _add_ev(session, path="file:///b.ckl", sha="b")
    _tag(session, evidence_id=ev.id, objective_id=objective.id)
    _add_finding(session, evidence_id=ev.id, rule_id="SV-2", cci_refs="cci-000015")
    out = corroborating_findings([objective.id], {"CCI-000015"}, session)
    assert len(out) == 1, "lowercase cci_refs must match uppercase cluster"


def test_cluster_lowercase_matches_uppercase_refs(session, objective):
    """Symmetric — caller may pass lowercase, finding may store uppercase."""
    ev = _add_ev(session, path="file:///c.ckl", sha="c")
    _tag(session, evidence_id=ev.id, objective_id=objective.id)
    _add_finding(session, evidence_id=ev.id, rule_id="SV-3", cci_refs="CCI-000015")
    out = corroborating_findings([objective.id], {"cci-000015"}, session)
    assert len(out) == 1


# ---------------------------------------------------------------------------
# Bug #3 — Windows backslash basename
# ---------------------------------------------------------------------------


def test_windows_absolute_path_basename(session, objective):
    """Local Windows path must NOT leak into the narrative-facing label."""
    ev = _add_ev(
        session,
        path=r"C:\Users\Noah.Jaskolski\evidence\firewall.ckl",
        sha="w",
        title=None,  # force the basename fallback branch
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id)
    _add_finding(session, evidence_id=ev.id, rule_id="SV-W", cci_refs="CCI-000015")
    out = corroborating_findings([objective.id], {"CCI-000015"}, session)
    assert len(out) == 1
    _, label = out[0]
    assert label == "firewall.ckl", f"expected basename, got {label!r}"
    assert "\\" not in label
    assert "Users" not in label


def test_unix_path_basename_unchanged(session, objective):
    """Regression: the original POSIX path branch must still work."""
    ev = _add_ev(session, path="file:///srv/evidence/scan.ckl", sha="u", title=None)
    _tag(session, evidence_id=ev.id, objective_id=objective.id)
    _add_finding(session, evidence_id=ev.id, rule_id="SV-U", cci_refs="CCI-000015")
    out = corroborating_findings([objective.id], {"CCI-000015"}, session)
    assert out[0][1] == "scan.ckl"


def test_title_wins_over_path_basename(session, objective):
    """When Evidence.title is set, the basename branch must NOT run."""
    ev = _add_ev(
        session,
        path=r"C:\should\not\appear.ckl",
        sha="t",
        title="Quarterly Firewall Scan",
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id)
    _add_finding(session, evidence_id=ev.id, rule_id="SV-T", cci_refs="CCI-000015")
    out = corroborating_findings([objective.id], {"CCI-000015"}, session)
    assert out[0][1] == "Quarterly Firewall Scan"


# ---------------------------------------------------------------------------
# _basename helper — direct unit tests so the OS-agnostic path logic is
# pinned independent of the corroboration join
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("", None),
        (None, None),
        ("foo.ckl", "foo.ckl"),
        ("/srv/a/b.ckl", "b.ckl"),
        ("file:///srv/a/b.ckl", "b.ckl"),
        (r"C:\Users\x\b.ckl", "b.ckl"),
        ("/srv/a/", "a"),  # trailing slash stripped
        (r"C:\Users\x\\", "x"),  # trailing backslash stripped
        ("mixed/path\\with\\both.ckl", "both.ckl"),  # both separators present
    ],
)
def test_basename_helper(raw, expected):
    assert _basename(raw) == expected


# ---------------------------------------------------------------------------
# Regression guard — NULL cci_refs must not crash the join
# ---------------------------------------------------------------------------


def test_null_cci_refs_does_not_crash(session, objective):
    ev = _add_ev(session, path="file:///null.ckl", sha="n")
    _tag(session, evidence_id=ev.id, objective_id=objective.id)
    _add_finding(session, evidence_id=ev.id, rule_id="SV-N", cci_refs=None)
    out = corroborating_findings([objective.id], {"CCI-000015"}, session)
    assert out == []


# ---------------------------------------------------------------------------
# Slice 0.2a — affected_hosts() canonicalization
#
# The host inventory join is the chokepoint shared by the POAM narrative and
# the assessor evidence bundle. These tests pin the conservative lexical
# normalization layer (case-fold, trailing-dot, unambiguous short→FQDN fold)
# WITHOUT IP/hostname fusion. The harder identity-resolution work lives in
# slice 0.2b's Asset table — when that lands, these tests should keep passing.
# ---------------------------------------------------------------------------


def _add_ev_with_hosts(session, *, path: str, sha: str, hosts: list[str]) -> Evidence:
    """Like _add_ev but seeds Evidence.host_inventory with a JSON host list."""
    ev = Evidence(
        path=path,
        sha256=sha,
        kind=EvidenceKind.PDF,
        size_bytes=1024,
        host_inventory=json.dumps(hosts),
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    return ev


def test_affected_hosts_collapses_case_variants(session, objective):
    """``Host-A`` and ``host-a`` are the same machine — one entry, lowercase."""
    ev = _add_ev_with_hosts(
        session, path="file:///case.ckl", sha="case", hosts=["Host-A", "host-a", "HOST-A"]
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id)
    out = affected_hosts([objective.id], session)
    assert out == ["host-a"]


def test_affected_hosts_strips_trailing_dot(session, objective):
    """FQDNs sometimes arrive root-terminated; that's the same host."""
    ev = _add_ev_with_hosts(
        session,
        path="file:///dot.ckl",
        sha="dot",
        hosts=["server01.corp.local.", "server01.corp.local"],
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id)
    out = affected_hosts([objective.id], session)
    assert out == ["server01.corp.local"]


def test_affected_hosts_folds_unambiguous_short_to_fqdn(session, objective):
    """Bare name collapses into its FQDN when exactly one FQDN matches.

    Cross-source case: short name from one CKL, FQDN from another scan of the
    same machine. With one FQDN candidate the fold is safe.
    """
    ev1 = _add_ev_with_hosts(
        session, path="file:///short.ckl", sha="s1", hosts=["server01"]
    )
    ev2 = _add_ev_with_hosts(
        session, path="file:///full.ckl", sha="s2", hosts=["server01.corp.local"]
    )
    _tag(session, evidence_id=ev1.id, objective_id=objective.id)
    _tag(session, evidence_id=ev2.id, objective_id=objective.id)
    out = affected_hosts([objective.id], session)
    assert out == ["server01.corp.local"]


def test_affected_hosts_keeps_ambiguous_short_separate(session, objective):
    """Two FQDNs share a first label → fold is unsafe; leave the bare name.

    server01.corp.local vs server01.dev.local are different machines; we can't
    tell which one a bare ``server01`` refers to, so all three stay.
    """
    ev = _add_ev_with_hosts(
        session,
        path="file:///amb.ckl",
        sha="amb",
        hosts=["server01", "server01.corp.local", "server01.dev.local"],
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id)
    out = affected_hosts([objective.id], session)
    assert out == ["server01", "server01.corp.local", "server01.dev.local"]


def test_affected_hosts_keeps_ip_and_hostname_separate(session, objective):
    """Without DNS truth, ``10.0.0.5`` and ``server01.corp.local`` MUST stay
    as two entries — fusing them belongs to the Asset resolver (slice 0.2b)."""
    ev = _add_ev_with_hosts(
        session,
        path="file:///ip.ckl",
        sha="ip",
        hosts=["10.0.0.5", "server01.corp.local"],
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id)
    out = affected_hosts([objective.id], session)
    assert out == ["10.0.0.5", "server01.corp.local"]


def test_affected_hosts_ipv4_not_folded_as_fqdn(session, objective):
    """An IPv4 dotted-quad has dots but is NOT a domain. The bare-name fold
    must not treat ``10`` as a short name that collapses into ``10.0.0.5``."""
    ev = _add_ev_with_hosts(
        session, path="file:///quad.ckl", sha="quad", hosts=["10", "10.0.0.5"]
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id)
    out = affected_hosts([objective.id], session)
    # Both kept: "10" is not an IP literal, "10.0.0.5" is — and the IP is not
    # eligible to be the fold target for "10".
    assert out == ["10", "10.0.0.5"]


def test_affected_hosts_ipv6_kept_separate_from_hostname(session, objective):
    """IPv6 literals stay separate from hostname-shaped tokens."""
    ev = _add_ev_with_hosts(
        session,
        path="file:///v6.ckl",
        sha="v6",
        hosts=["fe80::1ff:fe23:4567:890a", "server01.corp.local"],
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id)
    out = affected_hosts([objective.id], session)
    assert "fe80::1ff:fe23:4567:890a" in out
    assert "server01.corp.local" in out
    assert len(out) == 2


def test_affected_hosts_dedup_across_evidence_rows(session, objective):
    """Same hostname from two CKLs (with case differences) collapses to one."""
    ev1 = _add_ev_with_hosts(
        session, path="file:///a.ckl", sha="ca1", hosts=["Workstation-42"]
    )
    ev2 = _add_ev_with_hosts(
        session, path="file:///b.ckl", sha="ca2", hosts=["workstation-42"]
    )
    _tag(session, evidence_id=ev1.id, objective_id=objective.id)
    _tag(session, evidence_id=ev2.id, objective_id=objective.id)
    out = affected_hosts([objective.id], session)
    assert out == ["workstation-42"]


def test_affected_hosts_empty_and_whitespace_dropped(session, objective):
    """Empty strings and whitespace-only entries silently disappear — they
    aren't hosts, and surfacing them as ``""`` would be ugly in narratives."""
    ev = _add_ev_with_hosts(
        session,
        path="file:///ws.ckl",
        sha="ws",
        hosts=["", "   ", "host-real"],
    )
    _tag(session, evidence_id=ev.id, objective_id=objective.id)
    out = affected_hosts([objective.id], session)
    assert out == ["host-real"]
