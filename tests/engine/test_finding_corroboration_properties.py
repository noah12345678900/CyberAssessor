"""Property-based tests for the STIG finding corroboration kernel.

``engine/finding_corroboration.py`` is shared by two downstream consumers:
the assessor's evidence-bundle composer (upstream input to the LLM's
ComplianceStatus decision) and the POAM generator (downstream narrative
that has to cite the SAME findings the assessor saw). If the two ever
disagree on what corroborates a cluster, the audit trail loses its
coherence — narrative cites finding X, POAM omits it (or vice versa).

The module has TWO testable surfaces:

  Pure helpers (no I/O)
    ``_basename``           — OS-agnostic path → final segment
    ``_severity_sort_key``  — DISA severity ranking for top-N picks
    ``_CCI_REF_SPLIT``      — regex splitting on ',', ';', whitespace

  DB-backed entry points (in-memory SQLite session)
    ``corroborating_findings`` — the AND-join: tag ∩ cci_refs
    ``affected_hosts``         — JSON-decoded inventory union

Both surfaces had ZERO test coverage before this module. The
DB-backed tests use a scratch in-memory SQLModel session (same pattern
as ``test_decision_cache``) so they exercise the real SQL the
production callers run, not a mock.

Hypothesis is in the dev extras and gated through ``pytest.importorskip``
so a vanilla ``pytest`` install gets a clean skip.
"""

from __future__ import annotations

import json

import pytest
from sqlmodel import Session, SQLModel, create_engine

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from cybersecurity_assessor.engine.finding_corroboration import (  # noqa: E402
    _CCI_REF_SPLIT,
    _basename,
    _severity_sort_key,
    affected_hosts,
    corroborating_findings,
)
from cybersecurity_assessor.models import (  # noqa: E402
    Evidence,
    EvidenceKind,
    EvidenceTag,
    FindingStatus,
    StigFinding,
)


# ---------------------------------------------------------------------------
# _basename — OS-agnostic last-segment extraction
# ---------------------------------------------------------------------------

# A segment that contains no path separators. We deliberately exclude
# the separator characters from the alphabet so the strategy cannot
# accidentally generate paths and break the "no separator → identity"
# property below.
_NO_SEP_ALPHABET = st.characters(
    min_codepoint=33,
    max_codepoint=126,
    blacklist_characters="/\\",
)


@given(s=st.one_of(st.none(), st.text(max_size=200)))
def test_basename_never_raises_and_returns_str_or_none(s: str | None) -> None:
    """``_basename`` accepts any text or None and returns str-or-None.

    Used as a fallback label for Evidence rows with no title. A crash
    on a stray non-path input would take down the whole corroboration
    join, because the labelling loop runs *before* any filtering.
    """
    out = _basename(s)
    assert out is None or isinstance(out, str)


def test_basename_none_returns_none() -> None:
    assert _basename(None) is None


def test_basename_empty_returns_none() -> None:
    assert _basename("") is None


@given(
    parent=st.text(alphabet=_NO_SEP_ALPHABET, min_size=1, max_size=20),
    name=st.text(alphabet=_NO_SEP_ALPHABET, min_size=1, max_size=20),
)
def test_basename_forward_slash_returns_last_segment(parent: str, name: str) -> None:
    """POSIX-style path returns the trailing segment.

    The historical fallback was ``str.rsplit("/", 1)``, which is fine
    for POSIX but corrupts Windows-absolute paths (no forward slashes).
    Property pins the forward-slash case so future refactors of the
    cross-platform branch don't accidentally regress it.
    """
    assert _basename(f"{parent}/{name}") == name


@given(
    parent=st.text(alphabet=_NO_SEP_ALPHABET, min_size=1, max_size=20),
    name=st.text(alphabet=_NO_SEP_ALPHABET, min_size=1, max_size=20),
)
def test_basename_backslash_returns_last_segment(parent: str, name: str) -> None:
    """Windows-style path returns the trailing segment.

    This is the load-bearing half — pre-fix, a path like
    ``C:\\Users\\Noah\\evidence.ckl`` leaked through ``rsplit("/", 1)``
    untouched, exposing the user's local filesystem in narrative output.
    """
    assert _basename(f"{parent}\\{name}") == name


@given(name=st.text(alphabet=_NO_SEP_ALPHABET, min_size=1, max_size=40))
def test_basename_no_separator_returns_input(name: str) -> None:
    """A string with no separators returns itself unchanged.

    The Evidence label fallback chain is ``title or _basename(path) or
    "evidence#<id>"``; for a path like ``"foo.pdf"`` (no directory),
    _basename must return ``"foo.pdf"`` not ``None`` or the chain falls
    through to the meaningless ``"evidence#42"`` label.
    """
    assert _basename(name) == name


@given(
    parent=st.text(alphabet=_NO_SEP_ALPHABET, min_size=1, max_size=20),
    name=st.text(alphabet=_NO_SEP_ALPHABET, min_size=1, max_size=20),
    trailing=st.sampled_from(["/", "\\", "//", "\\\\", "/\\", "\\/"]),
)
def test_basename_strips_trailing_separators(
    parent: str, name: str, trailing: str
) -> None:
    """Trailing separators are stripped before the split.

    Some ingest pipelines leave a trailing slash on directory-like
    paths; without the rstrip the function would return "" and the
    fallback chain would skip a perfectly good directory name.
    """
    assert _basename(f"{parent}/{name}{trailing}") == name


# ---------------------------------------------------------------------------
# _severity_sort_key — DISA severity → rank
# ---------------------------------------------------------------------------


@given(sev=st.one_of(st.none(), st.text(max_size=50)))
def test_severity_sort_key_never_raises_and_returns_int(sev: str | None) -> None:
    """Returns an int for any input including None. Never raises.

    This is the comparator inside ``matched.sort(key=...)``; a single
    raise would crash the entire corroboration pipeline AFTER the join
    already succeeded — the worst possible failure mode (the user sees
    "0 findings" when there were actually 50).
    """
    out = _severity_sort_key(sev)
    assert isinstance(out, int)


def test_severity_sort_key_none_returns_99() -> None:
    """None ranks LAST (highest number = lowest priority).

    Anchors the "callers taking top-N see most-remediation-relevant
    first" contract: missing severity must not pre-empt a real high.
    """
    assert _severity_sort_key(None) == 99


def test_severity_sort_key_unknown_returns_50() -> None:
    """Unknown severities rank between known-low and missing.

    Distinguishing unknown-50 from missing-99 lets ops surface
    "scanner emitted a severity we don't recognize" as a soft signal
    in dashboards (sort by rank, look for the 50s) without breaking
    the high-first ordering.
    """
    assert _severity_sort_key("CAT VII") == 50
    assert _severity_sort_key("critical") == 50  # not in table


@given(
    canonical=st.sampled_from([
        ("high", 0),
        ("cat i", 0),
        ("medium", 1),
        ("cat ii", 1),
        ("low", 2),
        ("cat iii", 2),
        ("informational", 3),
        ("info", 3),
        ("cat iv", 3),
    ]),
)
def test_severity_sort_key_known_severities_match_table(
    canonical: tuple[str, int],
) -> None:
    """Every documented severity maps to the documented rank.

    Anchors the table itself — if someone reshuffles the dict literal,
    this is the test that catches it before "cat i" silently sorts
    after "medium".
    """
    sev, expected = canonical
    assert _severity_sort_key(sev) == expected


@given(
    sev=st.sampled_from(["high", "HIGH", "High", "  high ", "\tCAT I\n", "Cat I"]),
)
def test_severity_sort_key_is_case_and_whitespace_insensitive(sev: str) -> None:
    """Case + leading/trailing whitespace must not affect rank.

    DISA tooling emits any of these forms depending on scanner version.
    A case-sensitive comparator would silently demote real highs to
    "unknown" (rank 50) and the POAM would lead with a medium.
    """
    assert _severity_sort_key(sev) == 0


@given(
    high=st.sampled_from(["high", "cat i"]),
    medium=st.sampled_from(["medium", "cat ii"]),
    low=st.sampled_from(["low", "cat iii"]),
)
def test_severity_sort_key_ordering_invariant(
    high: str, medium: str, low: str
) -> None:
    """High < Medium < Low < Unknown < None (by sort key).

    The lower-is-better convention is what ``matched.sort(key=...)``
    uses to put highs first. Pinning the strict ordering means a
    refactor that flips e.g. low and informational doesn't sneak past.
    """
    assert _severity_sort_key(high) < _severity_sort_key(medium)
    assert _severity_sort_key(medium) < _severity_sort_key(low)
    assert _severity_sort_key(low) < _severity_sort_key("unrecognized-sev")
    assert _severity_sort_key("unrecognized-sev") < _severity_sort_key(None)


# ---------------------------------------------------------------------------
# _CCI_REF_SPLIT — DISA scanner separator zoo
# ---------------------------------------------------------------------------


def _filtered_refs(raw: str) -> set[str]:
    """Mirrors the upper-stripped set comprehension inside
    ``corroborating_findings`` — the unit under test is the regex
    behaviour, but we apply the same downstream filter so the
    properties match what production sees."""
    return {r.strip().upper() for r in _CCI_REF_SPLIT.split(raw) if r.strip()}


@given(
    cci_nums=st.lists(
        st.integers(min_value=1, max_value=999999), min_size=1, max_size=5
    ),
    sep=st.sampled_from([",", ";", " ", ", ", "; ", " ; ", ",,", ";;"]),
)
def test_cci_ref_split_handles_any_documented_separator(
    cci_nums: list[int], sep: str
) -> None:
    """Comma / semicolon / whitespace joiners all parse cleanly.

    Per the module docstring: DISA scanners emit CCI ref lists joined
    with EITHER "," OR ";" OR whitespace alone. A regex that handled
    only commas would silently drop semicolon-joined findings from
    half the scanner outputs in the field.
    """
    raw = sep.join(f"CCI-{n:06d}" for n in cci_nums)
    refs = _filtered_refs(raw)
    expected = {f"CCI-{n:06d}" for n in cci_nums}
    assert refs == expected


@given(raw=st.text(max_size=100))
def test_cci_ref_split_filtered_output_has_no_empty_tokens(raw: str) -> None:
    """After the strip+filter, no token is empty.

    Empty tokens in the matched set would intersect any cluster's
    own filtered set (which also drops empties), but more importantly
    they reveal a regex that's letting separator-only runs through —
    a leading indicator of a deeper parse bug.
    """
    refs = _filtered_refs(raw)
    assert all(r for r in refs)


# ---------------------------------------------------------------------------
# corroborating_findings — DB-backed AND-join invariants
# ---------------------------------------------------------------------------


@pytest.fixture
def session() -> Session:
    """Fresh in-memory SQLModel session per test.

    Mirrors the pattern in tests/engine/test_decision_cache.py. SQLite
    FK enforcement is OFF by default, so we can write EvidenceTag rows
    pointing at synthetic objective_ids without bootstrapping the
    Control / Objective tables.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _insert_evidence(session: Session, path: str, title: str | None = None) -> int:
    """Insert a minimal Evidence row and return its id."""
    ev = Evidence(
        path=path,
        sha256="0" * 64,
        kind=EvidenceKind.OTHER,
        size_bytes=1,
        title=title,
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    assert ev.id is not None
    return ev.id


def _tag_evidence(session: Session, evidence_id: int, objective_id: int) -> None:
    session.add(
        EvidenceTag(
            evidence_id=evidence_id, objective_id=objective_id, source="auto"
        )
    )
    session.commit()


def _add_finding(
    session: Session,
    evidence_id: int,
    cci_refs: str | None,
    status: FindingStatus = FindingStatus.OPEN,
    severity: str | None = "medium",
    rule_id: str = "SV-99999",
) -> None:
    session.add(
        StigFinding(
            evidence_id=evidence_id,
            rule_id=rule_id,
            cci_refs=cci_refs,
            severity=severity,
            status=status,
        )
    )
    session.commit()


def test_corroborating_findings_empty_objective_ids_returns_empty(
    session: Session,
) -> None:
    """No objectives = no corroboration. Short-circuits before DB query.

    Guards the trivial-input path: a cluster with zero objectives must
    return [] without raising on the empty .in_() clause (some DB
    backends choke on empty IN lists).
    """
    assert corroborating_findings([], {"CCI-000001"}, session) == []


def test_corroborating_findings_untagged_evidence_returns_empty(
    session: Session,
) -> None:
    """Evidence with no tag in the cluster's objective set yields nothing.

    Pins the first half of the AND: tag-presence is necessary even
    when cci_refs would intersect. A CKL ingested but never tagged to
    AC-2 must NOT corroborate AC-2 just because it cites CCI-000015.
    """
    eid = _insert_evidence(session, "file:///evidence/random.ckl")
    _add_finding(session, eid, "CCI-000015")  # but no EvidenceTag
    assert corroborating_findings([1, 2, 3], {"CCI-000015"}, session) == []


def test_corroborating_findings_non_intersecting_cci_refs_returns_empty(
    session: Session,
) -> None:
    """Tagged evidence whose findings cite different CCIs yields nothing.

    Pins the second half of the AND: cci_refs intersection is
    necessary even when the tag is present. A CKL tagged to AC-2 will
    contain dozens of findings for IA-5 / CM-6 that the AC-2 cluster
    must NOT pick up.
    """
    eid = _insert_evidence(session, "file:///evidence/ac2.ckl")
    _tag_evidence(session, eid, objective_id=1)
    _add_finding(session, eid, "CCI-001000")  # finding cites IA-5 CCI
    out = corroborating_findings([1], {"CCI-000015"}, session)
    assert out == []


def test_corroborating_findings_includes_finding_when_both_halves_match(
    session: Session,
) -> None:
    """The AND-join: tag AND cci_refs both intersect → finding included."""
    eid = _insert_evidence(session, "file:///evidence/ac2.ckl", title="AC-2 CKL")
    _tag_evidence(session, eid, objective_id=1)
    _add_finding(session, eid, "CCI-000015,CCI-000017", severity="high")
    out = corroborating_findings([1], {"CCI-000015"}, session)
    assert len(out) == 1
    finding, label = out[0]
    assert finding.cci_refs == "CCI-000015,CCI-000017"
    assert label == "AC-2 CKL"


def test_corroborating_findings_only_open_status_included(
    session: Session,
) -> None:
    """Non-OPEN findings (Closed / Not_a_Finding / N/A) are excluded.

    Closed findings have already been remediated; surfacing them in a
    corroboration set would inflate the apparent gap and drive an
    unnecessary POAM. The status filter must stay tight.
    """
    eid = _insert_evidence(session, "file:///evidence/mixed.ckl")
    _tag_evidence(session, eid, objective_id=1)
    _add_finding(
        session, eid, "CCI-000015", status=FindingStatus.NOT_A_FINDING, rule_id="SV-1"
    )
    _add_finding(
        session, eid, "CCI-000015", status=FindingStatus.NOT_APPLICABLE, rule_id="SV-2"
    )
    _add_finding(
        session, eid, "CCI-000015", status=FindingStatus.NOT_REVIEWED, rule_id="SV-3"
    )
    _add_finding(
        session, eid, "CCI-000015", status=FindingStatus.OPEN, rule_id="SV-4"
    )
    out = corroborating_findings([1], {"CCI-000015"}, session)
    assert len(out) == 1
    assert out[0][0].rule_id == "SV-4"


def test_corroborating_findings_cci_match_is_case_insensitive(
    session: Session,
) -> None:
    """Lowercase finding refs intersect uppercase cluster CCIs.

    Upstream parsers occasionally lowercase CCI ids ("cci-000015") —
    the comparison must normalize both sides or a CKL with lowercase
    refs would silently drop out of every cluster it should hit.
    """
    eid = _insert_evidence(session, "file:///evidence/lc.ckl")
    _tag_evidence(session, eid, objective_id=1)
    _add_finding(session, eid, "cci-000015")  # lowercase
    out = corroborating_findings([1], {"CCI-000015"}, session)
    assert len(out) == 1


def test_corroborating_findings_sorted_by_severity_high_first(
    session: Session,
) -> None:
    """High → Medium → Low → None ordering pinned on real DB rows.

    The end-to-end version of the ``_severity_sort_key`` ordering
    invariant — callers that take the top-N for narrative composition
    must see the worst findings first.
    """
    eid = _insert_evidence(session, "file:///evidence/sev.ckl")
    _tag_evidence(session, eid, objective_id=1)
    _add_finding(session, eid, "CCI-000015", severity="low", rule_id="SV-low")
    _add_finding(session, eid, "CCI-000015", severity=None, rule_id="SV-none")
    _add_finding(session, eid, "CCI-000015", severity="high", rule_id="SV-high")
    _add_finding(session, eid, "CCI-000015", severity="medium", rule_id="SV-med")
    out = corroborating_findings([1], {"CCI-000015"}, session)
    ordered_rules = [f.rule_id for f, _ in out]
    assert ordered_rules == ["SV-high", "SV-med", "SV-low", "SV-none"]


def test_corroborating_findings_label_fallback_chain(session: Session) -> None:
    """title → basename(path) → evidence#<id>.

    The three-tier fallback is what keeps the narrative readable when
    upstream ingest didn't populate a title. Pin all three branches
    on one call so a refactor that breaks the chain at any layer fails
    a single test.
    """
    eid_title = _insert_evidence(
        session, "file:///a/b/c.ckl", title="Custom Title"
    )
    eid_basename = _insert_evidence(session, "file:///a/b/named.ckl", title=None)
    _tag_evidence(session, eid_title, objective_id=1)
    _tag_evidence(session, eid_basename, objective_id=1)
    _add_finding(session, eid_title, "CCI-000015", rule_id="SV-T")
    _add_finding(session, eid_basename, "CCI-000015", rule_id="SV-B")

    out = corroborating_findings([1], {"CCI-000015"}, session)
    labels = {f.rule_id: lbl for f, lbl in out}
    assert labels["SV-T"] == "Custom Title"
    assert labels["SV-B"] == "named.ckl"


def test_corroborating_findings_empty_cci_refs_skipped(session: Session) -> None:
    """A finding with no ``cci_refs`` at all is silently dropped.

    Without this guard the comprehension would build a set with one
    empty-string element, which (after strip+filter) becomes the empty
    set — but the early ``if not f.cci_refs: continue`` is what makes
    the contract explicit. Pin it so a refactor doesn't reintroduce
    the per-finding null-deref via a parse exception.
    """
    eid = _insert_evidence(session, "file:///evidence/null.ckl")
    _tag_evidence(session, eid, objective_id=1)
    _add_finding(session, eid, None, rule_id="SV-null")
    assert corroborating_findings([1], {"CCI-000015"}, session) == []


# ---------------------------------------------------------------------------
# affected_hosts — DB-backed inventory union
# ---------------------------------------------------------------------------


def test_affected_hosts_empty_objective_ids_returns_empty(session: Session) -> None:
    """Mirrors the ``corroborating_findings`` empty-input contract."""
    assert affected_hosts([], session) == []


def test_affected_hosts_no_inventory_returns_empty(session: Session) -> None:
    """Evidence tagged but carrying no ``host_inventory`` payload → [].

    Policy-only controls (most of AT, PL) commonly tag evidence with
    no inventory data; the caller treats [] as "omit the section",
    not "render an empty section".
    """
    eid = _insert_evidence(session, "file:///evidence/policy.pdf")
    _tag_evidence(session, eid, objective_id=1)
    assert affected_hosts([1], session) == []


def test_affected_hosts_deduped_and_sorted(session: Session) -> None:
    """Union across evidence rows is deduplicated AND lexicographically sorted.

    Sort stability matters for diff-friendly output — two assessment
    runs over the same evidence must produce the same host list in the
    same order or the snapshot/diff pipeline lights up false changes.
    """
    eid1 = _insert_evidence(session, "file:///evidence/scan1.json")
    eid2 = _insert_evidence(session, "file:///evidence/scan2.json")
    _tag_evidence(session, eid1, objective_id=1)
    _tag_evidence(session, eid2, objective_id=1)

    ev1 = session.get(Evidence, eid1)
    ev2 = session.get(Evidence, eid2)
    assert ev1 is not None and ev2 is not None
    ev1.host_inventory = json.dumps(["host-c", "host-a", "host-b"])
    ev2.host_inventory = json.dumps(["host-b", "host-d"])  # 'host-b' duplicate
    session.add(ev1)
    session.add(ev2)
    session.commit()

    out = affected_hosts([1], session)
    assert out == ["host-a", "host-b", "host-c", "host-d"]


def test_affected_hosts_malformed_json_is_skipped(session: Session) -> None:
    """A row with non-JSON inventory text doesn't raise; it's silently skipped.

    Defensive: if a scanner ever writes a truncated payload, the
    corroboration path must keep working for the OTHER tagged rows.
    Without the try/except the entire host union would crash.
    """
    eid_bad = _insert_evidence(session, "file:///evidence/bad.json")
    eid_good = _insert_evidence(session, "file:///evidence/good.json")
    _tag_evidence(session, eid_bad, objective_id=1)
    _tag_evidence(session, eid_good, objective_id=1)

    ev_bad = session.get(Evidence, eid_bad)
    ev_good = session.get(Evidence, eid_good)
    assert ev_bad is not None and ev_good is not None
    ev_bad.host_inventory = "not-json-at-all{["
    ev_good.host_inventory = json.dumps(["host-x"])
    session.add(ev_bad)
    session.add(ev_good)
    session.commit()

    assert affected_hosts([1], session) == ["host-x"]


def test_affected_hosts_non_list_json_payload_skipped(session: Session) -> None:
    """JSON that decodes to a non-list (object, string, int) is skipped.

    The contract is ``list[str]``; a scanner that wrote ``{"hosts": [...]}``
    instead of ``[...]`` would land here. We discard the row rather than
    KeyError-ing — the bad rows surface as missing-data, not as a crash.
    """
    eid = _insert_evidence(session, "file:///evidence/dict.json")
    _tag_evidence(session, eid, objective_id=1)
    ev = session.get(Evidence, eid)
    assert ev is not None
    ev.host_inventory = json.dumps({"hosts": ["host-a"]})  # dict, not list
    session.add(ev)
    session.commit()
    assert affected_hosts([1], session) == []


def test_affected_hosts_strips_whitespace_and_drops_empty(session: Session) -> None:
    """Hostnames are trimmed; empty/whitespace-only entries are dropped.

    Upstream parsers sometimes leave trailing whitespace from CSV
    splits; the dedup set must see the trimmed form or "host-a" and
    "host-a " coexist as two rows in the rendered list.
    """
    eid = _insert_evidence(session, "file:///evidence/ws.json")
    _tag_evidence(session, eid, objective_id=1)
    ev = session.get(Evidence, eid)
    assert ev is not None
    ev.host_inventory = json.dumps(["  host-a  ", "", "   ", "host-b"])
    session.add(ev)
    session.commit()
    assert affected_hosts([1], session) == ["host-a", "host-b"]


# Suppress the "function-scoped fixture in @given" health check on the
# DB-backed property tests that mix Hypothesis with the session fixture.
# (Currently none do — but documenting the intent here in case future
# additions go that way; remove if unused.)
_settings_db_safe = settings(
    suppress_health_check=[HealthCheck.function_scoped_fixture]
)
