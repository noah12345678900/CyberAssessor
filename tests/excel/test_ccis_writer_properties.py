"""Property-based tests for the CCIS workbook writer's pure helpers.

The writer's I/O surface (``write_assessment``, ``insert_cci_row``) is
xlwings/COM-bound and out of scope for in-process fuzzing — those paths
are exercised by the integration tests against a live Excel instance.
What IS in scope here are the *pure* helpers the writer calls before
ever touching the workbook:

    ``_coerce_status``  — ComplianceStatus|str|None → str|None
    ``_coerce_date``    — datetime|None → str|None  (ISO-8601 date)
    ``_format_cite_refresh_footer`` — JSON pair-list → footer text
    ``_normalize_control_for_match`` — col B comparison key
    ``_canonical_cci``  — force canonical CCI-NNNNNN form

Beyond the per-helper contracts, this module enforces the
**writer↔reader normalizer agreement** invariant: any value the reader
canonicalizes one way must be canonicalized the SAME way by the writer.
A drift between the two would silently corrupt the workbook on a
write-after-read cycle (e.g. reader normalizes ``"AC-2 "`` → ``"AC-2"``,
writer's match-helper sees ``"AC-2"`` and inserts a duplicate row).

Hypothesis is in the dev extras and imported via ``pytest.importorskip``
so a user running ``pytest`` without the dev install gets a clean skip
rather than a collection error.
"""

from __future__ import annotations

import json
import re
from datetime import datetime

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from cybersecurity_assessor.excel.ccis_reader import (  # noqa: E402
    _normalize_cci_cell,
    _normalize_control,
)
from cybersecurity_assessor.excel.ccis_writer import (  # noqa: E402
    _canonical_cci,
    _coerce_date,
    _coerce_status,
    _format_cite_refresh_footer,
    _normalize_control_for_match,
)
from cybersecurity_assessor.models import ComplianceStatus  # noqa: E402

# Mirrors the reader's _CELL_VALUES — every payload openpyxl can emit.
_CELL_VALUES = st.one_of(
    st.none(),
    st.booleans(),
    st.text(max_size=200),
    st.integers(min_value=-(10**9), max_value=10**9),
    st.floats(allow_nan=False, allow_infinity=False, width=64),
    st.datetimes(
        min_value=datetime(1970, 1, 1),
        max_value=datetime(2100, 1, 1),
    ),
)


# ---------------------------------------------------------------------------
# _coerce_status — accepts enum, string, or None
# ---------------------------------------------------------------------------


@given(
    raw=st.one_of(
        st.none(),
        st.sampled_from(list(ComplianceStatus)),
        st.text(max_size=50),
    ),
)
def test_coerce_status_never_raises_and_returns_str_or_none(raw: object) -> None:
    """Returns either None or a non-empty string. Never raises.

    The writer feeds this into ``sheet.cells(row, N).value = ...``; a
    bare empty string would clobber Excel's existing status with a blank
    cell — the contract is "None means leave alone", not "None means
    blank". An empty-string regression here would silently wipe verdicts.
    """
    out = _coerce_status(raw)
    assert out is None or (isinstance(out, str) and out != "")


@given(status=st.sampled_from(list(ComplianceStatus)))
def test_coerce_status_enum_returns_value_string(status: ComplianceStatus) -> None:
    """A ComplianceStatus enum input returns ``status.value`` verbatim.

    Col N is read back as a plain string by eMASS; if the enum's display
    name (``status.name``) ever leaked through instead of its
    ``.value``, the workbook would carry ``"COMPLIANT"`` where eMASS
    expects ``"Compliant"`` and the macro-driven status histograms would
    show 100% "Other".
    """
    assert _coerce_status(status) == status.value


@given(s=st.text(alphabet=" \t\n\r\f\v", min_size=0, max_size=20))
def test_coerce_status_whitespace_only_returns_none(s: str) -> None:
    """Whitespace-only strings collapse to None — matches the reader's
    ``_coerce_text`` contract so an empty cell read from one workbook
    and written into another doesn't materialize as a blank verdict.
    """
    assert _coerce_status(s) is None


# ---------------------------------------------------------------------------
# _coerce_date — datetime → ISO-8601 string, None passthrough
# ---------------------------------------------------------------------------


_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@given(
    dt=st.one_of(
        st.none(),
        st.datetimes(
            min_value=datetime(1970, 1, 1),
            max_value=datetime(2100, 1, 1),
        ),
    ),
)
def test_coerce_date_returns_iso_date_string_or_none(dt: datetime | None) -> None:
    """None passes through; datetimes become ``YYYY-MM-DD`` strings.

    eMASS rejects anything that isn't ISO date on col O. If the writer
    ever leaked a ``str(datetime)`` (which adds the time portion) the
    workbook would carry ``"2026-06-05 00:00:00"`` and eMASS would mark
    the row's date_tested as invalid on next import.
    """
    out = _coerce_date(dt)
    if dt is None:
        assert out is None
    else:
        assert isinstance(out, str)
        assert _ISO_DATE_RE.match(out), f"Expected YYYY-MM-DD, got {out!r}"


@given(
    dt=st.datetimes(
        min_value=datetime(1970, 1, 1),
        max_value=datetime(2100, 1, 1),
    ),
)
def test_coerce_date_round_trips_via_strptime(dt: datetime) -> None:
    """The ISO string round-trips back through ``strptime`` to the SAME
    date components (year/month/day). Time portion is intentionally
    discarded — eMASS col O is date-only.
    """
    out = _coerce_date(dt)
    assert out is not None
    parsed = datetime.strptime(out, "%Y-%m-%d")
    assert (parsed.year, parsed.month, parsed.day) == (dt.year, dt.month, dt.day)


# ---------------------------------------------------------------------------
# _format_cite_refresh_footer — JSON pair list → footer text
# ---------------------------------------------------------------------------


@given(
    pairs=st.lists(
        st.tuples(
            st.text(min_size=1, max_size=40),
            st.text(min_size=1, max_size=40),
        ),
        min_size=1,
        max_size=5,
    ),
)
def test_format_cite_refresh_footer_includes_every_pair(
    pairs: list[tuple[str, str]],
) -> None:
    """Every (legacy, current) pair appears in the rendered footer.

    The footer's job is to tell the *next* assessment pass which doc
    cites to swap. Dropping a pair would leak a stale cite into the
    final narrative without surfacing it for review — the whole point
    of the citation-hygiene rail is defeated.
    """
    refs_json = json.dumps([list(p) for p in pairs])
    footer = _format_cite_refresh_footer(refs_json)
    assert footer is not None
    for legacy, current in pairs:
        assert legacy in footer
        assert current in footer


@given(raw=st.one_of(st.none(), st.just(""), st.just("   ")))
def test_format_cite_refresh_footer_empty_input_returns_generic_note(
    raw: str | None,
) -> None:
    """When the supersession layer couldn't reconstruct any pairs, the
    footer is the GENERIC "re-run assess after updating" lead-in — never
    None and never an empty string.

    A None return here would silently suppress the entire footer on the
    happy-path branch in ``_write_row``, hiding the fact that a
    rewrite_requested verdict went into the workbook.
    """
    out = _format_cite_refresh_footer(raw)
    assert out is not None
    assert "Cite refresh requested" in out


@given(
    raw=st.text(max_size=50).filter(
        lambda s: not s.strip().startswith("[") and not s.strip().startswith("{")
    ),
)
def test_format_cite_refresh_footer_malformed_json_returns_none(raw: str) -> None:
    """Non-JSON input (corrupt DB row, stray plaintext) returns None.

    The writer caller checks for None and skips the footer-append step;
    a falsy-but-non-None return (e.g. ``""``) would still get appended
    with the leading ``"\\n\\n"`` separator and leave a trailing blank
    block in the workbook.
    """
    # Only the empty/whitespace path goes through the "generic footer"
    # branch (handled by the previous test); everything else here is a
    # non-empty non-JSON string that must fail decode and return None.
    if raw.strip() == "":
        return  # filtered case — covered by the empty-input test
    out = _format_cite_refresh_footer(raw)
    assert out is None


@given(
    decoded=st.one_of(
        st.text(max_size=20).map(json.dumps),
        st.integers().map(json.dumps),
        st.booleans().map(json.dumps),
        st.dictionaries(st.text(max_size=10), st.text(max_size=10)).map(json.dumps),
    ),
)
def test_format_cite_refresh_footer_non_list_json_returns_none(decoded: str) -> None:
    """JSON that decodes to something other than a list (string, int,
    object) returns None — defends against a DB schema drift where
    ``rewrite_requested_refs`` got stored as a JSON object instead of
    the expected ``[[legacy, current], ...]`` array.
    """
    assert _format_cite_refresh_footer(decoded) is None


# ---------------------------------------------------------------------------
# _normalize_control_for_match ↔ reader._normalize_control agreement
# ---------------------------------------------------------------------------


@given(raw=_CELL_VALUES)
def test_writer_normalize_control_agrees_with_reader(raw: object) -> None:
    """Writer's match-helper and reader's normalizer must produce the
    SAME canonical form for any input.

    Drift here breaks ``insert_cci_row``: it scans col B with the
    writer's helper looking for an existing match against the user's
    requested control, but the reader has already canonicalized those
    cells one way upstream. If the two helpers disagree on, say,
    ``"AC-2 "`` vs ``"AC-2"``, the writer fails to find the existing
    rows and inserts a duplicate at the bottom of the sheet.
    """
    assert _normalize_control_for_match(raw) == _normalize_control(raw)


# ---------------------------------------------------------------------------
# _canonical_cci — integer extraction → canonical CCI-NNNNNN
# ---------------------------------------------------------------------------


_CANONICAL_CCI_RE = re.compile(r"^CCI-\d{6,}$")


@given(n=st.integers(min_value=1, max_value=9999999))
def test_canonical_cci_prefixed_and_bare_agree(n: int) -> None:
    """``CCI-N``, bare ``N``, and zero-padded variants all canonicalize
    to ``CCI-{n:06d}`` (at least 6 digits; more if n exceeds 999999).

    Same contract as ``ccis_reader._normalize_cci_cell`` — the two
    helpers MUST agree on canonical form or write-after-read cycles
    duplicate rows in ``insert_cci_row``.
    """
    expected = f"CCI-{n:06d}"
    assert _canonical_cci(f"CCI-{n}") == expected
    assert _canonical_cci(str(n)) == expected
    assert _canonical_cci(f"{n:06d}") == expected


@given(n=st.integers(min_value=1, max_value=999999))
def test_canonical_cci_agrees_with_reader_normalize(n: int) -> None:
    """For any CCI id the reader accepts, the writer produces the SAME
    canonical form.

    The reader is the source of truth for "is this a valid CCI cell";
    the writer is the source of truth for "what string do we write".
    These must converge or insert_cci_row writes a row the reader
    immediately re-canonicalizes to a different id, silently shifting
    every downstream join key by one parse.
    """
    raw = f"CCI-{n}"
    reader_form = _normalize_cci_cell(raw)
    writer_form = _canonical_cci(raw)
    assert reader_form == writer_form


@given(
    raw=st.text(max_size=30).filter(lambda s: not re.search(r"\d", s)),
)
def test_canonical_cci_rejects_inputs_with_no_digits(raw: str) -> None:
    """An input with no digits at all raises ValueError — the contract
    is "force canonical OR explicitly fail", never silently emit a
    junk id like ``"CCI-000000"`` that would silently orphan the row.
    """
    with pytest.raises(ValueError):
        _canonical_cci(raw)
