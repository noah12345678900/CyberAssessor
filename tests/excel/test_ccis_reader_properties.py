"""Property-based tests for the CCIS workbook reader.

The reader is the workbook-to-CcisRow boundary. Every downstream module
(validator, rules, supersession, the LLM prompt builder) trusts that
parsed rows are well-typed and that the coercion helpers never raise.
If a parsing helper crashes on an unexpected cell payload — a NaN, an
all-whitespace string, an int where a string was expected — the entire
assessment dies at workbook-load time, before the kernel even runs.

Invariants proven here are over the *pure* helpers (``_normalize_*``,
``_coerce_*``, ``_row_key``, ``_normalize_diff_value``,
``_ccis_to_oscal_control_id``). Disk/openpyxl paths are out of scope —
those are covered by ``test_assessor.py`` and the workbook fixtures.

Hypothesis is in the dev extras; the entire module imports it lazily
through ``pytest.importorskip`` so a user running ``pytest`` without the
dev install gets a clean skip rather than a collection error.
"""

from __future__ import annotations

import re
from datetime import datetime

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from cybersecurity_assessor.excel.ccis_reader import (  # noqa: E402
    CcisRow,
    _ccis_to_oscal_control_id,
    _coerce_bool_yes,
    _coerce_date,
    _coerce_text,
    _normalize_cci_cell,
    _normalize_control,
    _normalize_diff_value,
    _row_key,
)

# Cell-value strategy modelling what openpyxl emits via values_only=True.
# Excel cells round-trip through these Python types: None, str, int, float,
# bool, datetime. Booleans MUST come before ints (bool is a subclass of int
# in Python and ``st.one_of`` would otherwise never produce bool values).
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
# _coerce_text — strip-or-None contract
# ---------------------------------------------------------------------------


@given(raw=_CELL_VALUES)
def test_coerce_text_never_raises_and_returns_str_or_none(raw: object) -> None:
    """``_coerce_text`` accepts any cell payload openpyxl could emit and
    returns either None or a non-empty string.

    The "non-empty" half is load-bearing: downstream code uses ``if
    row.guidance:`` to decide whether to feed text to the LLM. If
    ``_coerce_text`` ever returned ``""`` instead of ``None`` for a
    whitespace-only cell, that branch would silently invert and the
    prompt would receive empty strings — a quiet corruption.
    """
    out = _coerce_text(raw)
    assert out is None or (isinstance(out, str) and out != "")


@given(raw=_CELL_VALUES)
def test_coerce_text_is_idempotent(raw: object) -> None:
    """``_coerce_text(_coerce_text(x))`` equals ``_coerce_text(x)``.

    Once normalized, re-normalizing is a no-op. Guards against a future
    refactor that adds trailing punctuation or case folding — both of
    which would break the read/write round-trip in ``ccis_writer``.
    """
    once = _coerce_text(raw)
    twice = _coerce_text(once)
    assert once == twice


@given(s=st.text(alphabet=" \t\n\r\f\v", min_size=0, max_size=20))
def test_coerce_text_whitespace_only_returns_none(s: str) -> None:
    """Any whitespace-only string (including the empty string) collapses
    to None — the contract that lets ``if row.field:`` substitute for
    explicit ``if row.field is not None and row.field.strip():`` checks
    everywhere downstream.
    """
    assert _coerce_text(s) is None


# ---------------------------------------------------------------------------
# _coerce_bool_yes — case-insensitive "YES" detection
# ---------------------------------------------------------------------------


@given(raw=_CELL_VALUES)
def test_coerce_bool_yes_never_raises_and_returns_bool(raw: object) -> None:
    """``_coerce_bool_yes`` accepts any cell payload and always returns a
    real ``bool`` (not a truthy int or None).

    Col A drives the "required for assessment" flag. A coercion that
    returned None or a non-bool would skip the row's inclusion check
    in the LLM batch builder, silently dropping required CCIs.
    """
    out = _coerce_bool_yes(raw)
    assert isinstance(out, bool)


@given(
    prefix=st.text(alphabet=" \t", max_size=5),
    suffix=st.text(alphabet=" \t", max_size=5),
    case_variant=st.sampled_from(["YES", "yes", "Yes", "YeS", "yEs"]),
)
def test_coerce_bool_yes_case_insensitive_with_padding(
    prefix: str, suffix: str, case_variant: str
) -> None:
    """Any case-variant of ``YES`` surrounded by whitespace returns True.

    The eMASS template uses exact-case ``YES`` but operators sometimes
    paste lowercase or pad with spaces. The contract is generous on input
    so a stray-whitespace row isn't silently treated as not-required.
    """
    assert _coerce_bool_yes(f"{prefix}{case_variant}{suffix}") is True


@given(
    text=st.text(max_size=50).filter(lambda s: s.strip().upper() != "YES"),
)
def test_coerce_bool_yes_only_yes_is_true(text: str) -> None:
    """Anything other than ``YES`` (case-insensitive, after strip) returns
    False.

    Closes the symmetric half of the contract: ``"Y"``, ``"yes please"``,
    arbitrary noise — none of these should silently promote a row to
    required.
    """
    assert _coerce_bool_yes(text) is False


# ---------------------------------------------------------------------------
# _coerce_date — never raises, datetime passthrough
# ---------------------------------------------------------------------------


@given(raw=_CELL_VALUES)
def test_coerce_date_never_raises_and_returns_datetime_or_none(raw: object) -> None:
    """``_coerce_date`` accepts any cell payload and returns a ``datetime``
    or None — never raises.

    Date cells frequently arrive malformed (string "TBD", float Excel
    serial, blank, partial ISO). The reader must absorb all of them and
    let downstream code treat the field as optional, rather than aborting
    the entire workbook parse on a single bad date cell.
    """
    out = _coerce_date(raw)
    assert out is None or isinstance(out, datetime)


@given(dt=st.datetimes(min_value=datetime(1970, 1, 1), max_value=datetime(2100, 1, 1)))
def test_coerce_date_passes_through_real_datetimes(dt: datetime) -> None:
    """A real ``datetime`` instance round-trips identity-equal.

    The reader receives ``datetime`` directly when openpyxl recognizes
    the cell as a date type. The function must NOT re-parse via strftime
    (which would lose subsecond precision and timezone awareness).
    """
    assert _coerce_date(dt) is dt


# ---------------------------------------------------------------------------
# _normalize_control — case + whitespace canonicalization
# ---------------------------------------------------------------------------


@given(raw=_CELL_VALUES)
def test_normalize_control_never_raises(raw: object) -> None:
    """Returns None or a string; never raises on arbitrary input.

    Col B drives every downstream lookup (control catalog join, OSCAL
    id translation, status grouping). A crash here means the whole
    workbook fails to parse.
    """
    out = _normalize_control(raw)
    assert out is None or isinstance(out, str)


@given(raw=_CELL_VALUES)
def test_normalize_control_is_idempotent(raw: object) -> None:
    """``_normalize_control(_normalize_control(x))`` equals
    ``_normalize_control(x)``.

    The function strips, uppercases, and removes spaces — a second pass
    must be a no-op or the snapshot/diff path will flag the same row as
    "edited" forever.
    """
    once = _normalize_control(raw)
    twice = _normalize_control(once)
    assert once == twice


# ---------------------------------------------------------------------------
# _normalize_cci_cell — bare-or-prefixed → canonical "CCI-NNNNNN"
# ---------------------------------------------------------------------------


_CANONICAL_CCI_RE = re.compile(r"^CCI-\d{6,}$")


@given(raw=_CELL_VALUES)
def test_normalize_cci_cell_never_raises_and_canonical_or_none(raw: object) -> None:
    """Returns None or a string matching ``^CCI-\\d{6,}$``.

    The CCI id is the join key for the entire objective table. A
    non-canonical id (e.g. ``"CCI-15"`` instead of ``"CCI-000015"``)
    would silently fail every downstream lookup and orphan the row.
    """
    out = _normalize_cci_cell(raw)
    assert out is None or _CANONICAL_CCI_RE.match(out), (
        f"_normalize_cci_cell returned non-canonical {out!r} for input {raw!r}"
    )


@given(n=st.integers(min_value=1, max_value=999999))
def test_normalize_cci_cell_prefixed_and_bare_agree(n: int) -> None:
    """``CCI-N`` and bare ``N`` (and zero-padded variants) all normalize
    to the same canonical form.

    Col H is allowed to hold either form (eMASS template inconsistency).
    The reader must produce one canonical id either way; otherwise
    ``by_cci()`` would key the same logical CCI under two strings and
    duplicate rows in every status histogram.
    """
    expected = f"CCI-{n:06d}"
    assert _normalize_cci_cell(f"CCI-{n}") == expected
    assert _normalize_cci_cell(str(n)) == expected
    assert _normalize_cci_cell(f"{n:06d}") == expected


@given(raw=_CELL_VALUES)
def test_normalize_cci_cell_is_idempotent(raw: object) -> None:
    """Running the normalizer twice yields the same result.

    Like ``_normalize_control``, idempotence is required for the
    snapshot/diff path — re-parsing the same workbook must NOT report
    every CCI row as changed.
    """
    once = _normalize_cci_cell(raw)
    twice = _normalize_cci_cell(once)
    assert once == twice


# ---------------------------------------------------------------------------
# _row_key — CcisRow ↔ dict equivalence
# ---------------------------------------------------------------------------


def _make_row(control_id: str, cci_id: str | None) -> CcisRow:
    """Minimal CcisRow factory for keying tests. Only control/cci matter."""
    return CcisRow(
        excel_row=42,
        required=False,
        control_id=control_id,
        ap_acronym=None,
        cci_id=cci_id,
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


@given(
    control=st.text(min_size=1, max_size=20),
    cci=st.one_of(st.none(), st.text(max_size=20)),
)
def test_row_key_ccisrow_and_dict_agree(control: str, cci: str | None) -> None:
    """For matching field values, ``_row_key(CcisRow(...))`` equals
    ``_row_key({"control_id": ..., "cci_id": ...})``.

    The diff path keys both the live ``CcisRow`` view and the JSON
    snapshot view — they MUST agree or every saved snapshot would
    report every row as added+removed on the next re-read.
    """
    row = _make_row(control_id=control, cci_id=cci)
    as_dict = {"control_id": control, "cci_id": cci}
    assert _row_key(row) == _row_key(as_dict)


@given(
    control=st.one_of(st.none(), st.just("")),
    cci=st.text(max_size=20),
)
def test_row_key_missing_control_returns_none(control: str | None, cci: str) -> None:
    """Empty/None control_id collapses to None regardless of cci_id.

    The diff key is a composite — losing either half makes the row
    un-keyable, and the documented contract is "return None so callers
    can filter it out" (not raise, not return a partial key).
    """
    as_dict = {"control_id": control, "cci_id": cci}
    assert _row_key(as_dict) is None


@given(
    control=st.text(min_size=1, max_size=20),
    cci=st.one_of(st.none(), st.just("")),
)
def test_row_key_missing_cci_returns_none(control: str, cci: str | None) -> None:
    """Symmetric half: empty/None cci_id collapses to None regardless of
    control_id.
    """
    as_dict = {"control_id": control, "cci_id": cci}
    assert _row_key(as_dict) is None


# ---------------------------------------------------------------------------
# _normalize_diff_value — whitespace collapse + idempotence
# ---------------------------------------------------------------------------


@given(raw=_CELL_VALUES)
def test_normalize_diff_value_is_idempotent(raw: object) -> None:
    """``_normalize_diff_value(_normalize_diff_value(x)) ==
    _normalize_diff_value(x)``.

    The diff path normalizes both sides of every cell comparison; if
    normalization weren't idempotent, comparing already-normalized
    snapshot data against fresh cells would flag spurious edits.
    """
    once = _normalize_diff_value(raw)
    twice = _normalize_diff_value(once)
    assert once == twice


@given(s=st.text(alphabet=" \t\n\r\f\v", min_size=0, max_size=20))
def test_normalize_diff_value_whitespace_only_is_none(s: str) -> None:
    """Whitespace-only strings normalize to None — matches the
    ``_coerce_text`` contract so a stray space added to a previously
    empty cell does NOT register as an edit.
    """
    assert _normalize_diff_value(s) is None


@given(dt=st.datetimes(min_value=datetime(1970, 1, 1), max_value=datetime(2100, 1, 1)))
def test_normalize_diff_value_datetime_to_iso_string(dt: datetime) -> None:
    """Datetime instances normalize to their ISO string form — matches
    what ``_row_to_snapshot_dict`` writes into the JSON sidecar, so
    comparing a live cell against the stored snapshot doesn't trip on
    type difference.
    """
    out = _normalize_diff_value(dt)
    assert out == dt.isoformat()


# ---------------------------------------------------------------------------
# _ccis_to_oscal_control_id — CCIS → OSCAL canonical form
# ---------------------------------------------------------------------------


@given(
    family=st.from_regex(r"[A-Z]{2}", fullmatch=True),
    num=st.integers(min_value=1, max_value=99),
    enhancement=st.one_of(st.none(), st.integers(min_value=1, max_value=99)),
)
def test_ccis_to_oscal_control_id_basic_shape(
    family: str, num: int, enhancement: int | None,
) -> None:
    """``AC-2`` → ``ac-2``; ``AC-2(1)`` → ``ac-2.1``.

    The OSCAL canonical form is the join key against the control
    catalog. A drift here means the entire CCIS workbook fails to
    match its 800-53 baseline — every row lands in
    ``missing_controls`` and no Objective rows get upserted.
    """
    if enhancement is None:
        ccis = f"{family}-{num}"
        expected = f"{family.lower()}-{num}"
    else:
        ccis = f"{family}-{num}({enhancement})"
        expected = f"{family.lower()}-{num}.{enhancement}"
    assert _ccis_to_oscal_control_id(ccis) == expected


@given(
    family=st.from_regex(r"[A-Z]{2}", fullmatch=True),
    num=st.integers(min_value=1, max_value=99),
    enhancement=st.one_of(st.none(), st.integers(min_value=1, max_value=99)),
)
def test_ccis_to_oscal_control_id_is_idempotent(
    family: str, num: int, enhancement: int | None,
) -> None:
    """Translating an already-OSCAL id is a no-op.

    Idempotence guards a refactor where someone accidentally calls the
    translator twice (e.g. once at parse, once at lookup) — the second
    call MUST NOT mangle the already-canonical form.
    """
    if enhancement is None:
        ccis = f"{family}-{num}"
    else:
        ccis = f"{family}-{num}({enhancement})"
    once = _ccis_to_oscal_control_id(ccis)
    twice = _ccis_to_oscal_control_id(once)
    assert once == twice
