"""Unit pins for the POAM residual-risk advisor (``poam/residual_advisor.py``).

The advisor is the LLM-powered card on PoamDetail that proposes a
residual-risk level after weighing boundary context and compensating
controls. This file pins three contracts that ship together in alembic
0011 / KERNEL_VERSION 0.1.0:

1. ``validate_response`` — the server-side guardrails that the LLM payload
   is forced through before it ever reaches the cache or the UI.
   * Accepts a well-formed payload and coerces it into ``ResidualSuggestion``.
   * Rejects ``suggested_residual`` strings outside the RiskLevel enum.
   * Rejects a ``confidence`` outside {low, medium, high}.
   * Rejects ``suggested_residual`` ABOVE ``raw_severity`` (the canonical
     never-upgrade rule from the prompt).
   * Truncates oversize ``rationale`` and ``key_factors`` strings rather
     than failing — the model occasionally exceeds the soft prompt caps.

2. Cache lifecycle — fingerprint + lookup + store + bump_hit + replay.
   * ``fingerprint`` is stable across runs for identical input.
   * Cache miss → LLM call → ``store_cache`` writes exactly one row.
   * Cache hit → ``bump_hit`` increments ``hit_count`` and ``replay``
     stamps ``cache_source = "cache_hit"``.
   * ``force_refresh=True`` skips the lookup even when a hit exists.

3. Retry / hard-abstain — the advisor must never crash the UI card.
   * One JSON-parse failure followed by a clean call returns the clean
     suggestion.
   * Two JSON-parse failures yield a ``[parse_error]`` low-confidence
     abstain that is NOT cached (so the next render gets a fresh attempt).
   * Two validation failures yield a ``[validation_error]`` abstain that
     is also NOT cached.

The LLM client is stubbed via the ``LlmResidualClient`` Protocol — a
tiny in-test class whose ``extract_system_context`` returns canned dicts
(or raises ``ValueError``) in a fixed sequence. No network, no API key.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterator

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- register tables
from cybersecurity_assessor.models import (  # noqa: E402
    Framework,
    Poam,
    PoamStatus,
    ResidualSuggestionCache,
    RiskLevel,
    Workbook,
)
from cybersecurity_assessor.poam import residual_advisor  # noqa: E402
from cybersecurity_assessor.poam.residual_advisor import (  # noqa: E402
    ADVISOR_KERNEL_VERSION,
    ADVISOR_PROMPT_SHA,
    ResidualSuggestion,
    ValidationError,
    _MAX_KEY_FACTORS,
    _RATIONALE_MAX_CHARS,
    _input_digest,
    bump_hit,
    fingerprint,
    lookup_cache,
    replay,
    store_cache,
    suggest_residual,
    validate_response,
)


# ---------------------------------------------------------------------------
# Stub LLM client (Protocol-compatible)
# ---------------------------------------------------------------------------


class StubLlm:
    """Returns canned responses in order; raises on a sentinel.

    Each entry in ``responses`` is either:
      * a ``dict`` — returned verbatim from ``extract_system_context``
      * an ``Exception`` instance — raised (simulates JSON-parse failure
        the real clients surface as ``ValueError``).

    Exhaustion of the queue is a test bug, so we raise ``AssertionError``
    rather than silently returning ``None`` (which would mask a regression
    where the advisor calls the model more times than expected).
    """

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    def extract_system_context(self, prompt: str) -> dict:
        self.calls += 1
        if not self._responses:
            raise AssertionError(
                f"StubLlm exhausted; advisor called LLM {self.calls} times"
            )
        nxt = self._responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def env(tmp_path: Path) -> Iterator[dict]:
    """In-memory SQLite + a single seeded POAM the advisor can target.

    No findings / no linked narratives — the advisor handles that empty
    case (the ``(none)`` branch in ``build_advisor_prompt``) and the
    cache lifecycle pins don't need the prompt body to be realistic.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    wb_path = tmp_path / "wb.xlsx"
    wb_path.write_bytes(b"x")

    with Session(engine) as s:
        framework = Framework(name="NIST SP 800-53", version="Rev 5")
        s.add(framework)
        s.commit()
        s.refresh(framework)

        workbook = Workbook(
            path=str(wb_path),
            filename=wb_path.name,
            framework_id=framework.id,
        )
        s.add(workbook)
        s.commit()
        s.refresh(workbook)

        poam = Poam(
            workbook_id=workbook.id,
            control_cluster="AC-2",
            vulnerability_description="Account review cadence not enforced.",
            status=PoamStatus.DRAFT,
            likelihood=RiskLevel.MODERATE,
            impact=RiskLevel.HIGH,
            raw_severity=RiskLevel.HIGH,
            residual_risk=RiskLevel.HIGH,
        )
        s.add(poam)
        s.commit()
        s.refresh(poam)

        yield {
            "session": s,
            "poam_id": poam.id,
            "workbook_id": workbook.id,
        }


# ---------------------------------------------------------------------------
# validate_response
# ---------------------------------------------------------------------------


class TestValidateResponse:
    def test_accepts_well_formed_payload(self) -> None:
        """Happy path — every field present, suggested ≤ raw, confidence
        in the enum. Returns a ``ResidualSuggestion`` with the literal
        values from the dict (no surprise coercion)."""
        out = validate_response(
            {
                "suggested_residual": "moderate",
                "rationale": "Airgapped + AC-3 enforcement compensates.",
                "confidence": "high",
                "key_factors": ["airgap", "mfa", "logging"],
            },
            raw_severity=RiskLevel.HIGH,
        )
        assert out.suggested_residual == RiskLevel.MODERATE
        assert out.rationale == "Airgapped + AC-3 enforcement compensates."
        assert out.confidence == "high"
        assert out.key_factors == ["airgap", "mfa", "logging"]

    def test_accepts_null_suggestion_for_abstain(self) -> None:
        """The model is REQUIRED to abstain when boundary context is
        insufficient — that path comes back as JSON null and validates."""
        out = validate_response(
            {
                "suggested_residual": None,
                "rationale": "Linked SC-7 narrative is empty; cannot judge.",
                "confidence": "low",
                "key_factors": [],
            },
            raw_severity=RiskLevel.HIGH,
        )
        assert out.suggested_residual is None
        assert out.confidence == "low"

    def test_rejects_residual_above_raw_severity(self) -> None:
        """The canonical hard rule — residual analysis only downgrades or
        holds. ``HIGH`` suggested against ``MODERATE`` raw must raise."""
        with pytest.raises(ValidationError, match="exceeds raw_severity"):
            validate_response(
                {
                    "suggested_residual": "high",
                    "rationale": "Internet-facing, no compensating controls.",
                    "confidence": "medium",
                    "key_factors": [],
                },
                raw_severity=RiskLevel.MODERATE,
            )

    def test_rejects_unknown_risk_level_string(self) -> None:
        """Enum-membership is enforced server-side so a typo in the model
        output ("med" instead of "moderate") never reaches the UI."""
        with pytest.raises(ValidationError, match="suggested_residual"):
            validate_response(
                {
                    "suggested_residual": "med",
                    "rationale": "ok",
                    "confidence": "low",
                },
                raw_severity=RiskLevel.HIGH,
            )

    def test_rejects_unknown_confidence(self) -> None:
        with pytest.raises(ValidationError, match="confidence"):
            validate_response(
                {
                    "suggested_residual": "low",
                    "rationale": "ok",
                    "confidence": "very-high",  # not in the enum
                },
                raw_severity=RiskLevel.HIGH,
            )

    def test_rejects_non_dict_payload(self) -> None:
        with pytest.raises(ValidationError, match="expected JSON object"):
            validate_response(["not", "a", "dict"], raw_severity=RiskLevel.HIGH)  # type: ignore[arg-type]

    def test_rejects_non_string_rationale(self) -> None:
        with pytest.raises(ValidationError, match="rationale"):
            validate_response(
                {
                    "suggested_residual": "low",
                    "rationale": 42,
                    "confidence": "low",
                },
                raw_severity=RiskLevel.HIGH,
            )

    def test_truncates_oversize_rationale(self) -> None:
        """Soft cap — model occasionally exceeds the prompt's ≤400 char
        guidance. Validator truncates instead of failing so the card
        always renders something."""
        long = "x" * (_RATIONALE_MAX_CHARS + 200)
        out = validate_response(
            {
                "suggested_residual": "low",
                "rationale": long,
                "confidence": "low",
            },
            raw_severity=RiskLevel.HIGH,
        )
        assert len(out.rationale) <= _RATIONALE_MAX_CHARS
        # Truncation marker preserved so a reader knows it was cut.
        assert out.rationale.endswith("\u2026")

    def test_caps_key_factors_list_length(self) -> None:
        """``key_factors`` is capped at :data:`_MAX_KEY_FACTORS` items so
        the UI doesn't render an unbounded bullet list."""
        items = [f"factor-{i}" for i in range(_MAX_KEY_FACTORS + 5)]
        out = validate_response(
            {
                "suggested_residual": "low",
                "rationale": "ok",
                "confidence": "low",
                "key_factors": items,
            },
            raw_severity=RiskLevel.HIGH,
        )
        assert len(out.key_factors) == _MAX_KEY_FACTORS

    def test_rejects_non_string_key_factor_item(self) -> None:
        with pytest.raises(ValidationError, match="key_factors items"):
            validate_response(
                {
                    "suggested_residual": "low",
                    "rationale": "ok",
                    "confidence": "low",
                    "key_factors": ["fine", 99, "also fine"],
                },
                raw_severity=RiskLevel.HIGH,
            )


# ---------------------------------------------------------------------------
# fingerprint + cache lifecycle
# ---------------------------------------------------------------------------


class TestCacheLifecycle:
    def test_fingerprint_stable_for_same_inputs(self) -> None:
        """``fingerprint`` over identical inputs must produce identical
        sha256 across calls. Without stability the cache never hits."""
        a = fingerprint(poam_id=42, input_digest="deadbeef")
        b = fingerprint(poam_id=42, input_digest="deadbeef")
        assert a == b
        # Differ on either knob → different fingerprint.
        assert a != fingerprint(poam_id=43, input_digest="deadbeef")
        assert a != fingerprint(poam_id=42, input_digest="other")

    def test_store_and_lookup_roundtrip(self, env) -> None:
        """Round-trip an LLM suggestion through the cache and confirm
        every persisted field matches the input."""
        fp = fingerprint(poam_id=env["poam_id"], input_digest="d1")
        suggestion = ResidualSuggestion(
            suggested_residual=RiskLevel.LOW,
            rationale="Airgapped + AC-3 enforcement compensates.",
            confidence="high",
            key_factors=["airgap", "logging"],
        )
        store_cache(env["session"], fp, poam_id=env["poam_id"], suggestion=suggestion)

        cached = lookup_cache(env["session"], fp)
        assert cached is not None
        assert cached.fingerprint == fp
        assert cached.poam_id == env["poam_id"]
        assert cached.advisor_version == ADVISOR_KERNEL_VERSION
        assert cached.prompt_sha == ADVISOR_PROMPT_SHA
        assert cached.hit_count == 0
        assert cached.last_hit_at is None

    def test_store_is_idempotent_on_duplicate_fingerprint(self, env) -> None:
        """SQLite PK uniqueness means a second store under the same fp
        is a silent no-op — same fingerprint requires same inputs by
        construction, so we don't need to rewrite the row."""
        fp = fingerprint(poam_id=env["poam_id"], input_digest="d1")
        s = ResidualSuggestion(
            suggested_residual=RiskLevel.LOW,
            rationale="r",
            confidence="low",
        )
        store_cache(env["session"], fp, poam_id=env["poam_id"], suggestion=s)
        store_cache(env["session"], fp, poam_id=env["poam_id"], suggestion=s)

        rows = env["session"].exec(
            __import__("sqlmodel").select(ResidualSuggestionCache)
        ).all()
        assert len(rows) == 1

    def test_bump_hit_increments_counter_and_stamps_timestamp(self, env) -> None:
        """``bump_hit`` is the telemetry hook on cache reuse. Without the
        counter we can't tell which suggestions are getting replayed vs
        re-computed."""
        fp = fingerprint(poam_id=env["poam_id"], input_digest="d1")
        store_cache(
            env["session"],
            fp,
            poam_id=env["poam_id"],
            suggestion=ResidualSuggestion(
                suggested_residual=RiskLevel.LOW,
                rationale="r",
                confidence="low",
            ),
        )
        cached = lookup_cache(env["session"], fp)
        assert cached is not None and cached.hit_count == 0

        bump_hit(env["session"], cached)
        bump_hit(env["session"], cached)

        refreshed = lookup_cache(env["session"], fp)
        assert refreshed is not None
        assert refreshed.hit_count == 2
        assert refreshed.last_hit_at is not None

    def test_replay_stamps_cache_source_marker(self, env) -> None:
        """``replay`` is the materialization step the route layer calls
        on a cache hit — it MUST tag the returned suggestion so telemetry
        and the UI can tell a hit from a fresh decision."""
        fp = fingerprint(poam_id=env["poam_id"], input_digest="d1")
        store_cache(
            env["session"],
            fp,
            poam_id=env["poam_id"],
            suggestion=ResidualSuggestion(
                suggested_residual=RiskLevel.MODERATE,
                rationale="Held at moderate; some compensation but uncertain.",
                confidence="medium",
                key_factors=["partial-mfa", "limited-logging"],
            ),
        )
        cached = lookup_cache(env["session"], fp)
        assert cached is not None

        out = replay(cached)
        assert out.suggested_residual == RiskLevel.MODERATE
        assert out.confidence == "medium"
        assert out.key_factors == ["partial-mfa", "limited-logging"]
        # The load-bearing tag.
        assert out.cache_source == "cache_hit"


# ---------------------------------------------------------------------------
# suggest_residual — retry, abstain, force_refresh
# ---------------------------------------------------------------------------


class TestSuggestResidual:
    def test_cache_miss_calls_llm_and_persists(self, env) -> None:
        """End-to-end happy path: empty cache → LLM call once → suggestion
        stored under the computed fingerprint with the LLM's payload."""
        llm = StubLlm(
            [
                {
                    "suggested_residual": "low",
                    "rationale": "Airgapped boundary + AC-3 enforcement.",
                    "confidence": "high",
                    "key_factors": ["airgap"],
                }
            ]
        )

        out = suggest_residual(
            poam_id=env["poam_id"], session=env["session"], llm=llm
        )
        assert llm.calls == 1
        assert out.suggested_residual == RiskLevel.LOW
        # Fresh decision — NOT a cache hit.
        assert out.cache_source is None

        # Verify the row landed.
        rows = env["session"].exec(
            __import__("sqlmodel").select(ResidualSuggestionCache)
        ).all()
        assert len(rows) == 1
        assert rows[0].poam_id == env["poam_id"]

    def test_cache_hit_short_circuits_llm_and_stamps_marker(self, env) -> None:
        """Second call against the same POAM (unchanged inputs) must not
        touch the LLM — it replays the cached row and the returned
        suggestion carries ``cache_source = "cache_hit"``."""
        # Prime the cache via a first call.
        llm = StubLlm(
            [
                {
                    "suggested_residual": "moderate",
                    "rationale": "Some compensation but boundary uncertain.",
                    "confidence": "medium",
                    "key_factors": ["partial-mfa"],
                }
            ]
        )
        first = suggest_residual(
            poam_id=env["poam_id"], session=env["session"], llm=llm
        )
        assert first.cache_source is None
        assert llm.calls == 1

        # Second call — same POAM, no fresh inputs. Pass a stub with NO
        # responses; if the cache path doesn't short-circuit, the stub
        # raises and the test fails noisily.
        empty_llm = StubLlm([])
        second = suggest_residual(
            poam_id=env["poam_id"], session=env["session"], llm=empty_llm
        )
        assert empty_llm.calls == 0
        assert second.cache_source == "cache_hit"
        assert second.suggested_residual == RiskLevel.MODERATE
        # bump_hit fired — the persisted row now has hit_count >= 1.
        fp = fingerprint(
            poam_id=env["poam_id"],
            input_digest=_input_digest_for(env),
        )
        cached = lookup_cache(env["session"], fp)
        assert cached is not None and cached.hit_count >= 1

    def test_force_refresh_bypasses_cache_lookup(self, env) -> None:
        """The "Refresh suggestion" UI button calls with ``force_refresh=True``
        — the advisor must re-issue the LLM call even when a cached row
        already exists."""
        suggest_residual(
            poam_id=env["poam_id"],
            session=env["session"],
            llm=StubLlm(
                [
                    {
                        "suggested_residual": "low",
                        "rationale": "first call",
                        "confidence": "low",
                    }
                ]
            ),
        )

        # Force-refresh — the stub MUST be hit even though a cache row exists.
        refresh_llm = StubLlm(
            [
                {
                    "suggested_residual": "moderate",
                    "rationale": "second call — fresh judgment",
                    "confidence": "medium",
                }
            ]
        )
        out = suggest_residual(
            poam_id=env["poam_id"],
            session=env["session"],
            llm=refresh_llm,
            force_refresh=True,
        )
        assert refresh_llm.calls == 1
        # Fresh call → NOT marked as cache hit even though a row existed.
        assert out.cache_source is None

    def test_one_parse_failure_then_clean_call_succeeds(self, env) -> None:
        """The retry budget is one — a parse failure followed by a clean
        response returns the clean suggestion and caches it."""
        llm = StubLlm(
            [
                ValueError("model emitted invalid JSON"),
                {
                    "suggested_residual": "low",
                    "rationale": "Recovered on retry.",
                    "confidence": "high",
                },
            ]
        )

        out = suggest_residual(
            poam_id=env["poam_id"], session=env["session"], llm=llm
        )
        assert llm.calls == 2
        assert out.suggested_residual == RiskLevel.LOW
        assert not out.rationale.startswith("[")  # NOT a hard-abstain marker.

        # Suggestion was cached.
        rows = env["session"].exec(
            __import__("sqlmodel").select(ResidualSuggestionCache)
        ).all()
        assert len(rows) == 1

    def test_two_parse_failures_hard_abstain_and_do_not_cache(self, env) -> None:
        """Retry budget exhausted on parse errors → low-confidence
        abstain tagged ``[parse_error]`` and NOT cached, so the next
        render gets a fresh attempt instead of replaying the failure."""
        llm = StubLlm(
            [
                ValueError("first malformed"),
                ValueError("second malformed"),
            ]
        )

        out = suggest_residual(
            poam_id=env["poam_id"], session=env["session"], llm=llm
        )
        assert llm.calls == 2
        assert out.suggested_residual is None
        assert out.confidence == "low"
        assert out.rationale.startswith("[parse_error]")

        # Critical contract — failure path NEVER pollutes the cache.
        rows = env["session"].exec(
            __import__("sqlmodel").select(ResidualSuggestionCache)
        ).all()
        assert rows == []

    def test_two_validation_failures_hard_abstain_marked_validation(
        self, env
    ) -> None:
        """Same as the parse-error path but for validator rejections —
        the rationale prefix changes to ``[validation_error]`` so an
        auditor reading the card can distinguish "model gave bad JSON"
        from "model gave a payload that violated the contract"."""
        llm = StubLlm(
            [
                # Both attempts violate never-above-raw-severity (the env
                # POAM has raw_severity=HIGH and we suggest a non-existent
                # higher level by way of an enum violation).
                {
                    "suggested_residual": "not-a-level",
                    "rationale": "bad",
                    "confidence": "low",
                },
                {
                    "suggested_residual": "also-not-a-level",
                    "rationale": "still bad",
                    "confidence": "low",
                },
            ]
        )

        out = suggest_residual(
            poam_id=env["poam_id"], session=env["session"], llm=llm
        )
        assert llm.calls == 2
        assert out.suggested_residual is None
        assert out.confidence == "low"
        assert out.rationale.startswith("[validation_error]")

        rows = env["session"].exec(
            __import__("sqlmodel").select(ResidualSuggestionCache)
        ).all()
        assert rows == []

    def test_missing_poam_raises(self, env) -> None:
        """An unknown POAM id is a programmer error from the route layer;
        the advisor surfaces it as ``ValueError`` so the caller's 404
        translation has something to catch."""
        with pytest.raises(ValueError, match="not found"):
            suggest_residual(
                poam_id=999999,
                session=env["session"],
                llm=StubLlm([]),
            )


# ---------------------------------------------------------------------------
# Helpers — local utilities so the cache-hit test can compute the same
# fingerprint suggest_residual uses internally.
# ---------------------------------------------------------------------------


def _input_digest_for(env: dict) -> str:
    """Re-compute the input digest for the seeded POAM exactly the way
    the advisor does so the cache-hit test can look up the persisted row.
    Mirrors the digest_for shape inside ``suggest_residual``."""
    with Session(env["session"].bind) as s:
        poam = s.get(Poam, env["poam_id"])
        assert poam is not None
        from cybersecurity_assessor.poam.residual_advisor import (
            _collect_contributing_findings,
            _collect_linked_narratives,
        )

        findings = _collect_contributing_findings(poam, s)
        narratives = _collect_linked_narratives(poam, s)
        return _input_digest(poam, findings, narratives)
