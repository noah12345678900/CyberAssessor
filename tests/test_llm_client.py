"""Tests for the Anthropic LLM client.

Covers the deterministic surface — message construction, response parsing,
prompt-cache wiring, token telemetry — without making real API calls. The
SDK client is stubbed via the ``_sdk_client`` constructor hook.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from cybersecurity_assessor.engine.assessor import LlmProposal
from cybersecurity_assessor.llm import client as client_mod
from cybersecurity_assessor.llm.client import (
    AnthropicClient,
    LlmResponseParseError,
    MissingApiKeyError,
    _coerce_status,
    build_user_message,
    parse_response,
)
from cybersecurity_assessor.models import ComplianceStatus


# ---------------------------------------------------------------------------
# Fake SDK
# ---------------------------------------------------------------------------


@dataclass
class _FakeBlock:
    type: str
    text: str


@dataclass
class _FakeUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0


@dataclass
class _FakeResponse:
    content: list[_FakeBlock]
    usage: _FakeUsage | None = None


@dataclass
class _FakeMessages:
    canned: list[_FakeResponse]
    calls: list[dict] = field(default_factory=list)

    def create(self, **kwargs: Any) -> _FakeResponse:
        self.calls.append(kwargs)
        if not self.canned:
            raise AssertionError("FakeMessages exhausted")
        return self.canned.pop(0)


@dataclass
class _FakeSdk:
    messages: _FakeMessages


def _ok_response(narrative: str, status: str = "Compliant", **usage_kwargs: Any) -> _FakeResponse:
    body = f'{{"status": "{status}", "narrative": "{narrative}"}}'
    return _FakeResponse(
        content=[_FakeBlock(type="text", text=f"Reasoning line.\n{body}")],
        usage=_FakeUsage(**usage_kwargs),
    )


# ---------------------------------------------------------------------------
# Status coercion
# ---------------------------------------------------------------------------


def test_coerce_status_strict_match():
    assert _coerce_status("Compliant") == ComplianceStatus.COMPLIANT
    assert _coerce_status("Non-Compliant") == ComplianceStatus.NON_COMPLIANT
    assert _coerce_status("Not Applicable") == ComplianceStatus.NOT_APPLICABLE


def test_coerce_status_safe_variants():
    assert _coerce_status("compliant") == ComplianceStatus.COMPLIANT
    assert _coerce_status("Non Compliant") == ComplianceStatus.NON_COMPLIANT
    assert _coerce_status("NonCompliant") == ComplianceStatus.NON_COMPLIANT
    assert _coerce_status("N/A") == ComplianceStatus.NOT_APPLICABLE
    assert _coerce_status("NA") == ComplianceStatus.NOT_APPLICABLE


def test_coerce_status_rejects_unknown():
    with pytest.raises(ValueError):
        _coerce_status("Mostly Compliant")


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


def test_parse_response_extracts_last_json_block():
    raw = (
        "Some reasoning here.\n"
        'Maybe a stray {"foo": "bar"} non-status object.\n'
        '{"status": "Compliant", "narrative": "Verified via USD00050010 §3.2."}'
    )
    # parse_response returns a ParsedResponse dataclass (status, narrative,
    # confidence, abstain); legacy tuple unpacking is no longer supported.
    parsed = parse_response(raw)
    assert parsed.status == ComplianceStatus.COMPLIANT
    assert "USD00050010" in parsed.narrative


def test_parse_response_handles_only_json():
    raw = '{"status": "Not Applicable", "narrative": "Implemented by AWS GovCloud."}'
    parsed = parse_response(raw)
    assert parsed.status == ComplianceStatus.NOT_APPLICABLE
    assert parsed.narrative.startswith("Implemented by AWS")


def test_parse_response_raises_on_no_json():
    with pytest.raises(LlmResponseParseError):
        parse_response("There is no json here at all.")


def test_parse_response_raises_on_missing_keys():
    with pytest.raises(LlmResponseParseError):
        parse_response('{"status": "Compliant"}')


def test_parse_response_raises_on_empty_narrative():
    with pytest.raises(LlmResponseParseError):
        parse_response('{"status": "Compliant", "narrative": "   "}')


def test_parse_response_raises_on_bad_status():
    with pytest.raises(LlmResponseParseError):
        parse_response('{"status": "Vibes", "narrative": "X."}')


def test_parse_response_handles_trailing_prose_after_envelope():
    """Regression (AC-17): the model emitted a COMPLETE valid JSON envelope and
    then a trailing prose 'Note: ...' after the closing brace. The old
    first-{-to-last-} scan swallowed the prose and json.loads raised
    'Extra data', then the legacy regex couldn't traverse the nested objects, so
    BOTH phases failed deterministically and the control parked at
    needs_review/llm-parse-error on every reassess. raw_decode stops at the
    object's closing brace and ignores the trailing note.
    """
    raw = (
        '{"status": "Non-Compliant", "narrative": "On-Prem residual is '
        'unsubstantiated.", "confidence": 0.9}\n\n'
        "Note: the On-Premises absence has no positive evidence span to quote."
    )
    parsed = parse_response(raw)
    assert parsed.status == ComplianceStatus.NON_COMPLIANT
    assert "On-Prem residual" in parsed.narrative


def test_parse_response_handles_nested_objects_and_arrays():
    """Regression (AC-17): a multi-scope envelope nests a narratives_by_scope
    object and a citations array of objects. The legacy regex body class
    [^{}]* cannot traverse the inner braces; raw_decode handles arbitrary
    nesting. Also pins that leading prose before the envelope is tolerated.
    """
    raw = (
        "Analyzing per scope:\n\n"
        '{"status": "Non-Compliant", "narrative": "Gap on On-Prem.", '
        '"narratives_by_scope": {"AWS GovCloud": "verified", "Azure": "inherited"}, '
        '"confidence": 0.9, '
        '"citations": [{"narrative_field": "narrative_cloud", "evidence_id": 2, '
        '"source_quote": "Customer fully inherits Azure Bastion."}]}'
    )
    parsed = parse_response(raw)
    assert parsed.status == ComplianceStatus.NON_COMPLIANT
    assert parsed.narrative == "Gap on On-Prem."


# ---------------------------------------------------------------------------
# User-message construction
# ---------------------------------------------------------------------------


def test_user_message_includes_row_fields(make_row):
    row = make_row(
        cci_id="CCI-000015",
        previous_results="Cited USD00050010 §3.2 last year.",
    )
    msg = build_user_message(row=row, corrective_context=None, prior_attempts=None)
    assert "AC-2(1)" in msg
    assert "CCI-000015" in msg
    assert "USD00050010" in msg
    # Corrective context absent → no rejection banner
    assert "Corrective context" not in msg


def test_user_message_puts_corrective_context_first(make_row):
    row = make_row()
    msg = build_user_message(
        row=row,
        corrective_context="Previous proposal mismatched status; fix it.",
        prior_attempts=None,
    )
    assert msg.startswith("## Corrective context")
    assert msg.index("Corrective context") < msg.index("CCIS row")


def test_user_message_renders_prior_attempts(make_row):
    row = make_row()
    prior = [
        LlmProposal(
            status=ComplianceStatus.COMPLIANT,
            narrative="No artifact found.",
        )
    ]
    msg = build_user_message(row=row, corrective_context="retry", prior_attempts=prior)
    assert "Prior attempts" in msg
    assert "No artifact found" in msg


# ---------------------------------------------------------------------------
# AnthropicClient.propose — happy path
# ---------------------------------------------------------------------------


def test_propose_returns_llm_proposal_with_telemetry(make_row):
    row = make_row()
    response = _ok_response(
        narrative="Verified via USD00050010 §3.2.",
        status="Compliant",
        input_tokens=120,
        output_tokens=40,
        cache_read_input_tokens=3000,
    )
    sdk = _FakeSdk(messages=_FakeMessages(canned=[response]))
    client = AnthropicClient(_sdk_client=sdk, system_prompt="SYSTEM")

    proposal = client.propose(row=row)

    assert proposal.status == ComplianceStatus.COMPLIANT
    assert "USD00050010" in proposal.narrative
    # input_tokens is the BASE (non-cache) input count only — cache reads are
    # split into cache_read_tokens so pricing can apply the ~10% cache rate
    # instead of treating them as full-price input (prior bug inflated cost
    # ~10x on cache-heavy runs).
    assert proposal.input_tokens == 120
    assert proposal.cache_read_tokens == 3000
    assert proposal.output_tokens == 40
    assert proposal.raw is not None


def test_propose_wires_system_prompt_with_cache_control(make_row):
    row = make_row()
    sdk = _FakeSdk(
        messages=_FakeMessages(canned=[_ok_response("Verified via USD00050010.")]),
    )
    client = AnthropicClient(_sdk_client=sdk, system_prompt="CACHED-PROMPT")

    client.propose(row=row)

    call = sdk.messages.calls[0]
    system = call["system"]
    assert isinstance(system, list)
    assert system[0]["text"] == "CACHED-PROMPT"
    assert system[0]["cache_control"] == {"type": "ephemeral"}
    # And the user turn carries the row.
    assert call["messages"][0]["role"] == "user"
    assert "AC-2(1)" in call["messages"][0]["content"]


def test_propose_passes_corrective_context_and_prior_attempts(make_row):
    row = make_row()
    sdk = _FakeSdk(messages=_FakeMessages(canned=[_ok_response("Verified.")]))
    client = AnthropicClient(_sdk_client=sdk, system_prompt="X")

    client.propose(
        row=row,
        corrective_context="Validator said status/narrative mismatch.",
        prior_attempts=[
            LlmProposal(status=ComplianceStatus.COMPLIANT, narrative="No artifact found.")
        ],
    )

    user_msg = sdk.messages.calls[0]["messages"][0]["content"]
    assert user_msg.startswith("## Corrective context")
    assert "Validator said" in user_msg
    assert "Prior attempts" in user_msg


# ---------------------------------------------------------------------------
# AnthropicClient.propose — parse failure path
# ---------------------------------------------------------------------------


def test_propose_returns_parse_error_sentinel_on_bad_response(make_row):
    row = make_row()
    bad = _FakeResponse(
        content=[_FakeBlock(type="text", text="I refuse to JSON.")],
        usage=_FakeUsage(input_tokens=50, output_tokens=10),
    )
    sdk = _FakeSdk(messages=_FakeMessages(canned=[bad]))
    client = AnthropicClient(_sdk_client=sdk, system_prompt="X")

    proposal = client.propose(row=row)

    # Sentinel proposal — Non-Compliant + parse_error tag so the validator
    # rejects, the orchestrator records the rejection, and the retry loop
    # gets another shot.
    assert proposal.status == ComplianceStatus.NON_COMPLIANT
    assert "[parse_error]" in proposal.narrative
    assert proposal.input_tokens == 50
    assert proposal.output_tokens == 10


def test_propose_ignores_non_text_content_blocks(make_row):
    row = make_row()
    mixed = _FakeResponse(
        content=[
            _FakeBlock(type="tool_use", text="ignored"),
            _FakeBlock(
                type="text",
                text='{"status": "Compliant", "narrative": "Verified via USD00050010."}',
            ),
        ],
        usage=_FakeUsage(input_tokens=1, output_tokens=2),
    )
    sdk = _FakeSdk(messages=_FakeMessages(canned=[mixed]))
    client = AnthropicClient(_sdk_client=sdk, system_prompt="X")

    proposal = client.propose(row=row)
    assert proposal.status == ComplianceStatus.COMPLIANT


# ---------------------------------------------------------------------------
# API-key resolution
# ---------------------------------------------------------------------------


def test_missing_api_key_raises(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    # Both code paths read the key via the already-imported `keyring` module
    # binding inside `config` and the lazy-imported `keyring` inside
    # `client._resolve_api_key`. Patch both bindings so the developer's
    # real Windows Credential Manager entry doesn't satisfy the lookup.
    from cybersecurity_assessor import config as _cfg
    from cybersecurity_assessor.llm import client as _client_mod

    monkeypatch.setattr(_cfg.keyring, "get_password", lambda *_a, **_kw: None)
    import sys
    import types

    fake_keyring = types.SimpleNamespace(get_password=lambda *_a, **_kw: None)
    monkeypatch.setitem(sys.modules, "keyring", fake_keyring)
    # Also blank any module-cached resolver so a stale config cache can't
    # leak a previously-resolved token.
    if hasattr(_client_mod, "_resolve_api_key"):
        pass  # nothing to invalidate — function is stateless

    with pytest.raises(MissingApiKeyError):
        # No _sdk_client → real construction path → key resolution runs.
        AnthropicClient(system_prompt="X")


def test_explicit_api_key_short_circuits_resolution(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # Even with no keyring entry, an explicit key + an injected SDK
    # client lets construction succeed.
    sdk = _FakeSdk(messages=_FakeMessages(canned=[]))
    client = AnthropicClient(api_key="sk-test", _sdk_client=sdk, system_prompt="X")
    assert client is not None


# ---------------------------------------------------------------------------
# Prompt-on-disk smoke
# ---------------------------------------------------------------------------


def test_default_system_prompt_loads_from_disk():
    # Clear the LRU cache so this test is isolated from prior reads.
    client_mod._load_system_prompt.cache_clear()
    text = client_mod._load_system_prompt()
    assert "CCIS Assessment System Prompt" in text
    # Sanity: rule #11 and supersession sections must be present.
    assert "Rule #11" in text
    assert "USD00050010" in text
