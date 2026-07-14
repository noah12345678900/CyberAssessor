"""OpenAIClient.describe_image — vision parity with AnthropicClient.

WHY THIS EXISTS
---------------
Vision (describe_image) was originally Anthropic-only; on the OpenAI provider
every image silently failed and degraded to OCR, so screenshot-heavy evidence
lost its vision-derived tags. These tests pin the OpenAI implementation's
contract so it can't regress:

* Correct OpenAI-standard payload shape (``image_url`` + ``data:`` URI), which
  is what makes it portable across real OpenAI, Azure, vLLM, LiteLLM, LM
  Studio, and Ollama's compat layer — not just one gateway.
* Full-resolution passthrough for in-guard images (downscaling would blur the
  small UI text the describer exists to read).
* Rescue-only downscale for an oversize outlier, never preemptive.
* Graceful "" on empty input, un-rescuable oversize, and SDK errors — the
  caller degrades to OCR and must never crash an ingest.
* Warn-once (not once-per-image) when a text-only endpoint rejects vision.
"""

from __future__ import annotations

import base64
from io import BytesIO

import pytest

from cybersecurity_assessor.llm.client import (
    _VISION_MAX_IMAGE_BYTES,
    OpenAIClient,
)


# --- Fake OpenAI SDK -------------------------------------------------------
# The real client calls ``self._client.chat.completions.create(**kwargs)`` and
# reads ``response.choices[0].message.content``. This stub records the last
# create() kwargs so a test can assert the exact payload shape.


class _FakeMessage:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeChoice:
    def __init__(self, content: str) -> None:
        self.message = _FakeMessage(content)


class _FakeResponse:
    def __init__(self, content: str) -> None:
        self.choices = [_FakeChoice(content)]
        self.id = "chatcmpl-test"
        self.model = "gpt-test"
        self.usage = None


class _FakeCompletions:
    def __init__(self, content: str = "a login console showing user alice", exc: Exception | None = None) -> None:
        self._content = content
        self._exc = exc
        self.calls: list[dict] = []

    def create(self, **kwargs):  # noqa: ANN003, ANN201
        self.calls.append(kwargs)
        if self._exc is not None:
            raise self._exc
        return _FakeResponse(self._content)


class _FakeChat:
    def __init__(self, completions: _FakeCompletions) -> None:
        self.completions = completions


class _FakeSDK:
    def __init__(self, completions: _FakeCompletions) -> None:
        self.chat = _FakeChat(completions)


def _client(completions: _FakeCompletions) -> OpenAIClient:
    return OpenAIClient(model="gpt-test", _sdk_client=_FakeSDK(completions))


def _small_png() -> bytes:
    """A tiny valid-ish PNG (header + filler). Never near the size guard."""
    return b"\x89PNG\r\n\x1a\n" + b"\x00" * 4096


# --- Payload shape ---------------------------------------------------------


def test_describe_image_builds_openai_data_uri_payload() -> None:
    comp = _FakeCompletions(content="Red Hat IdM console: user cybertest, groups docker, ssh_users")
    client = _client(comp)

    out = client.describe_image(_small_png(), media_type="image/png")

    assert "cybertest" in out
    assert len(comp.calls) == 1
    kw = comp.calls[0]
    assert kw["model"] == "gpt-test"
    assert kw["max_tokens"] == 768
    # One user message carrying a text block THEN an image_url block.
    messages = kw["messages"]
    assert len(messages) == 1 and messages[0]["role"] == "user"
    content = messages[0]["content"]
    assert content[0]["type"] == "text"
    assert content[1]["type"] == "image_url"
    url = content[1]["image_url"]["url"]
    assert url.startswith("data:image/png;base64,")
    # Round-trips back to the original bytes → sent at full resolution.
    payload = base64.b64decode(url.split(",", 1)[1])
    assert payload == _small_png()


def test_small_image_sent_full_resolution_no_downscale() -> None:
    comp = _FakeCompletions()
    client = _client(comp)
    img = _small_png()

    client.describe_image(img, media_type="image/png")

    url = comp.calls[0]["messages"][0]["content"][1]["image_url"]["url"]
    payload = base64.b64decode(url.split(",", 1)[1])
    # Byte-identical to input → not re-encoded / not shrunk.
    assert payload == img
    assert "image/png" in url


def test_jpg_media_type_normalized_to_jpeg() -> None:
    comp = _FakeCompletions()
    client = _client(comp)

    client.describe_image(_small_png(), media_type="image/jpg")

    url = comp.calls[0]["messages"][0]["content"][1]["image_url"]["url"]
    assert url.startswith("data:image/jpeg;base64,")


# --- Degradation contract --------------------------------------------------


def test_empty_bytes_returns_empty_no_call() -> None:
    comp = _FakeCompletions()
    client = _client(comp)
    assert client.describe_image(b"") == ""
    assert comp.calls == []  # never hits the SDK


def test_sdk_error_degrades_to_empty() -> None:
    comp = _FakeCompletions(exc=RuntimeError("boom"))
    client = _client(comp)
    assert client.describe_image(_small_png()) == ""


def test_oversize_undecodable_skips_to_ocr() -> None:
    # Over the guard AND not a decodable image → rescue returns None → "".
    comp = _FakeCompletions()
    client = _client(comp)
    junk = b"\xff" * (_VISION_MAX_IMAGE_BYTES + 1)
    assert client.describe_image(junk, media_type="image/png") == ""
    assert comp.calls == []  # never reached the model


# --- Rescue-only downscale -------------------------------------------------


def test_oversize_real_image_is_downscaled_to_fit_and_sent() -> None:
    pytest.importorskip("PIL")
    from PIL import Image

    # Dense noise so PNG can't compress → guaranteed over the guard.
    import random

    rng = random.Random(0)
    im = Image.new("RGB", (3000, 2500))
    px = im.load()
    for x in range(3000):
        for y in range(2500):
            px[x, y] = (rng.randint(0, 255), rng.randint(0, 255), rng.randint(0, 255))
    buf = BytesIO()
    im.save(buf, format="PNG")
    big = buf.getvalue()
    assert len(big) > _VISION_MAX_IMAGE_BYTES  # precondition

    comp = _FakeCompletions()
    client = _client(comp)
    out = client.describe_image(big, media_type="image/png")

    assert out  # got a description, not skipped
    url = comp.calls[0]["messages"][0]["content"][1]["image_url"]["url"]
    # Rescued to JPEG and under the cap.
    assert url.startswith("data:image/jpeg;base64,")
    sent = base64.b64decode(url.split(",", 1)[1])
    assert len(sent) <= _VISION_MAX_IMAGE_BYTES


# --- Warn-once on a vision-less endpoint -----------------------------------


def test_warns_once_per_model_when_vision_unsupported(caplog) -> None:
    comp = _FakeCompletions(exc=RuntimeError("model does not support image input"))
    client = _client(comp)

    import logging

    with caplog.at_level(logging.WARNING):
        assert client.describe_image(_small_png()) == ""
        assert client.describe_image(_small_png()) == ""
        assert client.describe_image(_small_png()) == ""

    unsupported = [r for r in caplog.records if "unsupported by model" in r.getMessage()]
    assert len(unsupported) == 1  # once for the model, not once per image
