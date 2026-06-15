"""Probe the configured Anthropic endpoint and print the raw usage envelope.

Fires ONE trivial Anthropic call through whatever base_url is configured
(Example gateway, api.anthropic.com, anything pasted in Settings) and prints:

  1. type(response.usage)
  2. repr(response.usage)
  3. _usage_as_dict(response.usage) — what the extractor sees
  4. _UsageBlock.from_sdk(response.usage) — what the extractor produces

Usage:
    cd C:\\Users\\Noah.Jaskolski\\Projects\\cybersecurity-assessor\\backend
    .venv\\Scripts\\python.exe probe_gateway_usage.py

Sidesteps the assess pipeline entirely so deterministic short-circuits don't
get in the way. ~5 seconds end-to-end.
"""

from __future__ import annotations

import json
import sys

from cybersecurity_assessor import config as _cfg
from cybersecurity_assessor.llm.client import _UsageBlock, _usage_as_dict


def main() -> int:
    base_url, resolved_key = _cfg.resolve_anthropic_endpoint()
    if not resolved_key:
        from cybersecurity_assessor.llm.client import _resolve_api_key

        resolved_key = _resolve_api_key(None)

    print(f"[probe] base_url = {base_url}")
    print(f"[probe] api_key  = {'<set>' if resolved_key else '<MISSING>'}")
    if not resolved_key:
        print("[probe] No API key resolvable — set ANTHROPIC_API_KEY or store in Settings.")
        return 2

    try:
        from anthropic import Anthropic
    except ImportError:
        print("[probe] anthropic SDK not installed in this env.")
        return 2

    client = Anthropic(api_key=resolved_key, base_url=base_url)
    print(f"[probe] firing trivial call to {base_url} ...")
    try:
        resp = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=16,
            messages=[{"role": "user", "content": "Reply with exactly: OK"}],
        )
    except Exception as exc:
        print(f"[probe] CALL FAILED: {type(exc).__name__}: {exc}")
        return 1

    raw_usage = getattr(resp, "usage", None)
    print()
    print("=" * 70)
    print(f"raw_usage type: {type(raw_usage).__name__}")
    print(f"raw_usage repr: {repr(raw_usage)[:500]}")
    print("=" * 70)
    coerced = _usage_as_dict(raw_usage)
    print("coerced dict:")
    try:
        print(json.dumps(coerced, indent=2, default=str))
    except Exception:
        print(repr(coerced))
    print("=" * 70)
    block = _UsageBlock.from_sdk(raw_usage)
    print("extracted _UsageBlock:")
    print(f"  input_tokens                = {block.input_tokens}")
    print(f"  output_tokens               = {block.output_tokens}")
    print(f"  cache_creation_input_tokens = {block.cache_creation_input_tokens}")
    print(f"  cache_read_input_tokens     = {block.cache_read_input_tokens}")
    print("=" * 70)
    if block.input_tokens == 0 and block.output_tokens == 0:
        print(">>> EXTRACTION FAILED <<<")
        print("The gateway returned data but the extractor produced zeros.")
        print("Send the coerced dict above so the extractor can be extended.")
        return 1
    print(">>> EXTRACTION OK — cost tracking will work for this gateway. <<<")
    return 0


if __name__ == "__main__":
    sys.exit(main())
