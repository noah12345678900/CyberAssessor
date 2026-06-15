"""Probe the configured OpenAI-compatible endpoint and print the raw usage envelope.

Companion to probe_gateway_usage.py, but exercises the OpenAI SDK path. The
Example AI gateway is OpenAI-shaped (POST /v1/chat/completions, Bearer auth,
{prompt_tokens, completion_tokens} usage envelope), so this is the path the
sidecar actually takes when llm_provider=openai.

Prints:
  1. type(response.usage) / repr(response.usage)
  2. _openai_usage(response) — what the extractor sees
  3. chat_usage_actual.model_cost_details if the gateway returned one
     (Example bonus block — true cost passthrough)

Usage:
    cd C:\\Users\\Noah.Jaskolski\\Projects\\cybersecurity-assessor\\backend
    .venv\\Scripts\\python.exe probe_gateway_openai.py
"""

from __future__ import annotations

import json
import sys

# Mirror server.py startup — patch ssl to use OS trust store BEFORE httpx loads.
# Corporate gateways are usually behind a private CA that certifi doesn't ship.
from cybersecurity_assessor import tls as _tls

_tls.install()

from cybersecurity_assessor import config as _cfg  # noqa: E402


def main() -> int:
    base_url, resolved_key = _cfg.resolve_openai_endpoint()
    print(f"[probe] base_url = {base_url}")
    print(f"[probe] api_key  = {'<set>' if resolved_key else '<MISSING>'}")
    if not resolved_key:
        print("[probe] No API key resolvable.")
        return 2

    cfg = _cfg.load_config()
    model = cfg.openai_model
    print(f"[probe] model    = {model}")

    try:
        from openai import OpenAI
    except ImportError:
        print("[probe] openai SDK not installed in this env.")
        return 2

    client = OpenAI(api_key=resolved_key, base_url=base_url)
    print(f"[probe] firing trivial call ...")
    try:
        resp = client.chat.completions.create(
            model=model,
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

    # Mirror what _openai_usage does in llm/client.py
    if raw_usage is not None:
        try:
            usage_dict = raw_usage.model_dump() if hasattr(raw_usage, "model_dump") else dict(raw_usage)
        except Exception:
            usage_dict = {
                k: getattr(raw_usage, k, None)
                for k in ("prompt_tokens", "completion_tokens", "total_tokens")
            }
        print("coerced usage dict:")
        print(json.dumps(usage_dict, indent=2, default=str))
        print("=" * 70)

        prompt_tokens = getattr(raw_usage, "prompt_tokens", 0) or 0
        completion_tokens = getattr(raw_usage, "completion_tokens", 0) or 0
        print(f"  prompt_tokens     = {prompt_tokens}")
        print(f"  completion_tokens = {completion_tokens}")
        print("=" * 70)

    # Example gateway bonus: chat_usage_actual.model_cost_details has true per-call cost
    full_dump = None
    try:
        full_dump = resp.model_dump() if hasattr(resp, "model_dump") else None
    except Exception:
        pass
    if full_dump:
        cua = full_dump.get("chat_usage_actual")
        if cua:
            print("chat_usage_actual (Example gateway passthrough):")
            print(json.dumps(cua, indent=2, default=str))
            print("=" * 70)
        else:
            # The OpenAI SDK may drop unknown top-level fields. Try the raw response.
            try:
                raw = resp.to_dict() if hasattr(resp, "to_dict") else None
            except Exception:
                raw = None
            if raw and "chat_usage_actual" in raw:
                print("chat_usage_actual (from to_dict):")
                print(json.dumps(raw["chat_usage_actual"], indent=2, default=str))
                print("=" * 70)
            else:
                print("(no chat_usage_actual block surfaced via SDK)")
                print("=" * 70)

    if raw_usage and (getattr(raw_usage, "prompt_tokens", 0) or 0) > 0:
        print(">>> EXTRACTION OK — cost tracking will work via OpenAIClient. <<<")
        return 0
    print(">>> EXTRACTION FAILED — usage block missing or zero. <<<")
    return 1


if __name__ == "__main__":
    sys.exit(main())
