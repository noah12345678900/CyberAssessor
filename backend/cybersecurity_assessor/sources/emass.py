"""eMASS connector — v0.1 stub.

Surface-area-only client so the Settings UI can render an "eMASS: not
configured" card instead of "feature missing". A real implementation is
deferred to v0.2+ when we have a test eMASS instance (cert + bearer) to
hit safely.

Stub contract pinned by ``backend/tests/sources/test_emass_stub.py``:

* ``test_connection()`` returns ``{"ok": False, "hint": "Not implemented in
  v0.1 — stub only"}`` regardless of inputs.
* ``list_systems``, ``get_system``, ``list_controls`` raise
  ``NotImplementedError`` with a "v0.2" message so callers that wander into
  them get a clear "wait for next release" signal rather than a 500.
"""

from __future__ import annotations

from typing import Any

_STUB_VERSION = "v0.2+ feature"


class EmassClient:
    """Minimal eMASS REST surface — stubbed for v0.1.

    Constructor accepts the inputs the real client will need so the Settings
    UI can wire its fields today and the v0.2 implementation only has to fill
    in method bodies (not the call signature).
    """

    def __init__(
        self,
        base_url: str,
        cert_path: str | None = None,
        api_key: str | None = None,
    ) -> None:
        self.base_url = base_url
        self.cert_path = cert_path
        self.api_key = api_key

    # ------------------------------------------------------------------
    # Probe
    # ------------------------------------------------------------------
    def test_connection(self) -> dict[str, Any]:
        """Always returns the canned stub payload — no network call.

        Real implementation will hit ``GET /api/system`` (a cheap auth probe)
        and return ``{"ok": True, "system_count": N}``.
        """
        return {
            "ok": False,
            "hint": "Not implemented in v0.1 — stub only",
        }

    # ------------------------------------------------------------------
    # Read APIs — deferred to v0.2+
    # ------------------------------------------------------------------
    def list_systems(self) -> list[dict[str, Any]]:
        raise NotImplementedError(f"eMASS connector is a {_STUB_VERSION}")

    def get_system(self, system_id: str) -> dict[str, Any]:
        raise NotImplementedError(f"eMASS connector is a {_STUB_VERSION}")

    def list_controls(self, system_id: str) -> list[dict[str, Any]]:
        raise NotImplementedError(f"eMASS connector is a {_STUB_VERSION}")
