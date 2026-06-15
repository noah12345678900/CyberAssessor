"""Stub-only tests for the eMASS connector surface.

The connector exists in v0.1 only so the Settings UI can show "not
configured" instead of "feature missing". These tests pin the stub
contract so v0.2+ implementers know what shape the rest of the app
expects.
"""

from __future__ import annotations

import pytest

from cybersecurity_assessor.sources.emass import EmassClient


def test_test_connection_returns_stub_payload():
    client = EmassClient(base_url="https://example.invalid")
    result = client.test_connection()
    assert result == {
        "ok": False,
        "hint": "Not implemented in v0.1 — stub only",
    }


def test_test_connection_ignores_real_inputs():
    # Stub never actually touches the network — passing real-looking creds
    # must still resolve to the same canned response.
    client = EmassClient(
        base_url="https://emass.disa.mil",
        cert_path="/path/to/cert.pem",
        api_key="real-looking-key",
    )
    assert client.test_connection()["ok"] is False


@pytest.mark.parametrize(
    "method,args",
    [
        ("list_systems", ()),
        ("get_system", ("sys-123",)),
        ("list_controls", ("sys-123",)),
    ],
)
def test_unimplemented_methods_raise(method: str, args: tuple):
    client = EmassClient(base_url="https://example.invalid")
    with pytest.raises(NotImplementedError, match="v0.2"):
        getattr(client, method)(*args)


def test_constructor_stores_inputs():
    client = EmassClient(
        base_url="https://emass.disa.mil",
        cert_path="C:/certs/client.pfx",
        api_key="abc",
    )
    assert client.base_url == "https://emass.disa.mil"
    assert client.cert_path == "C:/certs/client.pfx"
    assert client.api_key == "abc"
