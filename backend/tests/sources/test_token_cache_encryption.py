"""MSAL Graph token cache — at-rest encryption + plaintext migration (#9).

The MSAL cache holds refresh tokens (standing access to the org's SharePoint /
CUI), so it must not sit on disk in plaintext. These tests pin:

* encrypt→decrypt round-trips the serialized cache,
* on Windows the on-disk bytes are NOT the plaintext (DPAPI-wrapped); on
  non-Windows CI the identity fallback still round-trips so the suite passes,
* first-run migration: an existing plaintext .json is re-encrypted to .bin and
  the plaintext is DELETED (no lingering refresh token),
* clear_token_cache removes BOTH the .bin and any legacy .json.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor.evidence.sources import sharepoint as sp  # noqa: E402


@pytest.fixture
def _config_dir(tmp_path, monkeypatch):
    """Point config_dir() at a temp dir so the real user cache is never touched."""
    from cybersecurity_assessor import config as cfg

    monkeypatch.setattr(cfg, "config_dir", lambda: tmp_path)
    return tmp_path


def test_encrypt_decrypt_roundtrip():
    blob = sp._encrypt("serialized-msal-cache-with-refresh-token")
    assert sp._decrypt(blob) == "serialized-msal-cache-with-refresh-token"


def test_save_then_load_roundtrips(_config_dir):
    sp._save_cache_text("cache-payload-v1")
    assert _config_dir.joinpath("graph_token_cache.bin").exists()
    assert sp._load_cache_text() == "cache-payload-v1"


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI only on Windows")
def test_on_disk_bytes_are_encrypted_on_windows(_config_dir):
    secret = "SUPER-SECRET-REFRESH-TOKEN-abc123"
    sp._save_cache_text(secret)
    raw = _config_dir.joinpath("graph_token_cache.bin").read_bytes()
    # The plaintext must not appear verbatim in the DPAPI-wrapped blob.
    assert secret.encode("utf-8") not in raw


def test_plaintext_migration_deletes_legacy(_config_dir):
    legacy = _config_dir / "graph_token_cache.json"
    legacy.write_text("legacy-plaintext-cache", encoding="utf-8")
    # Load triggers migration.
    loaded = sp._load_cache_text()
    assert loaded == "legacy-plaintext-cache"
    # Plaintext is gone; encrypted .bin now holds it.
    assert not legacy.exists()
    bin_path = _config_dir / "graph_token_cache.bin"
    assert bin_path.exists()
    assert sp._load_cache_text() == "legacy-plaintext-cache"


def test_load_missing_returns_none(_config_dir):
    assert sp._load_cache_text() is None


def test_clear_removes_both_paths(_config_dir):
    (_config_dir / "graph_token_cache.json").write_text("x", encoding="utf-8")
    sp._save_cache_text("y")  # writes .bin
    assert sp.clear_token_cache() is True
    assert not (_config_dir / "graph_token_cache.json").exists()
    assert not (_config_dir / "graph_token_cache.bin").exists()
    # Second clear is a no-op → False.
    assert sp.clear_token_cache() is False
