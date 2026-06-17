"""Tests for the shared OCR helper (extractors/_ocr.py).

These exercise binary resolution (bundled-first / PATH / pytesseract probe)
and the never-raises contract — NOT a real Tesseract run, so they pass on a
CI box with no OCR binary. The image/PDF extractor tests cover the wiring;
the frozen-build smoke covers the real binary end to end.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from cybersecurity_assessor.evidence.extractors import _ocr


@pytest.fixture(autouse=True)
def _clear_resolver_cache():
    """_resolve_tesseract is lru_cached — reset around each test so monkeypatched
    PATH / _MEIPASS / vendor state is actually observed."""
    _ocr._resolve_tesseract.cache_clear()
    yield
    _ocr._resolve_tesseract.cache_clear()


def test_bundled_dir_found_via_meipass(tmp_path, monkeypatch):
    """Frozen layout: sys._MEIPASS/tesseract/tesseract.exe is preferred."""
    tess = tmp_path / "tesseract"
    tess.mkdir()
    (tess / "tesseract.exe").write_bytes(b"stub")
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    assert _ocr._bundled_tesseract_dir() == tess


def test_resolve_prefers_bundled_and_sets_env(tmp_path, monkeypatch):
    """When a bundled copy exists, _resolve points pytesseract at it and sets
    TESSDATA_PREFIX to the bundled tessdata."""
    tess = tmp_path / "tesseract"
    (tess / "tessdata").mkdir(parents=True)
    (tess / "tesseract.exe").write_bytes(b"stub")
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    monkeypatch.delenv("TESSDATA_PREFIX", raising=False)

    resolved = _ocr._resolve_tesseract()
    assert resolved == str(tess / "tesseract.exe")

    import os

    assert os.environ["TESSDATA_PREFIX"] == str(tess / "tessdata")
    import pytesseract

    assert pytesseract.pytesseract.tesseract_cmd == str(tess / "tesseract.exe")


def test_resolve_falls_back_to_path(monkeypatch):
    """No bundle → use a tesseract found on PATH."""
    monkeypatch.setattr(_ocr, "_bundled_tesseract_dir", lambda: None)
    monkeypatch.setattr(_ocr.shutil, "which", lambda name: r"C:\tools\tesseract.exe")
    assert _ocr._resolve_tesseract() == r"C:\tools\tesseract.exe"


def test_resolve_returns_none_when_nothing_available(monkeypatch):
    """No bundle, nothing on PATH, pytesseract probe fails → None (not a crash)."""
    monkeypatch.setattr(_ocr, "_bundled_tesseract_dir", lambda: None)
    monkeypatch.setattr(_ocr.shutil, "which", lambda name: None)

    import pytesseract

    def _boom():
        raise OSError("no binary")

    monkeypatch.setattr(pytesseract, "get_tesseract_version", _boom)
    assert _ocr._resolve_tesseract() is None
    assert _ocr.tesseract_available() is False


def test_ocr_image_returns_empty_when_unavailable(monkeypatch):
    """ocr_image must never raise — returns '' when no binary is resolvable."""
    monkeypatch.setattr(_ocr, "tesseract_available", lambda: False)
    # A bare object is fine; the function should short-circuit before touching it.
    assert _ocr.ocr_image(object()) == ""


def test_ocr_image_swallows_pytesseract_errors(monkeypatch):
    """If pytesseract itself throws, ocr_image degrades to '' (enrichment, not
    a hard dependency)."""
    monkeypatch.setattr(_ocr, "tesseract_available", lambda: True)
    import pytesseract

    def _boom(_img):
        raise RuntimeError("tesseract exploded")

    monkeypatch.setattr(pytesseract, "image_to_string", _boom)
    assert _ocr.ocr_image(object()) == ""
