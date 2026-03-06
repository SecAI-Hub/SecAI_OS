"""Tests for quarantine pipeline stages."""

import struct
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# Add services to path so we can import without installing
sys.path.insert(0, str(Path(__file__).parent.parent / "services" / "quarantine"))

from quarantine.pipeline import (
    _validate_gguf_header,
    _validate_safetensors_header,
    check_format_gate,
    check_hash_pin,
    check_static_scan,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_gguf_file(tmp_path: Path, version: int = 3) -> Path:
    """Create a minimal valid GGUF file."""
    p = tmp_path / "test.gguf"
    with open(p, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", version))
        f.write(b"\x00" * 100)  # padding
    return p


def make_safetensors_file(tmp_path: Path) -> Path:
    """Create a minimal valid safetensors file."""
    p = tmp_path / "test.safetensors"
    header = b'{"__metadata__": {}}'
    with open(p, "wb") as f:
        f.write(struct.pack("<Q", len(header)))
        f.write(header)
        f.write(b"\x00" * 100)  # tensor data
    return p


# ---------------------------------------------------------------------------
# Stage 1: Format gate
# ---------------------------------------------------------------------------

class TestFormatGate:
    def test_rejects_unsafe_extension(self, tmp_path):
        p = tmp_path / "model.pkl"
        p.write_bytes(b"fake")
        result = check_format_gate(p)
        assert not result["passed"]
        assert "unsafe format" in result["reason"]

    def test_rejects_unknown_extension(self, tmp_path):
        p = tmp_path / "model.bin"
        p.write_bytes(b"fake")
        result = check_format_gate(p)
        assert not result["passed"]

    def test_accepts_valid_gguf(self, tmp_path):
        p = make_gguf_file(tmp_path, version=3)
        result = check_format_gate(p)
        assert result["passed"]
        assert result["format"] == ".gguf"

    def test_accepts_valid_safetensors(self, tmp_path):
        p = make_safetensors_file(tmp_path)
        result = check_format_gate(p)
        assert result["passed"]
        assert result["format"] == ".safetensors"

    def test_rejects_bad_gguf_magic(self, tmp_path):
        p = tmp_path / "bad.gguf"
        p.write_bytes(b"FAKE" + struct.pack("<I", 3) + b"\x00" * 100)
        result = check_format_gate(p)
        assert not result["passed"]
        assert "header validation failed" in result["reason"]

    def test_rejects_bad_gguf_version(self, tmp_path):
        p = tmp_path / "bad.gguf"
        p.write_bytes(b"GGUF" + struct.pack("<I", 99) + b"\x00" * 100)
        result = check_format_gate(p)
        assert not result["passed"]
        assert "unsupported GGUF version" in result["reason"]

    def test_rejects_bad_safetensors_header(self, tmp_path):
        p = tmp_path / "bad.safetensors"
        # Valid length but header starts with 'X' instead of '{'
        p.write_bytes(struct.pack("<Q", 10) + b"X" + b"\x00" * 100)
        result = check_format_gate(p)
        assert not result["passed"]
        assert "header validation failed" in result["reason"]

    def test_rejects_truncated_file(self, tmp_path):
        p = tmp_path / "tiny.gguf"
        p.write_bytes(b"GG")  # too short
        result = check_format_gate(p)
        assert not result["passed"]


# ---------------------------------------------------------------------------
# Stage 1 header validation helpers
# ---------------------------------------------------------------------------

class TestGGUFHeader:
    def test_valid_v2(self, tmp_path):
        p = make_gguf_file(tmp_path, version=2)
        result = _validate_gguf_header(p)
        assert result["passed"]
        assert result["gguf_version"] == 2

    def test_valid_v3(self, tmp_path):
        p = make_gguf_file(tmp_path, version=3)
        result = _validate_gguf_header(p)
        assert result["passed"]
        assert result["gguf_version"] == 3


class TestSafetensorsHeader:
    def test_valid(self, tmp_path):
        p = make_safetensors_file(tmp_path)
        result = _validate_safetensors_header(p)
        assert result["passed"]
        assert result["header_size"] > 0

    def test_oversized_header(self, tmp_path):
        p = tmp_path / "big.safetensors"
        # Claim a 200MB header
        with open(p, "wb") as f:
            f.write(struct.pack("<Q", 200 * 1024 * 1024))
            f.write(b"{")
        result = _validate_safetensors_header(p)
        assert not result["passed"]
        assert "too large" in result["reason"]


# ---------------------------------------------------------------------------
# Stage 2: Hash pinning
# ---------------------------------------------------------------------------

class TestHashPin:
    def test_no_pin_passes(self):
        with patch("quarantine.pipeline._load_pinned_hashes", return_value={}):
            result = check_hash_pin("model.gguf", "abc123")
        assert result["passed"]
        assert not result["pinned"]

    def test_matching_pin_passes(self):
        pins = {"model.gguf": "abc123"}
        with patch("quarantine.pipeline._load_pinned_hashes", return_value=pins):
            result = check_hash_pin("model.gguf", "abc123")
        assert result["passed"]
        assert result["pinned"]
        assert result["match"]

    def test_mismatched_pin_fails(self):
        pins = {"model.gguf": "expected_hash"}
        with patch("quarantine.pipeline._load_pinned_hashes", return_value=pins):
            result = check_hash_pin("model.gguf", "wrong_hash")
        assert not result["passed"]
        assert "hash mismatch" in result["reason"]


# ---------------------------------------------------------------------------
# Stage 3: Static scan (modelscan not installed)
# ---------------------------------------------------------------------------

class TestStaticScan:
    def test_skipped_when_not_installed(self, tmp_path):
        p = make_gguf_file(tmp_path)
        result = check_static_scan(p)
        assert result["passed"]
        assert "skipped" in result.get("scanner", "")
