"""Tests for quarantine pipeline stages (7-stage comprehensive scanning)."""

import json
import struct
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Add services to path so we can import without installing
sys.path.insert(0, str(Path(__file__).parent.parent / "services" / "quarantine"))

from quarantine.pipeline import (
    DANGER_PATTERNS,
    SMOKE_PROMPTS,
    _check_file_entropy,
    _check_json_for_code,
    _validate_gguf_header,
    _validate_safetensors_header,
    check_diffusion_config_integrity,
    check_format_gate,
    check_format_gate_directory,
    check_hash_pin,
    check_provenance,
    check_source_policy,
    check_static_scan,
    run_pipeline,
    run_pipeline_directory,
    sha256_of_directory,
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


def make_safetensors_file(tmp_path: Path, name: str = "test.safetensors") -> Path:
    """Create a minimal valid safetensors file."""
    p = tmp_path / name
    header = b'{"__metadata__": {}}'
    with open(p, "wb") as f:
        f.write(struct.pack("<Q", len(header)))
        f.write(header)
        f.write(b"\x00" * 100)  # tensor data
    return p


def make_diffusion_dir(tmp_path: Path, name: str = "test-diffusion") -> Path:
    """Create a minimal valid diffusion model directory."""
    d = tmp_path / name
    d.mkdir()
    # model_index.json
    index = {
        "_class_name": "StableDiffusionPipeline",
        "_diffusers_version": "0.25.0",
        "unet": ["diffusers", "UNet2DConditionModel"],
        "vae": ["diffusers", "AutoencoderKL"],
        "text_encoder": ["transformers", "CLIPTextModel"],
    }
    (d / "model_index.json").write_text(json.dumps(index))
    # Component directories with safetensors
    for comp in ["unet", "vae", "text_encoder"]:
        comp_dir = d / comp
        comp_dir.mkdir()
        make_safetensors_file(comp_dir, "model.safetensors")
        (comp_dir / "config.json").write_text('{"sample_size": 64}')
    return d


# ---------------------------------------------------------------------------
# Stage 1: Source policy
# ---------------------------------------------------------------------------

class TestSourcePolicy:
    def test_local_import_passes(self):
        result = check_source_policy("")
        assert result["passed"]
        assert result["source"] == "local-import"

    def test_http_rejected(self):
        result = check_source_policy("http://evil.com/model.gguf")
        assert not result["passed"]
        assert "HTTPS" in result["reason"]

    def test_allowlisted_source_passes(self):
        with patch("quarantine.pipeline._load_source_allowlist", return_value=["https://huggingface.co/"]):
            result = check_source_policy("https://huggingface.co/some/model.gguf")
        assert result["passed"]

    def test_unknown_source_rejected(self):
        with patch("quarantine.pipeline._load_source_allowlist", return_value=["https://huggingface.co/"]):
            result = check_source_policy("https://evil.com/model.gguf")
        assert not result["passed"]
        assert "not in allowlist" in result["reason"]

    def test_no_allowlist_rejects_remote(self):
        with patch("quarantine.pipeline._load_source_allowlist", return_value=[]):
            result = check_source_policy("https://huggingface.co/model.gguf")
        assert not result["passed"]
        assert "no source allowlist" in result["reason"]


# ---------------------------------------------------------------------------
# Stage 2: Format gate
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
        p.write_bytes(struct.pack("<Q", 10) + b"X" + b"\x00" * 100)
        result = check_format_gate(p)
        assert not result["passed"]
        assert "header validation failed" in result["reason"]

    def test_rejects_truncated_file(self, tmp_path):
        p = tmp_path / "tiny.gguf"
        p.write_bytes(b"GG")  # too short
        result = check_format_gate(p)
        assert not result["passed"]


class TestFormatGateDirectory:
    def test_valid_diffusion_dir(self, tmp_path):
        d = make_diffusion_dir(tmp_path)
        result = check_format_gate_directory(d)
        assert result["passed"]
        assert result["format"] == "diffusion-directory"
        assert result["safetensors_count"] == 3

    def test_missing_model_index(self, tmp_path):
        d = tmp_path / "no-index"
        d.mkdir()
        result = check_format_gate_directory(d)
        assert not result["passed"]
        assert "missing model_index.json" in result["reason"]

    def test_rejects_pickle_in_dir(self, tmp_path):
        d = make_diffusion_dir(tmp_path, "with-pickle")
        (d / "unet" / "weights.pkl").write_bytes(b"fake pickle")
        result = check_format_gate_directory(d)
        assert not result["passed"]
        assert any("dangerous file" in i for i in result["issues"])

    def test_rejects_python_in_dir(self, tmp_path):
        d = make_diffusion_dir(tmp_path, "with-python")
        (d / "exploit.py").write_bytes(b"import os; os.system('rm -rf /')")
        result = check_format_gate_directory(d)
        assert not result["passed"]

    def test_rejects_code_in_json(self, tmp_path):
        d = make_diffusion_dir(tmp_path, "code-in-json")
        (d / "unet" / "config.json").write_text('{"cmd": "__import__(\'os\').system(\'rm -rf /\')"}')
        result = check_format_gate_directory(d)
        assert not result["passed"]
        assert any("suspicious content" in i for i in result["issues"])


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
        with open(p, "wb") as f:
            f.write(struct.pack("<Q", 200 * 1024 * 1024))
            f.write(b"{")
        result = _validate_safetensors_header(p)
        assert not result["passed"]
        assert "too large" in result["reason"]


# ---------------------------------------------------------------------------
# Stage 3: Hash pinning
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
# Stage 4: Provenance
# ---------------------------------------------------------------------------

class TestProvenance:
    def test_local_import_passes(self, tmp_path):
        p = make_gguf_file(tmp_path)
        result = check_provenance(p, "")
        assert result["passed"]
        assert result["provenance"] == "none"

    def test_remote_source_recorded(self, tmp_path):
        p = make_gguf_file(tmp_path)
        result = check_provenance(p, "https://huggingface.co/model.gguf")
        assert result["passed"]
        assert result["provenance"] == "recorded"


# ---------------------------------------------------------------------------
# Stage 5: Static scan (modelscan not installed)
# ---------------------------------------------------------------------------

class TestStaticScan:
    def test_skipped_when_not_installed(self, tmp_path):
        p = make_gguf_file(tmp_path)
        result = check_static_scan(p)
        assert result["passed"]


class TestEntropy:
    def test_normal_file_passes(self, tmp_path):
        p = tmp_path / "normal.gguf"
        # Write structured data (low entropy)
        p.write_bytes(b"\x00\x01\x02\x03" * 100000)
        result = _check_file_entropy(p)
        assert result["passed"]

    def test_small_file_passes(self, tmp_path):
        p = tmp_path / "tiny.bin"
        p.write_bytes(b"hello")
        result = _check_file_entropy(p)
        assert result["passed"]


# ---------------------------------------------------------------------------
# Stage 6: Smoke test prompt suite coverage
# ---------------------------------------------------------------------------

class TestSmokeTestSuite:
    def test_prompt_suite_has_all_categories(self):
        categories = {p["category"] for p in SMOKE_PROMPTS}
        required = {
            "baseline", "command_injection", "file_exfil",
            "network_exfil", "credential_theft", "pii_handling",
            "canary_leak", "jailbreak", "tool_abuse", "prompt_injection",
        }
        assert required.issubset(categories), f"missing: {required - categories}"

    def test_prompt_suite_minimum_size(self):
        assert len(SMOKE_PROMPTS) >= 20

    def test_danger_patterns_minimum_coverage(self):
        assert len(DANGER_PATTERNS) >= 40

    def test_danger_patterns_cover_critical_vectors(self):
        patterns_lower = [p.lower() for p in DANGER_PATTERNS]
        assert any("curl" in p for p in patterns_lower)
        assert any("subprocess" in p for p in patterns_lower)
        assert any("/etc/shadow" in p for p in patterns_lower)
        assert any("canary_token" in p for p in patterns_lower)
        assert any("reverse shell" in p for p in patterns_lower)
        assert any("socket" in p for p in patterns_lower)
        assert any("base64" in p for p in patterns_lower)

    def test_canary_tokens_present(self):
        canary_prompts = [p for p in SMOKE_PROMPTS if p["category"] == "canary_leak"]
        assert len(canary_prompts) >= 2
        # Canary tokens must also appear in danger patterns
        for p in canary_prompts:
            token = p["content"].split(":")[0].strip()
            assert any(token in dp for dp in DANGER_PATTERNS), f"canary {token} not in danger patterns"


# ---------------------------------------------------------------------------
# Stage 7: Diffusion deep scan
# ---------------------------------------------------------------------------

class TestDiffusionDeepScan:
    def test_valid_dir_passes(self, tmp_path):
        d = make_diffusion_dir(tmp_path)
        result = check_diffusion_config_integrity(d)
        assert result["passed"]
        assert "unet" in result["components"]

    def test_not_diffusion_dir_passes(self, tmp_path):
        d = tmp_path / "empty"
        d.mkdir()
        result = check_diffusion_config_integrity(d)
        assert result["passed"]  # gracefully skips

    def test_missing_component_flagged(self, tmp_path):
        d = make_diffusion_dir(tmp_path, "missing-comp")
        import shutil
        shutil.rmtree(d / "unet")
        result = check_diffusion_config_integrity(d)
        assert not result["passed"]
        assert any("missing" in i for i in result["issues"])

    def test_symlink_flagged(self, tmp_path):
        d = make_diffusion_dir(tmp_path, "with-symlink")
        (d / "unet" / "link.txt").symlink_to("/etc/passwd")
        result = check_diffusion_config_integrity(d)
        assert not result["passed"]
        assert any("symlink" in i for i in result["issues"])

    def test_suspicious_url_flagged(self, tmp_path):
        d = make_diffusion_dir(tmp_path, "sus-url")
        (d / "unet" / "config.json").write_text('{"url": "https://evil.com/exfil"}')
        result = check_diffusion_config_integrity(d)
        assert not result["passed"]
        assert any("suspicious URL" in i for i in result["issues"])


# ---------------------------------------------------------------------------
# Directory hash
# ---------------------------------------------------------------------------

class TestDirectoryHash:
    def test_deterministic(self, tmp_path):
        d = make_diffusion_dir(tmp_path)
        h1 = sha256_of_directory(d)
        h2 = sha256_of_directory(d)
        assert h1 == h2
        assert len(h1) == 64


# ---------------------------------------------------------------------------
# Full pipeline orchestrators
# ---------------------------------------------------------------------------

class TestRunPipeline:
    def test_valid_gguf_passes(self, tmp_path):
        p = make_gguf_file(tmp_path)
        h = "a" * 64
        policy = {"models": {"require_scan": False, "require_behavior_tests": False}}
        result = run_pipeline(p, h, policy)
        assert result["passed"]
        assert "source_policy" in result["details"]
        assert "format_gate" in result["details"]
        assert "provenance" in result["details"]

    def test_unsafe_format_fails(self, tmp_path):
        p = tmp_path / "bad.pkl"
        p.write_bytes(b"fake")
        result = run_pipeline(p, "abc", {})
        assert not result["passed"]
        assert result["reason"] == "format_gate"


class TestRunPipelineDirectory:
    def test_valid_diffusion_passes(self, tmp_path):
        d = make_diffusion_dir(tmp_path)
        h = sha256_of_directory(d)
        policy = {"models": {"require_scan": False}}
        result = run_pipeline_directory(d, h, policy)
        assert result["passed"]
        assert "diffusion_deep_scan" in result["details"]

    def test_diffusion_with_pickle_fails(self, tmp_path):
        d = make_diffusion_dir(tmp_path, "bad-diff")
        (d / "evil.pkl").write_bytes(b"malicious")
        h = sha256_of_directory(d)
        result = run_pipeline_directory(d, h, {})
        assert not result["passed"]
        assert result["reason"] == "format_gate"


# ---------------------------------------------------------------------------
# JSON code detection helper
# ---------------------------------------------------------------------------

class TestJsonCodeDetection:
    def test_clean_json_passes(self, tmp_path):
        p = tmp_path / "clean.json"
        p.write_text('{"key": "value", "num": 42}')
        issues = []
        _check_json_for_code(p, issues, tmp_path)
        assert len(issues) == 0

    def test_exec_detected(self, tmp_path):
        p = tmp_path / "evil.json"
        p.write_text(r'{"cmd": "exec(open(\"exploit.py\").read())"}')
        issues = []
        _check_json_for_code(p, issues, tmp_path)
        assert len(issues) > 0

    def test_import_detected(self, tmp_path):
        p = tmp_path / "evil2.json"
        p.write_text(r'{"x": "__import__(\"os\").system(\"ls\")"}')
        issues = []
        _check_json_for_code(p, issues, tmp_path)
        assert len(issues) > 0
