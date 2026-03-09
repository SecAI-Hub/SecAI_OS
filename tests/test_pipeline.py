"""Tests for quarantine pipeline stages (7-stage comprehensive scanning)."""

import json
import struct
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Add services to path so we can import without installing
sys.path.insert(0, str(Path(__file__).parent.parent / "services" / "quarantine"))
sys.path.insert(0, str(Path(__file__).parent.parent / "services"))

from quarantine.pipeline import (
    DANGER_PATTERNS,
    SMOKE_PROMPTS,
    WEIGHT_STATS_MAX_KURTOSIS,
    WEIGHT_STATS_MAX_ZERO_FRACTION,
    _analyze_weight_distribution,
    _check_file_entropy,
    _check_jinja_template,
    _check_json_for_code,
    _check_pickle_polyglot,
    _check_weight_anomalies,
    _compute_tensor_stats,
    _run_fickling_scan,
    _run_garak_scan,
    _run_gguf_guard_scan,
    _run_gguf_guard_manifest,
    _run_gguf_guard_fingerprint,
    _run_modelaudit,
    _scan_gguf_chat_template,
    _stats_from_values,
    _validate_gguf_header,
    _validate_safetensors_header,
    check_diffusion_config_integrity,
    check_format_gate,
    check_format_gate_directory,
    check_hash_pin,
    check_provenance,
    check_smoke_test,
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


def make_gguf_with_template(tmp_path: Path, template: str, name: str = "test.gguf") -> Path:
    """Create a GGUF file with a chat template embedded in metadata."""
    p = tmp_path / name
    key = b"tokenizer.chat_template"
    template_bytes = template.encode("utf-8")
    with open(p, "wb") as f:
        # Header
        f.write(b"GGUF")                          # magic
        f.write(struct.pack("<I", 3))              # version
        f.write(struct.pack("<Q", 0))              # tensor_count
        f.write(struct.pack("<Q", 1))              # metadata_kv_count (1 entry)
        # KV pair: key
        f.write(struct.pack("<Q", len(key)))       # key_length
        f.write(key)                                # key
        f.write(struct.pack("<I", 8))              # value_type = string
        f.write(struct.pack("<Q", len(template_bytes)))  # string_length
        f.write(template_bytes)                     # string data
        f.write(b"\x00" * 64)                      # padding
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
    def test_no_pin_local_import_passes(self):
        """Local imports (no source_url) use TOFU: pass but note pinning needed."""
        with patch("quarantine.pipeline._load_pinned_hashes", return_value={}):
            result = check_hash_pin("model.gguf", "abc123")
        assert result["passed"]
        assert not result["pinned"]
        assert "first-install trust" in result["note"]

    def test_no_pin_remote_fails(self):
        """Remote artifacts with no pinned hash must fail closed."""
        with patch("quarantine.pipeline._load_pinned_hashes", return_value={}):
            result = check_hash_pin("model.gguf", "abc123", source_url="https://huggingface.co/x")
        assert not result["passed"]
        assert "remote artifact has no pinned hash" in result["reason"]

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
    def test_fails_when_not_installed_and_required(self, tmp_path):
        """When require_scan is True (default), missing modelscan is a hard failure."""
        p = make_gguf_file(tmp_path)
        result = check_static_scan(p)
        assert not result["passed"]
        assert "required but not installed" in result["details"]["modelscan"]["reason"]

    def test_skipped_when_not_installed_and_not_required(self, tmp_path):
        """When require_scan is False, missing modelscan is acceptable."""
        p = make_gguf_file(tmp_path)
        policy = {"models": {"require_scan": False}}
        result = check_static_scan(p, policy=policy)
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
        assert len(SMOKE_PROMPTS) >= 40

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


# ---------------------------------------------------------------------------
# 7a: GGUF chat template SSTI scanning
# ---------------------------------------------------------------------------

class TestGGUFTemplateScan:
    def test_gguf_template_clean(self, tmp_path):
        """GGUF with a normal Jinja2 chat template passes."""
        template = (
            "{% for message in messages %}"
            "{{ message['role'] }}: {{ message['content'] }}\n"
            "{% endfor %}"
        )
        p = make_gguf_with_template(tmp_path, template)
        result = _scan_gguf_chat_template(p)
        assert result["passed"], f"clean template should pass: {result}"

    def test_gguf_template_ssti(self, tmp_path):
        """GGUF with __class__.__mro__ in template fails."""
        template = (
            "{% for message in messages %}"
            "{{ ''.__class__.__mro__[1].__subclasses__() }}"
            "{% endfor %}"
        )
        p = make_gguf_with_template(tmp_path, template, name="ssti.gguf")
        result = _scan_gguf_chat_template(p)
        assert not result["passed"], "SSTI template should fail"
        assert "issues" in result
        assert any("class traversal" in i for i in result["issues"])

    def test_gguf_template_os_system(self, tmp_path):
        """GGUF with os.system call in template fails."""
        template = "{{ os.system('whoami') }}"
        p = make_gguf_with_template(tmp_path, template, name="os_sys.gguf")
        result = _scan_gguf_chat_template(p)
        assert not result["passed"]

    def test_gguf_no_template(self, tmp_path):
        """GGUF with no chat template passes with note."""
        p = make_gguf_file(tmp_path)
        result = _scan_gguf_chat_template(p)
        assert result["passed"]
        assert "no chat template" in result.get("note", "")

    def test_jinja_checker_clean(self):
        """_check_jinja_template on normal template returns empty list."""
        template = "{% if user %}Hello {{ user }}{% endif %}"
        issues = _check_jinja_template(template, "test_key")
        assert issues == []

    def test_jinja_checker_subprocess(self):
        """_check_jinja_template catches subprocess reference."""
        template = "{{ subprocess.run(['ls']) }}"
        issues = _check_jinja_template(template, "test_key")
        assert len(issues) > 0
        assert any("Subprocess" in i for i in issues)


# ---------------------------------------------------------------------------
# 7b: Pickle polyglot detection & Fickling/ModelAudit graceful degradation
# ---------------------------------------------------------------------------

class TestPicklePolyglot:
    def test_pickle_polyglot_detection(self, tmp_path):
        """File with pickle opcodes in header is caught."""
        p = tmp_path / "fake.safetensors"
        # Write valid safetensors start, then inject pickle PROTO opcode
        header = b'{"__metadata__": {}}'
        with open(p, "wb") as f:
            f.write(struct.pack("<Q", len(header)))
            f.write(header)
            # Inject pickle PROTO v4 opcode in the data region (still within first 8KB)
            f.write(b"\x80\x04" + b"\x00" * 100)
        result = _check_pickle_polyglot(p)
        assert not result["passed"]
        assert "pickle polyglot" in result["reason"]

    def test_clean_file_passes(self, tmp_path):
        """Normal file with no pickle opcodes passes."""
        p = tmp_path / "clean.safetensors"
        header = b'{"__metadata__": {}}'
        with open(p, "wb") as f:
            f.write(struct.pack("<Q", len(header)))
            f.write(header)
            f.write(b"\x00" * 200)
        result = _check_pickle_polyglot(p)
        assert result["passed"]

    def test_polyglot_in_format_gate(self, tmp_path):
        """Format gate catches polyglot files."""
        p = tmp_path / "poly.safetensors"
        header = b'{"__metadata__": {}}'
        with open(p, "wb") as f:
            f.write(struct.pack("<Q", len(header)))
            f.write(header)
            f.write(b"cbuiltins\n" + b"\x00" * 100)
        result = check_format_gate(p)
        assert not result["passed"]
        assert "polyglot" in result["reason"]


class TestFicklingGraceful:
    def test_fickling_not_installed(self, tmp_path):
        """Graceful skip when fickling is not installed."""
        p = make_gguf_file(tmp_path)
        result = _run_fickling_scan(p)
        assert result["passed"]
        assert "not installed" in result.get("note", "")


class TestModelAuditGraceful:
    def test_modelaudit_not_installed(self, tmp_path):
        """Graceful skip when modelaudit is not installed."""
        p = make_gguf_file(tmp_path)
        result = _run_modelaudit(p)
        assert result["passed"]
        assert "not installed" in result.get("note", "")


# ---------------------------------------------------------------------------
# 7c: Expanded adversarial prompt suite
# ---------------------------------------------------------------------------

class TestExpandedAdversarialSuite:
    def test_expanded_adversarial_prompts(self):
        """Verify the prompt list has at least 40 entries."""
        assert len(SMOKE_PROMPTS) >= 40, f"expected >= 40 prompts, got {len(SMOKE_PROMPTS)}"

    def test_expanded_danger_patterns(self):
        """Verify danger patterns cover new categories."""
        patterns_lower = [p.lower() for p in DANGER_PATTERNS]
        # Data leakage
        assert any("system prompt" in p for p in patterns_lower)
        assert any("training data" in p for p in patterns_lower)
        # Multi-turn manipulation
        assert any("override accepted" in p for p in patterns_lower)
        assert any("maintenance mode" in p for p in patterns_lower)
        # Privacy probing
        assert any("192.168." in p for p in patterns_lower)

    def test_new_categories_present(self):
        """Verify new prompt categories exist."""
        categories = {p["category"] for p in SMOKE_PROMPTS}
        new_required = {
            "data_leakage", "hallucination", "encoding_bypass",
            "multi_turn", "privacy_probing",
        }
        assert new_required.issubset(categories), f"missing: {new_required - categories}"

    def test_prompt_suite_has_all_categories(self):
        """All original + new categories are present."""
        categories = {p["category"] for p in SMOKE_PROMPTS}
        required = {
            "baseline", "command_injection", "file_exfil",
            "network_exfil", "credential_theft", "pii_handling",
            "canary_leak", "jailbreak", "tool_abuse", "prompt_injection",
            "data_leakage", "hallucination", "encoding_bypass",
            "multi_turn", "privacy_probing",
        }
        assert required.issubset(categories), f"missing: {required - categories}"


# ---------------------------------------------------------------------------
# Provenance manifest & fs-verity
# ---------------------------------------------------------------------------

from quarantine.watcher import _write_provenance_manifest, _enable_fsverity


class TestProvenanceManifest:
    def test_creates_valid_json(self, tmp_path, monkeypatch):
        """_write_provenance_manifest creates a valid JSON file with all fields."""
        import quarantine.watcher as watcher_mod
        monkeypatch.setattr(watcher_mod, "REGISTRY_DIR", tmp_path)

        model_file = tmp_path / "test-model.gguf"
        model_file.write_bytes(b"\x00" * 100)

        _write_provenance_manifest(
            artifact_path=model_file,
            filename="test-model.gguf",
            file_hash="abc123" * 10 + "abcd",
            size_bytes=100,
            source_url="https://huggingface.co/test/model",
            source_revision="main",
            scan_results={"format_gate": "pass"},
            pipeline_details={"format_gate": {"passed": True}},
            fsverity_success=False,
        )

        manifest_path = tmp_path / "test-model.gguf.provenance.json"
        assert manifest_path.exists()

        manifest = json.loads(manifest_path.read_text())
        assert manifest["schema_version"] == "1.0"

        required_fields = [
            "artifact", "source", "scanners", "policy",
            "promotion", "scan_summary", "integrity",
        ]
        for field in required_fields:
            assert field in manifest, f"missing required field: {field}"

        assert manifest["artifact"]["filename"] == "test-model.gguf"
        assert manifest["artifact"]["sha256"] == "abc123" * 10 + "abcd"
        assert manifest["artifact"]["size_bytes"] == 100
        assert manifest["source"]["url"] == "https://huggingface.co/test/model"
        assert manifest["source"]["revision"] == "main"
        assert "timestamp" in manifest["promotion"]
        assert "hostname" in manifest["promotion"]
        assert manifest["integrity"]["fsverity_enabled"] is False
        assert manifest["integrity"]["fsverity_digest"] is None

    def test_local_import_defaults(self, tmp_path, monkeypatch):
        """Local imports get default source values."""
        import quarantine.watcher as watcher_mod
        monkeypatch.setattr(watcher_mod, "REGISTRY_DIR", tmp_path)

        model_file = tmp_path / "local-model.gguf"
        model_file.write_bytes(b"\x00" * 50)

        _write_provenance_manifest(
            artifact_path=model_file,
            filename="local-model.gguf",
            file_hash="def456" * 10 + "defg",
            size_bytes=50,
            source_url="",
            source_revision="",
            scan_results={},
            pipeline_details={},
        )

        manifest_path = tmp_path / "local-model.gguf.provenance.json"
        manifest = json.loads(manifest_path.read_text())
        assert manifest["source"]["url"] == "local-import"
        assert manifest["source"]["revision"] == "unknown"


class TestFsverity:
    def test_returns_false_when_not_installed(self, tmp_path):
        """_enable_fsverity returns False gracefully when fsverity tool is not installed."""
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"\x00" * 100)
        result = _enable_fsverity(model_file)
        assert result is False


# ---------------------------------------------------------------------------
# 8: Weight distribution statistical analysis
# ---------------------------------------------------------------------------

def _make_gguf_with_tensor(tmp_path: Path, tensor_data: bytes, dtype_id: int = 0,
                            tensor_name: str = "test.weight") -> Path:
    """Create a minimal GGUF file with one tensor containing given data."""
    p = tmp_path / "weight_test.gguf"
    name_bytes = tensor_name.encode("utf-8")
    n_dims = 1
    # For F32 (dtype 0), element count = len(data) / 4
    if dtype_id == 0:
        element_count = len(tensor_data) // 4
    elif dtype_id == 1:
        element_count = len(tensor_data) // 2
    elif dtype_id == 8:  # Q8_0
        element_count = (len(tensor_data) // 34) * 32
    else:
        element_count = len(tensor_data) // 4

    with open(p, "wb") as f:
        # GGUF header
        f.write(b"GGUF")                          # magic
        f.write(struct.pack("<I", 3))              # version
        f.write(struct.pack("<Q", 1))              # tensor_count
        f.write(struct.pack("<Q", 0))              # metadata_kv_count

        # Tensor info
        f.write(struct.pack("<Q", len(name_bytes)))
        f.write(name_bytes)
        f.write(struct.pack("<I", n_dims))          # n_dims
        f.write(struct.pack("<Q", element_count))   # dim[0]
        f.write(struct.pack("<I", dtype_id))        # dtype
        f.write(struct.pack("<Q", 0))               # offset (relative to data start)

        # Pad to 32-byte alignment
        pos = f.tell()
        alignment = 32
        pad = (alignment - (pos % alignment)) % alignment
        f.write(b"\x00" * pad)

        # Tensor data
        f.write(tensor_data)

    return p


class TestStatsFromValues:
    def test_normal_distribution(self):
        """Basic stats computation on a known list."""
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        stats = _stats_from_values(values)
        assert abs(stats["mean"] - 3.0) < 0.001
        assert stats["variance"] > 0
        assert stats["zero_fraction"] == 0.0
        assert stats["samples"] == 5

    def test_all_zeros(self):
        """All-zero values yield zero mean, zero variance."""
        values = [0.0] * 100
        stats = _stats_from_values(values)
        assert stats["mean"] == 0.0
        assert stats["variance"] == 0.0
        assert stats["zero_fraction"] == 1.0

    def test_kurtosis_normal_range(self):
        """Well-distributed values should have moderate kurtosis."""
        import random
        random.seed(42)
        values = [random.gauss(0, 1) for _ in range(10000)]
        stats = _stats_from_values(values)
        # Gaussian excess kurtosis should be near 0 (±1 for finite samples)
        assert abs(stats["kurtosis"]) < 2.0


class TestComputeTensorStats:
    def test_f32_tensor(self):
        """Compute stats on F32 tensor data."""
        # Pack 100 float32 values: 1.0, 2.0, ..., 100.0
        values = [float(i) for i in range(1, 101)]
        data = struct.pack(f"<{len(values)}f", *values)
        stats = _compute_tensor_stats(data, len(values), "f32")
        assert stats is not None
        assert abs(stats["mean"] - 50.5) < 0.1
        assert stats["variance"] > 0
        assert stats["zero_fraction"] == 0.0

    def test_f16_tensor(self):
        """Compute stats on F16 tensor data."""
        values = [float(i) for i in range(1, 101)]
        data = struct.pack(f"<{len(values)}e", *values)
        stats = _compute_tensor_stats(data, len(values), "f16")
        assert stats is not None
        assert abs(stats["mean"] - 50.5) < 1.0

    def test_too_few_elements(self):
        """Return None for very small tensors."""
        data = struct.pack("<4f", 1.0, 2.0, 3.0, 4.0)
        stats = _compute_tensor_stats(data, 4, "f32")
        assert stats is None


class TestCheckWeightAnomalies:
    def test_normal_stats_pass(self):
        """Normal weight statistics produce no anomalies."""
        stats = {"mean": 0.01, "variance": 0.05, "kurtosis": 2.5,
                 "zero_fraction": 0.1, "samples": 1000}
        issues = _check_weight_anomalies("layer.0.weight", stats)
        assert len(issues) == 0

    def test_extreme_mean_flagged(self):
        """Abnormally large mean is flagged."""
        stats = {"mean": 50.0, "variance": 1.0, "kurtosis": 0.0,
                 "zero_fraction": 0.0, "samples": 1000}
        issues = _check_weight_anomalies("layer.0.weight", stats)
        assert any("abnormal mean" in i for i in issues)

    def test_extreme_kurtosis_flagged(self):
        """Extremely peaked distribution is flagged as possible trojan."""
        stats = {"mean": 0.0, "variance": 1.0, "kurtosis": 200.0,
                 "zero_fraction": 0.0, "samples": 1000}
        issues = _check_weight_anomalies("layer.0.weight", stats)
        assert any("kurtosis" in i for i in issues)

    def test_mostly_zeros_flagged(self):
        """Nearly all-zero tensor is flagged as possibly corrupted."""
        stats = {"mean": 0.0, "variance": 0.0001, "kurtosis": 0.0,
                 "zero_fraction": 0.999, "samples": 1000}
        issues = _check_weight_anomalies("layer.0.weight", stats)
        assert any("zeros" in i for i in issues)


class TestAnalyzeWeightDistribution:
    def test_gguf_normal_weights(self, tmp_path):
        """Normal GGUF weights pass analysis."""
        import random
        random.seed(42)
        # Create F32 tensor data with normal-looking weights
        values = [random.gauss(0, 0.1) for _ in range(256)]
        tensor_data = struct.pack(f"<{len(values)}f", *values)
        p = _make_gguf_with_tensor(tmp_path, tensor_data, dtype_id=0)
        result = _analyze_weight_distribution(p)
        assert result["passed"]

    def test_gguf_all_zeros_flagged(self, tmp_path):
        """All-zero GGUF tensor is flagged."""
        tensor_data = b"\x00" * (256 * 4)  # 256 zero floats
        p = _make_gguf_with_tensor(tmp_path, tensor_data, dtype_id=0)
        result = _analyze_weight_distribution(p)
        assert not result["passed"]
        assert "zeros" in result.get("reason", "")

    def test_safetensors_normal_weights(self, tmp_path):
        """Normal safetensors weights pass analysis."""
        import random
        random.seed(42)
        values = [random.gauss(0, 0.1) for _ in range(256)]
        tensor_data = struct.pack(f"<{len(values)}f", *values)

        p = tmp_path / "normal.safetensors"
        header = json.dumps({
            "test.weight": {
                "dtype": "F32",
                "shape": [256],
                "data_offsets": [0, len(tensor_data)],
            }
        }).encode()
        with open(p, "wb") as f:
            f.write(struct.pack("<Q", len(header)))
            f.write(header)
            f.write(tensor_data)

        result = _analyze_weight_distribution(p)
        assert result["passed"]

    def test_unsupported_format_passes(self, tmp_path):
        """Unsupported file extensions pass gracefully."""
        p = tmp_path / "model.bin"
        p.write_bytes(b"\x00" * 100)
        result = _analyze_weight_distribution(p)
        assert result["passed"]
        assert "not supported" in result.get("note", "")

    def test_integrated_in_static_scan(self, tmp_path):
        """Weight analysis runs as part of check_static_scan."""
        p = make_gguf_file(tmp_path)
        result = check_static_scan(p)
        assert "weight_stats" in result.get("details", {})


# ---------------------------------------------------------------------------
# Garak LLM vulnerability scanner integration
# ---------------------------------------------------------------------------

class TestGarakIntegration:
    def test_garak_not_installed(self):
        """Graceful skip when garak is not installed."""
        # garak is almost certainly not installed in CI/test environments
        result = _run_garak_scan(port=9999)
        assert result["passed"]
        assert "not installed" in result.get("note", "") or "skipped" in result.get("note", "")

    def test_garak_returns_scanner_name(self):
        """Result always includes scanner identifier."""
        result = _run_garak_scan(port=9999)
        assert result.get("scanner") == "garak"

    def test_garak_integrated_in_smoke_test(self):
        """check_smoke_test function references garak (code structure check)."""
        import inspect
        source = inspect.getsource(check_smoke_test)
        assert "_run_garak_scan" in source
        assert "garak" in source


# ---------------------------------------------------------------------------
# gguf-guard integration
# ---------------------------------------------------------------------------

class TestGGUFGuardIntegration:
    def test_scan_not_installed_graceful(self, tmp_path):
        """Graceful skip when gguf-guard is not installed."""
        p = make_gguf_file(tmp_path)
        # Use a nonexistent binary path to simulate not installed
        with patch("quarantine.pipeline.GGUF_GUARD_BIN", "/nonexistent/gguf-guard"):
            result = _run_gguf_guard_scan(p)
        assert result["passed"]
        assert "not installed" in result.get("note", "")

    def test_scan_not_installed_required_fails(self, tmp_path):
        """When required=True and not installed, scan fails."""
        p = make_gguf_file(tmp_path)
        with patch("quarantine.pipeline.GGUF_GUARD_BIN", "/nonexistent/gguf-guard"):
            result = _run_gguf_guard_scan(p, policy={"gguf_guard": {"required": True}})
        assert not result["passed"]
        assert "required" in result.get("reason", "")

    def test_scan_skips_non_gguf(self, tmp_path):
        """Non-GGUF files are skipped."""
        p = tmp_path / "model.safetensors"
        p.write_bytes(b"\x00" * 100)
        result = _run_gguf_guard_scan(p)
        assert result["passed"]
        assert "not a GGUF file" in result.get("note", "")

    def test_scan_returns_scanner_name(self, tmp_path):
        """Result always includes scanner identifier."""
        p = make_gguf_file(tmp_path)
        with patch("quarantine.pipeline.GGUF_GUARD_BIN", "/nonexistent/gguf-guard"):
            result = _run_gguf_guard_scan(p)
        assert result.get("scanner") == "gguf-guard"

    def test_manifest_not_installed(self, tmp_path):
        """Manifest generation gracefully handles missing binary."""
        p = make_gguf_file(tmp_path)
        out = tmp_path / "manifest.json"
        with patch("quarantine.pipeline.GGUF_GUARD_BIN", "/nonexistent/gguf-guard"):
            result = _run_gguf_guard_manifest(p, out)
        assert not result["generated"]
        assert "not installed" in result.get("note", "")

    def test_manifest_skips_non_gguf(self, tmp_path):
        """Manifest generation skips non-GGUF files."""
        p = tmp_path / "model.safetensors"
        p.write_bytes(b"\x00" * 100)
        out = tmp_path / "manifest.json"
        result = _run_gguf_guard_manifest(p, out)
        assert not result["generated"]
        assert "not a GGUF file" in result.get("note", "")

    def test_fingerprint_not_installed(self, tmp_path):
        """Fingerprint returns None when binary not installed."""
        p = make_gguf_file(tmp_path)
        with patch("quarantine.pipeline.GGUF_GUARD_BIN", "/nonexistent/gguf-guard"):
            result = _run_gguf_guard_fingerprint(p)
        assert result is None

    def test_fingerprint_skips_non_gguf(self, tmp_path):
        """Fingerprint returns None for non-GGUF files."""
        p = tmp_path / "model.safetensors"
        p.write_bytes(b"\x00" * 100)
        result = _run_gguf_guard_fingerprint(p)
        assert result is None

    def test_integrated_in_static_scan(self, tmp_path):
        """gguf-guard runs as part of check_static_scan."""
        p = make_gguf_file(tmp_path)
        with patch("quarantine.pipeline.GGUF_GUARD_BIN", "/nonexistent/gguf-guard"):
            result = check_static_scan(p, policy={"models": {"require_scan": False}})
        assert "gguf_guard" in result.get("details", {})

    def test_integrated_in_pipeline(self):
        """run_pipeline references gguf-guard functions (code structure check)."""
        import inspect
        source = inspect.getsource(run_pipeline)
        assert "_run_gguf_guard_fingerprint" in source
        assert "_run_gguf_guard_manifest" in source
