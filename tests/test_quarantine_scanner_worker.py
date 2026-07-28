"""Tests for the credentialless quarantine scanner boundary."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "services" / "quarantine"))

from quarantine import scanner_worker


def test_scanner_worker_rejects_artifact_outside_quarantine(tmp_path, monkeypatch):
    quarantine = tmp_path / "quarantine"
    quarantine.mkdir()
    outside = tmp_path / "outside.gguf"
    outside.write_bytes(b"GGUF")
    monkeypatch.setenv("QUARANTINE_DIR", str(quarantine))

    with pytest.raises(ValueError, match="direct child"):
        scanner_worker._validated_artifact_path(str(outside))


def test_scanner_worker_detects_artifact_mutation(tmp_path, monkeypatch):
    quarantine = tmp_path / "quarantine"
    quarantine.mkdir()
    artifact = quarantine / "model.gguf"
    artifact.write_bytes(b"original")
    expected_hash = hashlib.sha256(b"original").hexdigest()

    calls = {"count": 0}

    def mutate_during_first_stage(*_args, **_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            artifact.write_bytes(b"modified")
        return {"passed": True}

    monkeypatch.setattr(scanner_worker, "_run_stage", mutate_during_first_stage)

    result = scanner_worker.scan(
        artifact,
        expected_hash,
        {},
        source_url="",
        directory=False,
    )

    assert result["passed"] is False
    assert result["reason"] == "artifact_changed_during_scan"


def test_scanner_worker_rejects_malformed_source_metadata(tmp_path, monkeypatch):
    artifact = tmp_path / "model.gguf"
    artifact.write_bytes(b"original")
    expected_hash = hashlib.sha256(b"original").hexdigest()
    with pytest.raises(ValueError, match="control characters"):
        scanner_worker.scan(
            artifact,
            expected_hash,
            {},
            source_url="https://example.invalid/model\ninjected",
            directory=False,
        )


def test_parser_exception_is_a_normal_rejection_not_restart(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "quarantine-scanner",
            "--artifact",
            "/claim/snapshot/poison.gguf",
            "--sha256",
            "a" * 64,
            "--policy",
            "/etc/policy.yaml",
        ],
    )
    monkeypatch.setattr(
        scanner_worker,
        "_validated_artifact_path",
        lambda _path: Path("/claim/snapshot/poison.gguf"),
    )
    monkeypatch.setattr(
        scanner_worker,
        "_policy_bundle_evidence",
        lambda _path: {"version": 1, "sha256": "b" * 64, "components": {}},
    )
    monkeypatch.setattr(scanner_worker, "_enable_child_subreaper", lambda: True)
    monkeypatch.setattr(
        scanner_worker,
        "_protect_coordinator_from_stage_processes",
        lambda: True,
    )
    monkeypatch.setattr(scanner_worker, "_load_policy", lambda _path: {})
    monkeypatch.setattr(
        scanner_worker,
        "scan",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ValueError("deterministic parser poison")
        ),
    )

    scanner_worker.main()

    output = json.loads(capsys.readouterr().out)
    assert output["passed"] is False
    assert output["reason"] == "artifact_parser_rejected"
    assert output["details"]["failure_class"] == "ValueError"
    assert "deterministic parser poison" not in json.dumps(output)


def test_coordinator_runs_each_required_stage_in_a_fresh_assignment(
    tmp_path,
    monkeypatch,
):
    artifact = tmp_path / "model.gguf"
    artifact.write_bytes(b"GGUF")
    expected_hash = hashlib.sha256(b"GGUF").hexdigest()
    stages = []

    def passed_stage(stage, *_args, **_kwargs):
        stages.append(stage)
        return {
            "passed": True,
            # A compromised stage can only place this inside its own result.
            "provenance": {"passed": True},
        }

    monkeypatch.setattr(scanner_worker, "_run_stage", passed_stage)
    result = scanner_worker.scan(
        artifact,
        expected_hash,
        {"models": {"require_behavior_tests": True}},
        source_url="",
        directory=False,
        policy_path=tmp_path / "policy.yaml",
    )

    assert stages == [
        "source_policy",
        "format_gate",
        "hash_pin",
        "provenance",
        "static_scan",
        "smoke_test",
    ]
    assert result["passed"] is True
    assert set(result["details"]) == {
        *stages,
        "hash",
    }
    assert result["details"]["source_policy"]["provenance"] == {"passed": True}
    assert result["details"]["provenance"] is not result["details"]["source_policy"]


def test_coordinator_disables_ptrace_and_core_dumps(monkeypatch):
    calls = []

    class FakeLibC:
        def prctl(self, *args):
            calls.append(("prctl", args))
            return 0

    monkeypatch.setattr(scanner_worker.sys, "platform", "linux")
    monkeypatch.setattr(
        scanner_worker.ctypes,
        "CDLL",
        lambda *_args, **_kwargs: FakeLibC(),
    )
    monkeypatch.setattr(
        scanner_worker.resource,
        "setrlimit",
        lambda resource_id, limits: calls.append(
            ("setrlimit", resource_id, limits)
        ),
    )

    assert scanner_worker._protect_coordinator_from_stage_processes() is True
    assert (
        "setrlimit",
        scanner_worker.resource.RLIMIT_CORE,
        (0, 0),
    ) in calls
    assert (
        "prctl",
        (scanner_worker.PR_SET_DUMPABLE, 0, 0, 0, 0),
    ) in calls


def test_real_stage_subprocess_boundary_executes_from_source_tree(tmp_path):
    artifact = tmp_path / "model.gguf"
    artifact.write_bytes(b"GGUF")
    policy_path = (
        Path(__file__).parent.parent
        / "files/system/etc/secure-ai/policy/policy.yaml"
    )

    result = scanner_worker._run_stage(
        "source_policy",
        artifact,
        hashlib.sha256(b"GGUF").hexdigest(),
        policy_path,
        source_url="",
        directory=False,
    )

    assert result["passed"] is True


def test_option_like_source_is_data_not_a_stage_argument(tmp_path):
    artifact = tmp_path / "model.gguf"
    artifact.write_bytes(b"GGUF")
    policy_path = (
        Path(__file__).parent.parent
        / "files/system/etc/secure-ai/policy/policy.yaml"
    )

    result = scanner_worker._run_stage(
        "source_policy",
        artifact,
        hashlib.sha256(b"GGUF").hexdigest(),
        policy_path,
        source_url="--directory",
        directory=False,
    )

    assert result["passed"] is False
    assert result.get("reason") != "stage_boundary_failed"


def test_poison_artifact_cli_exits_normally_with_rejection(tmp_path):
    artifact = tmp_path / "poison.gguf"
    artifact.write_bytes(b"not-a-valid-gguf")
    repo_root = Path(__file__).parent.parent
    policy_root = repo_root / "files/system/etc/secure-ai/policy"
    package_root = repo_root / "services/quarantine"
    environment = {
        **os.environ,
        "PYTHONPATH": str(package_root),
        "QUARANTINE_DIR": str(tmp_path),
        "MODELS_LOCK_PATH": str(policy_root / "models.lock.yaml"),
        "DIFFUSION_MODELS_LOCK_PATH": str(
            policy_root / "diffusion-models.lock.yaml"
        ),
        "SOURCES_ALLOWLIST_PATH": str(policy_root / "sources.allowlist.yaml"),
        "YARA_RULES_DIR": str(
            package_root / "quarantine/yara_rules"
        ),
    }
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "quarantine.scanner_worker",
            "--artifact",
            str(artifact),
            "--sha256",
            hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "--policy",
            str(policy_root / "policy.yaml"),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
        check=False,
    )

    assert completed.returncode == 0
    result = json.loads(completed.stdout)
    assert result["passed"] is False
    assert result["reason"] == "format_gate"


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Linux prctl/proc descendant reaping test",
)
def test_stage_subreaper_kills_setsid_escape(tmp_path):
    package_root = Path(__file__).parent.parent / "services/quarantine"
    pid_path = tmp_path / "escaped.pid"
    script = f"""\
import os
import subprocess
import sys
import time
from pathlib import Path
from quarantine import scanner_worker

assert scanner_worker._enable_child_subreaper()
child_code = '''\
import os
import time
from pathlib import Path
pid = os.fork()
if pid:
    os._exit(0)
os.setsid()
Path({str(pid_path)!r}).write_text(str(os.getpid()), encoding="ascii")
time.sleep(30)
'''
child = subprocess.Popen(
    [sys.executable, "-c", child_code],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    close_fds=True,
)
child.wait(timeout=5)
deadline = time.monotonic() + 5
while (
    (
        not Path({str(pid_path)!r}).exists()
        or not Path({str(pid_path)!r}).read_text(encoding="ascii")
    )
    and time.monotonic() < deadline
):
    time.sleep(0.01)
escaped_pid = int(Path({str(pid_path)!r}).read_text(encoding="ascii"))
scanner_worker._reap_reparented_stage_descendants()
try:
    os.kill(escaped_pid, 0)
except ProcessLookupError:
    raise SystemExit(0)
raise SystemExit("escaped scanner descendant survived reaping")
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=15,
        env={**os.environ, "PYTHONPATH": str(package_root)},
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
