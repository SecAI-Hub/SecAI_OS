"""Tests for the no-network Compose quarantine scanner sidecar."""

import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "services" / "quarantine"))

from quarantine import scanner_broker, watcher


def _request(artifact: Path) -> dict:
    return {
        "version": 1,
        "artifact": str(artifact),
        "sha256": "a" * 64,
        "source_url": "",
        "directory": False,
    }


def test_broker_json_rejects_duplicate_keys_and_nonfinite_numbers():
    with pytest.raises(ValueError, match="malformed"):
        scanner_broker._decode_strict_json_object(
            b'{"version":1,"version":2}',
        )
    with pytest.raises(ValueError, match="malformed"):
        scanner_broker._decode_strict_json_object(b'{"value":Infinity}')


def test_broker_accepts_only_private_claim_snapshot(monkeypatch, tmp_path):
    processing = tmp_path / "processing"
    claim_id = "a" * 32
    snapshot = processing / claim_id / "snapshot"
    snapshot.mkdir(parents=True)
    artifact = snapshot / "model.gguf"
    artifact.write_bytes(b"GGUF")
    monkeypatch.setattr(scanner_broker, "PROCESSING_DIR", processing)

    validated = scanner_broker._validate_request(
        claim_id,
        _request(artifact),
    )
    assert validated[0] == artifact

    outside = tmp_path / "outside.gguf"
    outside.write_bytes(b"GGUF")
    with pytest.raises(ValueError, match="outside the processing claim"):
        scanner_broker._validate_request(claim_id, _request(outside))


def test_broker_worker_cleans_descendants_and_excludes_credentials(
    monkeypatch,
    tmp_path,
):
    captured = {}

    class PassedProcess:
        pid = 789

        def poll(self):
            return 0

        def wait(self):
            return 0

    def passed_popen(command, **kwargs):
        captured["command"] = command
        captured["environment"] = kwargs["env"]
        kwargs["stdout"].write(b'{"passed":false,"reason":"poison","details":{}}')
        kwargs["stdout"].flush()
        return PassedProcess()

    monkeypatch.setenv("REGISTRY_TOKEN_PATH", "/run/secrets/registry.token")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", "/run/credentials/unit")
    monkeypatch.setattr(scanner_broker.subprocess, "Popen", passed_popen)
    killed = []
    monkeypatch.setattr(
        scanner_broker.os,
        "killpg",
        lambda pid, sig: killed.append((pid, sig)),
    )
    scanner_root = tmp_path / "snapshot"
    scanner_root.mkdir()
    artifact = scanner_root / "model.gguf"
    artifact.write_bytes(b"GGUF")

    result = scanner_broker._run_worker(
        "a" * 32,
        artifact,
        "b" * 64,
        "--directory",
        False,
    )

    assert result["passed"] is False
    assert killed == [(789, scanner_broker.signal.SIGKILL)]
    assert "REGISTRY_TOKEN_PATH" not in captured["environment"]
    assert "CREDENTIALS_DIRECTORY" not in captured["environment"]
    assert captured["environment"]["QUARANTINE_DIR"] == str(scanner_root)
    assert "--source-url=--directory" in captured["command"]


def test_broker_drops_job_volume_identity_before_worker(monkeypatch):
    calls = []
    monkeypatch.setattr(scanner_broker.sys, "platform", "linux")
    monkeypatch.setattr(scanner_broker.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        scanner_broker,
        "_limit_worker_output",
        lambda: calls.append(("limit",)),
    )
    monkeypatch.setattr(
        scanner_broker.os,
        "setgroups",
        lambda groups: calls.append(("groups", groups)),
    )
    monkeypatch.setattr(
        scanner_broker.os,
        "setgid",
        lambda gid: calls.append(("gid", gid)),
    )
    monkeypatch.setattr(
        scanner_broker.os,
        "setuid",
        lambda uid: calls.append(("uid", uid)),
    )

    scanner_broker._prepare_worker_process()

    assert calls == [
        ("limit",),
        ("groups", []),
        ("gid", scanner_broker.SCANNER_GID),
        ("uid", scanner_broker.SCANNER_UID),
    ]


def test_watcher_and_broker_round_trip_rejection(monkeypatch, tmp_path):
    jobs = tmp_path / "jobs"
    processing = tmp_path / "processing"
    claim_id = "c" * 32
    snapshot = processing / claim_id / "snapshot"
    snapshot.mkdir(parents=True)
    artifact = snapshot / "model.gguf"
    artifact.write_bytes(b"GGUF")
    jobs.mkdir()

    monkeypatch.setattr(scanner_broker, "JOB_DIR", jobs)
    monkeypatch.setattr(scanner_broker, "PROCESSING_DIR", processing)
    monkeypatch.setattr(
        scanner_broker,
        "_run_worker",
        lambda *_args, **_kwargs: {
            "passed": False,
            "reason": "artifact_parser_rejected",
            "details": {},
        },
    )
    monkeypatch.setattr(watcher, "SCANNER_JOB_DIR", jobs)

    request_path = jobs / f"{claim_id}.request.json"
    watcher._create_broker_request(request_path, _request(artifact))
    scanner_broker.scan_jobs_once()
    result = watcher._run_scanner_via_broker(
        artifact,
        "a" * 64,
        source_url="",
        directory=False,
    )

    assert result["passed"] is False
    assert result["reason"] == "artifact_parser_rejected"
    assert not list(jobs.iterdir())


def test_compose_scanner_has_real_no_network_and_no_credentials():
    repo_root = Path(__file__).parent.parent
    compose = yaml.safe_load(
        (repo_root / "deploy/sandbox/compose.yaml").read_text()
    )
    scanner = compose["services"]["quarantine-scanner"]
    watcher_service = compose["services"]["quarantine"]
    ui = compose["services"]["ui"]

    assert scanner["network_mode"] == "none"
    assert not scanner.get("networks")
    assert scanner["user"] == "0:0"
    assert set(scanner["group_add"]) >= {"65532", "65533"}
    assert set(scanner["cap_add"]) == {"SETUID", "SETGID"}
    scanner_mounts = json.dumps(scanner["volumes"])
    assert "/run/secrets" not in scanner_mounts
    processing_mount = next(
        mount
        for mount in scanner["volumes"]
        if isinstance(mount, dict)
        and mount.get("target") == "/var/lib/secure-ai/quarantine/processing"
    )
    assert processing_mount["read_only"] is True
    assert processing_mount["volume"]["subpath"] == "processing"
    assert watcher_service["environment"]["SCANNER_JOB_DIR"].endswith(
        "quarantine-scanner-jobs"
    )
    assert set(watcher_service["group_add"]) >= {"65532", "65533"}
    assert "quarantine-scanner" in watcher_service["depends_on"]

    ui_mount = next(
        mount
        for mount in ui["volumes"]
        if isinstance(mount, dict)
        and mount.get("target") == "/var/lib/secure-ai/quarantine/incoming"
    )
    assert ui_mount["volume"]["subpath"] == "incoming"

    start_script = (repo_root / "scripts/sandbox/start.sh").read_text()
    # The unprivileged watcher owns processing, while the root broker (which has
    # no DAC override capability) receives only group read/traverse access.
    assert (
        start_script.count(
            "chown -R 65534:65532 /volumes/quarantine/processing"
        )
        == 2
    )
    assert start_script.count(
        "chmod 2750 /volumes/quarantine/processing"
    ) == 2
    assert "chown -R 0:65533 /volumes/scanner-jobs" in start_script
    assert "chmod 0640 {} +" in start_script
    assert "chmod 2770 /volumes/scanner-jobs" in start_script


def test_compose_job_ipc_files_are_group_readable():
    watcher_source = Path(watcher.__file__).read_text()
    broker_source = Path(scanner_broker.__file__).read_text()

    # The setgid 65533 job directory assigns a common IPC group. Requests and
    # results are immutable to the peer but readable across the DAC boundary.
    assert watcher_source.count("0o640") >= 2
    assert "os.fchmod(descriptor, 0o640)" in broker_source
