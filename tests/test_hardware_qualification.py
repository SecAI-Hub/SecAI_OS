"""Tests for the redacted hardware qualification evidence collector."""

import importlib.util
import json
import stat
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "qualification" / "collect_hardware_evidence.py"
SPEC = importlib.util.spec_from_file_location("qualification_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
qualification = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualification)


def test_redaction_removes_machine_identifiers_recursively() -> None:
    raw = {
        "hostname": "secret-host",
        "safe": {
            "serial_number": "secret-serial",
            "driver": "550.1",
            "nested": [{"device_uuid": "secret-uuid", "name": "GPU"}],
        },
    }
    redacted = qualification.redact_mapping(raw)
    encoded = json.dumps(redacted)
    assert "secret-host" not in encoded
    assert "secret-serial" not in encoded
    assert "secret-uuid" not in encoded
    assert redacted["safe"]["driver"] == "550.1"
    assert redacted["safe"]["nested"][0]["name"] == "GPU"


def test_os_release_is_allowlisted(tmp_path: Path) -> None:
    os_release = tmp_path / "os-release"
    os_release.write_text(
        'ID=fedora\nVERSION_ID="44"\nNAME="Fedora Linux"\n'
        'VARIANT_ID=silverblue\nBUILD_ID=private-build\n',
        encoding="utf-8",
    )
    assert qualification.parse_os_release(os_release) == {
        "ID": "fedora",
        "VERSION_ID": "44",
        "VARIANT_ID": "silverblue",
    }


def test_atomic_report_is_owner_only(tmp_path: Path) -> None:
    target = tmp_path / "evidence.json"
    qualification.write_atomic(target, {"assurance": {"certified": False}})
    assert json.loads(target.read_text(encoding="utf-8"))["assurance"][
        "certified"
    ] is False
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_collector_never_self_certifies(monkeypatch) -> None:
    monkeypatch.setattr(
        qualification,
        "run_command",
        lambda *args, **kwargs: {"available": False},
    )
    monkeypatch.setattr(
        qualification,
        "rpm_ostree_evidence",
        lambda: {"available": False},
    )
    report = qualification.collect()
    assert report["assurance"]["certified"] is False
    assert report["assurance"]["classification"] == "evidence-only"


def test_collector_records_only_scoped_selinux_and_podman_security(monkeypatch) -> None:
    def fake_run(argv, timeout=15):
        del timeout
        if argv[0] == "getenforce":
            return {"available": True, "exit_code": 0, "stdout": "Enforcing"}
        if argv[0] == "sestatus":
            return {
                "available": True,
                "exit_code": 0,
                "stdout": (
                    "SELinux status: enabled\n"
                    "Current mode: enforcing\n"
                    "Loaded policy name: targeted\n"
                    "Hostname: must-not-appear\n"
                ),
            }
        if argv[0] == "ls" and argv[1] == "-Zd":
            return {
                "available": True,
                "exit_code": 0,
                "stdout": "system_u:object_r:etc_t:s0 /etc/secure-ai",
            }
        if argv[0] == "podman":
            return {
                "available": True,
                "exit_code": 0,
                "stdout": '{"rootless":false,"selinuxEnabled":true}',
            }
        return {"available": False}

    monkeypatch.setattr(qualification, "run_command", fake_run)
    monkeypatch.setattr(
        qualification,
        "rpm_ostree_evidence",
        lambda: {"available": False},
    )

    report = qualification.collect()
    assert report["schema_version"] == "1.1"
    selinux = report["mandatory_access_control"]["selinux"]
    assert selinux["enforcement"]["stdout"] == "Enforcing"
    assert selinux["status"]["fields"] == {
        "SELinux status": "enabled",
        "Current mode": "enforcing",
        "Loaded policy name": "targeted",
    }
    assert "must-not-appear" not in json.dumps(report)
    assert report["container_runtime"]["podman_security"] == {
        "rootless": False,
        "selinuxEnabled": True,
    }


def test_redaction_removes_sensitive_lines_from_text_probes() -> None:
    probe = {
        "available": True,
        "stdout": (
            "deviceName = Example GPU\n"
            "deviceUUID = 11111111-2222-3333-4444-555555555555\n"
            "Serial Number: customer-specific\n"
            "driverVersion = 1.2.3"
        ),
    }

    redacted = qualification.redact_mapping(probe)

    assert redacted["stdout"] == (
        "deviceName = Example GPU\n"
        "driverVersion = 1.2.3"
    )
    assert "11111111" not in json.dumps(redacted)
    assert "customer-specific" not in json.dumps(redacted)
