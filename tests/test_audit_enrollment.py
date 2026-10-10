"""Verifier enrollment and fault tests; all evidence is synthetic and temporary."""
from __future__ import annotations

import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from common.audit_chain import AuditChain

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "files/system/usr/libexec/secure-ai/verify-audit-chains.py"
spec = importlib.util.spec_from_file_location("enrollment_verifier", SCRIPT)
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


@pytest.fixture
def setup(monkeypatch, tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir(mode=0o750)
    state = tmp_path / "private"
    state.mkdir(mode=0o700)
    keys = tmp_path / "keys"
    keys.mkdir(mode=0o700)
    manifest = tmp_path / "formats.json"
    entry = {"file": "test-audit.jsonl", "format": "structured-jsonl", "required": False,
             "security_class": "structured-only", "services": []}
    manifest.write_text(json.dumps({"version": 2, "logs": [entry]}))
    manifest.chmod(0o644)
    for name, value in {"LOGS_DIR": logs, "RESULT_FILE": logs / "audit-verify-last.json",
                        "STATE_DIR": state, "STATE_FILE": state / "enrollment.json",
                        "KEY_DIR": keys, "MANIFEST_PATH": manifest}.items():
        monkeypatch.setattr(v, name, value)
    return entry, logs / entry["file"]


def result():
    return json.loads(v.RESULT_FILE.read_text())


def ledger():
    return json.loads(v.STATE_FILE.read_text())


def set_manifest(entry, *, version=2):
    v.MANIFEST_PATH.write_text(json.dumps({"version": version, "logs": [entry]}))


def write_log(path, text='{"event":"one"}\n'):
    path.write_text(text)
    path.chmod(0o640)


def test_explicit_first_install_then_optional_never_started(setup):
    assert v.main() == 1
    assert not v.STATE_FILE.exists()
    assert v.main(initialize=True) == 0
    assert result()["details"][0]["status"] == "not_applicable"
    assert v.main() == 0
    assert v.STATE_FILE.stat().st_mode & 0o777 == 0o600
    assert v.RESULT_FILE.stat().st_mode & 0o777 == 0o640


def test_existing_version_one_config_is_explicitly_adopted(setup):
    entry, path = setup
    entry.pop("services")
    set_manifest(entry, version=1)
    write_log(path)
    assert v.main(initialize=True) == 0
    path.unlink()
    assert v.main() == 1
    assert not result()["ready"]


def test_append_preserves_prefix_and_advances_ledger(setup):
    _, path = setup
    write_log(path)
    assert v.main(initialize=True) == 0
    old = ledger()["logs"][path.name]["files"][path.name]
    with path.open("a") as handle:
        handle.write('{"event":"two"}\n')
    assert v.main() == 0
    new = ledger()["logs"][path.name]["files"][path.name]
    assert new["size"] > old["size"]
    assert new["inode"] == old["inode"]
    assert new["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("damage", ["delete", "truncate", "replace", "rewrite", "symlink", "dangling", "directory", "fifo", "hardlink"])
def test_enrolled_file_damage_degrades_readiness(setup, damage):
    _, path = setup
    write_log(path)
    assert v.main(initialize=True) == 0
    original = path.read_bytes()
    if damage == "truncate":
        path.write_bytes(b"")
    elif damage == "rewrite":
        path.write_bytes(original.replace(b"one", b"two"))
    elif damage == "hardlink":
        os.link(path, path.with_name("second-link"))
    else:
        saved = path.with_name("saved")
        path.rename(saved)
        if damage == "replace":
            path.write_bytes(original)
        elif damage == "symlink":
            path.symlink_to(saved)
        elif damage == "dangling":
            path.symlink_to("missing")
        elif damage == "directory":
            path.mkdir()
        elif damage == "fifo":
            os.mkfifo(path)
    assert v.main() == 1
    assert result()["status"] == "failed"
    assert result()["failures"] == 1
    assert ledger()["logs"][path.name]["required"] is True
    assert v.main() == 1


@pytest.mark.parametrize("state", ["active", "activating", "reloading", "deactivating", "failed"])
def test_active_or_failed_service_requires_log_and_stays_enrolled(setup, monkeypatch, state):
    entry, _ = setup
    entry["services"] = ["secure-ai-test.service"]
    set_manifest(entry)
    monkeypatch.setattr(v, "_service_states", lambda _: {entry["services"][0]: state})
    assert v.main(initialize=True) == 1
    assert result()["details"][0]["status"] == "broken"
    monkeypatch.setattr(v, "_service_states", lambda _: {entry["services"][0]: "inactive"})
    assert v.main() == 1


def test_inactive_optional_then_active_then_deactivated(setup, monkeypatch):
    entry, path = setup
    entry["services"] = ["secure-ai-test.service"]
    set_manifest(entry)
    states = {entry["services"][0]: "inactive"}
    monkeypatch.setattr(v, "_service_states", lambda _: states)
    assert v.main(initialize=True) == 0
    assert result()["details"][0]["status"] == "not_applicable"
    states[entry["services"][0]] = "active"
    write_log(path)
    assert v.main() == 0
    states[entry["services"][0]] = "inactive"
    path.unlink()
    assert v.main() == 1


def test_offline_does_not_exempt_active_audit_service(setup, monkeypatch):
    monkeypatch.setenv("SERVICE_PROFILE", "offline")
    entry, _ = setup
    entry["services"] = ["secure-ai-test.service"]
    set_manifest(entry)
    monkeypatch.setattr(v, "_service_states", lambda _: {entry["services"][0]: "active"})
    assert v.main(initialize=True) == 1


@pytest.mark.parametrize("present", [False, True])
def test_unknown_service_activity_cannot_assert_readiness(setup, monkeypatch, present):
    entry, path = setup
    entry["services"] = ["secure-ai-test.service"]
    set_manifest(entry)
    if present:
        write_log(path)
    monkeypatch.setattr(v, "_service_states", lambda _: {entry["services"][0]: "unknown"})
    assert v.main(initialize=True) == 1
    assert "unavailable" in result()["details"][0]["detail"]


@pytest.mark.parametrize("failure", ["timeout", "nonzero", "malformed", "notfound", "inactive", "failed"])
def test_service_query_errors_are_distinguished_from_inactive(setup, monkeypatch, failure):
    entry, _ = setup
    entry["services"] = ["secure-ai-test.service"]
    def run(*args, **kwargs):
        assert args[0][0] == "/usr/bin/systemctl"
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args[0], 5)
        stdout = {"malformed": "LoadState=loaded\nActiveState=alien\n", "notfound": "LoadState=not-found\nActiveState=inactive\n",
                  "inactive": "LoadState=loaded\nActiveState=inactive\n", "failed": "LoadState=loaded\nActiveState=failed\n"}.get(failure, "")
        return subprocess.CompletedProcess(args[0], int(failure == "nonzero"), stdout)
    monkeypatch.setattr(v.subprocess, "run", run)
    states = v._service_states([entry])
    expected = "inactive" if failure in {"notfound", "inactive"} else "failed" if failure == "failed" else "unknown"
    assert states[entry["services"][0]] == expected


def test_required_missing_is_an_overall_failure(setup):
    entry, _ = setup
    entry["required"] = True
    set_manifest(entry)
    assert v.main(initialize=True) == 1
    assert result()["failures"] == 1


@pytest.mark.parametrize("damage", ["missing", "partial", "unsafe", "symlink"])
def test_private_state_damage_never_reinitializes(setup, damage):
    assert v.main(initialize=True) == 0
    if damage == "missing":
        v.STATE_FILE.unlink()
    elif damage == "partial":
        v.STATE_FILE.write_text('{"version":')
    elif damage == "unsafe":
        v.STATE_FILE.chmod(0o666)
    else:
        saved = v.STATE_FILE.with_name("saved")
        v.STATE_FILE.rename(saved)
        v.STATE_FILE.symlink_to(saved)
    assert v.main() == 1
    assert result()["ready"] is False
    if damage == "missing":
        assert not v.STATE_FILE.exists()


def test_result_disappearance_latches_even_if_recreated(setup):
    assert v.main(initialize=True) == 0
    v.RESULT_FILE.unlink()
    assert v.main() == 1
    assert ledger()["evidence_lost"] is True
    v.RESULT_FILE.write_text('{}\n')
    v.RESULT_FILE.chmod(0o640)
    assert v.main() == 1
    assert not result()["ready"]
    assert v.main() == 1


def test_result_tampering_latches_after_report_replacement(setup):
    assert v.main(initialize=True) == 0
    v.RESULT_FILE.write_text('{"status":"ok","ready":true}\n')
    assert v.main() == 1
    assert ledger()["evidence_lost"] is True
    assert v.main() == 1


def test_initialize_cannot_reset_enrollment_or_replace_report(setup):
    assert v.main(initialize=True) == 0
    state, report = v.STATE_FILE.read_bytes(), v.RESULT_FILE.read_bytes()
    assert v.main(initialize=True) == 1
    assert v.STATE_FILE.read_bytes() == state
    assert v.RESULT_FILE.read_bytes() == report


def test_manifest_change_cannot_forget_an_enrolled_log(setup):
    entry, path = setup
    write_log(path)
    assert v.main(initialize=True) == 0
    entry["file"] = "replacement-audit.jsonl"
    set_manifest(entry)
    assert v.main() == 1
    assert path.name in ledger()["logs"]


def test_checkpoint_or_archive_prevents_optional_absence(setup):
    entry, path = setup
    entry.update(format="python-hmac-chain", security_class="keyed-tamper-evident", key_file="test-key")
    set_manifest(entry)
    path.with_suffix('.jsonl.checkpoint').write_text('{"untrusted":true}\n')
    assert v.main(initialize=True) == 1
    assert ledger()["logs"][path.name]["required"] is True


def test_hmac_chain_enrollment_append_checkpoint_replacement_and_missing(setup):
    entry, path = setup
    entry.update(format="python-hmac-chain", security_class="keyed-tamper-evident", key_file="test-key")
    set_manifest(entry)
    key = v.KEY_DIR / "test-key"
    key.write_bytes(b"k" * 32)
    key.chmod(0o600)
    chain = AuditChain(str(path), key_path=str(key))
    chain.append("one", {})
    assert v.main(initialize=True) == 0
    chain.append("two", {})
    assert v.main() == 0
    path.with_suffix('.jsonl.checkpoint').unlink()
    assert v.main() == 1


def test_unkeyed_syntax_cannot_be_reported_as_keyed(setup):
    entry, path = setup
    entry.update(format="python-hmac-chain", security_class="keyed-tamper-evident", key_file="test-key")
    set_manifest(entry)
    key = v.KEY_DIR / "test-key"
    key.write_bytes(b"k" * 32)
    key.chmod(0o600)
    AuditChain(str(path)).append("legacy", {})
    assert v.main(initialize=True) == 1
    assert "unauthenticated" in result()["details"][0]["detail"]


@pytest.mark.parametrize("mode", [0o644, 0o660, 0o666])
def test_empty_keyed_chain_still_requires_safe_key(setup, mode):
    entry, path = setup
    entry.update(format="python-hmac-chain", security_class="keyed-tamper-evident", key_file="test-key")
    set_manifest(entry)
    key = v.KEY_DIR / "test-key"
    key.write_bytes(b"k" * 32)
    key.chmod(mode)
    write_log(path, "")
    assert v.main(initialize=True) == 1


@pytest.mark.parametrize("content", [b'{"event":"partial"}', b'\xff\n', b'[]\n', b'x' * (1024 * 1024 + 1) + b'\n'])
def test_malformed_or_incomplete_jsonl_is_failure(setup, content):
    _, path = setup
    path.write_bytes(content)
    assert v.main(initialize=True) == 1


@pytest.mark.parametrize("error", [errno.EBADF, errno.EACCES, errno.ENOSPC, errno.EIO])
def test_closed_unreadable_and_io_failed_log_descriptors(setup, monkeypatch, error):
    _, path = setup
    write_log(path)
    assert v.main(initialize=True) == 0
    original = v._open_regular
    def open_regular(target, **kwargs):
        if target == path:
            raise OSError(error, "injected evidence fault")
        return original(target, **kwargs)
    monkeypatch.setattr(v, "_open_regular", open_regular)
    assert v.main() == 1
    assert not result()["ready"]


@pytest.mark.parametrize("boundary", ["state_fsync", "directory_fsync", "state_replace", "result_write"])
def test_persistence_failure_and_restart_cannot_report_success(setup, monkeypatch, boundary):
    assert v.main(initialize=True) == 0
    with monkeypatch.context() as patch:
        def fail(*args, **kwargs):
            raise OSError(errno.ENOSPC, "injected persistence fault")
        if boundary == "state_fsync":
            patch.setattr(v.os, "fsync", fail)
        elif boundary == "directory_fsync":
            patch.setattr(v, "_sync_directory", fail)
        elif boundary == "state_replace":
            patch.setattr(v.os, "replace", fail)
        else:
            original = v._publish_result
            def publish(payload):
                if payload["status"] != "checking":
                    fail()
                return original(payload)
            patch.setattr(v, "_publish_result", publish)
        assert v.main() == 1
    assert v.main() == 1
    assert not result()["ready"]
    assert ledger()["evidence_lost"] is True


def test_concurrent_verifier_cannot_publish_over_active_owner(setup):
    assert v.main(initialize=True) == 0
    before = v.RESULT_FILE.read_bytes()
    with (v.STATE_DIR / "verifier.lock").open("rb") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert v.main() == 1
    assert v.RESULT_FILE.read_bytes() == before


def test_replacement_after_snapshot_is_not_a_verified_current_log(setup, monkeypatch):
    _, path = setup
    write_log(path)
    original = v._verify_snapshot
    def verify(entry, directory):
        checked = original(entry, directory)
        path.rename(path.with_name("old"))
        write_log(path)
        return checked
    monkeypatch.setattr(v, "_verify_snapshot", verify)
    assert v.main(initialize=True) == 1
    assert "changed during verification" in result()["details"][0]["detail"]


def test_stable_snapshot_same_size_rewrite_is_detected(setup, monkeypatch):
    _, path = setup
    write_log(path)
    original = v._verify_snapshot
    def verify(entry, directory):
        checked = original(entry, directory)
        write_log(path, '{"event":"two"}\n')
        return checked
    monkeypatch.setattr(v, "_verify_snapshot", verify)
    assert v.main(initialize=True) == 1


def test_real_process_restart_retains_deletion_requirement(setup):
    _, path = setup
    write_log(path)
    env = dict(os.environ, AUDIT_LOGS_DIR=str(v.LOGS_DIR), AUDIT_VERIFIER_STATE_DIR=str(v.STATE_DIR),
               AUDIT_FORMAT_MANIFEST=str(v.MANIFEST_PATH), AUDIT_HMAC_KEY_DIR=str(v.KEY_DIR), PYTHONPATH=str(ROOT / "services"))
    def run(*arguments):
        return subprocess.run([sys.executable, str(SCRIPT), *arguments], env=env, cwd=ROOT,
                              capture_output=True, text=True, timeout=10)
    assert run().returncode == 1
    assert run("--initialize").returncode == 0
    assert run().returncode == 0
    path.unlink()
    assert run().returncode == 1
    assert result()["details"][0]["valid"] is False
    assert run().returncode == 1


def test_native_verifier_has_private_state_and_no_logs_directory_write_access():
    unit = (ROOT / "files/system/usr/lib/systemd/system/secure-ai-audit-verify.service").read_text()
    assert "User=root\n" in unit
    assert "DynamicUser=yes" not in unit
    assert "CapabilityBoundingSet=CAP_DAC_READ_SEARCH\n" in unit
    assert "StateDirectory=secure-ai/audit-verifier\nStateDirectoryMode=0700" in unit
    assert "ReadOnlyPaths=/var/lib/secure-ai/logs\n" in unit
    assert "ReadWritePaths=/var/lib/secure-ai/logs\n" not in unit
    assert "ReadWritePaths=/var/lib/secure-ai/logs/audit-verify-last.json\n" in unit
    assert "InaccessiblePaths=-/var/lib/secure-ai/credentials" in unit
    assert "InaccessiblePaths=-/var/lib/secure-ai/vault" in unit
    assert "RestrictAddressFamilies=AF_UNIX" in unit
    assert "--initialize" not in next(line for line in unit.splitlines() if line.startswith("ExecStart="))


def test_repository_manifest_maps_only_existing_native_units():
    payload = json.loads((ROOT / "files/system/etc/secure-ai/config/audit-log-formats.json").read_text())
    assert payload["version"] == 2
    assert len(payload["logs"]) == 21
    assert all("services" in entry for entry in payload["logs"])
    for entry in payload["logs"]:
        for unit in entry["services"]:
            assert (ROOT / "files/system/usr/lib/systemd/system" / unit).is_file()


def test_legitimate_append_during_verification_is_retryable_not_corruption(setup, monkeypatch):
    _, path = setup
    write_log(path)
    assert v.main(initialize=True) == 0
    with monkeypatch.context() as patch:
        original = v._verify_snapshot
        def verify(entry, directory):
            checked = original(entry, directory)
            with path.open("a") as handle:
                handle.write('{"event":"concurrent"}\n')
            return checked
        patch.setattr(v, "_verify_snapshot", verify)
        assert v.main() == 1
    assert result()["details"][0]["status"] == "unavailable"
    assert result()["details"][0]["retryable"] is True
    assert ledger()["evidence_lost"] is False
    assert v.main() == 0


def test_existing_status_unsafe_owner_mode_does_not_get_adopted(setup):
    v.RESULT_FILE.write_text('{"status":"ok"}')
    v.RESULT_FILE.chmod(0o666)
    assert v.main(initialize=True) == 1
    assert not v.STATE_FILE.exists()


def test_explicit_initialization_under_private_umask_keeps_status_readable(setup):
    old_umask = os.umask(0o077)
    try:
        assert v.main(initialize=True) == 0
    finally:
        os.umask(old_umask)
    assert v.RESULT_FILE.stat().st_mode & 0o777 == 0o640
    assert v.STATE_FILE.stat().st_mode & 0o777 == 0o600


def test_explicit_upgrade_preserves_old_report_and_sets_reader_permissions(setup):
    v.RESULT_FILE.write_text('{"historical":"synthetic"}\n')
    v.RESULT_FILE.chmod(0o600)
    historical = v.RESULT_FILE.read_bytes()
    assert v.main(initialize=True) == 0
    assert (v.STATE_DIR / "pre-enrollment-result.json").read_bytes() == historical
    assert v.RESULT_FILE.stat().st_mode & 0o777 == 0o640
    assert v.RESULT_FILE.stat().st_gid == v.LOGS_DIR.stat().st_gid


def test_enrolled_result_mode_change_fails_closed(setup):
    assert v.main(initialize=True) == 0
    v.RESULT_FILE.chmod(0o600)
    assert v.main() == 1


def test_enrollment_unit_is_deliberate_and_has_no_unprivileged_activation_path():
    unit_dir = ROOT / 'files/system/usr/lib/systemd/system'
    name = 'secure-ai-audit-enroll.service'
    unit = (unit_dir / name).read_text()
    assert 'verify-audit-chains.py --initialize\n' in unit
    assert 'User=root\n' in unit
    assert '[Install]' not in unit
    assert 'ReadWritePaths=/var/lib/secure-ai/logs\n' in unit
    for other in unit_dir.rglob('*'):
        if other.is_file() and other != unit_dir / name:
            assert name not in other.read_text(), f'Unexpected enrollment activation reference: {other}'
    for path in (ROOT / 'recipes/recipe.yml', ROOT / 'files/system/etc/secure-ai/config/service-profile.json', ROOT / 'services/ui/ui/app.py'):
        assert name not in path.read_text()
    assert 'os.fchown(' not in SCRIPT.read_text()  # denied by the units' @privileged filter


@pytest.mark.parametrize('relative', ['example.service', 'example.service.d/10-unsafe.conf', 'nested/example.service.d/10-unsafe.conf'])
def test_enrollment_activation_scan_rejects_unit_and_nested_dropin_references(tmp_path, monkeypatch, relative):
    name = 'secure-ai-audit-enroll.service'
    unit = (ROOT / 'files/system/usr/lib/systemd/system' / name).read_text()
    unit_dir = tmp_path / 'files/system/usr/lib/systemd/system'
    unit_dir.mkdir(parents=True)
    (unit_dir / name).write_text(unit)
    unexpected = unit_dir / relative
    unexpected.parent.mkdir(parents=True, exist_ok=True)
    unexpected.write_text(f'[Unit]\nWants={name}\n')
    monkeypatch.setattr(sys.modules[__name__], 'ROOT', tmp_path)
    with pytest.raises(AssertionError, match='Unexpected enrollment activation reference'):
        test_enrollment_unit_is_deliberate_and_has_no_unprivileged_activation_path()


def test_abrupt_process_exit_after_ledger_commit_fails_on_fresh_restart(setup):
    assert v.main(initialize=True) == 0
    env = dict(os.environ, AUDIT_LOGS_DIR=str(v.LOGS_DIR), AUDIT_VERIFIER_STATE_DIR=str(v.STATE_DIR),
               AUDIT_FORMAT_MANIFEST=str(v.MANIFEST_PATH), AUDIT_HMAC_KEY_DIR=str(v.KEY_DIR), PYTHONPATH=str(ROOT / 'services'))
    program = '''import importlib.util, os, sys
spec = importlib.util.spec_from_file_location('crash_verifier', sys.argv[1])
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
original = v._write_state
def crash(state):
    original(state)
    os._exit(73)
v._write_state = crash
v.main()
'''
    crashed = subprocess.run([sys.executable, '-c', program, str(SCRIPT)], env=env, capture_output=True, timeout=10)
    assert crashed.returncode == 73
    assert result()['status'] == 'checking'
    restarted = subprocess.run([sys.executable, str(SCRIPT)], env=env, capture_output=True, timeout=10)
    assert restarted.returncode == 1
    assert ledger()['evidence_lost'] is True
    assert result()['ready'] is False


def test_missing_archive_at_initial_adoption_is_not_optional(setup):
    entry, path = setup
    entry.update(format='python-hmac-chain', security_class='keyed-tamper-evident', key_file='test-key')
    set_manifest(entry)
    path.with_name('test-audit.20260101.jsonl').write_text('{}\n')
    assert v.main(initialize=True) == 1
    assert ledger()['logs'][path.name]['required'] is True


def test_evidence_size_bound_is_explicit_failure(setup, monkeypatch):
    _, path = setup
    write_log(path)
    monkeypatch.setattr(v, 'MAX_LOG_BYTES', 2)
    assert v.main(initialize=True) == 1
    assert 'size limit' in result()['details'][0]['detail']
