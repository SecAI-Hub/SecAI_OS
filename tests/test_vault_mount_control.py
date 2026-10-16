"""Fixed PID1 protocol and real private cgroup-event fixtures, not live services."""
import importlib.util
import os
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

SOURCE = Path(__file__).parents[1] / "files/system/usr/libexec/secure-ai/vault-mount-control.py"
SPEC = importlib.util.spec_from_file_location("vault_mount_control_test", SOURCE)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class Manager:
    def __init__(self):
        self.actions = []
        self.pending = self.cancel_failure = False
        self.mount = {"Id": module.UNIT, "LoadState": "loaded", "ActiveState": "inactive",
                      "SubState": "dead", "Job": "", "ControlPID": "0", "What": module.WHAT,
                      "Where": module.WHERE, "Type": "ext4", "Options": "defaults,nodev,nosuid,noexec",
                      "SourcePath": "/etc/fstab", "FragmentPath": module.FRAGMENT_PATH}
        self.services = {
            name: {**{key: "" for key in module.native.PROPERTIES}, "Id": name,
                   "LoadState": "loaded", "ActiveState": "active", "SubState": "running",
                   "Job": "", "MainPID": "123", "ControlGroup": "/system.slice/" + name,
                   "KillMode": "control-group", "Delegate": "no", "ProtectControlGroups": "yes"}
            for name in module.CONSUMERS}

    def call(self, *args):
        action = args[0]
        if action == "show":
            value = self.mount if args[1] == module.UNIT else self.services[args[1]]
            return "\n".join(key + "=" + value for key, value in value.items())
        self.actions.append(args)
        if action == "cancel":
            if self.cancel_failure:
                raise module.native.Error("fixture cancel failed")
            for value in (self.mount, *self.services.values()):
                if value["Job"] == args[1]:
                    value.update(Job="", ActiveState="inactive", SubState="dead", ControlPID="0")
        elif args[-1] == module.UNIT:
            if action == "start" and self.pending:
                self.mount.update(Job="42", ActiveState="inactive", SubState="dead")
            else:
                self.mount.update(Job="", ActiveState="active" if action == "start" else "inactive",
                                  SubState="mounted" if action == "start" else "dead", ControlPID="0")
                if action == "start":
                    self.mount["Options"] = "rw,nosuid,nodev,noexec,relatime"
        elif action == "stop":
            for name in args[2:]:
                self.services[name].update(Job="", ActiveState="inactive", SubState="dead", MainPID="0")
        else:
            self.services[args[-1]].update(Job="", ActiveState="active", SubState="running", MainPID="123")
        return ""


@pytest.fixture
def manager(tmp_path, monkeypatch):
    value = Manager()
    monkeypatch.setattr(module.native, "manager", value.call)
    monkeypatch.setattr(module.native, "root_only", lambda: None)
    monkeypatch.setattr(module, "_SECONDS", 0.03)
    monkeypatch.setattr(module, "_DRAIN_SECONDS", 0.03)
    parent = tmp_path / "system.slice"
    parent.mkdir()
    for name in module.CONSUMERS:
        directory = parent / name
        directory.mkdir()
        (directory / "cgroup.events").write_text("populated 0\nfrozen 0\n")
    monkeypatch.setattr(module, "CGROUP_PARENT", parent)
    return value


def test_fixed_pid1_mount_start_stop_and_empty_job_format(manager):
    assert module.state() == ("absent", "")
    module.start()
    assert module.state() == ("expected", module.WHAT)
    module.stop()
    assert module.state() == ("absent", "")
    assert manager.actions == [("start", "--no-block", module.UNIT), ("stop", "--no-block", module.UNIT)]


@pytest.mark.parametrize("field,value", [
    ("What", "/dev/mapper/other"), ("Where", "/other"), ("Type", "tmpfs"),
    ("SourcePath", ""), ("FragmentPath", "/run/systemd/transient/" + module.UNIT),
    ("Options", "nodev,nosuid,exec"), ("Options", "nodev,nosuid,noexec,suid"),
    ("Options", "nodev,nosuid,noexec,bind"), ("Id", "another.mount"),
])
def test_foreign_mount_contract_never_reaches_mutation(manager, field, value):
    manager.mount[field] = value
    with pytest.raises(module.MountControlError):
        module.start()
    assert manager.actions == []


def test_definition_change_observed_during_settling_prevents_dispatch(manager, monkeypatch):
    original = manager.call
    shows = 0

    def changed(*args):
        nonlocal shows
        if args[0] == "show" and args[1] == module.UNIT:
            shows += 1
            if shows == 2:
                manager.mount["What"] = "/dev/mapper/foreign"
        return original(*args)

    monkeypatch.setattr(module.native, "manager", changed)
    with pytest.raises(module.MountControlError):
        module.start()
    assert manager.actions == []


def test_unconfigured_missing_unit_is_absent_but_cannot_start(manager):
    manager.mount.update(LoadState="not-found", SourcePath="", FragmentPath="", What="")
    assert module.state() == ("absent", "")
    module.stop()
    with pytest.raises(module.MountControlError, match="unavailable"):
        module.start()


@pytest.mark.parametrize("field,value", [("Job", "42"), ("ControlPID", "55"), ("SubState", "mounting")])
def test_transition_is_not_already_mounted(manager, field, value):
    manager.mount.update(ActiveState="active", SubState="mounted")
    manager.mount[field] = value
    assert module.state()[0] == "error"


def test_start_timeout_cancels_owned_decimal_job_and_settles(manager):
    manager.pending = True
    with pytest.raises(module.MountControlError, match="deadline"):
        module.start()
    assert ("cancel", "42") in manager.actions
    assert module.state() == ("absent", "")


def test_failed_cancel_never_claims_absence(manager):
    manager.pending = manager.cancel_failure = True
    with pytest.raises(module.MountControlError):
        module.start()
    assert manager.mount["Job"] == "42"
    assert module.state()[0] == "error"


def test_consumer_stop_drains_manager_and_real_pin_events(manager):
    module.stop_consumers()
    assert module.consumers_idle() is True
    assert manager.actions == [("stop", "--no-block", *module.CONSUMERS)]


def test_surviving_private_namespace_process_prevents_drain(manager):
    path = module.CGROUP_PARENT / module.CONSUMERS[0] / "cgroup.events"
    path.write_text("populated 1\nfrozen 0\n")
    with pytest.raises(module.MountControlError, match="deadline"):
        module.stop_consumers()
    assert module.consumers_idle() is False


def test_old_pending_consumer_job_is_not_idle(manager):
    module.stop_consumers()
    manager.services[module.CONSUMERS[1]]["Job"] = "71"
    assert module.consumers_idle() is False


def test_no_arbitrary_consumer_or_command_interface(manager):
    with pytest.raises(module.MountControlError, match="unsupported"):
        module.start_consumer("archive-selected.service")
    assert manager.actions == []


@pytest.fixture
def watchdog(manager, tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(SOURCE.parent))
    spec = importlib.util.spec_from_file_location("host_watchdog_test", SOURCE.with_name("vault-watchdog.py"))
    watch = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(watch)
    monkeypatch.setattr(watch.vault_mount, "native", module.native)
    monkeypatch.setattr(watch.vault_mount, "CGROUP_PARENT", module.CGROUP_PARENT)
    monkeypatch.setattr(watch.vault_mount, "_SECONDS", 0.03)
    monkeypatch.setattr(watch.vault_mount, "_DRAIN_SECONDS", 0.03)
    lock = tmp_path / "operation.lock"
    lock.touch(mode=0o600)
    monkeypatch.setattr(watch.vault_operation, "_LOCK_PATH", lock)
    monkeypatch.setattr(watch.vault_operation, "_OWNER_UID", os.geteuid())
    monkeypatch.setattr(watch.vault_operation, "_OWNER_GID", os.getegid())
    monkeypatch.setattr(watch, "audit_event", Mock())
    monkeypatch.setattr(watch, "write_state", Mock(return_value=True))
    return watch


@pytest.mark.parametrize("cancel_failure", [False, True])
def test_unlock_failed_job_is_drained_before_mapper_rollback(watchdog, manager, monkeypatch, cancel_failure):
    watch = watchdog
    manager.pending = True
    manager.cancel_failure = cancel_failure
    mapper = {"open": False}
    closes = []

    def crypto(argv, **kwargs):
        assert kwargs["pass_fds"]  # Existing operation lifetime handoff remains.
        if argv[:2] == ["cryptsetup", "open"]:
            mapper["open"] = True
        elif argv[:2] == ["cryptsetup", "close"]:
            assert manager.mount["Job"] == "" and manager.mount["ActiveState"] == "inactive"
            assert manager.mount["ControlPID"] == "0"
            assert all(value["Job"] == "" and value["ActiveState"] == "inactive"
                       for value in manager.services.values())
            closes.append(argv)
            mapper["open"] = False
        else:
            pytest.fail("unexpected direct operation: " + str(argv))
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(watch.subprocess, "run", crypto)
    monkeypatch.setattr(watch, "is_mapper_open", lambda: mapper["open"])
    monkeypatch.setattr(watch, "resolve_device", lambda *a, **kw: Path("/dev/fixture-only"))
    result = watch.unlock_vault("fixture-passphrase", "/dev/fixture-only")
    assert result["success"] is False
    assert bool(closes) is not cancel_failure
    assert mapper["open"] is cancel_failure
    assert ("cancel", "42") in manager.actions
    assert all(call.args[0] != "unlocked" for call in watch.write_state.call_args_list)


def test_private_verifier_cannot_claim_already_unlocked_after_pid1_transition(watchdog, manager, monkeypatch):
    manager.mount.update(ActiveState="active", SubState="mounted")

    def verified_private_view():
        manager.mount["Job"] = "43"
        return True

    monkeypatch.setattr(watchdog, "exact_vault_mount_verified", verified_private_view)
    relock = Mock(return_value=False)
    monkeypatch.setattr(watchdog, "_lock_vault_held", relock)
    assert watchdog.unlock_vault("fixture-passphrase")["success"] is False
    assert relock.call_count == 1


def test_surviving_consumer_prevents_host_unmount_or_mapper_close(watchdog, manager, monkeypatch):
    manager.mount.update(ActiveState="active", SubState="mounted")
    path = module.CGROUP_PARENT / module.CONSUMERS[0] / "cgroup.events"
    path.write_text("populated 1\nfrozen 0\n")
    monkeypatch.setattr(watchdog, "is_mapper_open", lambda: True)
    crypto = Mock(side_effect=AssertionError("must not close mapper or sync before drain"))
    monkeypatch.setattr(watchdog.subprocess, "run", crypto)
    assert watchdog.lock_vault("fixture") is False
    assert not any(call[:3] == ("stop", "--no-block", module.UNIT) for call in manager.actions)
    crypto.assert_not_called()


def test_changed_watchdog_retains_hardening_without_vault_rw_bind():
    unit = SOURCE.parents[2] / "lib/systemd/system/secure-ai-vault-watchdog.service"
    text = unit.read_text()
    for required in ("ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
                     "RestrictNamespaces=yes", "ReadWritePaths=/var/lib/secure-ai/logs"):
        assert required in text
    assert not any("/var/lib/secure-ai/vault" in line for line in text.splitlines()
                   if line.startswith("ReadWritePaths="))
