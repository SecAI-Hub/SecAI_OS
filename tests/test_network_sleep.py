"""Managed sleep closure and grant admission, with actual private-file fault tests."""

import fcntl
import importlib.util
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "sleep_network", ROOT / "files/system/usr/libexec/secure-ai/network-profile.py"
)
network = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(network)
READY = {
    "LoadState": "loaded",
    "ActiveState": "inactive",
    "SubState": "dead",
    "Job": "",
    "Result": "success",
    "UnitFileState": "enabled",
}


@pytest.fixture
def controller(tmp_path, monkeypatch):
    item = object.__new__(network.Controller)
    item.state = tmp_path / "private" / "policy.json"
    item.state.parent.mkdir(mode=0o700)
    item.boot_id = "12345678-1234-1234-1234-123456789abc"
    write = network.atomic_json
    read = network.read_safe_record
    owner = os.getuid()
    monkeypatch.setattr(
        network,
        "atomic_json",
        lambda path, value, mode: write(path, value, mode, owner=owner),
    )
    monkeypatch.setattr(
        network,
        "read_safe_record",
        lambda path, **kwargs: read(path, **(kwargs | {"owner": owner})),
    )
    events = []
    value = {"status": "verified", "effective_scope": "offline", "host_offline": True}
    monkeypatch.setattr(item, "close", lambda: events.append("close") or value)
    monkeypatch.setattr(item, "publish", lambda _value: events.append("publish"))
    return item, events


def systemd_reply(monkeypatch, state=None, *, code=0, output=None):
    text = (
        output
        if output is not None
        else "\n".join(
            key + "=" + value
            for key, value in (READY if state is None else state).items()
        )
        + "\n"
    )
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=code, stdout=text)

    monkeypatch.setattr(network.subprocess, "run", run)
    return calls


def test_first_boot_and_repeated_verified_release(controller, monkeypatch):
    item, events = controller
    calls = systemd_reply(monkeypatch)
    item.require_awake_grant()
    for _ in range(3):
        item.sleep_close()
        assert item.sleep_marker.stat().st_mode & 0o777 == 0o600
        with pytest.raises(network.SleepInhibited):
            item.require_awake_grant()
        item.sleep_release()
        assert not item.sleep_marker.exists()
        item.require_awake_grant()
    assert events == ["close", "close", "publish"] * 3
    assert len(calls) == 4


@pytest.mark.parametrize(
    "content", [b"", b"{", b"[]", b"null", b'{"version":true}', b'{"inhibited":1}']
)
def test_malformed_marker_denies_before_query_or_mutation(
    controller, monkeypatch, content
):
    item, events = controller
    item.sleep_marker.write_bytes(content)
    item.sleep_marker.chmod(0o600)
    calls = systemd_reply(monkeypatch)
    with pytest.raises(network.SleepInhibited):
        item.require_awake_grant()
    with pytest.raises((network.NetworkError, ValueError)):
        item.sleep_release()
    assert item.sleep_marker.read_bytes() == content
    assert not calls and not events


def test_marker_strict_types_and_wrong_boot_are_rejected(controller):
    item, _ = controller
    base = {"version": 1, "boot_id": item.boot_id, "inhibited": True}
    for value in [
        base | {"version": True},
        base | {"inhibited": 1},
        base | {"boot_id": "old"},
        base | {"extra": 1},
    ]:
        network.atomic_json(item.sleep_marker, value, 0o600)
        with pytest.raises(network.NetworkError):
            item.read_sleep_marker()


def test_symlink_marker_denies_and_is_not_replaced(controller, monkeypatch):
    item, events = controller
    item.sleep_marker.symlink_to(item.state.parent / "missing")
    systemd_reply(monkeypatch)
    with pytest.raises(network.SleepInhibited):
        item.require_awake_grant()
    with pytest.raises(OSError):
        item.sleep_close()
    assert item.sleep_marker.is_symlink() and not events


@pytest.mark.parametrize(
    ("key", "bad"),
    [
        ("LoadState", "not-found"),
        ("ActiveState", "activating"),
        ("ActiveState", "active"),
        ("ActiveState", "deactivating"),
        ("ActiveState", "failed"),
        ("SubState", "exited"),
        ("Job", "24 /job/24"),
        ("Result", "exit-code"),
        ("UnitFileState", "disabled"),
    ],
)
def test_removed_marker_during_lifecycle_or_failure_does_not_permit_grant(
    controller, monkeypatch, key, bad
):
    item, events = controller
    item.sleep_close()
    item.sleep_marker.unlink()  # Simulated privileged deletion, only one authority removed.
    systemd_reply(monkeypatch, READY | {key: bad})
    with pytest.raises(network.SleepInhibited):
        item.require_awake_grant()
    assert events == ["close"]


@pytest.mark.parametrize(
    "output", ["", "\n", "LoadState=loaded\n", "x\n" * 6, "Job=\n" * 6, "x" * 5000]
)
def test_unknown_systemd_reply_is_unavailable(controller, monkeypatch, output):
    item, events = controller
    systemd_reply(monkeypatch, output=output)
    with pytest.raises(network.SleepInhibited):
        item.require_awake_grant()
    assert not events


def test_systemd_command_failure_is_unavailable(controller, monkeypatch):
    item, _ = controller
    systemd_reply(monkeypatch, code=1)
    with pytest.raises(network.SleepInhibited):
        item.require_awake_grant()
    monkeypatch.setattr(
        network.subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(OSError("missing bus")),
    )
    with pytest.raises(network.SleepInhibited):
        item.require_awake_grant()


def test_creation_failure_never_claims_sleep_ready(controller, monkeypatch):
    item, events = controller
    monkeypatch.setattr(
        network, "atomic_json", lambda *args: (_ for _ in ()).throw(OSError("creation"))
    )
    with pytest.raises(OSError):
        item.sleep_close()
    assert not events


def test_close_failure_retains_inhibition(controller, monkeypatch):
    item, _ = controller
    monkeypatch.setattr(
        item, "close", lambda: (_ for _ in ()).throw(network.NetworkError("nft"))
    )
    with pytest.raises(network.NetworkError):
        item.sleep_close()
    item.read_sleep_marker()


def test_publication_failure_cannot_release_marker(controller, monkeypatch):
    item, events = controller
    item.sleep_close()
    monkeypatch.setattr(
        item, "publish", lambda value: (_ for _ in ()).throw(OSError("publish"))
    )
    with pytest.raises(OSError):
        item.sleep_release()
    item.read_sleep_marker()
    assert events == ["close", "close"]


def test_unlink_failure_keeps_marker_after_verified_offline(controller, monkeypatch):
    item, events = controller
    item.sleep_close()
    unlink = Path.unlink

    def fail(path, *args, **kwargs):
        if path == item.sleep_marker:
            raise OSError("unlink")
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail)
    with pytest.raises(OSError):
        item.sleep_release()
    item.read_sleep_marker()
    assert events == ["close", "close", "publish"]


def test_cli_lock_contention_prevents_both_grant_and_sleep_mutation(
    tmp_path, monkeypatch
):
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    item = SimpleNamespace(state=parent / "policy.json")
    original = Path.stat

    def root_stat(path, *args, **kwargs):
        return (
            SimpleNamespace(st_uid=0, st_mode=0o40700)
            if path == parent
            else original(path, *args, **kwargs)
        )

    monkeypatch.setattr(Path, "stat", root_stat)
    monkeypatch.setattr(network.os, "geteuid", lambda: 0)
    monkeypatch.setattr(network, "Controller", lambda: item)
    with (parent / "control.lock").open("w") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for command in ["grant", "sleep-close", "sleep-release"]:
            monkeypatch.setattr(sys, "argv", ["network-profile.py", command])
            assert network.main() == 1
    assert list(parent.iterdir()) == [parent / "control.lock"]


def test_required_unit_is_enabled_and_preserves_controller_sandbox():
    path = ROOT / "files/system/usr/lib/systemd/system/secure-ai-network-sleep.service"
    text = path.read_text()
    for field in [
        "Before=sleep.target",
        "RequiredBy=sleep.target",
        "RemainAfterExit=yes",
        "StopWhenUnneeded=yes",
        "RefuseManualStop=yes",
        "CapabilityBoundingSet=CAP_NET_ADMIN",
        "NoNewPrivileges=yes",
        "RestrictAddressFamilies=AF_UNIX AF_NETLINK",
        "IPAddressDeny=any",
        "ExecStart=/usr/libexec/secure-ai/network-profile.py sleep-close",
        "ExecStopPost=/usr/libexec/secure-ai/network-profile.py sleep-release",
    ]:
        assert field in text
    assert "ExecCondition=" not in text and "ExecStart=-" not in text
    recipe = yaml.safe_load((ROOT / "recipes/recipe.yml").read_text())
    system = next(
        module["system"] for module in recipe["modules"] if module["type"] == "systemd"
    )
    assert "secure-ai-network-sleep.service" in system["enabled"]
