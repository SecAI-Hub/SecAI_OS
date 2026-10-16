"""Fixed prehook/clock tests: PID1 and proc-mount records are synthetic.

Private regular files model kernel bytes; no mounts, units or root operations.
Expected root file IDs/root check are substituted in ordinary-user fixtures.
"""

import configparser
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

SOURCE = (
    Path(__file__).parents[1]
    / "files/system/usr/libexec/secure-ai/secure-data-namespace.py"
)
SPEC = importlib.util.spec_from_file_location("data_namespace_test", SOURCE)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
BOOT = "c402a509-2239-4662-8228-886f96eb90b7"
OTHER = "8682bd4a-53c2-46b5-b0a1-b10bc23e4643"


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    rows = {}
    calls = []
    role = "agent"
    group = tmp_path / "cgroup"
    alternate, original = tmp_path / "bound-boot", tmp_path / "original-boot"
    mountinfo = tmp_path / "mountinfo"
    alternate.write_text(BOOT + "\n")
    alternate.chmod(0o444)
    original.write_text(BOOT + "\n")
    original.chmod(0o444)
    monkeypatch.setenv("INVOCATION_ID", "a" * 32)
    monkeypatch.setattr(module.native, "root_only", lambda: None)
    monkeypatch.setattr(module, "_OWNER_UID", os.geteuid())
    monkeypatch.setattr(module, "_OWNER_GID", os.getegid())
    monkeypatch.setattr(module, "_SELF_CGROUP", group)
    monkeypatch.setattr(module, "_ALT_BOOT", alternate)
    monkeypatch.setattr(module, "_ORIGINAL_BOOT", original)
    monkeypatch.setattr(module, "_MOUNTINFO", mountinfo)
    real_mount = module.guard.mount_id
    identities = {
        (p.stat().st_dev, p.stat().st_ino): identifier
        for p, identifier in ((alternate, 100), (original, 101))
    }
    monkeypatch.setattr(
        module.guard,
        "mount_id",
        lambda fd: identities.get(
            (os.fstat(fd).st_dev, os.fstat(fd).st_ino), real_mount(fd)
        ),
    )

    def mounts():
        device = alternate.stat().st_dev
        major_minor = f"{os.major(device)}:{os.minor(device)}"
        mountinfo.write_text(
            "".join(
                f"{identifier} 1 {major_minor} /sys/kernel/random/boot_id {path} ro,nosuid,nodev,noexec - proc proc rw\n"
                for path, identifier in ((alternate, 100), (original, 101))
            )
        )

    def select(selected):
        nonlocal role
        role = selected
        unit = module._UNITS[role]
        rows.clear()
        rows.update(module._COMMON)
        rows.update(module._ROLES[role])
        rows.update(
            Id=unit,
            ControlPID=str(os.getpid()),
            ControlGroup="/system.slice/" + unit,
            InvocationID="a" * 32,
            FragmentPath=module._FRAGMENTS[role],
            PrivateTmp="yes",
        )
        group.write_text("0::/system.slice/" + unit + "\n")

    def manager(*args):
        calls.append(args)
        assert args[0] == "show"  # Read-only PID1 query, never a mutation.
        return "\n".join(key + "=" + value for key, value in rows.items())

    monkeypatch.setattr(module.native, "manager", manager)
    select(role)
    mounts()
    return SimpleNamespace(
        rows=rows,
        calls=calls,
        group=group,
        alternate=alternate,
        original=original,
        mountinfo=mountinfo,
        select=select,
        mounts=mounts,
        real_mount=real_mount,
    )


def metadata(mount):
    return {
        "device": 4,
        "inode": 5,
        "mount": mount,
        "mode": 0o700,
        "uid": module._OWNER_UID,
        "gid": module._OWNER_GID,
    }


@pytest.mark.parametrize("role", tuple(module._ROLES))
def test_actual_fixed_role_policy_and_valid_namespace_callback(fixture, role):
    fixture.select(role)
    capability = module.prehook_namespace(role)
    assert capability.trusted_root_rebind(metadata(1), metadata(2)) is True
    assert capability.clock.boot_id() == BOOT
    assert capability.clock.domain == module.guard.DOMAIN
    assert capability.clock.now_ns() > 0
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    parser.read(SOURCE.parents[2] / "lib/systemd/system" / module._UNITS[role])
    defaults = {
        "DynamicUser": "no",
        "ProcSubset": "all",
        "ProtectProc": "default",
        "ProtectSystem": "no",
        "NoNewPrivileges": "no",
    }
    for key, expected in module._ROLES[role].items():
        actual = parser["Service"].get(key, defaults.get(key, ""))
        assert actual.lower() == expected
    for key in ("KillMode", "Delegate", "ProtectControlGroups"):
        assert parser["Service"][key] == module._COMMON[key]


@pytest.mark.parametrize(
    "role", ["", "other", "agent.service", "secure-ai-agent.service", None, ["agent"]]
)
def test_no_arbitrary_role_unit_or_path_authority(fixture, role):
    with pytest.raises(module.Error):
        module.prehook_namespace(role)
    assert not fixture.calls


def test_nonroot_denied_before_pid1_query(fixture, monkeypatch):
    def real_root():
        if os.getuid() != 0 or os.geteuid() != 0:
            raise module.Error("root authority required")

    monkeypatch.setattr(module.native, "root_only", real_root)
    monkeypatch.setattr(module.os, "getuid", lambda: 12345)
    with pytest.raises(module.Error):
        module.prehook_namespace("agent")
    assert not fixture.calls


@pytest.mark.parametrize(
    "key,value",
    [
        ("Id", "alias.service"),
        ("ControlPID", "0"),
        ("ControlGroup", "/system.slice/other.service"),
        ("InvocationID", "b" * 32),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("LoadState", "masked"),
        ("MainPID", "1"),
        ("FragmentPath", "/etc/systemd/system/secure-ai-agent.service"),
        ("KillMode", "process"),
        ("Delegate", "yes"),
        ("ProtectControlGroups", "no"),
        ("DynamicUser", "no"),
        ("CapabilityBoundingSet", "cap_sys_admin"),
        ("NoNewPrivileges", "no"),
        ("ProcSubset", "all"),
        ("ProtectSystem", "no"),
        ("PrivateTmp", "no"),
    ],
)
def test_incorrect_caller_or_containment_denied(fixture, key, value):
    fixture.rows[key] = value
    with pytest.raises(module.Error):
        module.prehook_namespace("agent")


def test_kernel_cgroup_and_environment_are_independent(fixture, monkeypatch):
    fixture.group.write_text("0::/system.slice/secure-ai-agent.service/child\n")
    with pytest.raises(module.Error):
        module.prehook_namespace("agent")
    fixture.select("agent")
    monkeypatch.delenv("INVOCATION_ID")
    with pytest.raises(module.Error):
        module.prehook_namespace("agent")


def test_binding_failure_cannot_be_revived_by_restored_pid1_response(fixture):
    capability = module.prehook_namespace("agent")
    fixture.rows["ControlPID"] = "0"
    with pytest.raises(module.Error):
        capability.check()
    fixture.rows["ControlPID"] = str(os.getpid())
    with pytest.raises(module.Error):
        capability.trusted_root_rebind(metadata(1), metadata(2))
    with pytest.raises(module.Error):
        capability.clock.boot_id()


@pytest.mark.parametrize(
    "key,value",
    [
        ("device", 8),
        ("inode", 9),
        ("mode", 0o755),
        ("uid", 99999),
        ("gid", 99999),
        ("mount", True),
    ],
)
def test_only_namespace_mount_id_difference_is_approved(fixture, key, value):
    capability = module.prehook_namespace("agent")
    current = metadata(2)
    current[key] = value
    assert capability.trusted_root_rebind(metadata(1), current) is False
    with pytest.raises(module.Error):
        capability.check()


def test_identical_mount_or_unknown_identity_fields_are_not_rebinds(fixture):
    capability = module.prehook_namespace("agent")
    assert capability.trusted_root_rebind(metadata(1), metadata(1)) is False
    capability = module.prehook_namespace("agent")
    assert (
        capability.trusted_root_rebind(metadata(1), metadata(2) | {"extra": 0}) is False
    )


@pytest.mark.parametrize(
    "change",
    [
        "writable",
        "host-placeholder",
        "fake-filesystem",
        "wrong-proc-file",
        "wrong-point",
        "writable-mount",
        "duplicate-id",
        "wrong-device",
        "malformed",
    ],
)
def test_boot_clock_requires_real_readonly_proc_binding(fixture, change):
    capability = module.prehook_namespace("agent")
    text = fixture.mountinfo.read_text()
    if change == "writable":
        fixture.alternate.chmod(0o644)
    elif change == "host-placeholder":
        fixture.alternate.chmod(0o600)
        fixture.alternate.write_bytes(b"")
        fixture.alternate.chmod(0o444)
    elif change == "fake-filesystem":
        fixture.mountinfo.write_text(text.replace(" - proc proc ", " - tmpfs tmpfs "))
    elif change == "wrong-proc-file":
        fixture.mountinfo.write_text(
            text.replace("/sys/kernel/random/boot_id", "/sys/kernel/random/uuid")
        )
    elif change == "wrong-point":
        fixture.mountinfo.write_text(text.replace(str(fixture.alternate), "/wrong"))
    elif change == "writable-mount":
        fixture.mountinfo.write_text(text.replace(" ro,", " rw,"))
    elif change == "duplicate-id":
        fixture.mountinfo.write_text(text + text.splitlines()[0] + "\n")
    elif change == "wrong-device":
        fixture.mountinfo.write_text(text.replace(text.split()[2], "255:255"))
    else:
        fixture.alternate.chmod(0o600)
        fixture.alternate.write_text("not-a-uuid\n")
        fixture.alternate.chmod(0o444)
    with pytest.raises((RuntimeError, OSError, ValueError)):
        capability.clock.boot_id()
    with pytest.raises(module.Error):
        capability.check()


def test_real_regular_host_file_is_not_a_kernel_source(fixture, monkeypatch):
    # No synthetic mount records for this rejection: the ordinary fixture file
    # really resides on the test filesystem, not a proc mount.
    monkeypatch.setattr(module, "_MOUNTINFO", Path("/proc/self/mountinfo"))
    monkeypatch.setattr(module.guard, "mount_id", fixture.real_mount)
    with pytest.raises(module.Error):
        module.prehook_namespace("agent").clock.boot_id()


def test_visible_original_agrees_or_is_hidden(fixture):
    capability = module.prehook_namespace("agent")
    fixture.original.chmod(0o600)
    fixture.original.write_text(OTHER + "\n")
    fixture.original.chmod(0o444)
    with pytest.raises(module.Error, match="disagree"):
        capability.clock.boot_id()
    fixture.original.unlink()
    capability = module.prehook_namespace("agent")
    assert capability.clock.boot_id() == BOOT


@pytest.mark.parametrize("bad", ["closed", "stale-boot", "history"])
def test_namespace_permission_never_bypasses_gate_admission(fixture, tmp_path, bad):
    root, runtime = tmp_path / "authority", tmp_path / "runtime"
    root.mkdir(mode=0o700)
    runtime.mkdir(mode=0o700)

    class Clock(module.guard.LinuxClock):
        def boot_id(self):
            return BOOT

    module.guard.Gate.initialize(root, runtime, clock=Clock())
    if bad == "closed":
        gate = module.guard.Gate(root, runtime, clock=Clock())
        try:
            gate.close_for("3d0e03a4-c0a1-4696-9c8c-e38a1f7d6dfb")
        finally:
            gate.close()
    elif bad == "stale-boot":
        ready = json.loads((runtime / "ready.json").read_text())
        ready["boot"] = OTHER
        (runtime / "ready.json").write_text(json.dumps(ready))
    else:
        (root / "transactions/unknown").mkdir(mode=0o700)
    layout = json.loads((root / "layout.json").read_text())
    layout["root"]["mount"] += 100000
    (root / "layout.json").write_text(json.dumps(layout))
    before = {
        path: path.read_bytes()
        for path in (root / "layout.json", root / "gate.json", runtime / "ready.json")
    }
    with pytest.raises(module.Error):
        module.guard.Gate(root, runtime, clock=Clock())
    capability = module.prehook_namespace("agent")
    gate = module.guard.Gate(
        root,
        runtime,
        clock=capability.clock,
        trusted_root_rebind=capability.trusted_root_rebind,
    )
    try:
        with pytest.raises(module.Error):
            gate.lease()
    finally:
        gate.close()
    assert all(path.read_bytes() == data for path, data in before.items())


def test_visible_original_on_rw_proc_mount_keeps_exact_kernel_mapping(
    fixture, monkeypatch
):
    # Actual original pathname/bytes and proc inode; mount records and the
    # private alternate file's root ownership are explicit fixture substitutions.
    original = Path("/proc/sys/kernel/random/boot_id")
    kernel = original.read_text().strip()
    fixture.alternate.chmod(0o600)
    fixture.alternate.write_text(kernel + "\n")
    fixture.alternate.chmod(0o444)
    monkeypatch.setattr(module, "_ORIGINAL_BOOT", original)
    monkeypatch.setattr(module, "_OWNER_UID", 0)
    monkeypatch.setattr(module, "_OWNER_GID", 0)
    real_fstat = os.fstat
    alternate_id = (fixture.alternate.stat().st_dev, fixture.alternate.stat().st_ino)
    original_id = (original.stat().st_dev, original.stat().st_ino)

    def owner_fixture(fd):
        value = real_fstat(fd)
        if (value.st_dev, value.st_ino) == alternate_id:
            fields = list(value)
            fields[4] = fields[5] = 0
            return os.stat_result(fields)
        return value

    monkeypatch.setattr(module.os, "fstat", owner_fixture)
    monkeypatch.setattr(
        module.guard,
        "mount_id",
        lambda fd: (
            101
            if (real_fstat(fd).st_dev, real_fstat(fd).st_ino) == original_id
            else 100
        ),
    )
    a_dev = f"{os.major(alternate_id[0])}:{os.minor(alternate_id[0])}"
    o_dev = f"{os.major(original_id[0])}:{os.minor(original_id[0])}"
    fixture.mountinfo.write_text(
        f"100 1 {a_dev} /sys/kernel/random/boot_id {fixture.alternate} ro - proc proc rw\n"
        f"101 1 {o_dev} / /proc rw,nosuid,nodev,noexec - proc proc rw\n"
    )
    assert module.prehook_namespace("agent").clock.boot_id() == kernel
