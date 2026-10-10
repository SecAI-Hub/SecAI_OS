"""Native network contract and isolated packet evidence; no host mutations."""

import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "files/system/usr/libexec/secure-ai"
UNITS = ROOT / "files/system/usr/lib/systemd/system"
SPEC = importlib.util.spec_from_file_location(
    "network_profile", SCRIPTS / "network-profile.py"
)
network = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(network)


def test_offline_source_preserves_other_tables_and_has_no_implicit_acceptance():
    source = (ROOT / "files/system/etc/nftables/secure-ai.nft").read_text()
    assert "flush ruleset" not in source
    assert "flush ruleset" not in (ROOT / "files/system/etc/nftables.conf").read_text()
    assert 'egress devices = { "*" }' in source
    assert "elements =" not in source
    output = source.split("chain output {", 1)[1]
    assert "ct state established" not in output
    assert "policy drop" in output
    assert "meta skgid $TOR_GID" in source
    assert "meta skuid $AIRLOCK_UID" in source


def test_boot_and_network_managers_require_closed_guard():
    boot = (UNITS / "secure-ai-network-boot.service").read_text()
    assert (
        "Before=network-pre.target NetworkManager.service systemd-networkd.service"
        in boot
    )
    assert "After=local-fs.target systemd-sysusers.service" in boot
    assert "network-profile.py boot" in boot
    assert "Before=sysinit.target" in boot
    for manager in ("NetworkManager.service", "systemd-networkd.service"):
        binding = (UNITS / (manager + ".d") / "10-secure-ai-network.conf").read_text()
        assert "Requires=secure-ai-network-boot.service" in binding
        assert "After=secure-ai-network-boot.service" in binding
    tor = (UNITS / "secure-ai-tor.service").read_text()
    assert "network-online.target" not in tor
    assert "Requires=secure-ai-network-boot.service" in tor


def test_external_timers_disabled_and_guards_do_not_request_network_startup():
    recipe = yaml.safe_load((ROOT / "recipes/recipe.yml").read_text())
    system = next(
        module["system"] for module in recipe["modules"] if module["type"] == "systemd"
    )
    for timer in ("secure-ai-dns-leak-check.timer", "secure-ai-update-check.timer"):
        assert timer not in system["enabled"]
        assert timer in system["disabled"]
        unit = (UNITS / timer.replace(".timer", ".service")).read_text()
        assert (
            "ExecCondition=/usr/libexec/secure-ai/network-profile.py require-maintenance"
            in unit
        )
        assert "Wants=network-online.target" not in unit
    assert "secure-ai-network-boot.service" in system["enabled"]
    assert "secure-ai-network-status.timer" in system["enabled"]


def test_profile_transaction_closes_before_validation_and_never_resumes_saved_lease():
    source = (SCRIPTS / "apply-profile.sh").read_text()
    assert source.index('"$NETWORK_HELPER" close >/dev/null || fatal') < source.index(
        "local current_file="
    )
    assert 'requested="$previous"' not in source
    assert 'requested="offline_private"' in source
    assert source.index("write_audit profile_changed") < source.index(
        '"$NETWORK_HELPER" grant'
    )
    assert "network-profile.py" in source
    assert "install -d -m 3770 -o root -g secure-ai-logs" in source


@pytest.fixture
def grant_fixture(tmp_path, monkeypatch):
    controller = object.__new__(network.Controller)
    controller.state = tmp_path / "state.json"
    controller.resolvers = tmp_path / "resolv.conf"
    controller.resolvers.write_text("nameserver 198.18.0.2\n")
    controller.boot_id = "a" * 36
    monkeypatch.setattr(
        network,
        "read_safe",
        lambda *_args, **_kwargs: json.dumps(
            {"identities": {"tor_gid": 100, "airlock_uid": 101}}
        ).encode(),
    )
    events = []
    monkeypatch.setattr(controller, "observe", lambda: {"effective_scope": "offline"})
    monkeypatch.setattr(controller, "verify_resolver", lambda: None)
    monkeypatch.setattr(
        controller, "publish", lambda value: events.append(("publish", value["status"]))
    )
    monkeypatch.setattr(
        controller,
        "execute",
        lambda *_args, **kwargs: events.append(("nft", kwargs["source"])),
    )
    return controller, events


@pytest.mark.parametrize(
    ("scope", "seconds"),
    [
        ("offline", 300),
        ("research", 0),
        ("research", 3601),
        ("maintenance", 901),
        ("maintenance", True),
        ("invalid", 10),
    ],
)
def test_invalid_grant_has_no_firewall_or_status_side_effect(
    grant_fixture, scope, seconds
):
    controller, events = grant_fixture
    with pytest.raises(network.NetworkError):
        controller.grant(scope, seconds)
    assert not events


def test_grant_invalidates_old_offline_assertion_before_atomic_kernel_lease(
    grant_fixture,
):
    controller, events = grant_fixture
    controller.grant("research", 300)
    assert events[0] == ("publish", "unknown")
    assert events[1][0] == "nft"
    assert "timeout 300s" in events[1][1]
    assert "maintenance" not in events[1][1]


def test_status_invalidation_failure_never_opens_network(grant_fixture, monkeypatch):
    controller, events = grant_fixture

    def fail(_value):
        raise OSError("synthetic fsync failure")

    monkeypatch.setattr(controller, "publish", fail)
    with pytest.raises(OSError):
        controller.grant("maintenance", 300)
    assert not events


def test_existing_lease_cannot_be_silently_renewed(grant_fixture, monkeypatch):
    controller, events = grant_fixture
    monkeypatch.setattr(controller, "observe", lambda: {"effective_scope": "research"})
    with pytest.raises(network.NetworkError, match="close networking"):
        controller.grant("research", 300)
    assert not events


def test_unverified_resolver_binding_is_explicitly_unavailable(
    grant_fixture, monkeypatch
):
    controller, events = grant_fixture

    def fail():
        raise network.NetworkError("resolver binding unavailable")

    monkeypatch.setattr(controller, "verify_resolver", fail)
    with pytest.raises(network.NetworkError, match="resolver binding"):
        controller.grant("full_lab", 300)
    assert not events


def maintenance_record():
    now = time.time()
    return {
        "schema_version": 1,
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "checked_monotonic": time.monotonic(),
        "valid_for_seconds": 30,
        "checked_at": network.timestamp(now),
        "valid_until": network.timestamp(now + 30),
        "lease_expires_at": network.timestamp(now + 300),
        "status": "verified",
        "effective_scope": "maintenance",
        "host_offline": False,
        "ipv4_enforced": True,
        "ipv6_enforced": True,
        "arp_enforced": True,
        "allowed_egress": network.ALLOWED["maintenance"],
        "automatic_network_tasks": False,
        "evidence_source": "nftables_runtime",
    }


def test_complete_fresh_maintenance_record_is_accepted(monkeypatch):
    data = maintenance_record()
    monkeypatch.setattr(network, "read_safe", lambda *_args: json.dumps(data).encode())
    assert network.require_maintenance() == data


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("checked_monotonic", True),
        ("schema_version", True),
        ("host_offline", True),
        ("ipv4_enforced", False),
        ("ipv6_enforced", None),
        ("arp_enforced", "true"),
        ("allowed_egress", []),
        ("automatic_network_tasks", True),
        ("evidence_source", "configuration"),
        ("checked_at", "2099-01-01T00:00:00+00:00"),
        ("valid_until", "2000-01-01T00:00:00+00:00"),
        ("lease_expires_at", "2099-01-01T00:00:00+00:00"),
        ("valid_until", "2000-01-01T00:00:00"),
    ],
)
def test_maintenance_guard_rejects_false_assurance_and_wall_clock_inconsistency(
    monkeypatch, field, value
):
    data = maintenance_record()
    data[field] = value
    monkeypatch.setattr(network, "read_safe", lambda *_args: json.dumps(data).encode())
    with pytest.raises(network.NetworkError):
        network.require_maintenance()


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "offline",
        "unknown",
        "old_boot",
        "expired",
        "future",
        "nan",
        "unbounded",
    ],
)
def test_maintenance_guard_rejects_unknown_stale_or_inconsistent_state(
    monkeypatch, change
):
    data = maintenance_record()
    if change == "missing":
        data.pop("status")
    elif change == "offline":
        data["effective_scope"] = "offline"
    elif change == "unknown":
        data["status"] = "unknown"
    elif change == "old_boot":
        data["boot_id"] = "old"
    elif change == "expired":
        data["checked_monotonic"] -= 31
    elif change == "future":
        data["checked_monotonic"] += 10
    elif change == "nan":
        data["checked_monotonic"] = float("nan")
    elif change == "unbounded":
        data["valid_for_seconds"] = 31
    monkeypatch.setattr(network, "read_safe", lambda *_args: json.dumps(data).encode())
    with pytest.raises((network.NetworkError, KeyError)):
        network.require_maintenance()


def test_diagnostic_guard_precedes_every_external_probe():
    source = (SCRIPTS / "check-dns-leak.sh").read_text()
    assert source.index("require-maintenance") < source.index("dig +short")
    assert "curl " not in source
    assert "nft list ruleset" not in source
    assert 'dns_leak_detected":None' in source


def test_isolated_native_packet_qualification():
    nft = os.environ.get("SECAI_NFT_TEST_BINARY")
    if not nft:
        pytest.skip(
            "Explicit nftables >=1.1.6 private qualification runtime not selected"
        )
    completed = subprocess.run(
        [
            "unshare",
            "--user",
            "--map-root-user",
            "--net",
            sys.executable,
            str(ROOT / "tests/fixtures/network_profile_namespace.py"),
            str(ROOT),
            nft,
        ],
        capture_output=True,
        env={
            **os.environ,
            "SECAI_NAMESPACE_PARENT_IDS": json.dumps(
                {
                    name: os.readlink("/proc/self/ns/" + name)
                    for name in ("user", "net", "mnt")
                }
            ),
        },
        text=True,
        timeout=45,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["namespace_isolated"] is True
    assert result["passed"] >= 13


@pytest.mark.parametrize(
    "change",
    [
        "symlink",
        "hardlink",
        "writable",
        "oversize",
        "replacement",
        "truncated",
        "deleted",
        "closed",
    ],
)
def test_safe_file_reads_reject_unsafe_or_changed_evidence(
    tmp_path, monkeypatch, change
):
    target = tmp_path / "evidence"
    target.write_bytes(b"bounded evidence")
    target.chmod(0o600)
    if change == "symlink":
        original = tmp_path / "original"
        target.rename(original)
        target.symlink_to(original)
    elif change == "hardlink":
        os.link(target, tmp_path / "second")
    elif change == "writable":
        target.chmod(0o666)
    elif change == "oversize":
        target.write_bytes(b"x" * 33)
    else:
        original_read = network.os.read

        def raced(fd, size):
            if change == "closed":
                os.close(fd)
                return original_read(fd, size)
            data = original_read(fd, size)
            if change == "replacement":
                replacement = tmp_path / "new"
                replacement.write_bytes(data)
                replacement.chmod(0o600)
                replacement.replace(target)
            elif change == "truncated":
                target.write_bytes(b"")
            elif change == "deleted":
                target.unlink()
            return data

        monkeypatch.setattr(network.os, "read", raced)
    with pytest.raises((OSError, network.NetworkError)):
        network.read_safe(target, owner=os.geteuid(), limit=32)


def test_failed_atomic_state_replace_preserves_previous_record_and_removes_temp(
    tmp_path, monkeypatch
):
    target = tmp_path / "state.json"
    target.write_text('{"old":true}\n')
    target.chmod(0o600)

    def fail(*_args):
        raise OSError("synthetic rename failure")

    monkeypatch.setattr(network.os, "replace", fail)
    with pytest.raises(OSError):
        network.atomic_json(target, {"new": True}, 0o600, owner=os.geteuid())
    assert json.loads(target.read_text()) == {"old": True}
    assert sorted(path.name for path in tmp_path.iterdir()) == ["state.json"]


def test_successful_atomic_state_survives_reopen_with_exact_mode(tmp_path):
    target = tmp_path / "state.json"
    network.atomic_json(target, {"version": 1}, 0o600, owner=os.geteuid())
    assert json.loads(network.read_safe(target, private=True, owner=os.geteuid())) == {
        "version": 1
    }
    assert target.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("command", ["grant", "observe"])
def test_failed_command_closes_or_revokes_without_reenrolling_observer(
    tmp_path, monkeypatch, command
):
    from types import SimpleNamespace

    events = []
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)

    class Controller:
        state = parent / "state.json"

        def require_awake_grant(self):
            pass

        def grant(self, *_args):
            raise network.NetworkError("synthetic grant fault")

        def observe(self):
            raise network.NetworkError("missing reference")

        def close(self):
            events.append("close")

        def revoke(self):
            events.append("revoke")

        def unknown(self):
            return {"status": "unknown"}

        def publish(self, value):
            events.append(value["status"])

    original_stat = Path.stat

    def file_stat(path, *args, **kwargs):
        if path == parent:
            return SimpleNamespace(st_uid=0, st_mode=0o40700)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", file_stat)
    monkeypatch.setattr(network.os, "geteuid", lambda: 0)
    monkeypatch.setattr(network, "Controller", Controller)
    monkeypatch.setattr(
        sys, "argv", ["network-profile.py", command, "--scope", "research"]
    )
    assert network.main() == 1
    assert events == (
        ["close", "unknown"] if command == "grant" else ["revoke", "unknown"]
    )
    assert not (parent / "state.json").exists()


def test_airlock_and_profile_bind_only_boot_identity_through_restricted_proc():
    for name in ("secure-ai-airlock.service", "secure-ai-apply-profile.service"):
        unit = (UNITS / name).read_text()
        assert "ProcSubset=pid" in unit
        assert "BindReadOnlyPaths=/proc/sys/kernel/random/boot_id:" in unit
        assert "Environment=SECAI_NETWORK_BOOT_ID_PATH=" in unit
    airlock = (UNITS / "secure-ai-airlock.service").read_text()
    assert (
        "BindReadOnlyPaths=-/run/secure-ai-network/airlock-resolv.conf:/etc/resolv.conf"
        in airlock
    )
    assert (
        "ExecStartPre=/usr/libexec/secure-ai/network-profile.py attest-resolver"
        in airlock
    )
    assert "CapabilityBoundingSet=\n" in airlock


@pytest.mark.parametrize(
    "fixture", ["network_profile_namespace.py", "network_resolver_namespace.py"]
)
@pytest.mark.parametrize("reference", ["same_namespace", "missing", "empty"])
def test_namespace_fixture_refuses_missing_or_current_caller_identity(
    monkeypatch, fixture, reference
):
    spec = importlib.util.spec_from_file_location(
        "namespace_guard_fixture", ROOT / "tests/fixtures" / fixture
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if reference == "missing":
        monkeypatch.delenv("SECAI_NAMESPACE_PARENT_IDS", raising=False)
    else:
        identities = {
            name: os.readlink("/proc/self/ns/" + name)
            if reference == "same_namespace"
            else ""
            for name in ("user", "net", "mnt")
        }
        monkeypatch.setenv("SECAI_NAMESPACE_PARENT_IDS", json.dumps(identities))
    with pytest.raises((AssertionError, KeyError)):
        module.isolated()
