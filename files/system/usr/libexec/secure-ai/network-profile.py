#!/usr/bin/env python3
"""Explicit native network leases; normal observation can never open egress."""

from __future__ import annotations

import argparse
import copy
import fcntl
import grp
import hashlib
import ipaddress
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

TABLES = (("inet", "secure_ai"), ("netdev", "secure_ai_link"))
VALUES = {"inet": {"ipv4", "ipv6"}, "netdev": {"ip", "ip6", "arp"}}
SCOPES = ("offline", "research", "full_lab", "maintenance")
FRESHNESS = 30
ONLINE_SECONDS = 3600
MAINTENANCE_SECONDS = 300
BOOT_PATH = Path(
    os.environ.get("SECAI_NETWORK_BOOT_ID_PATH", "/proc/sys/kernel/random/boot_id")
)
ALLOWED = {
    "offline": [],
    "research": ["DHCP, ARP and IPv6 neighbor discovery", "Tor service TCP"],
    "full_lab": [
        "DHCP, ARP and IPv6 neighbor discovery",
        "Tor service TCP",
        "Airlock service HTTPS and direct DNS",
    ],
    "maintenance": [
        "DHCP, ARP and IPv6 neighbor discovery",
        "Tor service TCP",
        "Host HTTPS, DNS and NTP",
    ],
}


class NetworkError(RuntimeError):
    pass


class SleepInhibited(NetworkError):
    pass


def timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def read_safe_record(path: Path, *, private=False, limit=1024 * 1024, owner=0):
    if any(parent.is_symlink() for parent in path.absolute().parents):
        raise NetworkError("unsafe state path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        forbidden = 0o077 if private else 0o022
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_mode & forbidden
            or info.st_uid != owner
            or info.st_size > limit
        ):
            raise NetworkError("unsafe root-owned network state")
        data = os.read(fd, limit + 1)
        after = os.fstat(fd)
        linked = path.lstat()
        if (
            len(data) != info.st_size
            or identity(after) != identity(info)
            or identity(linked) != identity(info)
        ):
            raise NetworkError("network state changed during read")
        return data, info
    finally:
        os.close(fd)


def read_safe(path: Path, **kwargs) -> bytes:
    return read_safe_record(path, **kwargs)[0]


def atomic_json(path: Path, value: dict, mode: int, *, owner=0) -> None:
    if any(parent.is_symlink() for parent in path.absolute().parents):
        raise NetworkError("unsafe result path")
    path.parent.mkdir(
        mode=0o700 if mode == 0o600 else 0o755, parents=True, exist_ok=True
    )
    parent = path.parent.stat()
    if parent.st_uid != owner or parent.st_mode & 0o022:
        raise NetworkError("unsafe result directory")
    if path.exists() or path.is_symlink():
        read_safe(path, private=mode == 0o600, owner=owner)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            os.fchmod(handle.fileno(), mode)
            json.dump(value, handle, sort_keys=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def normalized(objects: list) -> list:
    result = copy.deepcopy(objects)
    for item in result:
        for kind, value in item.items():
            value.pop("handle", None)
            if kind == "set":
                value.pop("elem", None)
    return result


class Controller:
    def __init__(
        self,
        *,
        nft="/usr/sbin/nft",
        policy=Path("/etc/nftables/secure-ai.nft"),
        state=Path("/run/secure-ai-network/policy.json"),
        result=Path("/run/secure-ai/network-status.json"),
        boot=BOOT_PATH,
        resolvers=Path("/etc/resolv.conf"),
    ):
        self.nft, self.policy, self.state, self.result = nft, policy, state, result
        self.resolvers = resolvers
        self.resolver_file = state.parent / "airlock-resolv.conf"
        self.resolver_state = state.parent / "resolver.json"
        self.resolver_receipt = Path("/run/secure-ai-airlock-resolver/binding.json")
        self.boot_id = boot.read_text().strip()
        if not re.fullmatch("[0-9a-f-]{36}", self.boot_id):
            raise NetworkError("boot identity unavailable")

    def execute(self, *args, source=None):
        completed = subprocess.run(
            [self.nft, *args],
            input=source,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        if completed.returncode or len(completed.stdout) > 1024 * 1024:
            raise NetworkError("nftables operation unavailable")
        return completed.stdout

    def objects(self):
        objects = []
        for family, name in TABLES:
            parsed = json.loads(self.execute("-j", "list", "table", family, name))
            if not isinstance(parsed, dict) or not isinstance(
                parsed.get("nftables"), list
            ):
                raise NetworkError("invalid nftables observation")
            if any(
                not isinstance(item, dict)
                or len(item) != 1
                or not isinstance(next(iter(item.values())), dict)
                for item in parsed["nftables"]
            ):
                raise NetworkError("invalid nftables object")
            objects.extend(
                item for item in parsed["nftables"] if "metainfo" not in item
            )
        return objects

    def source(self):
        return read_safe(self.policy).decode("utf-8")

    def prepare_resolver(self):
        if self.observe()["effective_scope"] != "offline":
            raise NetworkError("close networking before preparing a resolver")
        candidates = [(Path("/run/NetworkManager/no-stub-resolv.conf"), 0)]
        try:
            candidates.append(
                (
                    Path("/run/systemd/resolve/resolv.conf"),
                    pwd.getpwnam("systemd-resolve").pw_uid,
                )
            )
        except KeyError:
            pass
        for source, owner in candidates:
            try:
                raw, original = read_safe_record(source, owner=owner, limit=65536)
            except FileNotFoundError:
                continue
            addresses = []
            for line in raw.decode("ascii").splitlines():
                fields = line.split("#", 1)[0].split()
                if fields and fields[0] == "nameserver":
                    if len(fields) != 2:
                        raise NetworkError("invalid trusted uplink resolver")
                    address = ipaddress.ip_address(fields[1])
                    if (
                        address.is_loopback
                        or address.is_unspecified
                        or address.is_multicast
                    ):
                        raise NetworkError("uplink resolver does not permit direct DNS")
                    if str(address) not in addresses:
                        addresses.append(str(address))
            if not 1 <= len(addresses) <= 3:
                raise NetworkError("trusted uplink DNS configuration unavailable")
            content = (
                "# SecAI airlock-only trusted uplink DNS\n"
                + "".join(f"nameserver {value}\n" for value in addresses)
                + "options timeout:2 attempts:1\n"
            ).encode()
            self.resolver_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(
                prefix=".resolver.", dir=self.resolver_file.parent
            )
            try:
                with os.fdopen(fd, "wb") as handle:
                    os.fchmod(handle.fileno(), 0o644)
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.resolver_file)
            finally:
                if os.path.lexists(temporary):
                    os.unlink(temporary)
            info = self.resolver_file.stat()
            atomic_json(
                self.resolver_state,
                {
                    "boot_id": self.boot_id,
                    "source": str(source),
                    "source_owner": owner,
                    "source_dev": original.st_dev,
                    "source_ino": original.st_ino,
                    "source_sha256": hashlib.sha256(raw).hexdigest(),
                    "dev": info.st_dev,
                    "ino": info.st_ino,
                    "sha256": hashlib.sha256(content).hexdigest(),
                },
                0o600,
            )
            return {
                "status": "prepared",
                "detail": "Restart airlock to bind the prepared resolver",
            }
        raise NetworkError(
            "no trusted direct uplink resolver exists; full lab unavailable"
        )

    def verify_resolver(self):
        saved = json.loads(read_safe(self.resolver_state, private=True))
        if saved["boot_id"] != self.boot_id or saved["source"] not in (
            "/run/NetworkManager/no-stub-resolv.conf",
            "/run/systemd/resolve/resolv.conf",
        ):
            raise NetworkError("prepared resolver reference unavailable")
        source = Path(saved["source"])
        raw, original = read_safe_record(
            source, owner=saved["source_owner"], limit=65536
        )
        if (original.st_dev, original.st_ino, hashlib.sha256(raw).hexdigest()) != (
            saved["source_dev"],
            saved["source_ino"],
            saved["source_sha256"],
        ):
            raise NetworkError(
                "uplink DNS changed; prepare and restart airlock before renewal"
            )
        actual, info = read_safe_record(self.resolver_file, limit=65536)
        identity = (info.st_dev, info.st_ino, hashlib.sha256(actual).hexdigest())
        if identity != (saved["dev"], saved["ino"], saved["sha256"]):
            raise NetworkError("prepared resolver changed or disappeared")
        owner = pwd.getpwnam("secure-ai-airlock").pw_uid
        receipt = json.loads(read_safe(self.resolver_receipt, owner=owner, limit=4096))
        current = self.service_state()
        if (
            current.get("ActiveState") != "active"
            or current.get("SubState") != "running"
            or not re.fullmatch("[0-9a-f]{32}", current.get("InvocationID", ""))
        ):
            raise NetworkError("airlock runtime invocation unavailable")
        if (
            receipt.get("status") != "bound"
            or receipt.get("boot_id") != self.boot_id
            or receipt.get("invocation_id") != current["InvocationID"]
            or receipt.get("read_only") is not True
            or (receipt.get("dev"), receipt.get("ino"), receipt.get("sha256"))
            != identity
        ):
            raise NetworkError(
                "restart airlock; resolver receipt does not match the current bound inode"
            )

    def service_state(self):
        result = subprocess.run(
            [
                "systemctl",
                "show",
                "secure-ai-airlock.service",
                "--property=ActiveState,SubState,InvocationID",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode or len(result.stdout) > 4096:
            raise NetworkError("airlock runtime binding unavailable")
        return dict(
            line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
        )

    def revoke(self):
        self.execute(
            "-f",
            "-",
            source="\n".join(
                f"flush set {family} {table} {name}"
                for family, table in TABLES
                for name in ("online", "full", "maintenance")
            )
            + "\n",
        )

    @property
    def sleep_marker(self):
        return self.state.parent / "sleep-inhibit.json"

    def require_awake_grant(self):
        """Called only after acquiring control.lock, before grant side effects."""
        try:
            if os.path.lexists(self.sleep_marker):
                raise SleepInhibited("network grants inhibited across system sleep")
            result = subprocess.run(
                [
                    "systemctl",
                    "show",
                    "secure-ai-network-sleep.service",
                    "--property=LoadState,ActiveState,SubState,Job,Result,UnitFileState",
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            lines = result.stdout.splitlines()
            if result.returncode or len(result.stdout) > 4096 or len(lines) != 6:
                raise SleepInhibited("network sleep guard unavailable")
            state = dict(line.split("=", 1) for line in lines)
            if state != {
                "LoadState": "loaded",
                "ActiveState": "inactive",
                "SubState": "dead",
                "Job": "",
                "Result": "success",
                "UnitFileState": "enabled",
            }:
                raise SleepInhibited("network sleep guard is not ready for grants")
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            raise SleepInhibited("network sleep guard unavailable") from error

    def sleep_close(self):
        """Inhibit new grants before the existing verified restrictive reset."""
        if os.path.lexists(self.sleep_marker):
            self.read_sleep_marker()
        atomic_json(
            self.sleep_marker,
            {"version": 1, "boot_id": self.boot_id, "inhibited": True},
            0o600,
        )
        return self.close()

    def read_sleep_marker(self):
        raw, info = read_safe_record(self.sleep_marker, private=True, limit=4096)
        value = json.loads(raw)
        if (
            not isinstance(value, dict)
            or set(value) != {"version", "boot_id", "inhibited"}
            or type(value["version"]) is not int
            or value["version"] != 1
            or value["boot_id"] != self.boot_id
            or value["inhibited"] is not True
        ):
            raise NetworkError("network sleep inhibition state unavailable")
        return info

    def sleep_release(self):
        """Publish verified offline before permitting a later explicit grant."""
        self.read_sleep_marker()
        value = self.close()
        self.publish(value)
        original = self.read_sleep_marker()
        if identity(self.sleep_marker.lstat()) != identity(original):
            raise NetworkError("network sleep inhibition state changed")
        self.sleep_marker.unlink()
        directory = os.open(
            self.state.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return value

    def close(self):
        """Explicit restrictive reset. It never inherits an old online lease."""
        source = self.source()
        source_digest = hashlib.sha256(source.encode()).hexdigest()
        # Empty boot sets confer no authority, even if identities are unavailable.
        try:
            identities = {
                "tor_gid": grp.getgrnam("secure-ai-tor").gr_gid,
                "airlock_uid": pwd.getpwnam("secure-ai-airlock").pw_uid,
            }
        except KeyError:
            identities = None
        if identities:
            source = source.replace(
                "define TOR_GID = 65534", f"define TOR_GID = {identities['tor_gid']}"
            )
            source = source.replace(
                "define AIRLOCK_UID = 65534",
                f"define AIRLOCK_UID = {identities['airlock_uid']}",
            )
        self.execute("-f", "-", source=source)
        objects = self.objects()
        if not any(
            item.get("chain", {}).get("family") == "netdev"
            and item["chain"].get("hook") == "egress"
            and item["chain"].get("dev") == "*"
            and item["chain"].get("policy") == "drop"
            for item in objects
        ):
            raise NetworkError(
                "wildcard egress hooks unavailable; nftables 1.1.6+ and kernel support required"
            )
        if any(item.get("set", {}).get("elem") for item in objects):
            raise NetworkError("offline policy unexpectedly contains an online lease")
        atomic_json(
            self.state,
            {
                "version": 1,
                "boot_id": self.boot_id,
                "source_sha256": source_digest,
                "objects": normalized(objects),
                "identities": identities,
            },
            0o600,
        )
        return self.observe()

    def observe(self):
        saved = json.loads(read_safe(self.state, private=True))
        if (
            set(saved)
            != {"version", "boot_id", "source_sha256", "objects", "identities"}
            or saved["version"] != 1
            or saved["boot_id"] != self.boot_id
            or saved["source_sha256"]
            != hashlib.sha256(self.source().encode()).hexdigest()
        ):
            raise NetworkError("runtime policy reference unavailable")
        objects = self.objects()
        if normalized(objects) != saved["objects"]:
            raise NetworkError("owned firewall rules changed")
        live = {}
        for item in objects:
            if "set" not in item:
                continue
            current = item["set"]
            elements = current.get("elem", [])
            remaining = []
            seen = set()
            for wrapped in elements:
                if not isinstance(wrapped, dict) or not isinstance(
                    wrapped.get("elem"), dict
                ):
                    raise NetworkError("invalid network lease element")
                elem = wrapped.get("elem", {})
                maximum = 900 if current["name"] == "maintenance" else ONLINE_SECONDS
                if (
                    set(elem) != {"val", "timeout", "expires"}
                    or elem["val"] in seen
                    or elem["val"] not in VALUES[current["family"]]
                    or type(elem["expires"]) is not int
                    or type(elem["timeout"]) is not int
                    or not 0 < elem["expires"] <= elem["timeout"] <= maximum
                ):
                    raise NetworkError("invalid or expiring network lease")
                seen.add(elem["val"])
                remaining.append(elem["expires"])
            if seen and seen != VALUES[current["family"]]:
                raise NetworkError("partial network lease")
            live[(current["family"], current["name"])] = (
                min(remaining) if remaining else 0
            )
        active = {
            name
            for name in ("online", "full", "maintenance")
            if live[("inet", name)] and live[("netdev", name)]
        }
        if any(
            bool(live[("inet", name)]) != bool(live[("netdev", name)])
            for name in ("online", "full", "maintenance")
        ) or active not in (
            set(),
            {"online"},
            {"online", "full"},
            {"online", "maintenance"},
        ):
            raise NetworkError("inconsistent network scopes")
        scope = (
            "maintenance"
            if "maintenance" in active
            else "full_lab"
            if "full" in active
            else "research"
            if active
            else "offline"
        )
        if scope == "full_lab":
            self.verify_resolver()
        remaining = min(value for value in live.values() if value) if active else None
        now = time.time()
        return {
            "schema_version": 1,
            "boot_id": self.boot_id,
            "checked_at": timestamp(now),
            "valid_until": timestamp(
                now + min(FRESHNESS, remaining) if remaining else now + FRESHNESS
            ),
            "checked_monotonic": time.monotonic(),
            "valid_for_seconds": min(FRESHNESS, remaining) if remaining else FRESHNESS,
            "status": "verified",
            "effective_scope": scope,
            "host_offline": scope == "offline",
            "ipv4_enforced": True,
            "ipv6_enforced": True,
            "arp_enforced": True,
            "lease_expires_at": timestamp(now + remaining) if remaining else None,
            "allowed_egress": ALLOWED[scope],
            "automatic_network_tasks": False,
            "evidence_source": "nftables_runtime",
            "detail": "Owned policy and kernel lease verified",
        }

    def grant(self, scope: str, seconds: int):
        if (
            scope not in ("research", "full_lab", "maintenance")
            or type(seconds) is not int
            or not 1 <= seconds <= (900 if scope == "maintenance" else ONLINE_SECONDS)
        ):
            raise NetworkError("invalid bounded network scope")
        current = self.observe()
        if current["effective_scope"] != "offline":
            raise NetworkError("close networking before granting or renewing a lease")
        saved = json.loads(read_safe(self.state, private=True))
        if not saved["identities"]:
            raise NetworkError("dedicated online service identities unavailable")
        if scope == "full_lab":
            self.verify_resolver()
        sets = ["online"] + (
            ["full"]
            if scope == "full_lab"
            else ["maintenance"]
            if scope == "maintenance"
            else []
        )
        lines = []
        for family, table in TABLES:
            for name in sets:
                values = ", ".join(
                    f"{value} timeout {seconds}s" for value in sorted(VALUES[family])
                )
                lines.append(f"add element {family} {table} {name} {{ {values} }}")
        # Never leave a still-fresh offline assertion while opening packets.
        self.publish(self.unknown())
        self.execute("-f", "-", source="\n".join(lines) + "\n")
        return self.observe()

    def publish(self, value):
        atomic_json(self.result, value, 0o644)

    def unknown(self):
        now = time.time()
        return {
            "schema_version": 1,
            "boot_id": self.boot_id,
            "checked_at": timestamp(now),
            "valid_until": timestamp(now + FRESHNESS),
            "checked_monotonic": time.monotonic(),
            "valid_for_seconds": FRESHNESS,
            "status": "unknown",
            "effective_scope": "unknown",
            "host_offline": None,
            "ipv4_enforced": None,
            "ipv6_enforced": None,
            "arp_enforced": None,
            "lease_expires_at": None,
            "allowed_egress": [],
            "automatic_network_tasks": False,
            "evidence_source": "nftables_runtime",
            "detail": "Runtime network enforcement unavailable",
        }


def require_maintenance(path=Path("/run/secure-ai/network-status.json")):
    value = json.loads(read_safe(path))
    if type(value["checked_monotonic"]) not in (int, float):
        raise NetworkError("invalid maintenance observation clock")
    now = time.monotonic()
    age = now - value["checked_monotonic"]
    dates = [
        datetime.fromisoformat(value[name])
        for name in ("checked_at", "valid_until", "lease_expires_at")
    ]
    if any(date.tzinfo is not timezone.utc for date in dates):
        raise NetworkError("invalid maintenance wall clock")
    checked, deadline, expiry = [date.timestamp() for date in dates]
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["boot_id"] != BOOT_PATH.read_text().strip()
        or value["status"] != "verified"
        or value["effective_scope"] != "maintenance"
        or value["host_offline"] is not False
        or any(
            value[name] is not True
            for name in ("ipv4_enforced", "ipv6_enforced", "arp_enforced")
        )
        or value["allowed_egress"] != ALLOWED["maintenance"]
        or value["automatic_network_tasks"] is not False
        or value["evidence_source"] != "nftables_runtime"
        or type(value["valid_for_seconds"]) is not int
        or not 0 < value["valid_for_seconds"] <= FRESHNESS
        or not 0 <= age < value["valid_for_seconds"]
        or not checked <= time.time() < deadline <= expiry
        or not 0 < expiry - checked <= 900
        or deadline - checked > value["valid_for_seconds"] + 0.001
    ):
        raise NetworkError("explicit current maintenance lease required")
    return value


def attest_resolver(
    path=Path("/etc/resolv.conf"),
    receipt=Path("/run/secure-ai-airlock-resolver/binding.json"),
):
    """Service-namespace receipt, tied to this systemd invocation; no authority."""
    value = {
        "status": "unavailable",
        "boot_id": BOOT_PATH.read_text().strip(),
        "invocation_id": os.environ.get("INVOCATION_ID", ""),
    }
    try:
        # /etc/resolv.conf may be a distribution symlink. Inspect the actual
        # opened file in this service mount namespace, not its source pathname.
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != 0
                or info.st_mode & 0o022
                or info.st_size > 65536
            ):
                raise NetworkError("unsafe bound resolver")
            raw = os.read(fd, 65537)
            if len(raw) != info.st_size or identity(os.fstat(fd)) != identity(info):
                raise NetworkError("bound resolver changed")
            value.update(
                status="bound",
                dev=info.st_dev,
                ino=info.st_ino,
                sha256=hashlib.sha256(raw).hexdigest(),
                read_only=bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY),
            )
        finally:
            os.close(fd)
    except (OSError, NetworkError):
        pass
    atomic_json(receipt, value, 0o644, owner=os.geteuid())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "boot",
            "close",
            "sleep-close",
            "sleep-release",
            "observe",
            "grant",
            "require-maintenance",
            "prepare-resolver",
            "attest-resolver",
        ),
    )
    parser.add_argument("--scope", choices=("research", "full_lab", "maintenance"))
    parser.add_argument("--seconds", type=int)
    args = parser.parse_args()
    if args.command == "attest-resolver":
        try:
            attest_resolver()
            return 0
        except (OSError, ValueError, NetworkError):
            return 1
    if args.command == "require-maintenance":
        try:
            require_maintenance()
            return 0
        except (OSError, ValueError, KeyError, TypeError, NetworkError):
            return 1
    if os.geteuid() != 0:
        return 1
    controller = Controller()
    controller.state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = controller.state.parent.stat()
    if (
        controller.state.parent.is_symlink()
        or parent.st_uid != 0
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        return 1
    fd = os.open(
        controller.state.parent / "control.lock",
        os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
        0o600,
    )
    acquired = False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        acquired = True
        if args.command in ("boot", "close"):
            value = controller.close()
        elif args.command == "sleep-close":
            value = controller.sleep_close()
        elif args.command == "sleep-release":
            value = controller.sleep_release()
        elif args.command == "prepare-resolver":
            controller.prepare_resolver()
            value = controller.observe()
        elif args.command == "grant":
            controller.require_awake_grant()
            value = controller.grant(
                args.scope,
                args.seconds
                if args.seconds is not None
                else (
                    MAINTENANCE_SECONDS
                    if args.scope == "maintenance"
                    else ONLINE_SECONDS
                ),
            )
        else:
            value = controller.observe()
        if args.command != "sleep-release":
            controller.publish(value)
        print(json.dumps(value))
        return 0
    except SleepInhibited as error:
        print(str(error), file=sys.stderr)
        return 1
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        NetworkError,
        subprocess.SubprocessError,
    ) as error:
        print(
            str(error)
            if isinstance(error, NetworkError)
            else "Network enforcement unavailable",
            file=sys.stderr,
        )
        if not acquired:
            return 1
        if args.command == "grant":
            # A failed grant/publication must never leave an unreported lease.
            try:
                controller.close()
            except (
                OSError,
                ValueError,
                KeyError,
                TypeError,
                NetworkError,
                subprocess.SubprocessError,
            ):
                pass
        elif args.command == "observe":
            # Missing references remain missing. Restrict existing leases on
            # observation failure without regenerating a trusted reference.
            try:
                controller.revoke()
            except (OSError, NetworkError, subprocess.SubprocessError):
                pass
        try:
            controller.publish(controller.unknown())
        except (OSError, NetworkError):
            pass
        return 1
    finally:
        os.close(fd)


if __name__ == "__main__":
    raise SystemExit(main())
