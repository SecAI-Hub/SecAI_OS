#!/usr/bin/env python3
"""Manage the short-lived rootful-Podman control-network anchor safely."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - the helper is Linux-only at runtime.
    fcntl = None


PROJECT_NAME = "secai-sandbox"
NETWORK_NAME = "secai-sandbox_ingress"
ANCHOR_NAME = "secai-sandbox-control-network-anchor"
STATE_FILENAME = "podman-control-anchor.json"
ANCHOR_ROLE = "control-network-anchor"
ROLE_LABEL = "io.secai.sandbox.role"
PROJECT_LABEL = "io.secai.sandbox.project"
LAUNCH_LABEL = "io.secai.sandbox.launch-id"
COMPOSE_PROJECT_LABELS = {
    "io.podman.compose.project": PROJECT_NAME,
    "com.docker.compose.project": PROJECT_NAME,
    "com.docker.compose.network": "ingress",
}
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
HEX_ID_RE = re.compile(r"^[0-9a-f]{64}$")
INTERFACE_RE = re.compile(r"^podman[0-9]+$")
PINNED_ALPINE_IMAGE = (
    "docker.io/library/alpine:3.23@"
    "sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40"
)
DEFAULT_CAPABILITIES = {
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_NET_BIND_SERVICE",
    "CAP_SETFCAP",
    "CAP_SETGID",
    "CAP_SETPCAP",
    "CAP_SETUID",
    "CAP_SYS_CHROOT",
}


class AnchorError(RuntimeError):
    """Raised when anchor state cannot be verified safely."""


@dataclass(frozen=True)
class AnchorState:
    container_id: str
    launch_id: str


def _run(
    podman: str,
    *args: str,
    timeout: float = 30,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            [podman, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AnchorError(f"Podman command failed: {args[0]}") from exc
    if check and result.returncode != 0:
        raise AnchorError(f"Podman command failed: {args[0]}")
    return result


def _validate_runtime_dir(runtime_dir: Path) -> None:
    try:
        item = runtime_dir.lstat()
    except OSError as exc:
        raise AnchorError("sandbox runtime directory is unavailable") from exc
    if (
        not stat.S_ISDIR(item.st_mode)
        or stat.S_ISLNK(item.st_mode)
        or item.st_uid != os.geteuid()
        or stat.S_IMODE(item.st_mode) & 0o077
    ):
        raise AnchorError("sandbox runtime path must be a real directory")


def _state_path(runtime_dir: Path) -> Path:
    return runtime_dir / STATE_FILENAME


def _valid_identifier(value: Any) -> bool:
    return isinstance(value, str) and bool(HEX_ID_RE.fullmatch(value))


def _load_state(runtime_dir: Path) -> AnchorState | None:
    path = _state_path(runtime_dir)
    try:
        item = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AnchorError("Podman anchor state is unreadable") from exc
    if not stat.S_ISREG(item.st_mode) or stat.S_ISLNK(item.st_mode):
        raise AnchorError("Podman anchor state must be a regular file")
    if (
        item.st_uid != os.geteuid()
        or stat.S_IMODE(item.st_mode) != 0o600
        or item.st_nlink != 1
    ):
        raise AnchorError("Podman anchor state permissions are unsafe")
    if item.st_size < 1 or item.st_size > 512:
        raise AnchorError("Podman anchor state has an invalid size")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened_item = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_item.st_mode)
            or opened_item.st_dev != item.st_dev
            or opened_item.st_ino != item.st_ino
            or opened_item.st_size != item.st_size
            or opened_item.st_uid != os.geteuid()
            or stat.S_IMODE(opened_item.st_mode) != 0o600
            or opened_item.st_nlink != 1
        ):
            raise AnchorError("Podman anchor state changed while opening")
        handle = os.fdopen(descriptor, "r", encoding="ascii")
        descriptor = -1
        with handle:
            payload = json.load(handle)
    except AnchorError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AnchorError("Podman anchor state is malformed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        not isinstance(payload, dict)
        or set(payload) != {"version", "container_id", "launch_id"}
        or payload.get("version") != 1
        or not _valid_identifier(payload.get("container_id"))
        or not _valid_identifier(payload.get("launch_id"))
    ):
        raise AnchorError("Podman anchor state is malformed")
    return AnchorState(
        container_id=payload["container_id"],
        launch_id=payload["launch_id"],
    )


def _write_state(runtime_dir: Path, state: AnchorState) -> None:
    path = _state_path(runtime_dir)
    temporary = runtime_dir / f".{STATE_FILENAME}.{os.getpid()}.{state.launch_id}"
    encoded = json.dumps(
        {
            "version": 1,
            "container_id": state.container_id,
            "launch_id": state.launch_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
        directory_descriptor = os.open(runtime_dir, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as exc:
        raise AnchorError("could not persist Podman anchor ownership") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _unlink_matching_state(runtime_dir: Path, state: AnchorState) -> None:
    recorded = _load_state(runtime_dir)
    if recorded is None:
        return
    if recorded != state:
        raise AnchorError("Podman anchor ownership changed concurrently")
    try:
        _state_path(runtime_dir).unlink()
    except OSError as exc:
        raise AnchorError("could not clear Podman anchor ownership") from exc


def _parse_single_object(result: subprocess.CompletedProcess[str], kind: str) -> dict[str, Any]:
    try:
        payload = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise AnchorError(f"Podman returned malformed {kind} metadata") from exc
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise AnchorError(f"Podman returned ambiguous {kind} metadata")
    return payload[0]


def _validate_local_podman(podman: str) -> None:
    result = _run(podman, "info", "--format", "json")
    try:
        payload = json.loads(result.stdout)
        host = payload["host"]
        security = host["security"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise AnchorError("Podman returned malformed host metadata") from exc
    if (
        not isinstance(host, dict)
        or host.get("serviceIsRemote") is not False
        or not isinstance(security, dict)
        or security.get("rootless") is not False
    ):
        raise AnchorError("Podman control networking requires a local rootful service")


def _network_gateway(podman: str) -> tuple[str, str, str]:
    result = _run(podman, "network", "inspect", NETWORK_NAME)
    payload = _parse_single_object(result, "network")
    labels = payload.get("labels")
    subnets = payload.get("subnets")
    if (
        payload.get("name") != NETWORK_NAME
        or payload.get("driver") != "bridge"
        or payload.get("internal") is not False
        or payload.get("ipv6_enabled") is not False
        or not isinstance(payload.get("network_interface"), str)
        or not INTERFACE_RE.fullmatch(payload["network_interface"])
        or not isinstance(labels, dict)
        or any(labels.get(key) != value for key, value in COMPOSE_PROJECT_LABELS.items())
        or not isinstance(subnets, list)
        or len(subnets) != 1
        or not isinstance(subnets[0], dict)
    ):
        raise AnchorError("Podman project ingress network is not Compose-compatible")
    try:
        subnet = ipaddress.ip_network(subnets[0]["subnet"])
        gateway = ipaddress.ip_address(subnets[0]["gateway"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AnchorError("Podman project ingress network has invalid addressing") from exc
    if (
        subnet.version != 4
        or gateway.version != 4
        or gateway not in subnet
        or gateway in {subnet.network_address, subnet.broadcast_address}
        or not any(subnet.subnet_of(private) for private in PRIVATE_NETWORKS)
    ):
        raise AnchorError("Podman project ingress gateway is not private")
    return str(gateway), payload["network_interface"], str(subnet)


def _ensure_network(podman: str) -> tuple[str, str, str]:
    exists = _run(
        podman,
        "network",
        "exists",
        NETWORK_NAME,
        check=False,
    )
    if exists.returncode == 1:
        _run(
            podman,
            "network",
            "create",
            "--driver",
            "bridge",
            "--label",
            f"io.podman.compose.project={PROJECT_NAME}",
            "--label",
            f"com.docker.compose.project={PROJECT_NAME}",
            "--label",
            "com.docker.compose.network=ingress",
            NETWORK_NAME,
        )
    elif exists.returncode != 0:
        raise AnchorError("could not verify the Podman project ingress network")
    return _network_gateway(podman)


def _container_payload(podman: str, container_id: str) -> dict[str, Any] | None:
    result = _run(
        podman,
        "container",
        "inspect",
        container_id,
        check=False,
    )
    if result.returncode == 0:
        return _parse_single_object(result, "container")
    exists = _run(
        podman,
        "container",
        "exists",
        container_id,
        check=False,
    )
    if exists.returncode == 1:
        return None
    raise AnchorError("could not verify the recorded Podman anchor")


def _validate_anchor(
    payload: dict[str, Any],
    state: AnchorState,
    *,
    require_running: bool,
) -> None:
    config = payload.get("Config")
    host = payload.get("HostConfig")
    network_settings = payload.get("NetworkSettings")
    current_state = payload.get("State")
    if not all(
        isinstance(item, dict)
        for item in (config, host, network_settings, current_state)
    ):
        raise AnchorError("Podman anchor metadata is incomplete")
    _validate_anchor_identity(payload, state)
    networks = network_settings.get("Networks")
    mounts = payload.get("Mounts")
    dropped_capabilities = host.get("CapDrop")
    expected_command = [
        "sh",
        "-c",
        'trap "exit 0" TERM INT; while :; do sleep 3600 & wait $!; done',
    ]
    if (
        config.get("User") != "65534:65534"
        or payload.get("ImageDigest") != PINNED_ALPINE_IMAGE.rsplit("@", 1)[1]
        or payload.get("Path") != "sh"
        or payload.get("Args") != expected_command[1:]
        or config.get("Cmd") != expected_command
        or mounts != []
        or config.get("Volumes") not in (None, {})
        or host.get("Binds") not in (None, [])
        or host.get("ReadonlyRootfs") is not True
        or host.get("Privileged") is not False
        or host.get("CapAdd") not in (None, [])
        or not isinstance(dropped_capabilities, list)
        or (
            "ALL" not in dropped_capabilities
            and not DEFAULT_CAPABILITIES.issubset(set(dropped_capabilities))
        )
        or any(
            not isinstance(capability, str)
            or not re.fullmatch(r"(?:ALL|CAP_[A-Z0-9_]+)", capability)
            for capability in dropped_capabilities
        )
        or payload.get("EffectiveCaps") not in (None, [])
        or payload.get("BoundingCaps") not in (None, [])
        or "no-new-privileges" not in (host.get("SecurityOpt") or [])
        or host.get("PidsLimit") != 16
        or host.get("Memory") != 33_554_432
        or host.get("MemorySwap") != 33_554_432
        or host.get("NanoCpus") != 100_000_000
        or host.get("IpcMode") != "private"
        or host.get("PidMode") != "private"
        or host.get("UTSMode") != "private"
        or host.get("AutoRemove") is not False
        or not isinstance(host.get("RestartPolicy"), dict)
        or host["RestartPolicy"].get("Name") != "no"
        or host.get("PortBindings") not in (None, {})
        or host.get("PublishAllPorts") is not False
        or host.get("ExtraHosts") not in (None, [])
        or host.get("Devices") not in (None, [])
        or not isinstance(networks, dict)
        or set(networks) != {NETWORK_NAME}
    ):
        raise AnchorError("Podman anchor failed ownership or hardening validation")
    if require_running and (
        current_state.get("Status") != "running"
        or current_state.get("Running") is not True
    ):
        raise AnchorError("Podman anchor is not running")


def _validate_anchor_identity(
    payload: dict[str, Any],
    state: AnchorState,
) -> None:
    config = payload.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if (
        payload.get("Id") != state.container_id
        or payload.get("Name") != ANCHOR_NAME
        or not isinstance(labels, dict)
        or labels.get(ROLE_LABEL) != ANCHOR_ROLE
        or labels.get(PROJECT_LABEL) != PROJECT_NAME
        or labels.get(LAUNCH_LABEL) != state.launch_id
    ):
        raise AnchorError("Podman anchor ownership could not be verified")


def _ip_metadata(*args: str) -> list[dict[str, Any]] | None:
    ip_command = shutil.which("ip")
    if not ip_command:
        return None
    try:
        result = subprocess.run(
            [ip_command, "-j", *args],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        payload = json.loads(result.stdout) if result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None
    if not isinstance(payload, list) or any(
        not isinstance(item, dict) for item in payload
    ):
        return None
    return payload


def _gateway_is_local(
    gateway: str,
    interface_name: str,
    subnet_value: str,
) -> bool:
    if fcntl is None or not INTERFACE_RE.fullmatch(interface_name):
        return False
    interface_probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        request = interface_name.encode("ascii").ljust(256, b"\0")
        response = fcntl.ioctl(interface_probe.fileno(), 0x8915, request)
        interface_address = socket.inet_ntoa(response[20:24])
    except (OSError, UnicodeError):
        return False
    finally:
        interface_probe.close()
    if interface_address != gateway:
        return False
    address_payload = _ip_metadata("address", "show")
    route_payload = _ip_metadata("route", "show", "table", "all")
    if address_payload is None or route_payload is None:
        return False
    gateway_interfaces = {
        item.get("ifname")
        for item in address_payload
        for address in item.get("addr_info", [])
        if isinstance(address, dict)
        and address.get("family") == "inet"
        and address.get("local") == gateway
    }
    if gateway_interfaces != {interface_name}:
        return False
    try:
        expected_subnet = ipaddress.ip_network(subnet_value)
    except ValueError:
        return False
    for route in route_payload:
        destination = route.get("dst")
        if destination in (None, "default") or route.get("dev") == interface_name:
            continue
        try:
            route_network = ipaddress.ip_network(destination)
        except (TypeError, ValueError):
            continue
        if (
            route_network.version == expected_subnet.version
            and route_network.overlaps(expected_subnet)
        ):
            return False
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((gateway, 0))
    except OSError:
        return False
    finally:
        probe.close()
    return True


def _wait_for_gateway(
    gateway: str,
    interface_name: str,
    subnet_value: str,
) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if _gateway_is_local(gateway, interface_name, subnet_value):
            return
        time.sleep(0.05)
    raise AnchorError("Podman project ingress gateway was not materialized locally")


def _remove_verified(
    podman: str,
    runtime_dir: Path,
    state: AnchorState,
) -> None:
    payload = _container_payload(podman, state.container_id)
    if payload is not None:
        _validate_anchor(payload, state, require_running=False)
        _run(
            podman,
            "rm",
            "--force",
            "--time",
            "2",
            state.container_id,
            timeout=15,
        )
        if _container_payload(podman, state.container_id) is not None:
            raise AnchorError("Podman anchor did not stop cleanly")
    _unlink_matching_state(runtime_dir, state)


def _remove_new_anchor(
    podman: str,
    runtime_dir: Path,
    launch_id: str,
    reported_id: str,
) -> None:
    target = reported_id if _valid_identifier(reported_id) else ANCHOR_NAME
    deadline = time.monotonic() + 2
    payload = None
    while time.monotonic() < deadline:
        payload = _container_payload(podman, target)
        if payload is not None:
            break
        time.sleep(0.05)
    if payload is None:
        return
    actual_id = payload.get("Id")
    if not _valid_identifier(actual_id):
        raise AnchorError("new Podman anchor ID could not be verified")
    state = AnchorState(actual_id, launch_id)
    _validate_anchor_identity(payload, state)
    _run(podman, "rm", "--force", "--time", "2", actual_id, timeout=15)
    if _container_payload(podman, actual_id) is not None:
        raise AnchorError("new Podman anchor did not stop cleanly")
    recorded = _load_state(runtime_dir)
    if recorded == state:
        _unlink_matching_state(runtime_dir, state)


def _unrecorded_anchor(
    podman: str,
) -> tuple[dict[str, Any], AnchorState] | None:
    payload = _container_payload(podman, ANCHOR_NAME)
    if payload is None:
        return None
    config = payload.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    container_id = payload.get("Id")
    launch_id = (
        labels.get(LAUNCH_LABEL) if isinstance(labels, dict) else None
    )
    if not _valid_identifier(container_id) or not _valid_identifier(launch_id):
        raise AnchorError("unrecorded Podman anchor ownership is ambiguous")
    state = AnchorState(container_id, launch_id)
    _validate_anchor(payload, state, require_running=False)
    return payload, state


def prepare(podman: str, runtime_dir: Path, image: str) -> tuple[str, AnchorState, bool]:
    if image != PINNED_ALPINE_IMAGE:
        raise AnchorError("Podman anchor image must be the pinned Alpine helper")
    _validate_local_podman(podman)
    gateway, interface_name, subnet_value = _ensure_network(podman)
    recorded = _load_state(runtime_dir)
    if recorded is not None:
        payload = _container_payload(podman, recorded.container_id)
        if payload is not None:
            _validate_anchor(payload, recorded, require_running=False)
            current_state = payload.get("State")
            if (
                isinstance(current_state, dict)
                and current_state.get("Status") == "running"
                and current_state.get("Running") is True
            ):
                _wait_for_gateway(gateway, interface_name, subnet_value)
                return gateway, recorded, False
            _remove_verified(podman, runtime_dir, recorded)
        else:
            _unlink_matching_state(runtime_dir, recorded)

    launch_id = secrets.token_hex(32)
    orphan = _unrecorded_anchor(podman)
    if orphan is not None:
        _, orphan_state = orphan
        _remove_new_anchor(
            podman,
            runtime_dir,
            orphan_state.launch_id,
            orphan_state.container_id,
        )

    container_id = ""
    state_written = False
    try:
        result = _run(
            podman,
            "run",
            "--detach",
            "--name",
            ANCHOR_NAME,
            "--label",
            f"{ROLE_LABEL}={ANCHOR_ROLE}",
            "--label",
            f"{PROJECT_LABEL}={PROJECT_NAME}",
            "--label",
            f"{LAUNCH_LABEL}={launch_id}",
            "--network",
            NETWORK_NAME,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "16",
            "--memory",
            "32m",
            "--memory-swap",
            "32m",
            "--cpus",
            "0.10",
            "--ipc",
            "private",
            "--pid",
            "private",
            "--uts",
            "private",
            "--restart",
            "no",
            "--user",
            "65534:65534",
            image,
            "sh",
            "-c",
            'trap "exit 0" TERM INT; while :; do sleep 3600 & wait $!; done',
            timeout=900,
        )
        output_lines = [
            line.strip() for line in result.stdout.splitlines() if line.strip()
        ]
        container_id = output_lines[-1] if output_lines else ""
        state = AnchorState(container_id=container_id, launch_id=launch_id)
        if not _valid_identifier(container_id):
            raise AnchorError("Podman returned an invalid anchor container ID")
        payload = _container_payload(podman, container_id)
        if payload is None:
            raise AnchorError("Podman anchor disappeared during startup")
        _validate_anchor(payload, state, require_running=True)
        _write_state(runtime_dir, state)
        state_written = True
        _wait_for_gateway(gateway, interface_name, subnet_value)
    except AnchorError:
        try:
            if state_written:
                _remove_verified(
                    podman,
                    runtime_dir,
                    AnchorState(container_id, launch_id),
                )
            else:
                _remove_new_anchor(
                    podman,
                    runtime_dir,
                    launch_id,
                    container_id,
                )
        except AnchorError:
            pass
        raise
    return gateway, state, True


def remove_owned(
    podman: str,
    runtime_dir: Path,
    state: AnchorState,
) -> None:
    if not _valid_identifier(state.container_id) or not _valid_identifier(state.launch_id):
        raise AnchorError("Podman anchor ownership arguments are invalid")
    _remove_verified(podman, runtime_dir, state)


def remove_recorded(podman: str, runtime_dir: Path) -> None:
    state = _load_state(runtime_dir)
    if state is not None:
        _remove_verified(podman, runtime_dir, state)
        return
    orphan = _unrecorded_anchor(podman)
    if orphan is not None:
        _, orphan_state = orphan
        _remove_new_anchor(
            podman,
            runtime_dir,
            orphan_state.launch_id,
            orphan_state.container_id,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-dir", required=True)
    parser.add_argument("--network", choices=(NETWORK_NAME,), default=NETWORK_NAME)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--image", required=True)
    subparsers.add_parser("remove-recorded")
    owned_parser = subparsers.add_parser("remove-owned")
    owned_parser.add_argument("--container-id", required=True)
    owned_parser.add_argument("--launch-id", required=True)
    args = parser.parse_args()

    podman = shutil.which("podman")
    if not podman:
        parser.error("podman was not found")
    runtime_dir = Path(args.runtime_dir).absolute()
    try:
        _validate_runtime_dir(runtime_dir)
        if args.operation == "prepare":
            gateway, state, created = prepare(podman, runtime_dir, args.image)
            print(
                gateway,
                state.container_id,
                state.launch_id,
                "1" if created else "0",
            )
        elif args.operation == "remove-recorded":
            remove_recorded(podman, runtime_dir)
        else:
            remove_owned(
                podman,
                runtime_dir,
                AnchorState(args.container_id, args.launch_id),
            )
    except AnchorError as exc:
        print(f"Podman control-network anchor error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
