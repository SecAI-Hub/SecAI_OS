#!/usr/bin/env python3
"""Verify that persistent appliance credentials reside above dm-crypt/LUKS."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

HOST_STATE_PATH = Path(
    os.getenv("SECURE_AI_HOST_STATE_PATH", "/var/lib/secure-ai/credentials")
)
SYS_DEV_BLOCK = Path(os.getenv("SECURE_AI_SYS_DEV_BLOCK", "/sys/dev/block"))
MAX_OUTPUT_BYTES = 65_536
MAX_DM_UUID_BYTES = 512
MAX_DEVICES = 64
MAJOR_MINOR_RE = re.compile(r"^[0-9]{1,7}:[0-9]{1,7}$")
LUKS_DM_UUID_RE = re.compile(r"^CRYPT-LUKS[12]-[0-9A-Fa-f-]+-.+$")


class HostStateEncryptionError(RuntimeError):
    """Persistent host state is not demonstrably backed by LUKS."""


def no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def backing_device_id() -> str:
    try:
        result = subprocess.run(
            (
                "findmnt",
                "--json",
                "--target",
                str(HOST_STATE_PATH),
                "--output",
                "MAJ:MIN,SOURCE,FSTYPE",
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HostStateEncryptionError("cannot inspect host-state mount") from exc
    if (
        result.returncode != 0
        or not result.stdout
        or len(result.stdout) > MAX_OUTPUT_BYTES
    ):
        raise HostStateEncryptionError("host-state mount is unavailable")
    try:
        payload = json.loads(
            result.stdout,
            object_pairs_hook=no_duplicate_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {value}")
            ),
        )
        filesystems = payload["filesystems"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise HostStateEncryptionError("findmnt returned malformed data") from exc
    if not isinstance(filesystems, list) or len(filesystems) != 1:
        raise HostStateEncryptionError("host-state mount identity is ambiguous")
    filesystem = filesystems[0]
    if not isinstance(filesystem, dict):
        raise HostStateEncryptionError("host-state mount entry is invalid")
    device_id = filesystem.get("maj:min")
    if not isinstance(device_id, str) or not MAJOR_MINOR_RE.fullmatch(device_id):
        raise HostStateEncryptionError("host-state block identity is unavailable")
    return device_id


def read_dm_uuid(device: Path) -> str:
    path = device / "dm" / "uuid"
    try:
        value = path.read_text(encoding="ascii").strip()
    except (FileNotFoundError, NotADirectoryError):
        return ""
    except (OSError, UnicodeError) as exc:
        raise HostStateEncryptionError("cannot read device-mapper identity") from exc
    if len(value.encode("ascii")) > MAX_DM_UUID_BYTES:
        raise HostStateEncryptionError("device-mapper identity is oversized")
    return value


def is_luks_backed(device_id: str) -> bool:
    root = SYS_DEV_BLOCK / device_id
    pending = [root]
    visited: set[Path] = set()
    while pending:
        try:
            device = pending.pop().resolve(strict=True)
        except OSError as exc:
            raise HostStateEncryptionError("host-state device graph is unavailable") from exc
        if device in visited:
            continue
        visited.add(device)
        if len(visited) > MAX_DEVICES:
            raise HostStateEncryptionError("host-state device graph is too large")
        if LUKS_DM_UUID_RE.fullmatch(read_dm_uuid(device)):
            return True
        slaves = device / "slaves"
        try:
            children = list(slaves.iterdir())
        except (FileNotFoundError, NotADirectoryError):
            children = []
        except OSError as exc:
            raise HostStateEncryptionError("cannot inspect backing devices") from exc
        if len(children) > MAX_DEVICES:
            raise HostStateEncryptionError("host-state device fanout is too large")
        pending.extend(children)
    return False


def verify() -> str:
    device_id = backing_device_id()
    if not is_luks_backed(device_id):
        raise HostStateEncryptionError(
            "persistent appliance credentials are not demonstrably LUKS-backed"
        )
    return device_id


def main() -> int:
    try:
        device_id = verify()
    except HostStateEncryptionError as exc:
        print(f"[host-state-encryption] FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "[host-state-encryption] verified LUKS-backed persistent state "
        f"(device {device_id})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
