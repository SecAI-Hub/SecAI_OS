#!/usr/bin/env python3
"""Fail unless the appliance vault is the expected initialized LUKS mount."""

from __future__ import annotations

import grp
import json
import os
import re
import stat
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

MAPPER_NAME = "secure-ai-vault"
MAPPER_SOURCE = f"/dev/mapper/{MAPPER_NAME}"
MOUNT_POINT = Path("/var/lib/secure-ai/vault")
CRYPTTAB = Path("/etc/crypttab")
MARKER = MOUNT_POINT / ".initialized"
MAX_CONFIG_BYTES = 65_536
MAX_MARKER_BYTES = 4_096
UUID_RE = re.compile(r"^[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$")
REQUIRED_DIRECTORIES = {
    "models": (0o2770, "secure-ai-registry"),
    "contained-models": (0o2770, "secure-ai-registry-containment"),
    "user_docs": (0o2750, "secure-ai-vault-read"),
    "outputs": (0o2770, "secure-ai-vault-write"),
}


class VaultVerificationError(RuntimeError):
    """The vault does not satisfy the production mount contract."""


def no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys instead of silently accepting the last one."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_bounded_regular(path: Path, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise VaultVerificationError(f"cannot open required file: {path}") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_size < 1
            or info.st_size > maximum
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise VaultVerificationError(f"unsafe required file: {path}")
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) != info.st_size:
            raise VaultVerificationError(f"required file changed while reading: {path}")
        return content
    finally:
        os.close(descriptor)


def crypttab_uuid() -> str:
    try:
        lines = read_bounded_regular(CRYPTTAB, MAX_CONFIG_BYTES).decode(
            "utf-8", "strict"
        ).splitlines()
    except UnicodeError as exc:
        raise VaultVerificationError("crypttab is not valid UTF-8") from exc
    matches: list[list[str]] = []
    for raw_line in lines:
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if fields[0] == MAPPER_NAME:
            matches.append(fields)
    if len(matches) != 1 or len(matches[0]) != 4:
        raise VaultVerificationError(
            "crypttab must contain exactly one complete secure-ai-vault entry"
        )
    fields = matches[0]
    if not fields[1].startswith("UUID="):
        raise VaultVerificationError("vault crypttab source must use an immutable UUID")
    luks_uuid = fields[1].removeprefix("UUID=")
    if not UUID_RE.fullmatch(luks_uuid):
        raise VaultVerificationError("vault crypttab UUID is malformed")
    options = set(fields[3].split(","))
    if "luks" not in options:
        raise VaultVerificationError("vault crypttab entry is not marked as LUKS")
    if "discard" in options:
        raise VaultVerificationError("vault crypttab must not enable discard")
    return luks_uuid.lower()


def mounted_filesystem() -> dict[str, str]:
    try:
        result = subprocess.run(
            [
                "findmnt",
                "--json",
                "--mountpoint",
                str(MOUNT_POINT),
                "--output",
                "SOURCE,FSTYPE,OPTIONS",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise VaultVerificationError("cannot inspect the vault mount") from exc
    if result.returncode != 0 or len(result.stdout) > MAX_CONFIG_BYTES:
        raise VaultVerificationError("the encrypted vault is not mounted")
    try:
        payload = json.loads(result.stdout)
        filesystems = payload["filesystems"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise VaultVerificationError("findmnt returned malformed mount data") from exc
    if not isinstance(filesystems, list) or len(filesystems) != 1:
        raise VaultVerificationError("vault mount identity is ambiguous")
    filesystem = filesystems[0]
    if not isinstance(filesystem, dict):
        raise VaultVerificationError("vault mount data has an invalid type")
    source = filesystem.get("source")
    if source != MAPPER_SOURCE and not (
        isinstance(source, str) and source.startswith(f"{MAPPER_SOURCE}[")
    ):
        raise VaultVerificationError("vault is not backed by the expected LUKS mapper")
    if filesystem.get("fstype") != "ext4":
        raise VaultVerificationError("vault filesystem must be ext4")
    raw_options = filesystem.get("options")
    if not isinstance(raw_options, str):
        raise VaultVerificationError("vault mount options are unavailable")
    options = set(raw_options.split(","))
    required = {"rw", "nodev", "nosuid", "noexec"}
    if not required.issubset(options):
        missing = ", ".join(sorted(required - options))
        raise VaultVerificationError(f"vault mount is missing required options: {missing}")
    return {
        "source": str(source),
        "fstype": "ext4",
        "options": raw_options,
    }


def verify_marker(expected_uuid: str) -> None:
    try:
        payload = json.loads(
            read_bounded_regular(MARKER, MAX_MARKER_BYTES).decode("utf-8", "strict"),
            object_pairs_hook=no_duplicate_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {value}")
            ),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise VaultVerificationError("vault initialization marker is malformed") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "initialized_at",
        "luks_uuid",
        "mapper",
        "mount_point",
        "schema_version",
    }:
        raise VaultVerificationError("vault initialization marker has an invalid schema")
    if payload["schema_version"] != 1:
        raise VaultVerificationError("vault initialization marker version is unsupported")
    if payload["mapper"] != MAPPER_NAME:
        raise VaultVerificationError("vault initialization marker names another mapper")
    if payload["mount_point"] != str(MOUNT_POINT):
        raise VaultVerificationError("vault initialization marker targets another path")
    marker_uuid = payload.get("luks_uuid")
    if not isinstance(marker_uuid, str) or marker_uuid.lower() != expected_uuid:
        raise VaultVerificationError("vault marker and crypttab UUID do not match")
    initialized_at = payload.get("initialized_at")
    if not isinstance(initialized_at, str) or len(initialized_at) > 128:
        raise VaultVerificationError("vault initialization time is invalid")
    try:
        initialized = datetime.fromisoformat(initialized_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VaultVerificationError("vault initialization time is malformed") from exc
    if initialized.tzinfo is None:
        raise VaultVerificationError("vault initialization time has no timezone")
    if initialized.astimezone(UTC) > datetime.now(UTC) + timedelta(minutes=5):
        raise VaultVerificationError("vault initialization time is in the future")


def verify_directories() -> None:
    try:
        root_info = MOUNT_POINT.lstat()
    except OSError as exc:
        raise VaultVerificationError("vault mount point is unavailable") from exc
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != 0
        or root_info.st_gid != 0
        or stat.S_IMODE(root_info.st_mode) != 0o711
    ):
        raise VaultVerificationError("unsafe vault mount-point ownership/mode")
    for name, (expected_mode, group_name) in REQUIRED_DIRECTORIES.items():
        path = MOUNT_POINT / name
        try:
            info = path.lstat()
            group_id = grp.getgrnam(group_name).gr_gid
        except (OSError, KeyError) as exc:
            raise VaultVerificationError(f"required vault directory is unavailable: {name}") from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != group_id
            or stat.S_IMODE(info.st_mode) != expected_mode
        ):
            raise VaultVerificationError(f"unsafe vault directory ownership/mode: {name}")


def verify() -> dict[str, str]:
    expected_uuid = crypttab_uuid()
    mount = mounted_filesystem()
    verify_marker(expected_uuid)
    verify_directories()
    return mount


def main() -> int:
    try:
        mount = verify()
    except VaultVerificationError as exc:
        print(f"[vault-mount] FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "[vault-mount] verified encrypted vault "
        f"({mount['source']}, {mount['fstype']}, hardened options)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
