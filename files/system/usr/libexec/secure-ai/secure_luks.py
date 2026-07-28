#!/usr/bin/python3
"""Small, strict helpers for the single SecAI OS LUKS volume."""

from __future__ import annotations

import json
import os
import re
import shlex
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Callable, Sequence

MAPPER_NAME = "secure-ai-vault"
CRYPTTAB_PATH = Path("/etc/crypttab")
UUID_RE = re.compile(
    r"^[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}$"
)
MAX_CRYPTTAB_BYTES = 1024 * 1024
MAX_METADATA_BYTES = 4 * 1024 * 1024


class LUKSError(RuntimeError):
    """A LUKS configuration or verification operation failed."""


def _no_duplicate_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_bounded(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise LUKSError(f"cannot open {path}: {error}") from error
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size > limit
        ):
            raise LUKSError(f"{path} must be a bounded regular file")
        data = os.read(descriptor, limit + 1)
    finally:
        os.close(descriptor)
    if len(data) > limit:
        raise LUKSError(f"{path} exceeds its size limit")
    return data


def parse_crypttab(
    path: Path = CRYPTTAB_PATH,
    mapper_name: str = MAPPER_NAME,
) -> tuple[list[str], int, list[str]]:
    data = _read_bounded(path, MAX_CRYPTTAB_BYTES)
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise LUKSError("crypttab is not UTF-8") from error

    matches: list[tuple[int, list[str]]] = []
    for index, line in enumerate(lines):
        try:
            fields = shlex.split(line, comments=True, posix=True)
        except ValueError as error:
            raise LUKSError(f"invalid crypttab line {index + 1}") from error
        if not fields:
            continue
        if len(fields) < 2 or len(fields) > 4:
            raise LUKSError(f"invalid crypttab field count on line {index + 1}")
        if fields[0] == mapper_name:
            matches.append((index, fields))
    if len(matches) != 1:
        raise LUKSError(
            f"expected exactly one {mapper_name} crypttab entry; found {len(matches)}"
        )
    index, fields = matches[0]
    return lines, index, fields


def resolve_device(
    source: str,
    *,
    require_block: bool = True,
) -> Path:
    if source.startswith("UUID="):
        uuid = source.removeprefix("UUID=")
        if not UUID_RE.fullmatch(uuid):
            raise LUKSError("crypttab contains an invalid LUKS UUID")
        candidate = Path("/dev/disk/by-uuid") / uuid
    elif source.startswith("/dev/"):
        candidate = Path(source)
    else:
        raise LUKSError("vault source must be UUID=... or an absolute /dev path")

    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise LUKSError(f"cannot resolve vault device {candidate}") from error
    if not str(resolved).startswith("/dev/"):
        raise LUKSError("resolved vault device is outside /dev")
    if require_block and not stat.S_ISBLK(resolved.stat().st_mode):
        raise LUKSError("resolved vault source is not a block device")
    return resolved


def configured_device(
    path: Path = CRYPTTAB_PATH,
    *,
    require_block: bool = True,
) -> Path:
    if path == CRYPTTAB_PATH:
        try:
            info = path.lstat()
        except OSError as error:
            raise LUKSError("cannot inspect crypttab") from error
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise LUKSError(
                "crypttab must be a root-owned, single-link, protected regular file"
            )
    _lines, _index, fields = parse_crypttab(path)
    return resolve_device(fields[1], require_block=require_block)


def default_runner(
    args: Sequence[str],
    *,
    input_data: bytes | None = None,
    timeout: int = 30,
) -> subprocess.CompletedProcess[bytes]:
    try:
        kwargs: dict[str, object] = {
            "check": False,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "timeout": timeout,
        }
        if input_data is None:
            kwargs["stdin"] = subprocess.DEVNULL
        else:
            kwargs["input"] = input_data
        return subprocess.run(
            list(args),
            **kwargs,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise LUKSError(f"command unavailable: {args[0]}") from error


def luks_metadata(
    device: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = default_runner,
) -> dict[str, object]:
    completed = runner(
        ("cryptsetup", "luksDump", "--dump-json-metadata", str(device)),
        timeout=30,
    )
    if completed.returncode != 0:
        raise LUKSError("could not read verified LUKS2 metadata")
    if len(completed.stdout) > MAX_METADATA_BYTES:
        raise LUKSError("LUKS metadata exceeds size limit")
    try:
        value = json.loads(
            completed.stdout,
            object_pairs_hook=_no_duplicate_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {value}")
            ),
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise LUKSError("cryptsetup returned invalid JSON metadata") from error
    if not isinstance(value, dict):
        raise LUKSError("LUKS metadata is not an object")
    if not isinstance(value.get("keyslots"), dict):
        raise LUKSError("LUKS metadata has no keyslot map")
    if not isinstance(value.get("tokens", {}), dict):
        raise LUKSError("LUKS metadata has an invalid token map")
    return value


def tpm2_token_count(metadata: dict[str, object]) -> int:
    tokens = metadata.get("tokens", {})
    if not isinstance(tokens, dict):
        raise LUKSError("LUKS token metadata is malformed")
    count = 0
    for token in tokens.values():
        if not isinstance(token, dict):
            raise LUKSError("LUKS token entry is malformed")
        if token.get("type") == "systemd-tpm2":
            count += 1
    return count


def keyslot_count(metadata: dict[str, object]) -> int:
    keyslots = metadata.get("keyslots")
    if not isinstance(keyslots, dict):
        raise LUKSError("LUKS keyslot metadata is malformed")
    return len(keyslots)


def update_crypttab_tpm2(
    *,
    enabled: bool,
    path: Path = CRYPTTAB_PATH,
    require_root_owner: bool = True,
) -> None:
    lines, index, fields = parse_crypttab(path)
    info = path.stat()
    if require_root_owner and (
        info.st_uid != 0 or info.st_mode & 0o022
    ):
        raise LUKSError("crypttab must be root-owned and not group/world writable")

    while len(fields) < 4:
        fields.append("none" if len(fields) == 2 else "luks")
    options = [value for value in fields[3].split(",") if value]
    options = [
        value for value in options
        if value != "tpm2-device=auto" and not value.startswith("tpm2-pcrs=")
    ]
    if enabled:
        options.extend(("tpm2-device=auto", "tpm2-pcrs=0+2+4+7"))
    fields[3] = ",".join(dict.fromkeys(options)) or "luks"
    lines[index] = " ".join(fields)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, stat.S_IMODE(info.st_mode))
        os.fchown(descriptor, info.st_uid, info.st_gid)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines).rstrip() + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        parent_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
