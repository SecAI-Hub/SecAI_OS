#!/usr/bin/python3
"""Fail-closed emergency containment and cryptographic vault erasure."""

from __future__ import annotations

import argparse
import fcntl
import getpass
import grp
import hashlib
import hmac
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Sequence

from secure_luks import (
    LUKSError,
    configured_device,
    keyslot_count,
    luks_metadata,
    tpm2_token_count,
    update_crypttab_tpm2,
)

SECURE_AI_ROOT = Path("/var/lib/secure-ai")
MAPPER_NAME = "secure-ai-vault"
MAPPER_PATH = Path("/dev/mapper") / MAPPER_NAME
MOUNT_POINT = SECURE_AI_ROOT / "vault"
PANIC_STATE = Path("/run/secure-ai/panic-state.json")
PANIC_LOCK = Path("/run/secure-ai/panic.lock")
AUDIT_LOG = SECURE_AI_ROOT / "logs" / "panic-audit.jsonl"
AUDIT_KEY = Path(
    os.getenv(
        "PANIC_AUDIT_HMAC_KEY_PATH",
        str(SECURE_AI_ROOT / "credentials" / "panic-audit-hmac.key"),
    )
)
MAX_PASSPHRASE_BYTES = 4096
MAX_AUDIT_BYTES = 64 * 1024 * 1024
PANIC_SERVICES = (
    "secure-ai-airlock.service",
    "secure-ai-tor.service",
    "secure-ai-searxng.service",
    "secure-ai-search-mediator.service",
    "secure-ai-agent.service",
    "secure-ai-inference.service",
    "secure-ai-diffusion.service",
    "secure-ai-registry.service",
    "secure-ai-tool-firewall.service",
    "secure-ai-mcp-firewall.service",
    "secure-ai-quarantine-watcher.service",
    "secure-ai-policy-engine.service",
    "secure-ai-vault-watchdog.service",
    "secure-ai-canary-watch.service",
    "secure-ai-ui.service",
)
PURGE_ROOTS = (
    SECURE_AI_ROOT / "agent",
    SECURE_AI_ROOT / "airlock",
    SECURE_AI_ROOT / "auth",
    SECURE_AI_ROOT / "data",
    SECURE_AI_ROOT / "gpu-integrity",
    SECURE_AI_ROOT / "import-staging",
    SECURE_AI_ROOT / "promotion-staging",
    SECURE_AI_ROOT / "quarantine" / "incoming",
    SECURE_AI_ROOT / "registry",
    SECURE_AI_ROOT / "state",
    SECURE_AI_ROOT / "tor",
    SECURE_AI_ROOT / "ui",
)


class PanicError(RuntimeError):
    """An emergency action could not be verified."""


def log(message: str) -> None:
    print(f"[securectl] {message}", flush=True)


def run_command(
    args: Sequence[str],
    *,
    input_data: bytes | None = None,
    timeout: int = 60,
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
        raise PanicError(f"required command failed to execute: {args[0]}") from error


def _group_id(name: str) -> int:
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError as error:
        raise PanicError(f"required group is unavailable: {name}") from error


def atomic_json(
    path: Path,
    value: dict[str, object],
    *,
    mode: int,
    group: str,
) -> None:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise PanicError(f"refusing symlink state path: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=parent
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, 0, _group_id(group))
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        directory_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def write_state(
    level: int,
    status: str,
    results: Sequence[dict[str, object]],
    *,
    detail: str = "",
    audit_verified: bool,
) -> None:
    value: dict[str, object] = {
        "schema_version": 1,
        "panic_active": True,
        "level": level,
        "status": status,
        "timestamp": datetime.now(UTC).isoformat(),
        "audit_verified": audit_verified,
        "results": list(results),
    }
    if detail:
        value["detail"] = detail[:512]
    atomic_json(
        PANIC_STATE,
        value,
        mode=0o640,
        group="secure-ai-services",
    )


def _strict_json(data: bytes) -> dict[str, object]:
    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = value
        return result

    value = json.loads(
        data,
        object_pairs_hook=no_duplicates,
        parse_constant=lambda constant: (_ for _ in ()).throw(
            ValueError(f"invalid JSON constant: {constant}")
        ),
    )
    if not isinstance(value, dict):
        raise ValueError("JSON value is not an object")
    return value


def _audit_hash(
    previous: str,
    event: str,
    data: dict[str, object],
    timestamp: str,
    key: bytes,
) -> str:
    canonical = json.dumps(
        {
            "prev_hash": previous,
            "event": event,
            "data": data,
            "timestamp": timestamp,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


def _load_audit_key(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o077
            or info.st_size > 4096
        ):
            raise PanicError("panic audit key has unsafe ownership, mode, or type")
        stored = os.read(descriptor, 4097)
        stripped = stored.strip(b" \t\r\n")
        key = (
            stripped
            if stripped
            and all(0x21 <= octet <= 0x7E for octet in stripped)
            else stored
        )
    finally:
        os.close(descriptor)
    if len(key) < 32 or len(key) > 4096:
        raise PanicError("panic audit key length is invalid")
    return key


def _verify_audit_bytes(data: bytes, key: bytes) -> tuple[int, str]:
    if len(data) > MAX_AUDIT_BYTES:
        raise PanicError("panic audit log exceeds size limit")
    count = 0
    previous = ""
    for raw_line in data.splitlines():
        if not raw_line.strip():
            continue
        if len(raw_line) > 1024 * 1024:
            raise PanicError("panic audit entry exceeds size limit")
        try:
            entry = _strict_json(raw_line)
        except (ValueError, json.JSONDecodeError) as error:
            raise PanicError("panic audit log is malformed") from error
        required = {
            "timestamp",
            "event",
            "data",
            "prev_hash",
            "entry_hash",
            "algorithm",
        }
        if set(entry) != required or entry.get("algorithm") != "hmac-sha256":
            raise PanicError("panic audit log has an unsupported entry format")
        event = entry.get("event")
        timestamp = entry.get("timestamp")
        payload = entry.get("data")
        if (
            not isinstance(event, str)
            or not isinstance(timestamp, str)
            or not isinstance(payload, dict)
            or entry.get("prev_hash") != previous
        ):
            raise PanicError("panic audit log linkage or field type is invalid")
        expected = _audit_hash(previous, event, payload, timestamp, key)
        stored = entry.get("entry_hash")
        if not isinstance(stored, str) or not hmac.compare_digest(stored, expected):
            raise PanicError("panic audit HMAC verification failed")
        previous = stored
        count += 1
    return count, previous


def _verify_audit_checkpoint(count: int, previous: str, key: bytes) -> None:
    checkpoint_path = AUDIT_LOG.with_suffix(AUDIT_LOG.suffix + ".checkpoint")
    if count == 0:
        if checkpoint_path.exists() or checkpoint_path.is_symlink():
            raise PanicError("panic audit checkpoint exists for an empty log")
        return
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(checkpoint_path, flags)
    except OSError as error:
        raise PanicError("panic audit checkpoint is missing") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            raise PanicError("panic audit checkpoint is unsafe")
        raw = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    try:
        checkpoint = _strict_json(raw)
    except (ValueError, json.JSONDecodeError) as error:
        raise PanicError("panic audit checkpoint is malformed") from error
    if set(checkpoint) != {"entries", "last_hash", "hmac"}:
        raise PanicError("panic audit checkpoint schema is invalid")
    stored_hmac = checkpoint.pop("hmac")
    canonical = json.dumps(
        checkpoint,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    expected_hmac = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    if (
        not isinstance(stored_hmac, str)
        or not hmac.compare_digest(stored_hmac, expected_hmac)
        or checkpoint.get("entries") != count
        or checkpoint.get("last_hash") != previous
    ):
        raise PanicError("panic audit checkpoint does not match the log")


def append_audit(event: str, data: dict[str, object]) -> None:
    key = _load_audit_key(AUDIT_KEY)
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    flags = (
        os.O_RDWR
        | os.O_APPEND
        | os.O_CREAT
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(AUDIT_LOG, flags, 0o640)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
            raise PanicError("panic audit path is not a root-owned regular file")
        os.fchmod(descriptor, 0o640)
        os.fchown(descriptor, 0, _group_id("secure-ai-logs"))
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_AUDIT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_AUDIT_BYTES:
                raise PanicError("panic audit log exceeds size limit")
        count, previous = _verify_audit_bytes(b"".join(chunks), key)
        _verify_audit_checkpoint(count, previous, key)
        timestamp = datetime.now(UTC).isoformat()
        entry_hash = _audit_hash(previous, event, data, timestamp, key)
        entry = {
            "timestamp": timestamp,
            "event": event,
            "data": data,
            "prev_hash": previous,
            "entry_hash": entry_hash,
            "algorithm": "hmac-sha256",
        }
        encoded = (
            json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        os.lseek(descriptor, 0, os.SEEK_END)
        if os.write(descriptor, encoded) != len(encoded):
            raise PanicError("short panic audit write")
        os.fsync(descriptor)

        checkpoint = {
            "entries": count + 1,
            "last_hash": entry_hash,
        }
        canonical = json.dumps(
            checkpoint,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        checkpoint["hmac"] = hmac.new(
            key, canonical, hashlib.sha256
        ).hexdigest()
        atomic_json(
            AUDIT_LOG.with_suffix(AUDIT_LOG.suffix + ".checkpoint"),
            checkpoint,
            mode=0o640,
            group="secure-ai-logs",
        )
    finally:
        os.close(descriptor)


def _unit_loaded(unit: str) -> bool:
    result = run_command(
        ("systemctl", "show", "--property=LoadState", "--value", unit),
        timeout=15,
    )
    return result.returncode == 0 and result.stdout.strip() == b"loaded"


def contain_services() -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for unit in PANIC_SERVICES:
        if not _unit_loaded(unit):
            results.append(
                {
                    "action": "runtime_mask_service",
                    "target": unit,
                    "success": True,
                    "detail": "unit not installed",
                }
            )
            continue
        stopped = run_command(
            ("systemctl", "mask", "--runtime", "--now", unit),
            timeout=45,
        )
        active = run_command(("systemctl", "is-active", unit), timeout=15)
        enabled = run_command(("systemctl", "is-enabled", unit), timeout=15)
        success = (
            stopped.returncode == 0
            and active.stdout.strip() in {b"inactive", b"failed"}
            and active.returncode != 0
            and enabled.stdout.strip() in {b"masked", b"masked-runtime"}
        )
        results.append(
            {
                "action": "runtime_mask_service",
                "target": unit,
                "success": success,
                "detail": "inactive and runtime-masked" if success else "verification failed",
            }
        )
    return results


def lock_vault() -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    synced = run_command(("sync",), timeout=60)
    results.append(
        {
            "action": "sync_filesystems",
            "target": str(MOUNT_POINT),
            "success": synced.returncode == 0,
            "detail": "completed" if synced.returncode == 0 else "sync failed",
        }
    )
    mounted = run_command(("mountpoint", "-q", str(MOUNT_POINT)), timeout=15)
    if mounted.returncode == 0:
        unmounted = run_command(("umount", "--", str(MOUNT_POINT)), timeout=60)
        verified = run_command(("mountpoint", "-q", str(MOUNT_POINT)), timeout=15)
        success = unmounted.returncode == 0 and verified.returncode != 0
    else:
        success = True
    results.append(
        {
            "action": "unmount_vault",
            "target": str(MOUNT_POINT),
            "success": success,
            "detail": "not mounted" if mounted.returncode != 0 else "unmounted",
        }
    )

    if MAPPER_PATH.exists():
        closed = run_command(("cryptsetup", "close", MAPPER_NAME), timeout=60)
        status = run_command(("cryptsetup", "status", MAPPER_NAME), timeout=15)
        close_success = (
            closed.returncode == 0
            and status.returncode != 0
            and not MAPPER_PATH.exists()
        )
    else:
        close_success = True
    results.append(
        {
            "action": "close_vault_mapper",
            "target": MAPPER_NAME,
            "success": close_success,
            "detail": "closed or already inactive",
        }
    )
    return results


def lockdown() -> list[dict[str, object]]:
    results = contain_services()
    results.extend(lock_vault())
    return results


def _all_success(results: Sequence[dict[str, object]]) -> bool:
    return all(result.get("success") is True for result in results)


def _read_passphrase(stdin_mode: bool) -> str:
    if stdin_mode:
        data = sys.stdin.buffer.readline(MAX_PASSPHRASE_BYTES + 1)
        if len(data) > MAX_PASSPHRASE_BYTES or not data.endswith(b"\n"):
            raise PanicError("vault passphrase input is missing or too long")
        try:
            return data.rstrip(b"\r\n").decode("utf-8")
        except UnicodeDecodeError as error:
            raise PanicError("vault passphrase is not UTF-8") from error
    try:
        return getpass.getpass("Vault passphrase: ", stream=None)
    except (EOFError, OSError) as error:
        raise PanicError("a local TTY is required for destructive panic levels") from error


def _verify_luks_passphrase(device: Path, passphrase: str) -> None:
    if not passphrase:
        raise PanicError("vault passphrase is required")
    result = run_command(
        (
            "cryptsetup",
            "open",
            "--test-passphrase",
            "--key-file",
            "-",
            str(device),
        ),
        input_data=passphrase.encode("utf-8") + b"\n",
        timeout=60,
    )
    if result.returncode != 0:
        raise PanicError("vault passphrase verification failed")


def _vault_uuid(device: Path) -> str:
    result = run_command(("cryptsetup", "luksUUID", str(device)), timeout=30)
    value = result.stdout.decode("ascii", "strict").strip() if result.returncode == 0 else ""
    if not value or any(char not in "0123456789abcdefABCDEF-" for char in value):
        raise PanicError("could not obtain a valid vault UUID")
    return value


def _confirm_destruction(expected: str, supplied: str | None) -> None:
    if supplied is None:
        try:
            supplied = input(f"Type {expected} to continue: ")
        except (EOFError, OSError) as error:
            raise PanicError("a local confirmation prompt is required") from error
    if not hmac.compare_digest(supplied, expected):
        raise PanicError("destructive confirmation did not match")


def _remove_legacy_tpm_files() -> list[str]:
    directory = SECURE_AI_ROOT / "keys" / "tpm2"
    allowed = {
        "vault-key.sealed",
        "vault-key.sealed.pub",
        "vault-key.sealed.priv",
        "pcr-policy.dat",
        "primary.ctx",
        "pcr-baseline.bin",
    }
    removed: list[str] = []
    if not directory.exists():
        return removed
    if directory.is_symlink() or not directory.is_dir():
        raise PanicError("legacy TPM key path is unsafe")
    for child in directory.iterdir():
        if child.name not in allowed:
            raise PanicError(f"unexpected file in legacy TPM key directory: {child.name}")
        info = child.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise PanicError(f"legacy TPM key artifact is not a regular file: {child.name}")
        child.unlink()
        removed.append(child.name)
    return removed


def remove_hardware_unlock(device: Path) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    before = tpm2_token_count(luks_metadata(device))
    if before:
        wiped = run_command(
            ("systemd-cryptenroll", str(device), "--wipe-slot=tpm2"),
            timeout=120,
        )
        after = tpm2_token_count(luks_metadata(device))
        success = wiped.returncode == 0 and after == 0
    else:
        success = True
        after = 0
    results.append(
        {
            "action": "remove_tpm2_unlock",
            "target": "LUKS2 token metadata",
            "success": success,
            "detail": f"tokens before={before}, after={after}",
        }
    )
    if success:
        update_crypttab_tpm2(enabled=False)

    header_backup = SECURE_AI_ROOT / "keys" / "luks-header-backup"
    if header_backup.exists() or header_backup.is_symlink():
        info = header_backup.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise PanicError("local LUKS header backup path is unsafe")
        header_backup.unlink()
        header_removed = True
    else:
        header_removed = False
    results.append(
        {
            "action": "unlink_local_header_backup",
            "target": str(header_backup),
            "success": True,
            "detail": "removed" if header_removed else "not present",
        }
    )

    removed = _remove_legacy_tpm_files()
    results.append(
        {
            "action": "remove_legacy_tpm_artifacts",
            "target": str(SECURE_AI_ROOT / "keys" / "tpm2"),
            "success": True,
            "detail": f"removed {len(removed)} known artifacts",
        }
    )
    return results


def _purge_directory_contents(root: Path) -> int:
    if not root.exists():
        return 0
    if root.is_symlink() or not root.is_dir():
        raise PanicError(f"purge root is not a real directory: {root}")
    resolved = root.resolve(strict=True)
    secure_root = SECURE_AI_ROOT.resolve(strict=True)
    if secure_root not in resolved.parents or resolved == secure_root:
        raise PanicError(f"purge root escaped the appliance boundary: {root}")

    removed = 0
    for entry in list(os.scandir(root)):
        path = Path(entry.path)
        info = entry.stat(follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            removed += _purge_directory_contents(path)
            path.rmdir()
        elif stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            path.unlink()
        else:
            raise PanicError(f"refusing special file during local-state purge: {path}")
        removed += 1
    return removed


def purge_local_state() -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for root in PURGE_ROOTS:
        count = _purge_directory_contents(root)
        results.append(
            {
                "action": "unlink_local_state",
                "target": str(root),
                "success": True,
                "detail": (
                    f"unlinked {count} entries; flash/COW media overwrite is not claimed"
                ),
            }
        )

    logs_root = SECURE_AI_ROOT / "logs"
    preserved = {
        AUDIT_LOG.name,
        AUDIT_LOG.with_suffix(AUDIT_LOG.suffix + ".checkpoint").name,
    }
    removed_logs = 0
    if logs_root.exists():
        for entry in os.scandir(logs_root):
            if entry.name in preserved:
                continue
            info = entry.stat(follow_symlinks=False)
            path = Path(entry.path)
            if stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                path.unlink()
                removed_logs += 1
            elif stat.S_ISDIR(info.st_mode):
                removed_logs += _purge_directory_contents(path)
                path.rmdir()
                removed_logs += 1
            else:
                raise PanicError(f"refusing special file in log purge: {path}")
    results.append(
        {
            "action": "unlink_non_panic_logs",
            "target": str(logs_root),
            "success": True,
            "detail": f"unlinked {removed_logs} entries; keyed panic evidence preserved",
        }
    )
    return results


def erase_vault(device: Path) -> list[dict[str, object]]:
    erased = run_command(
        ("cryptsetup", "luksErase", "--batch-mode", str(device)),
        timeout=180,
    )
    remaining = keyslot_count(luks_metadata(device))
    success = erased.returncode == 0 and remaining == 0
    return [
        {
            "action": "cryptographic_erase_vault",
            "target": str(device),
            "success": success,
            "detail": f"remaining LUKS keyslots={remaining}",
        }
    ]


def countdown(seconds: int) -> None:
    for remaining in range(seconds, 0, -1):
        log(f"emergency action in {remaining} second(s); Ctrl+C cancels")
        time.sleep(1)


def execute_panic(
    level: int,
    *,
    no_countdown: bool,
    passphrase_stdin: bool,
    destructive_confirmation: str | None,
) -> int:
    results: list[dict[str, object]] = []
    audit_verified = False
    device: Path | None = None

    if level >= 2:
        try:
            device = configured_device()
            metadata = luks_metadata(device)
            if keyslot_count(metadata) < 1:
                raise PanicError("vault has no usable LUKS keyslots")
            passphrase = _read_passphrase(passphrase_stdin)
            _verify_luks_passphrase(device, passphrase)
            del passphrase
            uuid = _vault_uuid(device)
            expected = (
                f"REMOVE-HARDWARE-UNLOCK-{uuid}"
                if level == 2
                else f"DESTROY-VAULT-{uuid}"
            )
            _confirm_destruction(expected, destructive_confirmation)
        except (LUKSError, OSError, UnicodeError) as error:
            raise PanicError(str(error)) from error

    try:
        append_audit(
            "emergency_panic_started",
            {
                "level": level,
                "severity": "CRITICAL",
                "requested_by_uid": os.getuid(),
            },
        )
        audit_verified = True
    except (OSError, PanicError) as error:
        if level >= 2:
            raise PanicError(
                f"destructive panic refused because keyed audit is unavailable: {error}"
            ) from error
        log(f"WARNING: keyed panic audit unavailable: {error}")

    write_state(
        level,
        "locking",
        results,
        audit_verified=audit_verified,
    )
    if not no_countdown:
        countdown(5)

    results.extend(lockdown())
    if not _all_success(results):
        write_state(
            level,
            "failed",
            results,
            detail="one or more containment actions could not be verified",
            audit_verified=audit_verified,
        )
        if audit_verified:
            append_audit("emergency_panic_failed", {"level": level, "results": results})
        return 1

    final_status = "locked"
    if level >= 2:
        assert device is not None
        results.extend(remove_hardware_unlock(device))
        final_status = "hardware_unlock_removed"
    if level == 3 and _all_success(results):
        assert device is not None
        results.extend(erase_vault(device))
        if _all_success(results):
            results.extend(purge_local_state())
        final_status = "vault_erased"

    success = _all_success(results)
    if not success:
        final_status = "failed"
    try:
        if audit_verified:
            append_audit(
                "emergency_panic_completed" if success else "emergency_panic_failed",
                {
                    "level": level,
                    "status": final_status,
                    "results": results,
                },
            )
    except (OSError, PanicError) as error:
        success = False
        final_status = "failed"
        results.append(
            {
                "action": "append_final_audit",
                "target": str(AUDIT_LOG),
                "success": False,
                "detail": str(error)[:256],
            }
        )
    write_state(
        level,
        final_status,
        results,
        audit_verified=audit_verified,
    )
    log(f"panic level {level} status: {final_status}")
    return 0 if success else 1


def show_status() -> int:
    if not PANIC_STATE.exists():
        print('{"panic_active":false}')
        return 0
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(PANIC_STATE, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
                raise PanicError("panic state is not a bounded regular file")
            data = os.read(descriptor, 1024 * 1024 + 1)
        finally:
            os.close(descriptor)
        value = _strict_json(data)
    except (OSError, ValueError, json.JSONDecodeError, PanicError) as error:
        print(
            json.dumps(
                {
                    "panic_active": True,
                    "status": "state_invalid",
                    "error": str(error),
                },
                separators=(",", ":"),
            )
        )
        return 1
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return 0


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="securectl",
        description="Secure AI appliance emergency control",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status")
    panic = subparsers.add_parser("panic")
    panic.add_argument("level", type=int, choices=(1, 2, 3))
    panic.add_argument("--no-countdown", action="store_true")
    panic.add_argument(
        "--passphrase-stdin",
        action="store_true",
        help="read a single vault passphrase line from stdin (root automation only)",
    )
    panic.add_argument(
        "--destructive-confirmation",
        help="exact non-secret UUID-bound confirmation phrase",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if args.command == "status":
        return show_status()
    if os.geteuid() != 0:
        log("panic commands must run as root")
        return 1
    if args.level == 1 and (
        args.passphrase_stdin or args.destructive_confirmation is not None
    ):
        log("destructive-authentication options are invalid for panic level 1")
        return 2

    PANIC_LOCK.parent.mkdir(parents=True, exist_ok=True)
    lock_descriptor = os.open(
        PANIC_LOCK,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(lock_descriptor, 0o600)
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log("another panic operation is already running")
            return 1
        try:
            return execute_panic(
                args.level,
                no_countdown=args.no_countdown,
                passphrase_stdin=args.passphrase_stdin,
                destructive_confirmation=args.destructive_confirmation,
            )
        except (OSError, PanicError, LUKSError) as error:
            log(f"ERROR: {error}")
            return 1
    finally:
        os.close(lock_descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
