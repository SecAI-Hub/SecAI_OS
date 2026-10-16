#!/usr/bin/env python3
"""
Secure AI Appliance — Vault Auto-Lock Watchdog

Monitors the last-activity timestamp and automatically locks the LUKS vault
after a configurable period of inactivity. When the vault is locked:
  1. All running inference/diffusion workers are stopped
  2. The vault filesystem is unmounted
  3. The LUKS mapper is closed

The vault must be manually unlocked from a trusted local root console to
resume operation. The web UI never receives the LUKS passphrase.

Activity is tracked via a timestamp file written by the UI on every
authenticated API request.

Usage:
  vault-watchdog.py [--interval SECONDS] [--timeout MINUTES]
  vault-watchdog.py --lock-once [--reason REASON]
  vault-watchdog.py --unlock-once [--partition /dev/DEVICE]

The interactive unlock command reads the passphrase from the controlling
terminal with echo disabled. It never accepts a passphrase argument.
"""

import argparse
import getpass
import importlib.util
import json
import logging
import math
import os
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from secure_luks import (
    UUID_RE,
    LUKSError,
    configured_device,
    parse_crypttab,
    resolve_device,
)

_operation_spec = importlib.util.spec_from_file_location(
    "vault_operation_lock", Path(__file__).with_name("vault-operation-lock.py"))
assert _operation_spec and _operation_spec.loader
vault_operation = importlib.util.module_from_spec(_operation_spec)
_operation_spec.loader.exec_module(vault_operation)

_mount_spec = importlib.util.spec_from_file_location(
    "vault_mount_control", Path(__file__).with_name("vault-mount-control.py"))
assert _mount_spec and _mount_spec.loader
vault_mount = importlib.util.module_from_spec(_mount_spec)
_mount_spec.loader.exec_module(vault_mount)

logging.basicConfig(
    level=logging.INFO,
    format="[vault-watchdog] %(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("vault-watchdog")

MAPPER_NAME = "secure-ai-vault"
MOUNT_POINT = "/var/lib/secure-ai/vault"
ACTIVITY_FILE = os.getenv("VAULT_ACTIVITY_FILE", "/run/secure-ai/last-activity")
STATE_FILE = os.getenv("VAULT_STATE_FILE", "/run/secure-ai/vault-state")
AUDIT_LOG = "/var/lib/secure-ai/logs/vault-audit.jsonl"
VAULT_VERIFY = "/usr/libexec/secure-ai/verify-vault-mount.py"
_BOOT_ID_PATHS = (Path("/proc/sys/kernel/random/boot_id"), Path("/run/secure-ai-vault-boot-id"))
_PENDING = "pending_operation"
_MAX_STATE_BYTES = 16384


class RuntimeIntentError(RuntimeError):
    """Runtime intent is unavailable or cannot authorize same-boot reconciliation."""


def _boot_id() -> str:
    """Use only the kernel identity and its fixed read-only sandbox bind."""
    values = set()
    for index, path in enumerate(_BOOT_ID_PATHS):
        try:
            with path.open("r", encoding="ascii") as handle:
                raw = handle.read(65)
        except FileNotFoundError:
            continue
        # systemd leaves an empty bind-target placeholder in the host view.
        # Only the secondary empty file is unavailable; the kernel source is strict.
        if index == 1 and raw == "":
            continue
        value = raw.strip()
        if not vault_mount.native.guard.valid_uuid(value):
            raise RuntimeIntentError("invalid kernel boot identity")
        values.add(value)
    if len(values) != 1:
        raise RuntimeIntentError("kernel boot identity unavailable or inconsistent")
    return values.pop()


def _state_record() -> dict:
    try:
        with open(STATE_FILE, "rb") as handle:
            raw = handle.read(_MAX_STATE_BYTES + 1)
    except FileNotFoundError:
        return {}
    if not raw:  # Includes the empty tmpfiles-provisioned runtime record.
        return {}
    try:
        value = vault_mount.native.guard.strict_json(raw, _MAX_STATE_BYTES)
    except (vault_mount.native.guard.RecoveryError, RecursionError) as exc:
        raise RuntimeIntentError("invalid runtime state") from exc
    if not isinstance(value, dict):
        raise RuntimeIntentError("invalid runtime state object")
    return value


def _pending_operation(record: dict) -> dict | None:
    if _PENDING not in record:
        return None
    value = record[_PENDING]
    if (not isinstance(value, dict) or
            set(value) != {"version", "boot_id", "operation_id", "action"} or
            type(value["version"]) is not int or value["version"] != 1 or
            not vault_mount.native.guard.valid_uuid(value["boot_id"]) or
            not vault_mount.native.guard.valid_uuid(value["operation_id"]) or
            not isinstance(value["action"], str) or value["action"] not in {"lock", "unlock"}):
        raise RuntimeIntentError("invalid or unsupported runtime operation intent")
    return value


def _begin_operation(action: str) -> bool:
    """Persist before mutation; rollback retains the original pending operation."""
    try:
        pending = _pending_operation(_state_record())
        boot = _boot_id()
        if pending is not None and pending["boot_id"] != boot:
            raise RuntimeIntentError("runtime intent belongs to another boot; local review required")
        if pending is None:
            pending = {"version": 1, "boot_id": boot, "operation_id": str(uuid.uuid4()), "action": action}
        return write_state("error", "vault runtime operation in progress", _pending=pending)
    except (RuntimeIntentError, OSError, UnicodeError):
        log.exception("vault runtime intent could not be established")
        write_state("error", "vault runtime intent unavailable; local review required")
        return False


def _reconcile_operation(*, operation_fd: int) -> bool:
    """Current-boot interruption only: fixed relock, never replay stored commands."""
    try:
        pending = _pending_operation(_state_record())
        if pending is None:
            return True
        if pending["boot_id"] != _boot_id():
            raise RuntimeIntentError("runtime intent belongs to another boot")
    except (RuntimeIntentError, OSError, UnicodeError):
        write_state("error", "invalid or other-boot runtime intent; local review required")
        return False
    if not _lock_vault_held("interrupted_runtime_operation", operation_fd=operation_fd):
        write_state("error", "interrupted vault operation cleanup unconfirmed")
        return False
    # A success result alone cannot erase a marker left by incomplete cleanup.
    try:
        return _pending_operation(_state_record()) is None
    except (RuntimeIntentError, OSError, UnicodeError):
        return False

# Services to stop when locking the vault
SERVICES_TO_STOP = list(vault_mount.CONSUMERS)

# Default settings
DEFAULT_TIMEOUT = 30  # minutes
DEFAULT_CHECK_INTERVAL = 30  # seconds
GRACE_PERIOD = 60  # seconds — warn before locking
MAX_FUTURE_ACTIVITY_SKEW = 300  # seconds


def activity_timestamp() -> tuple[str, float]:
    """Return (valid|missing|invalid, timestamp) for the activity record."""
    try:
        raw = Path(ACTIVITY_FILE).read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return "missing", 0.0
    except (OSError, UnicodeError):
        return "invalid", 0.0
    try:
        value = float(raw)
    except ValueError:
        return "invalid", 0.0
    now = time.time()
    if (
        not math.isfinite(value)
        or value < 0
        or value > now + MAX_FUTURE_ACTIVITY_SKEW
    ):
        return "invalid", 0.0
    return "valid", value


def read_last_activity() -> float:
    """Read a valid last-activity timestamp, or 0.0 for compatibility."""
    status, value = activity_timestamp()
    return value if status == "valid" else 0.0


def write_state(state: str, detail: str = "", *, _pending: dict | None = None, _complete: bool = False) -> bool:
    """Atomic status update; observations/errors cannot erase operation intent.

    The private completion flag is used only after verified terminal operations.
    """
    temporary = ""
    try:
        previous = _state_record()
        pending = previous.get(_PENDING)
        marked = _PENDING in previous
        if _pending is not None:
            pending = _pending_operation({_PENDING: _pending})
            marked = True
        if _complete and marked:
            valid = _pending_operation({_PENDING: pending})
            if valid is None or valid["boot_id"] != _boot_id():
                raise RuntimeIntentError("cannot complete invalid or other-boot operation")
            marked = False
        if marked and state not in {"error", "unknown"}:
            state, detail = "error", "vault runtime operation incomplete; cleanup required"
        state_path = Path(STATE_FILE)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "state": state,
            "timestamp": time.time(),
            "detail": detail,
        }
        if marked:
            data[_PENDING] = pending
        fd, temporary = tempfile.mkstemp(
            prefix=f".{state_path.name}.",
            dir=state_path.parent,
        )
        try:
            os.fchmod(fd, 0o640)
            if os.geteuid() == 0:
                # /run/secure-ai is root:secure-ai-services. Preserve that
                # read-only UI visibility when the atomic rename replaces the
                # tmpfiles-created inode.
                os.fchown(fd, 0, state_path.parent.stat().st_gid)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        os.replace(temporary, state_path)
        temporary = ""
        parent_fd = os.open(state_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        return True
    except (OSError, RuntimeIntentError, UnicodeError) as e:
        log.error("failed to write state file: %s", e)
        return False
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def read_state() -> dict:
    """Read current vault state."""
    try:
        return _state_record() or {"state": "unknown", "timestamp": 0}
    except (OSError, RuntimeIntentError, UnicodeError):
        return {"state": "unknown", "timestamp": 0}


def vault_mount_state() -> tuple[str, str]:
    """Report PID1's host mount state, never a cached/private findmnt view."""
    try:
        return vault_mount.state()
    except (RuntimeError, OSError, subprocess.SubprocessError):
        return "error", ""


def mounted_vault_source() -> str:
    """Return a mounted source for compatibility with status callers."""
    state, source = vault_mount_state()
    return source if state in {"expected", "unexpected"} else ""


def is_vault_mounted() -> bool:
    """Check that the exact vault mountpoint uses the expected LUKS mapper."""
    state, _source = vault_mount_state()
    return state == "expected"


def is_mapper_open() -> bool:
    """Check if the LUKS mapper device exists."""
    return Path(f"/dev/mapper/{MAPPER_NAME}").exists()


def exact_vault_mount_verified() -> bool:
    """Run the same exact contract gate used by vault-dependent units."""
    try:
        result = subprocess.run(
            [VAULT_VERIFY],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def vault_has_configuration() -> bool:
    """Return whether protected crypttab declares the UUID-bound vault."""
    try:
        path = Path("/etc/crypttab")
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            return False
        _lines, _index, fields = parse_crypttab(path)
    except (LUKSError, OSError):
        return False
    if len(fields) != 4 or not fields[1].startswith("UUID="):
        return False
    if not UUID_RE.fullmatch(fields[1].removeprefix("UUID=")):
        return False
    options = set(fields[3].split(","))
    return "luks" in options and "discard" not in options


def audit_event(event: str, **kwargs):
    """Write a vault audit event (best-effort, vault may be locked)."""
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "event": event,
        **kwargs,
    }
    try:
        log_path = Path(AUDIT_LOG)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # vault may already be unmounted
    log.info("audit: %s %s", event, json.dumps(kwargs) if kwargs else "")


def stop_services() -> bool:
    """Drain fixed consumers' PID1 jobs and independently pinned cgroups."""
    try:
        vault_mount.stop_consumers()
        return True
    except (RuntimeError, OSError, subprocess.SubprocessError):
        log.exception("vault consumers did not drain")
        return False


def _host_absent_and_idle() -> bool:
    try:
        return vault_mount_state()[0] == "absent" and vault_mount.consumers_idle()
    except (RuntimeError, OSError, subprocess.SubprocessError):
        return False


def start_services() -> tuple[bool, list[str]]:
    """Restart enabled services after unlocking and report every failure."""
    failures = []
    for svc in SERVICES_TO_STOP:
        try:
            enabled = subprocess.run(
                ["systemctl", "is-enabled", "--quiet", svc],
                capture_output=True, text=True, timeout=10,
            )
            if enabled.returncode != 0:
                log.info("not restarting disabled service %s", svc)
                continue
            vault_mount.start_consumer(svc)
            log.info("started %s", svc)
        except (RuntimeError, OSError, subprocess.SubprocessError) as e:
            failures.append(svc)
            log.error("failed to start %s: %s", svc, e)
    return not failures, failures


def close_mapper(*, operation_fd: int) -> bool:
    """Close the fixed vault mapper and verify that it disappeared."""
    try:
        result = subprocess.run(
            ["cryptsetup", "close", MAPPER_NAME],
            capture_output=True, text=True, timeout=30, pass_fds=(operation_fd,),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.error("cryptsetup close failed: %s", exc)
        return False
    if result.returncode != 0:
        log.error("cryptsetup close failed: %s", result.stderr.strip())
        return False
    return not is_mapper_open()


def lock_vault(reason: str = "idle_timeout") -> bool:
    """Serialize the complete relock, including consumer stop and state commit."""
    try:
        with vault_operation.operation() as held:
            return _lock_vault_held(reason, operation_fd=held.fd)
    except (vault_operation.VaultOperationError, OSError):
        log.error("vault relock not confirmed: operation exclusion unavailable or changed")
        return False


def _lock_vault_held(reason: str, *, operation_fd: int) -> bool:
    """Lock the vault: stop services, unmount, close LUKS."""
    if not _begin_operation("lock"):
        return False
    log.warning("LOCKING VAULT — reason: %s", reason)
    audit_event("vault_lock", reason=reason)

    mount_state, mount_source = vault_mount_state()
    if mount_state == "unexpected":
        stop_services()
        detail = (
            "cannot determine vault mount state"
            if mount_state == "error"
            else f"unexpected filesystem mounted at vault path: {mount_source}"
        )
        write_state("error", detail)
        audit_event("vault_mount_state_error", state=mount_state)
        return False

    # 1. Stop every service that has access to the encrypted mount.
    if not stop_services():
        write_state("error", "one or more vault consumers could not be stopped")
        return False

    if mount_state == "absent" and not is_mapper_open():
        if not _host_absent_and_idle():
            write_state("error", "host vault absence or consumer drain unconfirmed")
            return False
        state = "locked" if vault_has_configuration() else "setup_required"
        if not write_state(state, reason, _complete=True):
            return False
        log.info("vault is not mounted (%s)", state)
        return True

    # 2. Sync filesystem
    try:
        subprocess.run(["sync"], check=True, timeout=10, pass_fds=(operation_fd,))
    except Exception as e:
        log.error("filesystem sync failed: %s", e)
        write_state("error", f"filesystem sync failed: {e}")
        return False

    # PID1 owns the host mount; a successful client exit alone is not proof.
    try:
        vault_mount.stop()
        if not _host_absent_and_idle():
            raise RuntimeError("host mount or consumer drain unconfirmed")
    except (RuntimeError, OSError, subprocess.SubprocessError):
        write_state("error", "host vault unmount or consumer drain unconfirmed")
        return False

    # 4. Close LUKS
    if is_mapper_open():
        if not close_mapper(operation_fd=operation_fd):
            write_state("error", "cryptsetup close failed")
            return False

    if not _host_absent_and_idle():
        write_state("error", "vault reactivation observed after mapper close")
        return False
    if not write_state("locked", reason, _complete=True):
        return False
    log.info("vault locked successfully")
    return True


def unlock_vault(passphrase: str, partition: str = "") -> dict:
    """Serialize unlock and its failure relock under one operation exclusion."""
    try:
        with vault_operation.operation() as held:
            return _unlock_vault_held(passphrase, partition, operation_fd=held.fd)
    except (vault_operation.VaultOperationError, OSError):
        return {"success": False, "error": "vault operation exclusion unavailable or changed; completion not confirmed"}


def _unlock_vault_held(passphrase: str, partition: str = "", *, operation_fd: int) -> dict:
    """Unlock the vault: open LUKS, mount, start services.

    The partition is read from /etc/crypttab if not provided.
    Returns {"success": True/False, "error": "..."}.
    """
    if (
        not passphrase
        or "\x00" in passphrase
        or len(passphrase.encode("utf-8")) > 4096
    ):
        return {"success": False, "error": "vault passphrase is empty or too long"}

    if not _reconcile_operation(operation_fd=operation_fd):
        return {"success": False, "error": "interrupted vault operation requires confirmed cleanup or local review"}

    initial_mount_state, initial_source = vault_mount_state()
    if initial_mount_state == "expected":
        if exact_vault_mount_verified() and vault_mount_state()[0] == "expected":
            return {"success": True, "detail": "already unlocked"}
        relocked = _lock_vault_held("preexisting_mount_verification_failed", operation_fd=operation_fd)
        detail = "pre-existing vault mount failed exact verification"
        if not relocked:
            detail += "; automatic relock failed"
        return {"success": False, "error": detail}
    if initial_mount_state in {"unexpected", "error"}:
        detail = (
            "vault mount state is unavailable"
            if initial_mount_state == "error"
            else f"vault path is occupied by an unexpected source: {initial_source}"
        )
        write_state("error", detail)
        return {"success": False, "error": detail}

    # 1. Open LUKS
    opened_here = not is_mapper_open()
    if opened_here:
        if not partition:
            partition = _find_partition_from_crypttab()
            if not partition:
                return {"success": False, "error": "cannot determine vault partition"}
        try:
            partition = str(resolve_device(partition, require_block=True))
        except (LUKSError, OSError):
            return {
                "success": False,
                "error": "vault partition must resolve to an exact block device",
            }
    if not _begin_operation("unlock"):
        return {"success": False, "error": "vault runtime intent could not be persisted"}
    if opened_here:
        try:
            proc = subprocess.run(
                [
                    "cryptsetup",
                    "open",
                    "--type",
                    "luks",
                    "--batch-mode",
                    "--tries",
                    "1",
                    "--key-file",
                    "-",
                    partition,
                    MAPPER_NAME,
                ],
                input=passphrase.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                pass_fds=(operation_fd,),
            )
            if proc.returncode != 0:
                audit_event("vault_unlock_failed", reason="authentication_or_device_error")
                return {"success": False, "error": "incorrect passphrase or device error"}
        except (OSError, subprocess.SubprocessError) as exc:
            audit_event("vault_unlock_failed", reason="cryptsetup_execution_error")
            return {"success": False, "error": f"cryptsetup failed: {exc}"}

    # PID1 performs the mount in the host namespace. The fresh verifier also
    # checks the current sandbox view after inward propagation.
    try:
        vault_mount.start()
        if vault_mount_state()[0] != "expected" or not exact_vault_mount_verified():
            raise RuntimeError("host mount or fresh exact verification failed")
    except (RuntimeError, OSError, subprocess.SubprocessError):
        # Cancel/drain any delayed job and prove host absence BEFORE closing a
        # mapper opened here. Preserve the mapper if that proof is unavailable.
        cleanup_confirmed = False
        try:
            if not stop_services():
                raise RuntimeError("consumer drain unconfirmed")
            vault_mount.stop()
            cleanup_confirmed = vault_mount_state()[0] == "absent" and vault_mount.consumers_idle()
        except (RuntimeError, OSError, subprocess.SubprocessError):
            log.exception("failed mount job cleanup unconfirmed")
        cleanup_failed = not cleanup_confirmed
        if opened_here and cleanup_confirmed:
            cleanup_failed = not close_mapper(operation_fd=operation_fd)
        detail = "mount failed; cleanup unconfirmed, mapper retained" if cleanup_failed else "mount failed"
        audit_event("vault_unlock_failed", reason="host_mount_failed")
        write_state("error", detail)
        return {"success": False, "error": detail}

    # 3. Start only services configured to start on this appliance.
    services_started, failures = start_services()
    if not services_started:
        detail = f"vault mounted but services failed to start: {', '.join(failures)}"
        audit_event("vault_unlock_partial", failed_services=failures)
        relocked = _lock_vault_held("service_restart_failed", operation_fd=operation_fd)
        if not relocked:
            detail += "; automatic relock failed"
        write_state("error", detail)
        return {"success": False, "error": detail}

    # 4. Reset the idle timer after the UI runtime directory exists.
    if not touch_activity():
        detail = "vault activity timer could not be initialized"
        relocked = _lock_vault_held("activity_timer_initialization_failed", operation_fd=operation_fd)
        if not relocked:
            detail += "; automatic relock failed"
        write_state("error", detail)
        return {"success": False, "error": detail}

    if vault_mount_state()[0] != "expected":
        relocked = _lock_vault_held("host_mount_changed_before_commit", operation_fd=operation_fd)
        detail = "host vault mount changed before unlock commit"
        if not relocked:
            detail += "; automatic relock failed"
        write_state("error", detail)
        return {"success": False, "error": detail}
    if not write_state("unlocked", _complete=True):
        detail = "vault state could not be persisted"
        relocked = _lock_vault_held("state_persistence_failed", operation_fd=operation_fd)
        if not relocked:
            detail += "; automatic relock failed"
        return {"success": False, "error": detail}
    audit_event("vault_unlock")
    log.info("vault unlocked successfully")
    return {"success": True}


def touch_activity() -> bool:
    """Atomically update activity while preserving runtime-directory ownership."""
    temporary = ""
    try:
        activity_path = Path(ACTIVITY_FILE)
        parent = activity_path.parent
        if not parent.is_dir():
            return False
        parent_stat = parent.stat()
        fd, temporary = tempfile.mkstemp(prefix=".last-activity.", dir=parent)
        try:
            os.fchmod(fd, 0o660)
            if os.geteuid() == 0:
                os.fchown(fd, parent_stat.st_uid, parent_stat.st_gid)
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(str(time.time()))
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        os.replace(temporary, activity_path)
        temporary = ""
        return True
    except OSError as exc:
        log.error("failed to persist vault activity timestamp: %s", exc)
        return False
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def _find_partition_from_crypttab() -> str:
    """Resolve the one protected, UUID-bound vault crypttab entry."""
    try:
        return str(configured_device(require_block=True))
    except (LUKSError, OSError):
        return ""


def _initial_observation(*, operation_fd: int):
    """Observe unmarked runtime state, preserving ordinary fresh-boot adoption."""
    mount_state, _mount_source = vault_mount_state()
    if mount_state == "expected":
        if not exact_vault_mount_verified():
            _lock_vault_held("startup_exact_mount_verification_failed", operation_fd=operation_fd)
        elif not write_state("unlocked") or not touch_activity():
            _lock_vault_held("activity_timer_initialization_failed", operation_fd=operation_fd)
    elif mount_state == "absent" and not is_mapper_open() and not vault_has_configuration():
        write_state("setup_required", "encrypted vault is not configured")
    else:
        _lock_vault_held(f"startup_mount_state_{mount_state}", operation_fd=operation_fd)


def watchdog_loop(timeout_minutes: int, check_interval: int):
    """Main watchdog loop. Monitors activity and locks on idle timeout."""
    timeout_seconds = timeout_minutes * 60
    grace_warned = False

    log.info("vault watchdog started (timeout=%dm, check=%ds)", timeout_minutes, check_interval)

    # Reconcile only while holding per-operation exclusion, never for the daemon lifetime.
    try:
        with vault_operation.operation() as held:
            # Pending runtime work takes precedence over mount/status adoption.
            if not _reconcile_operation(operation_fd=held.fd):
                log.error("vault initial reconciliation incomplete")
            else:
                _initial_observation(operation_fd=held.fd)
    except (vault_operation.VaultOperationError, OSError):
        log.error("vault initial reconciliation deferred: operation exclusion unavailable")

    while True:
        time.sleep(check_interval)
        try:
            with vault_operation.operation() as held:
                if not _reconcile_operation(operation_fd=held.fd):
                    grace_warned = False
                    continue
                mount_state, _mount_source = vault_mount_state()
                if mount_state != "expected":
                    if mount_state != "absent" or is_mapper_open():
                        _lock_vault_held(f"runtime_mount_state_{mount_state}", operation_fd=held.fd)
                        grace_warned = False
                        continue
                    state = read_state()
                    expected_state = "locked" if vault_has_configuration() else "setup_required"
                    if state.get("state") != expected_state:
                        write_state(expected_state, "vault not mounted")
                    grace_warned = False
                    continue
                if not exact_vault_mount_verified():
                    _lock_vault_held("runtime_exact_mount_verification_failed", operation_fd=held.fd)
                    grace_warned = False
                    continue

                activity_state, last = activity_timestamp()
                if activity_state == "invalid":
                    _lock_vault_held("invalid_activity_timestamp", operation_fd=held.fd)
                    grace_warned = False
                    continue
                if activity_state == "missing":
                    if not touch_activity():
                        _lock_vault_held("activity_timer_initialization_failed", operation_fd=held.fd)
                    grace_warned = False
                    continue

                idle = time.time() - last

                # Grace period warning
                if idle >= (timeout_seconds - GRACE_PERIOD) and not grace_warned:
                    remaining = int(timeout_seconds - idle)
                    log.warning("vault will lock in %d seconds due to inactivity", max(remaining, 0))
                    write_state("locking_soon", f"locking in {max(remaining, 0)}s")
                    grace_warned = True

                # Lock if idle timeout exceeded
                if idle >= timeout_seconds:
                    _lock_vault_held("idle_timeout", operation_fd=held.fd)
                    grace_warned = False

                # Reset grace warning if activity resumed
                if idle < (timeout_seconds - GRACE_PERIOD):
                    if grace_warned:
                        log.info("activity detected, lock cancelled")
                        write_state("unlocked")
                    grace_warned = False
        except (vault_operation.VaultOperationError, OSError):
            log.error("vault observation deferred: operation exclusion unavailable")


def main():
    parser = argparse.ArgumentParser(description="Vault auto-lock watchdog")
    parser.add_argument(
        "--timeout", type=int,
        default=int(os.getenv("VAULT_TIMEOUT", DEFAULT_TIMEOUT)),
        help="Idle timeout in minutes (default: 30)",
    )
    parser.add_argument(
        "--interval", type=int,
        default=int(os.getenv("VAULT_CHECK_INTERVAL", DEFAULT_CHECK_INTERVAL)),
        help="Check interval in seconds (default: 30)",
    )
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument(
        "--lock-once",
        action="store_true",
        help="Perform one fail-closed relock attempt and exit.",
    )
    actions.add_argument(
        "--unlock-once",
        action="store_true",
        help="Prompt locally for the passphrase, unlock once, and exit.",
    )
    parser.add_argument(
        "--reason",
        default="operator_request",
        help="Fixed audit reason for --lock-once.",
    )
    parser.add_argument(
        "--partition",
        default="",
        help="Optional /dev path for --unlock-once (otherwise use /etc/crypttab).",
    )
    args = parser.parse_args()

    if os.getuid() != 0:
        log.error("must run as root")
        sys.exit(1)

    if args.lock_once:
        sys.exit(0 if lock_vault(args.reason) else 1)
    if args.unlock_once:
        try:
            passphrase = getpass.getpass("Vault passphrase: ")
        except (EOFError, KeyboardInterrupt):
            log.error("vault unlock cancelled")
            sys.exit(1)
        if not passphrase:
            log.error("vault passphrase cannot be empty")
            sys.exit(1)
        result = unlock_vault(passphrase, args.partition)
        passphrase = ""
        if not result["success"]:
            log.error("%s", result["error"])
            sys.exit(1)
        sys.exit(0)
    if args.partition:
        parser.error("--partition requires --unlock-once")
    watchdog_loop(args.timeout, args.interval)


if __name__ == "__main__":
    main()
