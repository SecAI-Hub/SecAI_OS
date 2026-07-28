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
import json
import logging
import math
import os
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from secure_luks import (
    UUID_RE,
    LUKSError,
    configured_device,
    parse_crypttab,
    resolve_device,
)

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

# Services to stop when locking the vault
SERVICES_TO_STOP = [
    "secure-ai-inference.service",
    "secure-ai-diffusion.service",
    "secure-ai-agent.service",
    "secure-ai-mcp-firewall.service",
    "secure-ai-tool-firewall.service",
    "secure-ai-integrity-monitor.service",
    "secure-ai-quarantine-watcher.service",
    "secure-ai-registry.service",
    "secure-ai-vault-mounted.service",
]

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


def write_state(state: str, detail: str = "") -> bool:
    """Atomically write current vault state without following the target."""
    temporary = ""
    try:
        state_path = Path(STATE_FILE)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "state": state,
            "timestamp": time.time(),
            "detail": detail,
        }
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
        return True
    except OSError as e:
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
        return json.loads(Path(STATE_FILE).read_text())
    except (OSError, json.JSONDecodeError):
        return {"state": "unknown", "timestamp": 0}


def vault_mount_state() -> tuple[str, str]:
    """Return (absent|expected|unexpected|error, source) for the vault."""
    try:
        result = subprocess.run(
            ["findmnt", "-n", "-o", "SOURCE", "--mountpoint", MOUNT_POINT],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return "error", ""
    source = result.stdout.strip()
    if result.returncode == 1 and not source:
        return "absent", ""
    if result.returncode != 0 or not source or "\n" in source:
        return "error", source
    if source == f"/dev/mapper/{MAPPER_NAME}" or source.startswith(
        f"/dev/mapper/{MAPPER_NAME}["
    ):
        return "expected", source
    return "unexpected", source


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
    """Stop inference/diffusion/UI services before locking."""
    all_stopped = True
    for svc in SERVICES_TO_STOP:
        try:
            result = subprocess.run(
                ["systemctl", "stop", svc],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                all_stopped = False
                log.error("failed to stop %s: %s", svc, result.stderr.strip())
            else:
                log.info("stopped %s", svc)
        except Exception as e:
            all_stopped = False
            log.error("failed to stop %s: %s", svc, e)
    return all_stopped


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
            result = subprocess.run(
                ["systemctl", "start", svc],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                failures.append(svc)
                log.error("failed to start %s: %s", svc, result.stderr.strip())
            else:
                log.info("started %s", svc)
        except (OSError, subprocess.SubprocessError) as e:
            failures.append(svc)
            log.error("failed to start %s: %s", svc, e)
    return not failures, failures


def close_mapper() -> bool:
    """Close the fixed vault mapper and verify that it disappeared."""
    try:
        result = subprocess.run(
            ["cryptsetup", "close", MAPPER_NAME],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.error("cryptsetup close failed: %s", exc)
        return False
    if result.returncode != 0:
        log.error("cryptsetup close failed: %s", result.stderr.strip())
        return False
    return not is_mapper_open()


def lock_vault(reason: str = "idle_timeout") -> bool:
    """Lock the vault: stop services, unmount, close LUKS."""
    log.warning("LOCKING VAULT — reason: %s", reason)
    audit_event("vault_lock", reason=reason)

    mount_state, mount_source = vault_mount_state()
    if mount_state in {"error", "unexpected"}:
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
        state = "locked" if vault_has_configuration() else "setup_required"
        if not write_state(state, reason):
            return False
        log.info("vault is not mounted (%s)", state)
        return True

    # 2. Sync filesystem
    try:
        subprocess.run(["sync"], check=True, timeout=10)
    except Exception as e:
        log.error("filesystem sync failed: %s", e)
        write_state("error", f"filesystem sync failed: {e}")
        return False

    # 3. Unmount
    if mount_state == "expected":
        try:
            result = subprocess.run(
                ["umount", MOUNT_POINT],
                capture_output=True, text=True, timeout=30,
            )
        except Exception as e:
            log.error("unmount failed: %s", e)
            write_state("error", f"unmount failed: {e}")
            return False
        after_state, _after_source = vault_mount_state()
        if result.returncode != 0 or after_state != "absent":
            detail = result.stderr.strip() or f"mount state after unmount: {after_state}"
            log.error("unmount failed: %s", detail)
            write_state("error", f"unmount failed: {detail}")
            return False

    # 4. Close LUKS
    if is_mapper_open():
        if not close_mapper():
            write_state("error", "cryptsetup close failed")
            return False

    if not write_state("locked", reason):
        return False
    log.info("vault locked successfully")
    return True


def unlock_vault(passphrase: str, partition: str = "") -> dict:
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

    initial_mount_state, initial_source = vault_mount_state()
    if initial_mount_state == "expected":
        if exact_vault_mount_verified():
            return {"success": True, "detail": "already unlocked"}
        relocked = lock_vault("preexisting_mount_verification_failed")
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
            )
            if proc.returncode != 0:
                audit_event("vault_unlock_failed", reason="authentication_or_device_error")
                return {"success": False, "error": "incorrect passphrase or device error"}
        except (OSError, subprocess.SubprocessError) as exc:
            audit_event("vault_unlock_failed", reason="cryptsetup_execution_error")
            return {"success": False, "error": f"cryptsetup failed: {exc}"}

    # 2. Mount
    mount_completed = False
    try:
        Path(MOUNT_POINT).mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "mount",
                "-o",
                "nodev,nosuid,noexec",
                "--",
                f"/dev/mapper/{MAPPER_NAME}",
                MOUNT_POINT,
            ],
            capture_output=True, check=True, timeout=30,
        )
        mount_completed = True
        mounted_state, _mounted_source = vault_mount_state()
        if mounted_state != "expected":
            raise RuntimeError(
                f"mounted source did not match the expected mapper: {mounted_state}"
            )
        if not exact_vault_mount_verified():
            raise RuntimeError("exact encrypted vault mount verification failed")
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        unmount_failed = False
        if mount_completed:
            try:
                unmounted = subprocess.run(
                    ["umount", MOUNT_POINT],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                unmount_failed = unmounted.returncode != 0
            except (OSError, subprocess.SubprocessError):
                unmount_failed = True
        cleanup_failed = opened_here and (unmount_failed or not close_mapper())
        detail = (
            "mount failed and newly opened mapper cleanup failed"
            if cleanup_failed
            else "mount failed"
        )
        audit_event("vault_unlock_failed", reason=detail.replace(" ", "_"))
        write_state("error", detail)
        return {"success": False, "error": f"{detail}: {exc}"}

    # 3. Start only services configured to start on this appliance.
    services_started, failures = start_services()
    if not services_started:
        detail = f"vault mounted but services failed to start: {', '.join(failures)}"
        audit_event("vault_unlock_partial", failed_services=failures)
        relocked = lock_vault("service_restart_failed")
        if not relocked:
            detail += "; automatic relock failed"
        write_state("error", detail)
        return {"success": False, "error": detail}

    # 4. Reset the idle timer after the UI runtime directory exists.
    if not touch_activity():
        detail = "vault activity timer could not be initialized"
        relocked = lock_vault("activity_timer_initialization_failed")
        if not relocked:
            detail += "; automatic relock failed"
        write_state("error", detail)
        return {"success": False, "error": detail}

    if not write_state("unlocked"):
        detail = "vault state could not be persisted"
        relocked = lock_vault("state_persistence_failed")
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


def watchdog_loop(timeout_minutes: int, check_interval: int):
    """Main watchdog loop. Monitors activity and locks on idle timeout."""
    timeout_seconds = timeout_minutes * 60
    grace_warned = False

    log.info("vault watchdog started (timeout=%dm, check=%ds)", timeout_minutes, check_interval)

    # Set initial state
    mount_state, _mount_source = vault_mount_state()
    if mount_state == "expected":
        if not exact_vault_mount_verified():
            lock_vault("startup_exact_mount_verification_failed")
        elif not write_state("unlocked") or not touch_activity():
            lock_vault("activity_timer_initialization_failed")
    elif mount_state == "absent" and not is_mapper_open() and not vault_has_configuration():
        write_state("setup_required", "encrypted vault is not configured")
    else:
        lock_vault(f"startup_mount_state_{mount_state}")

    while True:
        time.sleep(check_interval)

        mount_state, _mount_source = vault_mount_state()
        if mount_state != "expected":
            if mount_state != "absent" or is_mapper_open():
                lock_vault(f"runtime_mount_state_{mount_state}")
                grace_warned = False
                continue
            state = read_state()
            expected_state = "locked" if vault_has_configuration() else "setup_required"
            if state.get("state") != expected_state:
                write_state(expected_state, "vault not mounted")
            grace_warned = False
            continue
        if not exact_vault_mount_verified():
            lock_vault("runtime_exact_mount_verification_failed")
            grace_warned = False
            continue

        activity_state, last = activity_timestamp()
        if activity_state == "invalid":
            lock_vault("invalid_activity_timestamp")
            grace_warned = False
            continue
        if activity_state == "missing":
            if not touch_activity():
                lock_vault("activity_timer_initialization_failed")
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
            lock_vault("idle_timeout")
            grace_warned = False

        # Reset grace warning if activity resumed
        if idle < (timeout_seconds - GRACE_PERIOD):
            if grace_warned:
                log.info("activity detected, lock cancelled")
                write_state("unlocked")
            grace_warned = False


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
