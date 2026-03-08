#!/usr/bin/env python3
"""
Secure AI Appliance — Vault Auto-Lock Watchdog

Monitors the last-activity timestamp and automatically locks the LUKS vault
after a configurable period of inactivity. When the vault is locked:
  1. All running inference/diffusion workers are stopped
  2. The vault filesystem is unmounted
  3. The LUKS mapper is closed

The vault must be manually unlocked via the UI or CLI to resume operation.

Activity is tracked via a timestamp file written by the UI on every
authenticated API request.

Usage: vault-watchdog.py [--interval SECONDS] [--timeout MINUTES]
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="[vault-watchdog] %(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("vault-watchdog")

MAPPER_NAME = "secure-ai-vault"
MOUNT_POINT = "/var/lib/secure-ai"
ACTIVITY_FILE = "/run/secure-ai/last-activity"
STATE_FILE = "/run/secure-ai/vault-state"
AUDIT_LOG = "/var/lib/secure-ai/logs/vault-audit.jsonl"

# Services to stop when locking the vault
SERVICES_TO_STOP = [
    "secure-ai-inference.service",
    "secure-ai-diffusion.service",
    "secure-ai-ui.service",
]

# Default settings
DEFAULT_TIMEOUT = 30  # minutes
DEFAULT_CHECK_INTERVAL = 30  # seconds
GRACE_PERIOD = 60  # seconds — warn before locking


def read_last_activity() -> float:
    """Read the last-activity timestamp. Returns 0.0 if not found."""
    try:
        return float(Path(ACTIVITY_FILE).read_text().strip())
    except (OSError, ValueError):
        return 0.0


def write_state(state: str, detail: str = ""):
    """Write current vault state to the state file."""
    try:
        Path(STATE_FILE).parent.mkdir(parents=True, exist_ok=True)
        data = {
            "state": state,
            "timestamp": time.time(),
            "detail": detail,
        }
        Path(STATE_FILE).write_text(json.dumps(data))
    except OSError as e:
        log.error("failed to write state file: %s", e)


def read_state() -> dict:
    """Read current vault state."""
    try:
        return json.loads(Path(STATE_FILE).read_text())
    except (OSError, json.JSONDecodeError):
        return {"state": "unknown", "timestamp": 0}


def is_vault_mounted() -> bool:
    """Check if the vault LUKS partition is mounted."""
    try:
        result = subprocess.run(
            ["findmnt", "-n", "-o", "SOURCE", MOUNT_POINT],
            capture_output=True, text=True, timeout=5,
        )
        return MAPPER_NAME in result.stdout
    except Exception:
        return False


def is_mapper_open() -> bool:
    """Check if the LUKS mapper device exists."""
    return Path(f"/dev/mapper/{MAPPER_NAME}").exists()


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


def stop_services():
    """Stop inference/diffusion/UI services before locking."""
    for svc in SERVICES_TO_STOP:
        try:
            subprocess.run(
                ["systemctl", "stop", svc],
                capture_output=True, timeout=30,
            )
            log.info("stopped %s", svc)
        except Exception as e:
            log.warning("failed to stop %s: %s", svc, e)


def start_services():
    """Restart services after unlocking."""
    for svc in SERVICES_TO_STOP:
        try:
            subprocess.run(
                ["systemctl", "start", svc],
                capture_output=True, timeout=30,
            )
            log.info("started %s", svc)
        except Exception as e:
            log.warning("failed to start %s: %s", svc, e)


def lock_vault(reason: str = "idle_timeout") -> bool:
    """Lock the vault: stop services, unmount, close LUKS."""
    log.warning("LOCKING VAULT — reason: %s", reason)
    audit_event("vault_lock", reason=reason)

    # 1. Stop services
    stop_services()

    # 2. Sync filesystem
    try:
        subprocess.run(["sync"], timeout=10)
    except Exception:
        pass

    # 3. Unmount
    try:
        result = subprocess.run(
            ["umount", MOUNT_POINT],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            # Force unmount if busy
            subprocess.run(
                ["umount", "-l", MOUNT_POINT],
                capture_output=True, timeout=30,
            )
    except Exception as e:
        log.error("unmount failed: %s", e)

    # 4. Close LUKS
    try:
        result = subprocess.run(
            ["cryptsetup", "close", MAPPER_NAME],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            log.error("cryptsetup close failed: %s", result.stderr)
            write_state("error", f"cryptsetup close failed: {result.stderr.strip()}")
            return False
    except Exception as e:
        log.error("cryptsetup close failed: %s", e)
        write_state("error", str(e))
        return False

    write_state("locked", reason)
    log.info("vault locked successfully")
    return True


def unlock_vault(passphrase: str, partition: str = "") -> dict:
    """Unlock the vault: open LUKS, mount, start services.

    The partition is read from /etc/crypttab if not provided.
    Returns {"success": True/False, "error": "..."}.
    """
    if is_vault_mounted():
        return {"success": True, "detail": "already unlocked"}

    # Find the partition from crypttab if not specified
    if not partition:
        partition = _find_partition_from_crypttab()
        if not partition:
            return {"success": False, "error": "cannot determine vault partition"}

    # 1. Open LUKS
    try:
        proc = subprocess.run(
            ["cryptsetup", "open", partition, MAPPER_NAME],
            input=passphrase,
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            audit_event("vault_unlock_failed", error=proc.stderr.strip())
            return {"success": False, "error": "incorrect passphrase or device error"}
    except Exception as e:
        return {"success": False, "error": str(e)}

    # 2. Mount
    try:
        Path(MOUNT_POINT).mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["mount", f"/dev/mapper/{MAPPER_NAME}", MOUNT_POINT],
            capture_output=True, check=True, timeout=30,
        )
    except Exception as e:
        return {"success": False, "error": f"mount failed: {e}"}

    # 3. Touch activity file
    touch_activity()

    # 4. Start services
    start_services()

    write_state("unlocked")
    audit_event("vault_unlock")
    log.info("vault unlocked successfully")
    return {"success": True}


def touch_activity():
    """Update the last-activity timestamp."""
    try:
        Path(ACTIVITY_FILE).parent.mkdir(parents=True, exist_ok=True)
        Path(ACTIVITY_FILE).write_text(str(time.time()))
    except OSError:
        pass


def _find_partition_from_crypttab() -> str:
    """Read /etc/crypttab to find the vault partition."""
    try:
        for line in Path("/etc/crypttab").read_text().splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] == MAPPER_NAME:
                device = parts[1]
                # Resolve UUID= references
                if device.startswith("UUID="):
                    uuid = device[5:]
                    dev_path = Path(f"/dev/disk/by-uuid/{uuid}")
                    if dev_path.exists():
                        return str(dev_path.resolve())
                return device
    except OSError:
        pass
    return ""


def watchdog_loop(timeout_minutes: int, check_interval: int):
    """Main watchdog loop. Monitors activity and locks on idle timeout."""
    timeout_seconds = timeout_minutes * 60
    grace_warned = False

    log.info("vault watchdog started (timeout=%dm, check=%ds)", timeout_minutes, check_interval)

    # Set initial state
    if is_vault_mounted():
        write_state("unlocked")
        touch_activity()
    else:
        write_state("locked", "vault not mounted at startup")
        log.info("vault is not mounted, waiting for unlock...")

    while True:
        time.sleep(check_interval)

        # If vault is not mounted, nothing to watch
        if not is_vault_mounted():
            state = read_state()
            if state.get("state") != "locked":
                write_state("locked", "vault not mounted")
            grace_warned = False
            continue

        last = read_last_activity()
        if last == 0.0:
            # No activity recorded yet — touch it now
            touch_activity()
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
    args = parser.parse_args()

    if os.getuid() != 0:
        log.error("must run as root")
        sys.exit(1)

    watchdog_loop(args.timeout, args.interval)


if __name__ == "__main__":
    main()
