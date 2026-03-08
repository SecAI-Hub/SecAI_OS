#!/usr/bin/env python3
"""
Secure AI Appliance — Landlock LSM Filesystem Policy Enforcer

Applies per-service Landlock filesystem access restrictions at process start.
Designed to be called as ExecStartPre= in systemd units, or as a wrapper.

Usage:
  landlock-apply.py <service-name>
  landlock-apply.py --check   # verify Landlock availability

Landlock is a Linux Security Module (kernel 5.13+) that restricts filesystem
access on a per-process basis. If Landlock is unavailable, a warning is logged
and execution continues (graceful degradation).

Policies are defined in /etc/secure-ai/policy/landlock.yaml.
"""

import ctypes
import ctypes.util
import json
import logging
import os
import struct
import sys
from pathlib import Path

import yaml

logging.basicConfig(
    level=logging.INFO,
    format="[landlock-apply] %(levelname)s %(message)s",
)
log = logging.getLogger("landlock-apply")

POLICY_PATH = os.getenv(
    "LANDLOCK_POLICY_PATH",
    "/etc/secure-ai/policy/landlock.yaml",
)

# Landlock ABI constants (kernel UAPI)
LANDLOCK_CREATE_RULESET_VERSION = 1 << 0

# Access rights for files (Landlock ABI v1+)
LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12

# Grouped access levels
ACCESS_RO = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
ACCESS_RW = (
    ACCESS_RO
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_DIR
)
ACCESS_EXE = LANDLOCK_ACCESS_FS_EXECUTE

ALL_ACCESS = (
    ACCESS_RW
    | ACCESS_EXE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM
)

# Syscall numbers (x86_64)
SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446

# Rule types
LANDLOCK_RULE_PATH_BENEATH = 1


def _load_libc():
    """Load libc for syscall access."""
    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        return None
    return ctypes.CDLL(libc_name, use_errno=True)


def check_landlock_available() -> int:
    """Check if Landlock is available. Returns ABI version or 0."""
    libc = _load_libc()
    if not libc:
        return 0

    try:
        # landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
        # returns the ABI version on success
        result = libc.syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            None,
            0,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
        if result >= 0:
            return result
    except Exception:
        pass
    return 0


def _access_for_mode(mode: str) -> int:
    """Convert 'ro', 'rw', 'exe' to Landlock access flags."""
    if mode == "ro":
        return ACCESS_RO
    elif mode == "rw":
        return ACCESS_RW
    elif mode == "exe":
        return ACCESS_EXE | ACCESS_RO  # exe implies read
    else:
        log.warning("unknown access mode '%s', defaulting to ro", mode)
        return ACCESS_RO


def apply_landlock(service_name: str) -> bool:
    """Apply Landlock restrictions for the named service.

    Returns True on success, False on failure (or if Landlock unavailable).
    """
    abi_version = check_landlock_available()
    if abi_version == 0:
        log.warning("Landlock not available on this kernel — skipping enforcement")
        return False

    log.info("Landlock ABI version %d available", abi_version)

    # Load policy
    try:
        with open(POLICY_PATH) as f:
            policy = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as e:
        log.error("failed to load policy: %s", e)
        return False

    service_policy = policy.get("services", {}).get(service_name)
    if not service_policy:
        log.warning("no Landlock policy for service '%s' — skipping", service_name)
        return False

    paths = service_policy.get("paths", [])
    if not paths:
        log.warning("empty path list for service '%s'", service_name)
        return False

    libc = _load_libc()
    if not libc:
        return False

    # 1. Create ruleset with all filesystem access handled
    # struct landlock_ruleset_attr { __u64 handled_access_fs; }
    ruleset_attr = struct.pack("Q", ALL_ACCESS)
    ruleset_fd = libc.syscall(
        SYS_LANDLOCK_CREATE_RULESET,
        ruleset_attr,
        len(ruleset_attr),
        0,
    )
    if ruleset_fd < 0:
        errno = ctypes.get_errno()
        log.error("landlock_create_ruleset failed: errno=%d", errno)
        return False

    # 2. Add rules for each allowed path
    for entry in paths:
        path = entry.get("path", "")
        access_mode = entry.get("access", "ro")

        if not os.path.exists(path):
            log.debug("path does not exist, skipping: %s", path)
            continue

        access_flags = _access_for_mode(access_mode)

        try:
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        except OSError as e:
            log.warning("cannot open path %s: %s", path, e)
            continue

        # struct landlock_path_beneath_attr { __u64 allowed_access; __s32 parent_fd; }
        # Padding to 16 bytes (8 + 4 + 4 padding)
        rule_attr = struct.pack("Qi", access_flags, fd)

        result = libc.syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            rule_attr,
            0,
        )
        os.close(fd)

        if result < 0:
            errno = ctypes.get_errno()
            log.warning("landlock_add_rule failed for %s: errno=%d", path, errno)
        else:
            log.debug("allowed %s access to %s", access_mode, path)

    # 3. Enforce the ruleset on the current process
    # First, drop ability to gain new privileges (required by Landlock)
    PR_SET_NO_NEW_PRIVS = 38
    libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

    result = libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0)
    os.close(ruleset_fd)

    if result < 0:
        errno = ctypes.get_errno()
        log.error("landlock_restrict_self failed: errno=%d", errno)
        return False

    log.info("Landlock policy applied for '%s' (%d path rules)", service_name, len(paths))
    return True


def main():
    if len(sys.argv) < 2:
        print("Usage: landlock-apply.py <service-name>")
        print("       landlock-apply.py --check")
        sys.exit(1)

    if sys.argv[1] == "--check":
        abi = check_landlock_available()
        if abi > 0:
            print(f"Landlock available (ABI version {abi})")
            sys.exit(0)
        else:
            print("Landlock not available")
            sys.exit(1)

    service = sys.argv[1]
    success = apply_landlock(service)
    if not success:
        # Non-fatal: log warning but allow service to start
        log.warning("Landlock not enforced for '%s' — continuing without", service)
    sys.exit(0)


if __name__ == "__main__":
    main()
