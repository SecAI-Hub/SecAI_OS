#!/usr/bin/env python3
"""
Secure AI Appliance — Landlock LSM Filesystem Policy Enforcer

Applies per-service Landlock filesystem access restrictions at process start.
Designed to be called as ExecStartPre= in systemd units, or as a wrapper.

Usage:
  landlock-apply.py [--require] <service-name> -- <command> [args...]
  landlock-apply.py --check   # verify Landlock availability

Landlock is a Linux Security Module (kernel 5.13+) that restricts filesystem
access on a per-process basis. Production wrappers use --require and fail
closed if the kernel or a complete policy is unavailable. Non-production
callers may omit --require to request explicit graceful degradation.

Policies are defined in /etc/secure-ai/policy/landlock.yaml.
"""

import ctypes
import ctypes.util
import logging
import os
import platform
import struct
import sys

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
LANDLOCK_ACCESS_FS_REFER = 1 << 13       # ABI v2
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14    # ABI v3
LANDLOCK_ACCESS_FS_IOCTL_DEV = 1 << 15   # ABI v5

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

ABI_V1_ACCESS = (
    ACCESS_RW
    | ACCESS_EXE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM
)

# Linux uses these syscall numbers on the Fedora architectures supported by
# this appliance. Refuse unknown architectures rather than invoking an
# unrelated syscall number.
LANDLOCK_SYSCALLS = {
    "x86_64": (444, 445, 446),
    "amd64": (444, 445, 446),
    "aarch64": (444, 445, 446),
    "arm64": (444, 445, 446),
}

# Rule types
LANDLOCK_RULE_PATH_BENEATH = 1


def _load_libc():
    """Load libc for syscall access."""
    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        return None
    return ctypes.CDLL(libc_name, use_errno=True)


def _syscall_numbers(machine: str | None = None) -> tuple[int, int, int] | None:
    """Return Landlock syscall numbers for a supported Fedora architecture."""
    return LANDLOCK_SYSCALLS.get((machine or platform.machine()).lower())


def _handled_access_for_abi(abi_version: int) -> int:
    """Build the complete filesystem rights mask supported by this ABI."""
    handled = ABI_V1_ACCESS
    if abi_version >= 2:
        handled |= LANDLOCK_ACCESS_FS_REFER
    if abi_version >= 3:
        handled |= LANDLOCK_ACCESS_FS_TRUNCATE
    if abi_version >= 5:
        handled |= LANDLOCK_ACCESS_FS_IOCTL_DEV
    return handled


def check_landlock_available() -> int:
    """Check if Landlock is available. Returns ABI version or 0."""
    libc = _load_libc()
    syscalls = _syscall_numbers()
    if not libc or not syscalls:
        return 0
    create_ruleset, _, _ = syscalls

    try:
        # landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
        # returns the ABI version on success
        result = libc.syscall(
            create_ruleset,
            None,
            0,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
        if result >= 0:
            return result
    except Exception:
        pass
    return 0


def _access_for_mode(mode: str, abi_version: int = 1) -> int:
    """Convert 'ro', 'rw', 'exe' to Landlock access flags."""
    if mode == "ro":
        return ACCESS_RO
    elif mode == "rw":
        access = ACCESS_RW
        # REFER and TRUNCATE are mutation rights: grant them only to explicitly
        # writable rules. IOCTL_DEV is likewise excluded from read-only paths.
        if abi_version >= 2:
            access |= LANDLOCK_ACCESS_FS_REFER
        if abi_version >= 3:
            access |= LANDLOCK_ACCESS_FS_TRUNCATE
        if abi_version >= 5:
            access |= LANDLOCK_ACCESS_FS_IOCTL_DEV
        return access
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

    paths = list(service_policy.get("paths", []))
    if service_policy.get("include_common_paths", True):
        paths = list(policy.get("common_paths", [])) + paths
    if not paths:
        log.warning("empty path list for service '%s'", service_name)
        return False

    libc = _load_libc()
    syscalls = _syscall_numbers()
    if not libc or not syscalls:
        log.error("unsupported architecture for Landlock syscalls: %s", platform.machine())
        return False
    create_ruleset, add_rule, restrict_self = syscalls

    # 1. Create a ruleset handling every filesystem right supported by the
    # detected ABI. Omitting newer rights leaves those operations unrestricted.
    # struct landlock_ruleset_attr { __u64 handled_access_fs; }
    handled_access = _handled_access_for_abi(abi_version)
    ruleset_attr = struct.pack("Q", handled_access)
    ruleset_fd = libc.syscall(
        create_ruleset,
        ruleset_attr,
        len(ruleset_attr),
        0,
    )
    if ruleset_fd < 0:
        errno = ctypes.get_errno()
        log.error("landlock_create_ruleset failed: errno=%d", errno)
        return False

    # 2. Add rules for each allowed path
    added_rules = 0
    rule_failed = False
    for entry in paths:
        path = entry.get("path", "")
        access_mode = entry.get("access", "ro")

        if not os.path.exists(path):
            if entry.get("required", False):
                log.error("required Landlock path does not exist: %s", path)
                rule_failed = True
            else:
                log.debug("optional path does not exist, skipping: %s", path)
            continue

        access_flags = _access_for_mode(access_mode, abi_version)

        try:
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        except OSError as e:
            log.error("cannot open path %s: %s", path, e)
            rule_failed = True
            continue

        # struct landlock_path_beneath_attr { __u64 allowed_access; __s32 parent_fd; }
        # Padding to 16 bytes (8 + 4 + 4 padding)
        rule_attr = struct.pack("Qi", access_flags, fd)

        result = libc.syscall(
            add_rule,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            rule_attr,
            0,
        )
        os.close(fd)

        if result < 0:
            errno = ctypes.get_errno()
            log.warning("landlock_add_rule failed for %s: errno=%d", path, errno)
            rule_failed = True
        else:
            added_rules += 1
            log.debug("allowed %s access to %s", access_mode, path)

    if rule_failed or added_rules == 0:
        os.close(ruleset_fd)
        log.error("refusing partial/empty Landlock policy for '%s'", service_name)
        return False

    # 3. Enforce the ruleset on the current process
    # First, drop ability to gain new privileges (required by Landlock)
    PR_SET_NO_NEW_PRIVS = 38
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        errno = ctypes.get_errno()
        os.close(ruleset_fd)
        log.error("prctl(PR_SET_NO_NEW_PRIVS) failed: errno=%d", errno)
        return False

    result = libc.syscall(restrict_self, ruleset_fd, 0)
    os.close(ruleset_fd)

    if result < 0:
        errno = ctypes.get_errno()
        log.error("landlock_restrict_self failed: errno=%d", errno)
        return False

    log.info("Landlock policy applied for '%s' (%d path rules)", service_name, len(paths))
    return True


def main():
    if len(sys.argv) < 2:
        print("Usage: landlock-apply.py [--require] <service-name> -- <command> [args...]")
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

    require = False
    args = sys.argv[1:]
    if args and args[0] == "--require":
        require = True
        args = args[1:]
    if not args:
        log.error("service name is required")
        sys.exit(2)
    service = args[0]
    command = []
    if "--" in args[1:]:
        separator = args.index("--")
        command = args[separator + 1 :]
    if not command:
        log.error("a command is required after --")
        sys.exit(2)

    success = apply_landlock(service)
    if not success:
        if require:
            log.error("Landlock is required for '%s'; refusing to execute", service)
            sys.exit(1)
        log.warning("Landlock not enforced for '%s' — continuing without", service)

    # Landlock restrictions are inherited across execve.  Applying them in an
    # ExecStartPre process would confine only that helper and then disappear.
    log.info("executing confined service: %s", command[0])
    os.execvp(command[0], command)


if __name__ == "__main__":
    main()
