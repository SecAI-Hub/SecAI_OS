#!/usr/bin/python3 -I
"""Fail Tor startup unless its private state and enforcing labels are ready."""
import grp
import os
import pwd
import stat
import sys
from pathlib import Path

LOG_LIMIT = 64 * 1024 * 1024


class TorStartupError(ValueError):
    pass


def require_enforcing(path):
    if path.read_bytes() != b"1":
        raise TorStartupError("Tor requires enforcing SELinux")


def check_path(path, uid, gid, mode, label, *, directory=False):
    if any(parent.is_symlink() for parent in path.absolute().parents):
        raise TorStartupError("Tor prerequisite has a symlinked parent")
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or (not directory and info.st_nlink != 1):
        raise TorStartupError("Tor prerequisite has an unsafe file type or link count")
    if info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) != mode:
        raise TorStartupError("Tor prerequisite ownership or mode requires offline recovery")
    context = os.getxattr(path, "security.selinux", follow_symlinks=False).decode("ascii").rstrip("\x00\n")
    parts = context.split(":")
    if len(parts) < 4 or parts[2] != label:
        raise TorStartupError("Tor prerequisite SELinux label requires offline recovery")
    return info


def check_startup():
    if os.geteuid() != 0:
        raise TorStartupError("Tor prerequisite check requires its privileged system unit")
    require_enforcing(Path("/sys/fs/selinux/enforce"))
    user = pwd.getpwnam("secure-ai-tor")
    group = grp.getgrnam("secure-ai-tor")
    if user.pw_uid == 0 or user.pw_gid != group.gr_gid:
        raise TorStartupError("Tor requires its dedicated primary account and group")
    check_path(Path("/etc/secure-ai/tor/torrc"), 0, 0, 0o644, "tor_etc_t")
    check_path(Path("/var/lib/secure-ai/tor"), user.pw_uid, group.gr_gid, 0o700, "tor_var_lib_t", directory=True)
    log = check_path(Path("/var/lib/secure-ai/logs/tor.log"), user.pw_uid, group.gr_gid, 0o600, "tor_var_log_t")
    if log.st_size >= LOG_LIMIT:
        raise TorStartupError("Tor log reached its file ceiling; rotate it before restarting")


def main():
    try:
        check_startup()
    except (OSError, UnicodeError, KeyError, TorStartupError) as error:
        print(str(error) if isinstance(error, TorStartupError) else "Tor prerequisites unavailable", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
