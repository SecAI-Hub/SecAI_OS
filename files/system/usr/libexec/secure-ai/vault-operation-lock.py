"""Fixed advisory exclusion for installed vault operations, not global quiescence."""
from __future__ import annotations

import fcntl
import os
import stat
import sys
import time
from pathlib import Path

_LOCK_PATH = Path("/run/secure-ai/vault-operation.lock")
_OWNER_UID = _OWNER_GID = 0
_ACQUIRE_SECONDS = 10.0
_SETUP_FD = 9
_SETUP_MARKER = "SECAI_VAULT_OPERATION_FD"


class VaultOperationError(RuntimeError):
    """Exclusion is unavailable; no vault operation is authorized."""


def _directory_id(fd: int) -> tuple:
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != _OWNER_UID or info.st_mode & 0o022:
        raise VaultOperationError("unsafe vault operation lock directory")
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _file_id(info: os.stat_result) -> tuple:
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != 0
            or info.st_uid != _OWNER_UID or info.st_gid != _OWNER_GID
            or stat.S_IMODE(info.st_mode) != 0o600):
        raise VaultOperationError("unsafe preprovisioned vault operation lock")
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _open_parent() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for part in _LOCK_PATH.parent.parts[1:]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        _directory_id(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _check(parent: int, fd: int, directory: tuple, identity: tuple) -> None:
    current = _open_parent()
    try:
        if _directory_id(parent) != directory or _directory_id(current) != directory:
            raise VaultOperationError("vault operation lock directory changed")
        named = os.stat(_LOCK_PATH.name, dir_fd=current, follow_symlinks=False)
        if _file_id(os.fstat(fd)) != identity or _file_id(named) != identity:
            raise VaultOperationError("vault operation lock identity changed")
    finally:
        os.close(current)


class operation:
    """Per-operation, bounded exclusive flock; never create or replace its inode.

    This lock covers cooperating installed helpers only. It is not reentrant;
    rollback must use the caller's already-held internal operation functions.
    """

    def __init__(self):
        self.fd = self.parent = -1

    def __enter__(self):
        try:
            if sys.platform != "linux" or os.getuid() != _OWNER_UID or os.geteuid() != _OWNER_UID:
                raise VaultOperationError("vault operation exclusion requires root")
            self.parent = _open_parent()
            # Linux local-filesystem flock works on a read-only descriptor. No
            # writable bind mount or mutation of the stable inode is required.
            self.fd = os.open(_LOCK_PATH.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                              dir_fd=self.parent)
            self.directory = _directory_id(self.parent)
            self.identity = _file_id(os.fstat(self.fd))
            deadline = time.monotonic() + _ACQUIRE_SECONDS
            while True:
                self.check()
                if time.monotonic() > deadline:
                    raise VaultOperationError("vault operation busy")
                try:
                    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise VaultOperationError("vault operation busy") from None
                    time.sleep(min(0.05, remaining))
            self.check()
            if time.monotonic() > deadline:
                raise VaultOperationError("vault operation acquisition expired")
            return self
        except (OSError, VaultOperationError) as exc:
            self.close()
            raise VaultOperationError("vault operation exclusion unavailable") from exc
        except BaseException:
            self.close()
            raise

    def check(self) -> None:
        _check(self.parent, self.fd, self.directory, self.identity)

    def close(self) -> None:
        # Closing our OFD reference releases it normally. Explicit LOCK_UN would
        # incorrectly unlock a setup shell's inherited reference to the same OFD.
        for name in ("fd", "parent"):
            fd = getattr(self, name)
            if fd >= 0:
                os.close(fd)
                setattr(self, name, -1)

    def __exit__(self, kind, value, traceback):
        try:
            if kind is None:
                try:
                    self.check()
                except OSError as exc:
                    raise VaultOperationError("vault operation exclusion changed") from exc
        finally:
            self.close()


def _validate_setup() -> None:
    """Validate/acquire the fixed inherited OFD; leave the shell's FD locked."""
    fd = parent = -1
    try:
        if os.getuid() != _OWNER_UID or os.geteuid() != _OWNER_UID:
            raise VaultOperationError("vault setup exclusion requires root")
        fd = os.dup(_SETUP_FD)
        parent = _open_parent()
        directory, identity = _directory_id(parent), _file_id(os.fstat(fd))
        _check(parent, fd, directory, identity)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _check(parent, fd, directory, identity)
    finally:
        for descriptor in (fd, parent):
            if descriptor >= 0:
                os.close(descriptor)


def main() -> int:
    try:
        if sys.argv[1:] == ["validate-setup"]:
            _validate_setup()
            return 0
        if len(sys.argv) != 3 or sys.argv[1] != "setup":
            raise VaultOperationError("only fixed vault setup/FD validation is supported")
        with operation() as held:
            if held.parent == _SETUP_FD:
                moved = fcntl.fcntl(held.parent, fcntl.F_DUPFD_CLOEXEC, _SETUP_FD + 1)
                os.close(held.parent)
                held.parent = moved
            os.dup2(held.fd, _SETUP_FD, inheritable=True)
            os.set_inheritable(_SETUP_FD, True)
            setup = str(Path(__file__).with_name("setup-vault.sh"))
            try:
                os.execve(setup, [setup, sys.argv[2]], {**os.environ, _SETUP_MARKER: str(_SETUP_FD)})
            finally:
                if held.fd != _SETUP_FD:
                    os.close(_SETUP_FD)
        return 1  # execve must replace this process.
    except (OSError, VaultOperationError):
        print("ERROR: vault operation exclusion unavailable; no operation authorized", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
