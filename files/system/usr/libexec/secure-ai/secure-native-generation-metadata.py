#!/usr/bin/python3 -IB
"""B2 metadata planning only; no ownership changes or active restore.

Old generation metadata comes from pinned filesystem descriptors and is never
normalized to incoming target metadata. Incoming documents/outputs use only the
installed inventory, locally allocated groups and installed SELinux policy.
These records are not archive-supplied authority or a native adapter. Callers
must still qualify writer coverage, mount binding, policy stability and replay.
"""
from __future__ import annotations

import errno
import grp
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
from typing import Callable, NamedTuple

_spec = importlib.util.spec_from_file_location(
    "metadata_guard", Path(__file__).with_name("secure-maintenance-guard.py"))
assert _spec and _spec.loader
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)
inventory = guard._inventory
Error = guard.RecoveryError
INVENTORY = Path("/etc/secure-ai/config/backup-inventory.json")
EXPECTED = {
    "user-documents": ("vault/user_docs", "secure-ai-vault-read", "2750"),
    "user-outputs": ("vault/outputs", "secure-ai-vault-write", "2770"),
}


def snapshot_existing(fd: int) -> dict:
    """Capture actual metadata, not permission to activate it or a byte snapshot."""
    before = os.fstat(fd)
    try:
        inventory.check_metadata(fd, before)
    except inventory.ArchiveError as exc:
        raise Error("unsupported existing generation metadata") from exc
    try:
        label = os.getxattr(fd, "security.selinux")
    except OSError as exc:
        if exc.errno not in (errno.ENODATA, errno.ENOTSUP):
            raise
        label = None
    if label is not None and len(label) > 4096:
        raise Error("existing SELinux metadata exceeds bound")
    if inventory.identity(before) != inventory.identity(os.fstat(fd)):
        raise Error("existing generation metadata changed while reading")
    return {
        "kind": "directory" if stat.S_ISDIR(before.st_mode) else "file",
        "uid": before.st_uid, "gid": before.st_gid,
        "mode": stat.S_IMODE(before.st_mode),
        "selinux_hex": None if label is None else label.hex(),
    }


def _probe(command: list[str], maximum: int) -> bytes:
    try:
        result = subprocess.run(
            command, stdin=subprocess.DEVNULL, capture_output=True, timeout=5,
            env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise Error("installed SELinux target policy unavailable") from exc
    if result.returncode or len(result.stdout) > maximum or len(result.stderr) > 8192:
        raise Error("installed SELinux target policy probe failed")
    return result.stdout.strip()


def _target_context(path: Path, directory: bool, check: Callable[[], None] | None = None) -> str:
    def probe(command: list[str], maximum: int) -> bytes:
        if check is not None:
            check()
        value = _probe(command, maximum)
        if check is not None:
            check()
        return value

    command = ["/usr/sbin/getenforce"]
    if probe(command, 32) != b"Enforcing":
        raise Error("enforcing SELinux required for native target metadata")
    raw = probe([
        "/usr/sbin/matchpathcon", "-N", "-n", "-m", "dir" if directory else "file", str(path),
    ], 4096)
    if (not raw or raw.count(b":") < 2 or any(value < 33 or value > 126 for value in raw)
            or probe(command, 32) != b"Enforcing"):
        raise Error("unavailable or unstable native target context")
    return raw.decode("ascii")


class IncomingPolicy(NamedTuple):
    class_id: str
    target: Path
    group_name: str
    gid: int
    directory_mode: int
    inventory_sha256: str

    def profile(self) -> dict:
        """Serializable local contract; never reconstructed as archive authority."""
        return {
            "class": self.class_id, "target": str(self.target), "group": self.group_name,
            "gid": self.gid, "directory_mode": self.directory_mode,
            "inventory_sha256": self.inventory_sha256,
        }

    def target_metadata(self, relative: str, *, directory: bool,
                        check: Callable[[], None] | None = None) -> dict:
        if check is not None:
            check()
        if type(directory) is not bool:
            raise Error("explicit target object type required")
        try:
            relative = inventory.relative_name(relative, inventory.Limits(), root=directory)
        except inventory.ArchiveError as exc:
            raise Error("invalid native target relative name") from exc
        path = self.target / relative
        return {
            "class": self.class_id, "uid": 0, "gid": self.gid,
            "mode": self.directory_mode if directory else 0o640,
            "selinux": _target_context(path, directory) if check is None else _target_context(path, directory, check),
            "inventory_sha256": self.inventory_sha256,
        }


def installed_incoming_policy(class_id: str) -> IncomingPolicy:
    if type(class_id) is not str or class_id not in EXPECTED:
        raise Error("native incoming class is unsupported")
    try:
        selected = inventory.load_inventory(INVENTORY, trusted=True)
        local = inventory.local_policy(selected, class_id)
    except (OSError, inventory.ArchiveError) as exc:
        raise Error("installed incoming metadata contract unavailable") from exc
    target, group, mode = EXPECTED[class_id]
    expected = {
        "target": target, "owner": "root", "group": group, "file_mode": "0640",
        "directory_mode": mode, "disposition": "inert-data",
    }
    source = next(item for item in selected["classes"] if item["id"] == class_id)
    if (local != expected or source["source"] != "var/lib/secure-ai/" + target
            or source["shape"] != "tree" or source["required"] is not True):
        raise Error("native incoming policy requires a reviewed adapter")
    try:
        gid = grp.getgrnam(group).gr_gid
    except KeyError as exc:
        raise Error("installed native target group unavailable") from exc
    if type(gid) is not int or not 0 < gid < 2**32 - 1:
        raise Error("invalid local native target group")
    return IncomingPolicy(
        class_id, Path("/var/lib/secure-ai") / target, group, gid, int(mode, 8),
        hashlib.sha256(guard.encode(selected)).hexdigest(),
    )


if __name__ == "__main__":
    raise SystemExit("native metadata planner only; active restore remains unavailable")
