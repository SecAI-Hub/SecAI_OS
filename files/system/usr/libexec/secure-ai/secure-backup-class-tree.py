#!/usr/bin/python3 -IB
"""Internal verified v3 object envelope to one inert logical class tree.

The caller must independently authenticate the backup and retain its canonical
manifest digest. This adapter verifies the extracted envelope again; it grants
no live destination, freshness, credential or activation authority.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import importlib.util
import os
from pathlib import Path
import stat

_spec = importlib.util.spec_from_file_location(
    "class_tree_v3", Path(__file__).with_name("secure-backup-v3.py"))
assert _spec and _spec.loader
v3 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(v3)
inventory, Error = v3.inventory, v3.ArchiveError


class _EnvelopeBudget:
    def __init__(self, limits, operation):
        self.local, self.operation = inventory.Budget(limits), operation

    def check(self) -> None:
        self.operation.check()
        self.local.check()

    def add(self, size: int = 0, path: str = "") -> None:
        self.check()
        self.local.add(size, path)


def _digest(fd: int, size: int, budget) -> str:
    count, digest = 0, hashlib.sha256()
    while True:
        budget.check()
        data = os.read(fd, min(65536, size + 1 - count))
        if not data:
            break
        count += len(data)
        if count > size:
            raise Error("extracted object grew during verification")
        digest.update(data)
    if count != size:
        raise Error("extracted object length differs")
    return digest.hexdigest()


class ClassTree:
    """SourceTree-compatible selected view; every envelope file is verified."""

    def __init__(self, root: Path, class_id: str, verified_manifest_sha256: str,
                 installed: dict, limits, budget):
        self.envelope = None
        try:
            if (type(class_id) is not str or class_id not in {"user-documents", "user-outputs"}
                    or type(verified_manifest_sha256) is not str
                    or not v3.DIGEST.fullmatch(verified_manifest_sha256)):
                raise Error("explicit supported class and verified manifest digest required")
            # The manifest and two envelope directories are framing, not class
            # payload. Permit only this fixed bounded overhead during census;
            # validate_manifest still enforces every original logical ceiling.
            values = vars(limits).copy()
            values.update(total=limits.total + limits.manifest,
                          file=max(limits.file, limits.manifest), entries=limits.entries + 3,
                          manifest=limits.manifest + 4096)
            envelope_limits = inventory.Limits(**values)
            self.envelope = inventory.SourceTree(root, envelope_limits, _EnvelopeBudget(envelope_limits, budget))
            self.fd, self.mount = self.envelope.fd, self.envelope.mount
            files = {}
            directories = set()
            for record in self.envelope.records:
                budget.check()
                directory = record["kind"] == "directory"
                identity = self.envelope.directories[record["path"]] if directory else record["identity"]
                if (identity[4] != os.geteuid()
                        or stat.S_IMODE(identity[2]) != (0o700 if directory else 0o600)):
                    raise Error("object envelope is not caller-owned private inert data")
                if directory:
                    directories.add(record["path"])
                else:
                    files[record["path"]] = record
            if "manifest.json" not in files or files["manifest.json"]["size"] > limits.manifest:
                raise Error("bounded extracted manifest required")
            with self.envelope.file(files["manifest.json"]) as fd:
                data = bytearray()
                while True:
                    budget.check()
                    chunk = os.read(fd, min(65536, limits.manifest + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                    if len(data) > limits.manifest:
                        raise Error("extracted manifest exceeds limit")
            manifest = inventory.strict_json(bytes(data), limits.manifest)
            if hashlib.sha256(inventory.encode(manifest)).hexdigest() != verified_manifest_sha256:
                raise Error("extracted manifest differs from verified receipt")
            actual = {}
            for name, record in files.items():
                if name == "manifest.json":
                    continue
                v3.object_name(name)
                if record["size"] > limits.file:
                    raise Error("extracted payload exceeds per-file limit")
                with self.envelope.file(record) as fd:
                    actual[name] = {"size": record["size"], "sha256": _digest(fd, record["size"], budget)}
            manifest = v3.validate_manifest(manifest, actual, installed, limits)
            expected_directories = {"", "objects"} if actual else {""}
            if directories != expected_directories:
                raise Error("unexpected extracted envelope directories")
            if manifest["classes"][class_id]["disposition"] not in {"included", "empty"}:
                raise Error("selected class has no verified logical root")
            self.inventory_sha256 = manifest["inventory_sha256"]
            self.manifest_sha256 = verified_manifest_sha256
            self.records, self.directories = [], {}
            for record in sorted((r for r in manifest["directories"] if r["class"] == class_id),
                                 key=lambda r: (r["path"].count("/"), r["path"])):
                budget.add(path=record["path"])
                self.records.append({"path": record["path"], "kind": "directory"})
                # Logical directories have no envelope inode. Their privacy
                # derives from the pinned envelope root, not archived metadata.
                self.directories[record["path"]] = self.envelope.directories[""]
            for record in sorted((r for r in manifest["objects"] if r["class"] == class_id),
                                 key=lambda r: r["path"]):
                budget.add(record["size"], record["path"])
                self.records.append({"path": record["path"], "kind": "file", "size": record["size"],
                                     "identity": files[record["id"]]["identity"],
                                     "sha256": record["sha256"], "object": files[record["id"]]})
            self.envelope.verify()
            budget.check()
        except BaseException:
            self.close()
            raise

    @contextmanager
    def file(self, record: dict):
        assert self.envelope is not None
        with self.envelope.file(record["object"]) as fd:
            yield fd

    def verify(self) -> None:
        assert self.envelope is not None
        self.envelope.verify()

    def close(self) -> None:
        if self.envelope is not None:
            self.envelope.close()
            self.envelope = None


if __name__ == "__main__":
    raise SystemExit("internal verified archive class mapping; active restore remains unavailable")
