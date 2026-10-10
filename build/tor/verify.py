#!/usr/bin/env python3
"""Validate the committed Tor source contract and its staged offline handoff."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

HEX = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,254}\Z")
VERSION = "0.4.9.14"


def json_object(data: bytes) -> dict:
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result
    def constant(_):
        raise ValueError("nonfinite JSON value")
    result = json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    if not isinstance(result, dict):
        raise TypeError("JSON object required")
    return result


def stable_bytes(path: Path, maximum: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError("input is not a bounded regular file")
        data = handle.read(maximum + 1)
        after = os.fstat(handle.fileno())
        current = path.lstat()
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_mtime_ns, info.st_ctime_ns)
    if len(data) > maximum or len(data) != before.st_size or identity(before) != identity(after) or identity(after) != identity(current):
        raise ValueError("input changed during verification")
    return data


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_contract(path: Path) -> tuple[dict, bytes]:
    raw = stable_bytes(path, 128 << 10)
    lock = json_object(raw)
    required = {"schema_version", "version", "architecture", "release", "upstream_signature", "fedora_signature", "remote_inputs", "local_inputs", "build", "provenance", "qualification_limits"}
    if set(lock) != required or type(lock["schema_version"]) is not int or lock["schema_version"] != 1 or lock["version"] != VERSION or lock["architecture"] != "x86_64" or lock["release"] != "1.fc44.secai1":
        raise ValueError("unsupported Tor source contract")
    names = set()
    for kind in ("remote_inputs", "local_inputs"):
        entries = lock[kind]
        if not isinstance(entries, dict) or not entries:
            raise ValueError("empty source input contract")
        for name, row in entries.items():
            fields = {"sha256", "bytes", "url" if kind == "remote_inputs" else "path"}
            if not NAME.fullmatch(name) or name in names or not isinstance(row, dict) or set(row) != fields:
                raise ValueError("invalid source input identity")
            if not isinstance(row["sha256"], str) or not HEX.fullmatch(row["sha256"]) or type(row["bytes"]) is not int or not 0 < row["bytes"] <= 16 << 20:
                raise ValueError("invalid source input bounds")
            if kind == "local_inputs":
                value = PurePosixPath(row["path"])
                if value.is_absolute() or ".." in value.parts or str(value) != row["path"]:
                    raise ValueError("invalid committed input path")
            else:
                from urllib.parse import urlsplit
                value = urlsplit(row["url"])
                if value.scheme != "https" or not value.hostname or value.username or value.password or value.fragment:
                    raise ValueError("source URL must be HTTPS")
            names.add(name)
    if "source.lock.json" in names or "TOR_SOURCE_MANIFEST.json" in names:
        raise ValueError("reserved source contract member")
    if lock["upstream_signature"] != {"signer": "514102454D0A87DB0767A1EBBE6A0531C18A9179", "primary": "1C1BC007A9F607AA8152C040BEA7B180B1491921", "good_keyid": "BE6A0531C18A9179"}:
        raise ValueError("unapproved upstream signing identity")
    return lock, raw


def check_input(path: Path, row: dict) -> bytes:
    data = stable_bytes(path, row["bytes"])
    if len(data) != row["bytes"] or digest(data) != row["sha256"]:
        raise ValueError("source input checksum or size mismatch: " + path.name)
    return data


def accept_gpg_status(status: str, identity: dict) -> None:
    valid = [line.split() for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
    if "[GNUPG:] GOODSIG " + identity["good_keyid"] + " " not in status or not any(len(row) >= 12 and row[2] == identity["signer"] and row[-1] == identity["primary"] for row in valid):
        raise ValueError("current pinned upstream signature unavailable")
    if any(marker in status for marker in ("BADSIG", "REVKEYSIG", "ERRSIG", "NO_PUBKEY")):
        raise ValueError("invalid upstream signature status")
    # The same retained certificate also produces Goulet EXPKEYSIG. It is not
    # counted as current authentication; the pinned ahf GOODSIG is mandatory.


def authenticate_upstream(stage: Path, lock: dict) -> dict:
    archive = "tor-" + lock["version"] + ".tar.gz"
    expected = lock["remote_inputs"][archive]["sha256"] + "  " + archive + "\n"
    if stable_bytes(stage / (archive + ".sha256sum"), 4096) != expected.encode("ascii"):
        raise ValueError("upstream checksum manifest does not name exact source")
    with tempfile.TemporaryDirectory(prefix="tor-signature-") as home:
        result = subprocess.run(["gpgv", "--homedir", home, "--status-fd", "1", "--keyring", str((stage / "tor-keyring.gpg").resolve()), str(stage / (archive + ".sha256sum.asc")), str(stage / (archive + ".sha256sum"))], capture_output=True, text=True, timeout=20, check=False)
    if result.returncode:
        raise ValueError("upstream signature verification failed")
    accept_gpg_status(result.stdout, lock["upstream_signature"])
    prefix = "tor-" + lock["version"]
    with tarfile.open(stage / archive, "r:gz") as source:
        total = 0
        for count, member in enumerate(source, 1):
            total += member.size
            path = PurePosixPath(member.name)
            if count > 5000 or total > 80 << 20 or member.size > 32 << 20 or path.is_absolute() or ".." in path.parts or (member.name != prefix and not member.name.startswith(prefix + "/")) or not (member.isdir() or member.isreg()):
                raise ValueError("upstream archive payload exceeds source contract")
        configure = source.extractfile(prefix + "/configure.ac").read(128 << 10).decode("utf-8")
        if not re.search(r"AC_INIT\(\[tor\],\s*\[" + re.escape(lock["version"]) + r"\]\)", configure):
            raise ValueError("source payload is not the approved stable Tor version")
    return {"signer": lock["upstream_signature"]["signer"], "primary": lock["upstream_signature"]["primary"]}


def verify_stage(stage: Path, contract: Path, global_manifest: Path | None = None) -> tuple[dict, dict]:
    if stage.is_symlink() or not stage.is_dir():
        raise ValueError("regular staged input directory required")
    lock, raw = load_contract(contract)
    expected = {**lock["remote_inputs"], **lock["local_inputs"], "source.lock.json": {"sha256": digest(raw), "bytes": len(raw)}}
    if {p.name for p in stage.iterdir()} != set(expected) | {"TOR_SOURCE_MANIFEST.json"}:
        raise ValueError("missing or extra staged source inputs")
    manifest_raw = stable_bytes(stage / "TOR_SOURCE_MANIFEST.json", 128 << 10)
    manifest = json_object(manifest_raw)
    if set(manifest) != {"schema_version", "version", "contract_sha256", "inputs"} or type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1 or manifest["version"] != lock["version"] or manifest["contract_sha256"] != digest(raw):
        raise ValueError("invalid staged source manifest")
    expected_manifest = {name: {"sha256": row["sha256"], "bytes": row["bytes"]} for name, row in expected.items()}
    if manifest["inputs"] != expected_manifest:
        raise ValueError("staged source manifest differs from approved contract")
    for name, row in expected.items():
        check_input(stage / name, row)
    if global_manifest is not None:
        outer = json_object(stable_bytes(global_manifest, 1 << 20))
        if outer.get("tor_source_manifest_sha256") != digest(manifest_raw) or outer.get("tor_source_contract_sha256") != digest(raw):
            raise ValueError("global source-prep Tor digest binding mismatch")
    authenticate_upstream(stage, lock)
    return lock, manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", type=Path)
    parser.add_argument("--contract", type=Path, default=Path(__file__).with_name("source.lock.json"))
    parser.add_argument("--global-manifest", type=Path)
    args = parser.parse_args()
    lock, manifest = verify_stage(args.stage, args.contract, args.global_manifest)
    print(json.dumps({"version": lock["version"], "contract_sha256": manifest["contract_sha256"], "inputs": len(manifest["inputs"]), "authenticated": True}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        raise SystemExit("Tor source verification failed: " + str(error))
