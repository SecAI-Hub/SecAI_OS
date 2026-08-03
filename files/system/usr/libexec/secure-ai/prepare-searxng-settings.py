#!/usr/bin/env python3
"""Inject a systemd credential into an ephemeral SearXNG settings file."""

from __future__ import annotations

import argparse
import os
import re
import stat
import tempfile
from pathlib import Path

import yaml


MAX_CREDENTIAL_BYTES = 65
MAX_SETTINGS_BYTES = 1024 * 1024
SECRET_RE = re.compile(r"[0-9a-f]{64}")
PUBLIC_SECRET_MARKER = "required-runtime-credential"


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"duplicate settings key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, type=Path)
    parser.add_argument("--credential", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def _read_regular(path: Path, maximum: int) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > maximum
        ):
            raise ValueError(f"refusing unsafe input file: {path}")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            content = handle.read(maximum + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(content) > maximum:
        raise ValueError(f"input file exceeds safety limit: {path}")
    return content


def _load_settings(path: Path) -> dict:
    content = _read_regular(path, MAX_SETTINGS_BYTES)
    try:
        settings = yaml.load(content, Loader=_UniqueKeyLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError("base SearXNG settings are invalid") from exc
    if not isinstance(settings, dict) or not isinstance(settings.get("server"), dict):
        raise ValueError("base SearXNG settings have no server mapping")
    if settings["server"].get("secret_key") != PUBLIC_SECRET_MARKER:
        raise ValueError("base SearXNG secret marker is missing or unexpected")
    return settings


def _load_credential(path: Path) -> str:
    try:
        value = _read_regular(path, MAX_CREDENTIAL_BYTES).decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("SearXNG credential is not ASCII") from exc
    if not SECRET_RE.fullmatch(value):
        raise ValueError("SearXNG credential is not a canonical 256-bit token")
    return value


def _validate_output_parent(path: Path) -> None:
    parent = path.parent
    metadata = parent.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or parent.is_symlink():
        raise ValueError("SearXNG runtime settings directory is unsafe")
    try:
        existing = path.lstat()
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(existing.st_mode)
        or existing.st_nlink != 1
        or existing.st_uid != os.geteuid()
    ):
        raise ValueError("existing SearXNG runtime settings file is unsafe")


def _atomic_write(path: Path, content: bytes) -> None:
    _validate_output_parent(path)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def main() -> int:
    args = _arguments()
    settings = _load_settings(args.base)
    settings["server"]["secret_key"] = _load_credential(args.credential)
    encoded = yaml.safe_dump(
        settings,
        allow_unicode=False,
        default_flow_style=False,
        sort_keys=False,
    ).encode("utf-8")
    if len(encoded) > MAX_SETTINGS_BYTES:
        raise ValueError("rendered SearXNG settings exceed safety limit")
    _atomic_write(args.output, encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
