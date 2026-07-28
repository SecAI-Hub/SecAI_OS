#!/usr/bin/env python3
"""Validate SecAI runtime profiles and perform atomic profile state I/O."""

from __future__ import annotations

import argparse
import grp
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


VALID_PROFILES = frozenset({"offline_private", "research", "full_lab"})
DEFAULT_PROFILE = "offline_private"
PROFILE_FIELDS = {
    "description",
    "mode",
    "session_mode",
    "agent_mode",
    "rationale",
    "services_enabled",
    "services_disabled",
}
UNIT_RE = re.compile(r"^secure-ai-[a-z0-9-]+\.(?:service|path|timer)$")
NETWORK_UNITS = {
    "secure-ai-airlock.service",
    "secure-ai-tor.service",
    "secure-ai-searxng.service",
    "secure-ai-search-mediator.service",
}


class ProfileError(RuntimeError):
    """Profile input is malformed or violates a safety invariant."""


class _UniqueSafeLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: _UniqueSafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ProfileError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _safe_regular(path: Path, *, required: bool, root_owned: bool = True) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if required:
            raise ProfileError(f"required file is missing: {path}")
        return False
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ProfileError(f"file must be regular and not a symbolic link: {path}")
    if root_owned and os.geteuid() == 0 and metadata.st_uid != 0:
        raise ProfileError(f"file must be owned by root: {path}")
    if metadata.st_mode & 0o022:
        raise ProfileError(f"file must not be writable by group or other users: {path}")
    return True


def _load_yaml(path: Path) -> Any:
    _safe_regular(path, required=True)
    try:
        return yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueSafeLoader)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ProfileError(f"invalid YAML in {path}: {exc}") from exc


def _unique_json(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProfileError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _validate_name(name: Any) -> str:
    if not isinstance(name, str) or name not in VALID_PROFILES:
        raise ProfileError(f"invalid profile name: {name!r}")
    return name


def load_definitions(config_path: Path, unit_root: Path) -> dict[str, dict[str, Any]]:
    config = _load_yaml(config_path)
    if not isinstance(config, dict):
        raise ProfileError("appliance configuration must be a mapping")
    profile = config.get("profile")
    if not isinstance(profile, dict):
        raise ProfileError("appliance configuration has no profile mapping")
    if profile.get("default") != DEFAULT_PROFILE:
        raise ProfileError("the baked default profile must be offline_private")
    definitions = profile.get("definitions")
    if not isinstance(definitions, dict) or set(definitions) != VALID_PROFILES:
        raise ProfileError("profile definitions must contain exactly the supported profiles")

    validated: dict[str, dict[str, Any]] = {}
    controlled_sets: list[set[str]] = []
    for name in sorted(VALID_PROFILES):
        definition = definitions[name]
        if not isinstance(definition, dict) or set(definition) != PROFILE_FIELDS:
            raise ProfileError(f"profile {name} has missing or unexpected fields")
        enabled = definition["services_enabled"]
        disabled = definition["services_disabled"]
        if not isinstance(enabled, list) or not isinstance(disabled, list):
            raise ProfileError(f"profile {name} service fields must be arrays")
        if not enabled:
            raise ProfileError(f"profile {name} must enable its required services")
        if len(enabled) != len(set(enabled)) or len(disabled) != len(set(disabled)):
            raise ProfileError(f"profile {name} contains duplicate service entries")
        if set(enabled) & set(disabled):
            raise ProfileError(f"profile {name} enables and disables the same service")
        for unit in [*enabled, *disabled]:
            if not isinstance(unit, str) or not UNIT_RE.fullmatch(unit):
                raise ProfileError(f"profile {name} contains an invalid unit name: {unit!r}")
            unit_path = unit_root / unit
            if unit_path.is_symlink() or not unit_path.is_file():
                raise ProfileError(f"profile {name} references a missing unit: {unit}")
        controlled_sets.append(set(enabled) | set(disabled))
        validated[name] = definition

    if not all(current == controlled_sets[0] for current in controlled_sets[1:]):
        raise ProfileError(
            "every profile must explicitly enable or disable the same controlled unit set"
        )
    offline = validated[DEFAULT_PROFILE]
    if not NETWORK_UNITS.issubset(set(offline["services_disabled"])):
        raise ProfileError("offline_private must disable every network-capable service")
    return validated


def read_current_profile(state_path: Path, override_path: Path) -> dict[str, Any]:
    if _safe_regular(override_path, required=False):
        override = _load_yaml(override_path)
        if not isinstance(override, dict) or set(override) != {"profile"}:
            raise ProfileError("operator override must contain exactly one profile field")
        return {
            "profile": _validate_name(override["profile"]),
            "locked": True,
            "source": "operator_override",
        }

    if _safe_regular(state_path, required=False):
        try:
            state = json.loads(
                state_path.read_text(encoding="utf-8"),
                object_pairs_hook=_unique_json,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ProfileError(f"non-finite JSON value: {value}")
                ),
            )
            if not isinstance(state, dict) or "active" not in state:
                raise ProfileError("profile state must contain active")
            return {
                "profile": _validate_name(state["active"]),
                "locked": False,
                "source": "runtime_state",
            }
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ProfileError) as exc:
            print(
                f"secure-profile-plan: invalid runtime state; using {DEFAULT_PROFILE}: {exc}",
                file=sys.stderr,
            )
    return {
        "profile": DEFAULT_PROFILE,
        "locked": False,
        "source": "safe_default",
    }


def read_request(request_path: Path) -> str:
    _safe_regular(request_path, required=True, root_owned=False)
    metadata = request_path.lstat()
    if metadata.st_size <= 0 or metadata.st_size > 32:
        raise ProfileError("profile request has an invalid size")
    try:
        raw = request_path.read_bytes()
    except OSError as exc:
        raise ProfileError(f"cannot read profile request: {exc}") from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if b"\n" in raw or b"\r" in raw:
        raise ProfileError("profile request must contain exactly one line")
    try:
        name = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProfileError("profile request must be ASCII") from exc
    return _validate_name(name)


def _atomic_json(
    path: Path,
    payload: dict[str, Any],
    mode: int,
    group_name: str = "root",
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise ProfileError(f"state parent is unsafe: {path.parent}")
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ProfileError(f"refusing to replace non-regular state path: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), mode)
            if os.geteuid() == 0:
                try:
                    group_id = grp.getgrnam(group_name).gr_gid
                except KeyError as exc:
                    raise ProfileError(
                        f"required state group does not exist: {group_name}"
                    ) from exc
                os.fchown(handle.fileno(), 0, group_id)
        os.replace(temporary, path)
        parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def write_state(path: Path, profile: str, changed_by: str) -> None:
    _validate_name(profile)
    if not re.fullmatch(r"[a-z0-9_-]{1,32}", changed_by):
        raise ProfileError("invalid changed_by value")
    _atomic_json(
        path,
        {
            "active": profile,
            "changed_at": datetime.now(timezone.utc).isoformat(),
            "changed_by": changed_by,
        },
        0o644,
    )


def write_result(
    path: Path,
    status: str,
    profile: str,
    previous: str,
    detail: str,
) -> None:
    if status not in {
        "in_progress",
        "success",
        "failed",
        "rolled_back",
        "rollback_failed",
    }:
        raise ProfileError("invalid result status")
    if profile:
        _validate_name(profile)
    if previous:
        _validate_name(previous)
    if len(detail) > 1024:
        raise ProfileError("result detail is too long")
    _atomic_json(
        path,
        {
            "status": status,
            "profile": profile,
            "previous": previous,
            "detail": detail,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        0o640,
        "secure-ai-services",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    current = subparsers.add_parser("current")
    current.add_argument("--state", type=Path, required=True)
    current.add_argument("--override", type=Path, required=True)

    request = subparsers.add_parser("request")
    request.add_argument("--file", type=Path, required=True)

    plan = subparsers.add_parser("plan")
    plan.add_argument("--config", type=Path, required=True)
    plan.add_argument("--unit-root", type=Path, required=True)
    plan.add_argument("--profile", choices=sorted(VALID_PROFILES), required=True)

    state = subparsers.add_parser("write-state")
    state.add_argument("--file", type=Path, required=True)
    state.add_argument("--profile", choices=sorted(VALID_PROFILES), required=True)
    state.add_argument("--changed-by", required=True)

    result = subparsers.add_parser("write-result")
    result.add_argument("--file", type=Path, required=True)
    result.add_argument("--status", required=True)
    result.add_argument("--profile", default="")
    result.add_argument("--previous", default="")
    result.add_argument("--detail", default="")
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "current":
            output = read_current_profile(args.state, args.override)
        elif args.command == "request":
            output = {"profile": read_request(args.file)}
        elif args.command == "plan":
            definitions = load_definitions(args.config, args.unit_root)
            definition = definitions[args.profile]
            output = {
                "profile": args.profile,
                "services_enabled": definition["services_enabled"],
                "services_disabled": definition["services_disabled"],
                "controlled_services": sorted(
                    set(definition["services_enabled"])
                    | set(definition["services_disabled"])
                ),
            }
        elif args.command == "write-state":
            write_state(args.file, args.profile, args.changed_by)
            output = {"status": "written"}
        elif args.command == "write-result":
            write_result(
                args.file,
                args.status,
                args.profile,
                args.previous,
                args.detail,
            )
            output = {"status": "written"}
        else:  # pragma: no cover
            raise ProfileError("unknown command")
        print(json.dumps(output, separators=(",", ":")))
        return 0
    except (OSError, ProfileError) as exc:
        print(f"secure-profile-plan: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
