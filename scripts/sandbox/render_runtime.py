#!/usr/bin/env python3
"""Render sandbox runtime policy/config overlays for compose profiles."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path


def _copy_tree(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        target = dst / item.name
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True)
        else:
            shutil.copy2(item, target)


def _write_text(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(data)


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle)
        handle.write("\n")


def _replace_in_section(text: str, section: str, key: str, value: str) -> str:
    lines = text.splitlines()
    in_section = False
    replaced = False

    for idx, line in enumerate(lines):
        if not in_section and line.strip() == f"{section}:":
            in_section = True
            continue
        if in_section and line and not line.startswith(" "):
            in_section = False
        if in_section and line.startswith(f"  {key}:"):
            lines[idx] = f"  {key}: {value}"
            replaced = True
            break

    if not replaced:
        raise ValueError(f"failed to replace {section}.{key}")
    return "\n".join(lines) + "\n"


def _derive_profile(*, enable_search: bool, enable_airlock: bool, enable_diffusion: bool) -> str:
    """Map the selected compose features to the closest supported profile."""
    if enable_diffusion:
        return "full_lab"
    if enable_search or enable_airlock:
        return "research"
    return "offline_private"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--runtime-dir", required=True)
    parser.add_argument("--enable-search", action="store_true")
    parser.add_argument("--enable-airlock", action="store_true")
    parser.add_argument("--enable-diffusion", action="store_true")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    runtime_dir = Path(args.runtime_dir).resolve()

    source_policy = repo_root / "files" / "system" / "etc" / "secure-ai" / "policy"
    source_config = repo_root / "files" / "system" / "etc" / "secure-ai" / "config"

    runtime_policy = runtime_dir / "policy"
    runtime_config = runtime_dir / "config"
    runtime_state = runtime_dir / "state"

    _copy_tree(source_policy, runtime_policy)
    _copy_tree(source_config, runtime_config)

    policy_path = runtime_policy / "policy.yaml"
    config_path = runtime_config / "appliance.yaml"
    profile_path = runtime_state / "profile.json"

    policy_text = policy_path.read_text(encoding="utf-8")
    config_text = config_path.read_text(encoding="utf-8")
    airlock_enabled = args.enable_airlock or args.enable_search

    policy_text = _replace_in_section(
        policy_text, "search", "enabled", "true" if args.enable_search else "false"
    )
    policy_text = _replace_in_section(
        policy_text, "airlock", "enabled", "true" if airlock_enabled else "false"
    )
    config_text = _replace_in_section(
        config_text,
        "appliance",
        "mode",
        '"online-augmented"' if (args.enable_search or airlock_enabled) else '"local-only"',
    )

    profile = _derive_profile(
        enable_search=args.enable_search,
        enable_airlock=airlock_enabled,
        enable_diffusion=args.enable_diffusion,
    )

    _write_text(policy_path, policy_text)
    _write_text(config_path, config_text)
    _write_json(profile_path, {"active": profile})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
