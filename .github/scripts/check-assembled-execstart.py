#!/usr/bin/env python3
"""Fail when a systemd execution directive references an unavailable executable.

With no arguments the check models the assembled image from committed
files plus the explicit outputs of build-services.sh. With --rootfs it
validates those same targets against directories copied from the final OCI
image, which catches staging/installation omissions.
"""

from __future__ import annotations

import argparse
import os
import shlex
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parents[2]
UNIT_ROOT = REPO_ROOT / "files/system/usr/lib/systemd/system"

RPM_EXECUTABLES = {
    "/bin/bash",
    "/bin/rm",
    "/usr/bin/python3",
    "/usr/bin/tor",
}

EXEC_DIRECTIVES = {
    "ExecCondition",
    "ExecReload",
    "ExecStart",
    "ExecStartPost",
    "ExecStartPre",
    "ExecStop",
    "ExecStopPost",
}

BUILD_OUTPUTS = {
    "/usr/bin/llama-server",
    "/usr/local/bin/gguf-guard",
    "/usr/local/bin/securectl",
    *{
        f"/usr/libexec/secure-ai/{name}"
        for name in (
            "agent",
            "airlock",
            "diffusion-worker",
            "first-boot-check.sh",
            "gpu-integrity-watch",
            "incident-recorder",
            "integrity-monitor",
            "mcp-firewall",
            "policy-engine",
            "quarantine-watcher",
            "registry",
            "runtime-attestor",
            "search-mediator",
            "secai-enable-diffusion.sh",
            "secai-setup-wizard.sh",
            "tool-firewall",
            "ui",
        )
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rootfs", type=Path)
    return parser.parse_args()


def committed_path(path: str) -> Path:
    return REPO_ROOT / "files/system" / path.removeprefix("/")


def available(path: str, rootfs: Path | None) -> bool:
    if path in RPM_EXECUTABLES:
        return True
    if rootfs is not None:
        candidate = rootfs / path.removeprefix("/")
        return (
            candidate.is_file()
            and not candidate.is_symlink()
            and os.access(candidate, os.X_OK)
        )
    candidate = committed_path(path)
    return (
        candidate.is_file()
        and not candidate.is_symlink()
        and os.access(candidate, os.X_OK)
    ) or path in BUILD_OUTPUTS


def executable_targets(command: str) -> list[str]:
    # systemd permits prefixes that alter execution semantics.
    command = command.lstrip("-@:+!")
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as exc:
        raise ValueError(f"invalid ExecStart quoting: {exc}") from exc
    if not tokens:
        return []

    targets = [tokens[0]]
    if "--" in tokens:
        index = tokens.index("--")
        if index + 1 < len(tokens):
            targets.append(tokens[index + 1])
    if (
        tokens[0] == "/usr/bin/python3"
        and len(tokens) > 1
        and tokens[1].startswith("/")
    ):
        targets.append(tokens[1])
    return [target for target in targets if PurePosixPath(target).is_absolute()]


def main() -> int:
    args = parse_args()
    errors: list[str] = []
    checked = 0
    for unit in sorted(UNIT_ROOT.glob("*.service")):
        for line_number, line in enumerate(
            unit.read_text(encoding="utf-8").splitlines(), start=1
        ):
            directive, separator, command = line.partition("=")
            if separator == "" or directive not in EXEC_DIRECTIVES:
                continue
            try:
                targets = executable_targets(command)
            except ValueError as exc:
                errors.append(f"{unit.name}:{line_number}: {exc}")
                continue
            for target in targets:
                checked += 1
                if not available(target, args.rootfs):
                    errors.append(
                        f"{unit.name}:{line_number}: unavailable ExecStart target "
                        f"{target}"
                    )

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    mode = "assembled image" if args.rootfs else "assembly model"
    print(f"Validated {checked} absolute systemd execution targets against {mode}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
