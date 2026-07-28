"""Single-stage quarantine parser/scanner subprocess.

This module is the only layer that imports the artifact parsing pipeline. The
credentialless coordinator launches a fresh instance for each required stage,
assigns its output only to that stage, and destroys the whole process group
before starting the next stage.
"""

import argparse
import json
import logging
import os
import re
import stat
from pathlib import Path

import yaml

from quarantine import pipeline

log = logging.getLogger("quarantine.scanner-stage")

MAX_POLICY_BYTES = 4 * 1024 * 1024
MAX_SOURCE_URL_BYTES = 4096
STAGES = {
    "source_policy",
    "format_gate",
    "hash_pin",
    "provenance",
    "static_scan",
    "smoke_test",
    "diffusion_deep_scan",
}


def _load_policy(path: Path) -> dict:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > MAX_POLICY_BYTES
        ):
            raise ValueError("scanner policy is invalid or too large")
        raw = handle.read(MAX_POLICY_BYTES + 1)
    policy = yaml.safe_load(raw) or {}
    if not isinstance(policy, dict):
        raise ValueError("scanner policy root must be a mapping")
    return policy


def _validated_artifact_path(raw_path: str, directory: bool) -> Path:
    scanner_root = Path(
        os.getenv("QUARANTINE_DIR", "/var/lib/secure-ai/quarantine/processing")
    ).resolve(strict=True)
    artifact = Path(raw_path)
    if artifact.parent.resolve(strict=True) != scanner_root:
        raise ValueError("artifact must be a direct child of the scanner root")
    metadata = artifact.lstat()
    if artifact.is_symlink() or directory != stat.S_ISDIR(metadata.st_mode):
        raise ValueError("artifact type does not match stage request")
    if not directory and (
        not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
    ):
        raise ValueError("artifact must be a single-link regular file")
    return artifact


def _validate_source(source_url: str) -> None:
    if (
        len(source_url.encode("utf-8")) > MAX_SOURCE_URL_BYTES
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in source_url)
    ):
        raise ValueError("source URL is invalid")


def run_stage(
    stage: str,
    artifact: Path,
    expected_sha256: str,
    policy: dict,
    *,
    source_url: str,
    directory: bool,
) -> dict:
    if stage not in STAGES:
        raise ValueError("unknown scanner stage")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("expected SHA-256 is malformed")
    _validate_source(source_url)

    if stage == "source_policy":
        result = pipeline.check_source_policy(source_url)
    elif stage == "format_gate":
        result = (
            pipeline.check_format_gate_directory(artifact)
            if directory
            else pipeline.check_format_gate(artifact, policy=policy)
        )
    elif stage == "hash_pin":
        original_pin = pipeline.check_hash_pin(
            artifact.name,
            expected_sha256,
            source_url=source_url,
        )
        if directory:
            manifest = pipeline.check_huggingface_directory_manifest(
                artifact,
                source_url,
            )
            unpinned_remote = (
                original_pin == {
                    "passed": False,
                    "reason": "remote artifact has no pinned hash",
                }
            )
            acceptable_directory_hash = (
                original_pin.get("passed") is True
                or unpinned_remote
            )
            if (
                source_url
                and acceptable_directory_hash
                and manifest.get("passed") is True
            ):
                result = {
                    "passed": True,
                    "pinned": True,
                    "match": True,
                    "mechanism": "image-owned-huggingface-manifest",
                    "manifest_sha256": manifest["manifest_sha256"],
                    "revision": manifest["revision"],
                    "directory_hash_pin": original_pin,
                    "huggingface_manifest": manifest,
                }
            else:
                result = {
                    "passed": False,
                    "reason": (
                        "directory requires an immutable image-owned "
                        "Hugging Face manifest"
                    ),
                    "directory_hash_pin": original_pin,
                    "huggingface_manifest": manifest,
                }
        else:
            result = original_pin
    elif stage == "provenance":
        result = pipeline.check_provenance(artifact, source_url)
    elif stage == "static_scan":
        result = (
            pipeline.check_static_scan_directory(artifact, policy=policy)
            if directory
            else pipeline.check_static_scan(artifact, policy=policy)
        )
    elif stage == "smoke_test":
        if directory or artifact.suffix.lower() != ".gguf":
            raise ValueError("behavioral stage is not applicable to this artifact")
        result = pipeline.check_smoke_test(artifact, policy=policy)
    else:
        if not directory:
            raise ValueError("diffusion deep scan requires a directory artifact")
        result = pipeline.check_diffusion_config_integrity(artifact)

    if not isinstance(result, dict) or type(result.get("passed")) is not bool:
        raise ValueError("scanner stage returned an invalid result")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one quarantine admission stage")
    parser.add_argument("--stage", required=True, choices=sorted(STAGES))
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--source-url", default="")
    parser.add_argument("--directory", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    try:
        artifact = _validated_artifact_path(args.artifact, args.directory)
        result = run_stage(
            args.stage,
            artifact,
            args.sha256,
            _load_policy(Path(args.policy)),
            source_url=args.source_url,
            directory=args.directory,
        )
    except Exception as exc:
        # A stage-specific parser failure is an ordinary fail-closed result.
        # The coordinator still reaps this process group and does not allow it
        # to populate any other stage's result.
        log.warning(
            "scanner stage %s rejected artifact (%s)",
            args.stage,
            type(exc).__name__,
        )
        result = {
            "passed": False,
            "reason": "stage_parser_rejected",
            "failure_class": type(exc).__name__,
        }

    print(
        json.dumps(
            {
                "version": 1,
                "stage": args.stage,
                "result": result,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    )


if __name__ == "__main__":
    main()
