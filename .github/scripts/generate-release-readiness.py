#!/usr/bin/env python3
"""Validate release evidence and emit a machine-readable readiness decision."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

SHA40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
STABLE_TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
REQUIRED_SYSTEM_RESULTS = ("boot", "reboot", "update", "rollback", "negative_security")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object in {path}")
    return value


def component_properties(document: dict) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    component = document.get("metadata", {}).get("component", {})
    for item in component.get("properties", []):
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            result.setdefault(item["name"], []).append(str(item.get("value", "")))
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--designation", choices=("candidate", "stable"), required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--image-ref", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--required-profile", required=True)
    parser.add_argument("--ci-evidence", required=True, type=Path)
    parser.add_argument("--sbom", action="append", default=[], type=Path)
    parser.add_argument("--release-manifest", required=True, type=Path)
    parser.add_argument("--artifact-verification", required=True, type=Path)
    parser.add_argument("--provenance-evidence", required=True, type=Path)
    parser.add_argument("--hardware-evidence", type=Path)
    parser.add_argument("--system-validation", type=Path)
    parser.add_argument("--signoff", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def exact_release_binding(
    document: dict, source_commit: str, image_digest: str
) -> bool:
    return (
        document.get("source_commit") == source_commit
        and document.get("image_digest") == image_digest
    )


def main() -> int:
    args = parse_args()
    errors: list[str] = []

    if not SHA40.fullmatch(args.source_commit):
        errors.append("source commit is not an immutable 40-character SHA")
    if not DIGEST.fullmatch(args.image_digest):
        errors.append("image digest is not a canonical sha256 digest")
    if args.designation == "stable" and not STABLE_TAG.fullmatch(args.tag):
        errors.append("stable designation requires a vMAJOR.MINOR.PATCH tag")
    if args.designation == "candidate" and STABLE_TAG.fullmatch(args.tag):
        errors.append("a stable-version tag cannot be designated candidate")

    ci = load_json(args.ci_evidence)
    ci_requirements = ci.get("required_checks", [])
    ci_valid = (
        ci.get("source_commit") == args.source_commit
        and isinstance(ci_requirements, list)
        and bool(ci_requirements)
    )
    passed_checks = 0
    if ci_valid:
        for requirement in ci_requirements:
            runs = requirement.get("check_runs", []) if isinstance(requirement, dict) else []
            if (
                isinstance(runs, list)
                and bool(runs)
                and all(
                    isinstance(run, dict)
                    and run.get("conclusion") == "success"
                    and run.get("head_sha") == args.source_commit
                    and bool(run.get("details_url"))
                    for run in runs
                )
            ):
                passed_checks += 1
            else:
                ci_valid = False
    if not ci_valid or passed_checks != len(ci_requirements):
        errors.append("required CI evidence is missing, unsuccessful, or for another commit")

    manifest = load_json(args.release_manifest)
    manifest_image = manifest.get("image", {})
    manifest_build = manifest.get("build", {})
    expected_pinned = f"{args.image_ref}@{args.image_digest}"
    if manifest_image.get("digest") != args.image_digest:
        errors.append("release manifest image digest does not match readiness input")
    if manifest_image.get("ref_pinned") != expected_pinned:
        errors.append("release manifest does not contain the canonical pinned image ref")
    if manifest_build.get("commit_sha") != args.source_commit:
        errors.append("release manifest is bound to a different source commit")
    if (
        manifest.get("deployment", {}).get("required_service_profile")
        != args.required_profile
    ):
        errors.append("release manifest does not enforce the required service profile")

    sbom_results: list[dict[str, object]] = []
    for path in sorted(args.sbom):
        document = load_json(path)
        components = document.get("components")
        root_component = document.get("metadata", {}).get("component")
        valid = (
            document.get("bomFormat") == "CycloneDX"
            and isinstance(root_component, dict)
            and bool(root_component.get("name"))
            and isinstance(components, list)
            and len(components) > 0
        )
        dependency_count = 0
        source_file_count = 0
        completeness = "tool-generated"
        if isinstance(components, list):
            dependency_count = sum(
                1 for component in components
                if isinstance(component, dict) and component.get("type") == "library"
            )
            source_file_count = sum(
                1 for component in components
                if isinstance(component, dict) and component.get("type") == "file"
            )
        properties = component_properties(document)
        if "secai:dependencyCompleteness" in properties:
            completeness = properties["secai:dependencyCompleteness"][0]
            try:
                declared_dependencies = int(
                    properties["secai:dependencyComponentCount"][0]
                )
                declared_sources = int(
                    properties["secai:sourceFileComponentCount"][0]
                )
            except (KeyError, ValueError, IndexError):
                valid = False
            else:
                valid = (
                    valid
                    and declared_dependencies == dependency_count
                    and declared_sources == source_file_count
                    and (
                        (completeness in {"locked", "direct-locked"} and dependency_count > 0)
                        or (completeness == "none-required" and dependency_count == 0)
                    )
                )
        if not valid:
            errors.append(f"empty, misleading, or invalid CycloneDX SBOM: {path.name}")
        sbom_results.append(
            {
                "file": path.name,
                "sha256": sha256(path),
                "component_count": len(components) if isinstance(components, list) else 0,
                "dependency_component_count": dependency_count,
                "source_file_component_count": source_file_count,
                "dependency_completeness": completeness,
                "result": "pass" if valid else "fail",
            }
        )
    if not sbom_results:
        errors.append("no SBOMs supplied")

    artifact = load_json(args.artifact_verification)
    artifact_valid = exact_release_binding(
        artifact, args.source_commit, args.image_digest
    ) and artifact.get("result") == "pass"
    checksum_file = args.release_manifest.parent / "SHA256SUMS"
    if not checksum_file.is_file() or artifact.get("checksum_sha256") != sha256(
        checksum_file
    ):
        artifact_valid = False
    if not artifact_valid:
        errors.append("signed artifact checksum verification evidence is invalid")

    provenance = load_json(args.provenance_evidence)
    provenance_valid = (
        exact_release_binding(provenance, args.source_commit, args.image_digest)
        and provenance.get("image_ref") == expected_pinned
        and provenance.get("signature_verified") is True
        and provenance.get("cyclonedx_attestation_verified") is True
        and provenance.get("slsa_attestation_verified") is True
    )
    if not provenance_valid:
        errors.append("image signature/provenance verification evidence is invalid")

    hardware: dict[str, object] = {"status": "unavailable"}
    if args.hardware_evidence and args.hardware_evidence.is_file():
        document = load_json(args.hardware_evidence)
        valid = (
            exact_release_binding(document, args.source_commit, args.image_digest)
            and document.get("status") == "qualified"
            and isinstance(document.get("hardware"), list)
            and len(document["hardware"]) > 0
            and bool(document.get("tested_at"))
        )
        hardware = {
            "status": "qualified" if valid else "invalid",
            "file": args.hardware_evidence.name,
            "sha256": sha256(args.hardware_evidence),
            "qualified_systems": len(document.get("hardware", [])) if valid else 0,
        }
        if not valid:
            errors.append("hardware qualification evidence is incomplete or misbound")
    else:
        errors.append(
            f"{args.designation} release has no hardware qualification evidence"
        )

    system_validation: dict[str, object] = {"status": "unavailable"}
    if args.system_validation and args.system_validation.is_file():
        document = load_json(args.system_validation)
        results = document.get("results", {})
        valid = (
            exact_release_binding(document, args.source_commit, args.image_digest)
            and bool(document.get("tested_at"))
            and isinstance(results, dict)
            and all(results.get(name) == "pass" for name in REQUIRED_SYSTEM_RESULTS)
        )
        system_validation = {
            "status": "passed" if valid else "invalid",
            "file": args.system_validation.name,
            "sha256": sha256(args.system_validation),
            "results": {
                name: results.get(name, "missing") for name in REQUIRED_SYSTEM_RESULTS
            },
        }
        if not valid:
            errors.append("boot/reboot/update/rollback/negative test evidence is invalid")
    else:
        errors.append(
            f"{args.designation} release has no system validation evidence"
        )

    signoff: dict[str, object] = {"status": "unavailable"}
    if args.signoff and args.signoff.is_file():
        document = load_json(args.signoff)
        valid = (
            exact_release_binding(document, args.source_commit, args.image_digest)
            and document.get("status") == "approved"
            and document.get("evidence_reviewed") is True
            and bool(document.get("approver"))
            and bool(document.get("approved_at"))
        )
        signoff = {
            "status": "approved" if valid else "invalid",
            "file": args.signoff.name,
            "sha256": sha256(args.signoff),
            "approver": document.get("approver", ""),
        }
        if not valid:
            errors.append("human release signoff is missing, invalid, or misbound")
    else:
        errors.append(f"{args.designation} release has no human signoff evidence")

    mandatory_complete = not errors
    evidence = {
        "schema_version": 2,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "release": {
            "tag": args.tag,
            "designation": args.designation,
            "mandatory_evidence_complete": mandatory_complete,
        },
        "source": {"commit": args.source_commit, "immutable": bool(SHA40.fullmatch(args.source_commit))},
        "image": {
            "ref": args.image_ref,
            "digest": args.image_digest,
            "ref_pinned": expected_pinned,
        },
        "deployment": {"required_service_profile": args.required_profile},
        "results": {
            "tests": {
                "result": "pass" if ci_valid else "fail",
                "required_checks": len(ci_requirements),
                "passed_checks": passed_checks,
                "evidence_file": args.ci_evidence.name,
                "evidence_sha256": sha256(args.ci_evidence),
            },
            "sboms": {
                "result": "pass" if sbom_results and all(
                    item["result"] == "pass" for item in sbom_results
                ) else "fail",
                "documents": sbom_results,
            },
            "provenance": {"result": "pass" if provenance_valid else "fail"},
            "checksums": {"result": "pass" if artifact_valid else "fail"},
            "hardware_qualification": hardware,
            "system_validation": system_validation,
            "human_signoff": signoff,
        },
        "release_manifest": {
            "file": args.release_manifest.name,
            "sha256": sha256(args.release_manifest),
        },
        "errors": errors,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(
        f"Wrote {args.output}: designation={args.designation}, "
        f"mandatory_evidence_complete={str(mandatory_complete).lower()}"
    )
    if args.designation == "stable" and not mandatory_complete:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
