#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CVE_PATTERN = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)
DEFAULT_MANIFEST_PATH = "/opt/python/share/secai-cpython-build.json"

VEX_METADATA: dict[str, dict[str, str]] = {
    "CVE-2026-6100": {
        "justification": "vulnerable_code_not_present",
        "impact_statement": (
            "The custom CPython runtime includes the decompressor dangling-pointer "
            "cleanup fix for lzma, bz2, and gzip error handling."
        ),
    },
    "CVE-2026-4786": {
        "justification": "vulnerable_code_not_present",
        "impact_statement": (
            "The custom CPython runtime includes the webbrowser action-token "
            "validation fix that blocks shell-command injection through %action."
        ),
    },
    "CVE-2026-3298": {
        "justification": "vulnerable_code_not_in_execute_path",
        "impact_statement": (
            "The generated runtime is built for Linux, not Windows, and also carries "
            "the recvfrom_into boundary-check patch."
        ),
    },
    "CVE-2026-1502": {
        "justification": "vulnerable_code_not_present",
        "impact_statement": (
            "The custom CPython runtime rejects CR/LF bytes in HTTP proxy tunnel "
            "hosts and headers."
        ),
    },
    "CVE-2025-15366": {
        "justification": "vulnerable_code_not_present",
        "impact_statement": (
            "The custom CPython runtime rejects control characters in imaplib "
            "commands."
        ),
    },
    "CVE-2025-15367": {
        "justification": "vulnerable_code_not_present",
        "impact_statement": (
            "The custom CPython runtime rejects control characters in poplib "
            "commands."
        ),
    },
    "CVE-2025-12781": {
        "justification": "vulnerable_code_not_present",
        "impact_statement": (
            "The custom CPython runtime hardens alternative-alphabet and URL-safe "
            "Base64 decoding so standard-alphabet characters are rejected or "
            "discarded instead of being silently accepted."
        ),
    },
}

GLIBC_UNICODE_LOCALE_CVE = "CVE-2026-5928"
GLIBC_UNICODE_LOCALE_METADATA = {
    "justification": "inline_mitigations_already_exist",
    "impact_statement": (
        "The runtime entrypoint enforces a UTF-8 locale and aborts startup if the "
        "effective character type locale is not Unicode. CVE-2026-5928 requires "
        "overlapping single-byte and multibyte character encodings, which are not "
        "possible in the enforced Unicode-only locale configuration."
    ),
}

GLIBC_INSPECTION_SCRIPT = r"""
import json
import locale
import os
import platform
from pathlib import Path


def read_os_release() -> dict[str, str]:
    data = {}
    path = Path("/etc/os-release")
    if not path.exists():
        return data
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        data[key] = value.strip().strip('"')
    return data


def find_apk_version(package_name: str) -> str | None:
    path = Path("/lib/apk/db/installed")
    if not path.exists():
        return None
    current_name = None
    current_version = None
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw_line:
            if current_name == package_name:
                return current_version
            current_name = None
            current_version = None
            continue
        if raw_line.startswith("P:"):
            current_name = raw_line[2:]
        elif raw_line.startswith("V:"):
            current_version = raw_line[2:]
    if current_name == package_name:
        return current_version
    return None


lang = os.environ.get("LANG")
lc_all = os.environ.get("LC_ALL")
ctype_locale = None
locale_error = None
try:
    ctype_locale = locale.setlocale(locale.LC_CTYPE, "")
except locale.Error as exc:
    locale_error = str(exc)

payload = {
    "lang": lang,
    "lc_all": lc_all,
    "preferred_encoding": locale.getpreferredencoding(False),
    "ctype_locale": ctype_locale,
    "locale_error": locale_error,
    "glibc_version": find_apk_version("glibc"),
    "arch": platform.machine(),
    "os_release": read_os_release(),
}
print(json.dumps(payload))
"""


@dataclass(frozen=True)
class ImageBuildMetadata:
    image_ref: str
    python_version: str
    cves: tuple[str, ...]


@dataclass(frozen=True)
class UnicodeLocaleGlibcMetadata:
    image_ref: str
    package_purl: str


def run_command(args: list[str]) -> str:
    result = subprocess.run(args, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def normalize_timestamp(value: str | None) -> str:
    if value:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def extract_cves_from_manifest(manifest: dict[str, Any]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for patch in manifest.get("patches", []):
        name = patch.get("name", "")
        for cve in CVE_PATTERN.findall(name):
            normalized = cve.upper()
            if normalized not in seen:
                seen.add(normalized)
                ordered.append(normalized)
    return tuple(ordered)


def load_build_manifest(
    image_ref: str,
    manifest_path: str = DEFAULT_MANIFEST_PATH,
    command_runner=run_command,
) -> dict[str, Any]:
    output = command_runner(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "/opt/python/bin/python3",
            image_ref,
            "-c",
            (
                "from pathlib import Path; "
                f"print(Path({manifest_path!r}).read_text(encoding='utf-8'))"
            ),
        ]
    )
    return json.loads(output)


def collect_image_build_metadata(
    image_refs: list[str],
    manifest_path: str = DEFAULT_MANIFEST_PATH,
    command_runner=run_command,
) -> list[ImageBuildMetadata]:
    metadata: list[ImageBuildMetadata] = []
    for image_ref in image_refs:
        manifest = load_build_manifest(
            image_ref=image_ref,
            manifest_path=manifest_path,
            command_runner=command_runner,
        )
        python_version = str(manifest.get("upstream_version", "")).strip()
        if not python_version:
            raise ValueError(f"{image_ref} is missing upstream_version in {manifest_path}")
        cves = extract_cves_from_manifest(manifest)
        if not cves:
            raise ValueError(f"{image_ref} does not advertise any CVE-tagged patches in {manifest_path}")
        metadata.append(
            ImageBuildMetadata(
                image_ref=image_ref,
                python_version=python_version,
                cves=cves,
            )
        )
    return metadata


def load_unicode_locale_glibc_metadata(
    image_ref: str,
    command_runner=run_command,
) -> UnicodeLocaleGlibcMetadata | None:
    output = command_runner(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "/opt/python/bin/python3",
            image_ref,
            "-c",
            GLIBC_INSPECTION_SCRIPT,
        ]
    )
    inspection = json.loads(output)
    glibc_version = str(inspection.get("glibc_version") or "").strip()
    if not glibc_version:
        return None

    os_release = inspection.get("os_release") or {}
    distro_id = str(os_release.get("ID") or "").strip().lower()
    distro_version = str(os_release.get("VERSION_ID") or "").strip()
    if distro_id != "wolfi" or not distro_version:
        raise ValueError(f"{image_ref} has glibc installed but is not a Wolfi runtime")

    locale_error = inspection.get("locale_error")
    if locale_error:
        raise ValueError(f"{image_ref} could not activate its locale: {locale_error}")

    for field in ("lang", "lc_all", "preferred_encoding", "ctype_locale"):
        value = str(inspection.get(field) or "").strip()
        if "UTF-8" not in value.upper():
            raise ValueError(f"{image_ref} is not enforcing a UTF-8 locale for {field}")

    arch = str(inspection.get("arch") or "").strip()
    if not arch:
        raise ValueError(f"{image_ref} did not report an architecture for glibc metadata")

    package_purl = (
        f"pkg:apk/{distro_id}/glibc@{glibc_version}"
        f"?arch={arch}&distro={distro_id}-{distro_version}"
    )
    return UnicodeLocaleGlibcMetadata(
        image_ref=image_ref,
        package_purl=package_purl,
    )


def collect_unicode_locale_glibc_metadata(
    image_refs: list[str],
    command_runner=run_command,
) -> list[UnicodeLocaleGlibcMetadata]:
    metadata: list[UnicodeLocaleGlibcMetadata] = []
    for image_ref in image_refs:
        image_metadata = load_unicode_locale_glibc_metadata(
            image_ref=image_ref,
            command_runner=command_runner,
        )
        if image_metadata is not None:
            metadata.append(image_metadata)
    return metadata


def build_statement(vulnerability: str, images: list[ImageBuildMetadata], timestamp: str) -> dict[str, Any]:
    metadata = VEX_METADATA.get(
        vulnerability,
        {
            "justification": "vulnerable_code_not_present",
            "impact_statement": (
                "The custom CPython runtime includes a vendor-applied fix for this "
                "CVE; verify the build manifest for exact patch provenance."
            ),
        },
    )
    products = [
        {
            "@id": image.image_ref,
            "subcomponents": [{"@id": f"pkg:generic/python@{image.python_version}"}],
        }
        for image in images
    ]
    return {
        "vulnerability": {"name": vulnerability},
        "products": products,
        "status": "not_affected",
        "justification": metadata["justification"],
        "impact_statement": metadata["impact_statement"],
        "timestamp": timestamp,
    }


def build_unicode_locale_glibc_statement(
    metadata: UnicodeLocaleGlibcMetadata,
    timestamp: str,
) -> dict[str, Any]:
    return {
        "vulnerability": {"name": GLIBC_UNICODE_LOCALE_CVE},
        "products": [
            {
                "@id": metadata.image_ref,
                "subcomponents": [{"@id": metadata.package_purl}],
            }
        ],
        "status": "not_affected",
        "justification": GLIBC_UNICODE_LOCALE_METADATA["justification"],
        "impact_statement": GLIBC_UNICODE_LOCALE_METADATA["impact_statement"],
        "timestamp": timestamp,
    }


def build_vex_document(
    images: list[ImageBuildMetadata],
    *,
    author: str,
    role: str,
    document_id: str,
    timestamp: str,
    extra_statements: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    vulnerabilities = sorted({cve for image in images for cve in image.cves})
    statements = []
    for vulnerability in vulnerabilities:
        affected_images = [image for image in images if vulnerability in image.cves]
        statements.append(build_statement(vulnerability, affected_images, timestamp))
    if extra_statements:
        statements.extend(extra_statements)
    statements.sort(
        key=lambda statement: (
            statement["vulnerability"]["name"],
            json.dumps(statement["products"], sort_keys=True),
        )
    )
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": document_id,
        "author": author,
        "role": role,
        "timestamp": timestamp,
        "version": 1,
        "statements": statements,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate an OpenVEX document for sandbox images that carry the custom "
            "patched CPython runtime."
        )
    )
    parser.add_argument(
        "--image",
        action="append",
        required=True,
        dest="images",
        help=(
            "Image reference to include in the VEX document. Use the same reference "
            "you plan to scan with Grype (for example secai-sandbox-ui:latest)."
        ),
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to write the generated OpenVEX document.",
    )
    parser.add_argument(
        "--manifest-path",
        default=DEFAULT_MANIFEST_PATH,
        help=f"Manifest path inside the image (default: {DEFAULT_MANIFEST_PATH}).",
    )
    parser.add_argument(
        "--author",
        default="SecAI OS",
        help="OpenVEX author value.",
    )
    parser.add_argument(
        "--role",
        default="Vendor",
        help="OpenVEX role value.",
    )
    parser.add_argument(
        "--document-id",
        help="OpenVEX document identifier. Defaults to a timestamped secai.local URL.",
    )
    parser.add_argument(
        "--timestamp",
        help="Document timestamp in ISO 8601 form. Defaults to the current UTC time.",
    )
    parser.add_argument(
        "--include-unicode-locale-glibc",
        action="store_true",
        help=(
            "Inspect the selected images for a UTF-8-only runtime locale guard and, "
            "when present, emit a not_affected VEX statement for glibc "
            f"{GLIBC_UNICODE_LOCALE_CVE}."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    timestamp = normalize_timestamp(args.timestamp)
    document_id = args.document_id or f"https://secai.local/vex/custom-python-{timestamp}"

    images = collect_image_build_metadata(
        image_refs=args.images,
        manifest_path=args.manifest_path,
    )
    extra_statements = []
    if args.include_unicode_locale_glibc:
        glibc_metadata = collect_unicode_locale_glibc_metadata(image_refs=args.images)
        extra_statements.extend(
            build_unicode_locale_glibc_statement(metadata, timestamp)
            for metadata in glibc_metadata
        )
    document = build_vex_document(
        images,
        author=args.author,
        role=args.role,
        document_id=document_id,
        timestamp=timestamp,
        extra_statements=extra_statements,
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "output": str(output_path),
                "images": [image.image_ref for image in images],
                "statements": [statement["vulnerability"]["name"] for statement in document["statements"]],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
