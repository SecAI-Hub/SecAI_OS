#!/usr/bin/env python3
"""Strictly verify a SecAI OS forensic bundle and its dedicated HMAC."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any


DEFAULT_MAXIMUM = 64 * 1024**2
CONTENT_FIELDS = {
    "exported_at",
    "incidents",
    "audit_entries",
    "system_state",
    "policy_digest",
}
REQUIRED_FIELDS = CONTENT_FIELDS | {
    "canonical_payload",
    "bundle_hash",
    "signature",
}


class VerificationError(RuntimeError):
    """The supplied bundle is malformed, modified, or unauthenticated."""


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strict_loads(data: bytes) -> Any:
    return json.loads(
        data,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )


def _read_regular_file(path: Path, maximum: int, label: str) -> bytes:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise VerificationError(f"{label} must be a regular file, not a symbolic link")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        raise VerificationError(f"{label} has an invalid size")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(data) > maximum:
        raise VerificationError(f"{label} exceeds the size limit")
    return data


def verify_bundle(bundle_path: Path, key_path: Path, maximum: int = DEFAULT_MAXIMUM) -> dict:
    if maximum <= 0 or maximum > DEFAULT_MAXIMUM:
        raise VerificationError("invalid verification size limit")
    try:
        raw_bundle = _read_regular_file(bundle_path, maximum, "forensic bundle")
        bundle = _strict_loads(raw_bundle)
        if not isinstance(bundle, dict):
            raise VerificationError("bundle must be a JSON object")
        if set(bundle) != REQUIRED_FIELDS:
            missing = sorted(REQUIRED_FIELDS - set(bundle))
            extra = sorted(set(bundle) - REQUIRED_FIELDS)
            raise VerificationError(
                f"unexpected bundle schema (missing={missing}, extra={extra})"
            )

        encoded_payload = bundle["canonical_payload"]
        if not isinstance(encoded_payload, str):
            raise VerificationError("canonical_payload must be base64 text")
        try:
            payload = base64.b64decode(encoded_payload, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise VerificationError("canonical_payload is not valid base64") from exc
        if not payload or len(payload) > maximum:
            raise VerificationError("canonical_payload has an invalid size")

        digest = hashlib.sha256(payload).digest()
        stored_hash = bundle["bundle_hash"]
        if (
            not isinstance(stored_hash, str)
            or len(stored_hash) != 64
            or stored_hash != stored_hash.lower()
        ):
            raise VerificationError("bundle_hash is not canonical lowercase SHA-256")
        try:
            stored_digest = bytes.fromhex(stored_hash)
        except ValueError as exc:
            raise VerificationError("bundle_hash is not hexadecimal") from exc
        if not hmac.compare_digest(digest, stored_digest):
            raise VerificationError("bundle hash mismatch")

        key = _read_regular_file(key_path, 4096, "forensic HMAC key").strip()
        if len(key) < 32:
            raise VerificationError("forensic HMAC key is shorter than 32 bytes")
        signature = bundle["signature"]
        if (
            not isinstance(signature, str)
            or len(signature) != 64
            or signature != signature.lower()
        ):
            raise VerificationError("signature is not canonical lowercase HMAC-SHA256")
        try:
            supplied_signature = bytes.fromhex(signature)
        except ValueError as exc:
            raise VerificationError("signature is not hexadecimal") from exc
        expected_signature = hmac.new(key, digest, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_signature, supplied_signature):
            raise VerificationError("forensic HMAC signature mismatch")

        content = _strict_loads(payload)
        if not isinstance(content, dict) or set(content) != CONTENT_FIELDS:
            raise VerificationError("canonical payload has an unexpected schema")
        exposed = {field: bundle[field] for field in CONTENT_FIELDS}
        if content != exposed:
            raise VerificationError(
                "canonical payload does not match exposed bundle fields"
            )
        if not isinstance(content["exported_at"], str):
            raise VerificationError("exported_at must be text")
        if not isinstance(content["incidents"], list):
            raise VerificationError("incidents must be an array")
        if not isinstance(content["audit_entries"], list):
            raise VerificationError("audit_entries must be an array")
        if not isinstance(content["system_state"], dict):
            raise VerificationError("system_state must be an object")
        if not isinstance(content["policy_digest"], str):
            raise VerificationError("policy_digest must be text")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, VerificationError):
            raise
        raise VerificationError(str(exc)) from exc

    return {
        "bundle_hash": stored_hash,
        "incidents": len(content["incidents"]),
        "audit_entries": len(content["audit_entries"]),
        "exported_at": content["exported_at"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--maximum-bytes", type=int, default=DEFAULT_MAXIMUM)
    args = parser.parse_args()
    try:
        summary = verify_bundle(args.bundle, args.key, args.maximum_bytes)
    except VerificationError as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1
    print("VERIFIED: bundle content hash and dedicated HMAC signature are valid")
    print(f"  Hash: {summary['bundle_hash']}")
    print(f"  Incidents: {summary['incidents']}")
    print(f"  Audit entries: {summary['audit_entries']}")
    print(f"  Exported at: {summary['exported_at']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
