"""Authenticity and parser tests for offline forensic verification."""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = (
    REPO_ROOT
    / "files/system/usr/libexec/secure-ai/secure-forensic-verify.py"
)
SPEC = importlib.util.spec_from_file_location("secure_forensic_verify", HELPER_PATH)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


def _write_bundle(tmp_path: Path, *, key: bytes = b"k" * 32) -> tuple[Path, Path, dict]:
    content = {
        "exported_at": "2026-07-27T12:00:00Z",
        "incidents": [{"id": "inc-1", "description": "test"}],
        "audit_entries": ['{"event":"test"}'],
        "system_state": {"service": "incident-recorder"},
        "policy_digest": "a" * 64,
    }
    payload = json.dumps(content, separators=(",", ":"), ensure_ascii=False).encode()
    digest = hashlib.sha256(payload).digest()
    bundle = {
        **content,
        "canonical_payload": base64.b64encode(payload).decode(),
        "bundle_hash": digest.hex(),
        "signature": hmac.new(key, digest, hashlib.sha256).hexdigest(),
    }
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    key_path = tmp_path / "forensic.key"
    key_path.write_bytes(key)
    key_path.chmod(0o600)
    return bundle_path, key_path, bundle


def test_valid_bundle_verifies_raw_digest_hmac(tmp_path: Path) -> None:
    bundle_path, key_path, _bundle = _write_bundle(tmp_path)
    summary = verifier.verify_bundle(bundle_path, key_path)
    assert summary["incidents"] == 1
    assert summary["audit_entries"] == 1


def test_exposed_fields_must_match_authenticated_payload(tmp_path: Path) -> None:
    bundle_path, key_path, bundle = _write_bundle(tmp_path)
    bundle["incidents"][0]["description"] = "tampered"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    with pytest.raises(verifier.VerificationError, match="exposed bundle fields"):
        verifier.verify_bundle(bundle_path, key_path)


def test_payload_tampering_breaks_hash(tmp_path: Path) -> None:
    bundle_path, key_path, bundle = _write_bundle(tmp_path)
    payload = base64.b64decode(bundle["canonical_payload"])
    bundle["canonical_payload"] = base64.b64encode(payload + b" ").decode()
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    with pytest.raises(verifier.VerificationError, match="hash mismatch"):
        verifier.verify_bundle(bundle_path, key_path)


def test_wrong_key_breaks_signature(tmp_path: Path) -> None:
    bundle_path, _key_path, _bundle = _write_bundle(tmp_path)
    wrong_key = tmp_path / "wrong.key"
    wrong_key.write_bytes(b"z" * 32)
    with pytest.raises(verifier.VerificationError, match="signature mismatch"):
        verifier.verify_bundle(bundle_path, wrong_key)


def test_missing_signature_is_rejected(tmp_path: Path) -> None:
    bundle_path, key_path, bundle = _write_bundle(tmp_path)
    bundle["signature"] = ""
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    with pytest.raises(verifier.VerificationError, match="signature"):
        verifier.verify_bundle(bundle_path, key_path)


def test_unknown_schema_field_is_rejected(tmp_path: Path) -> None:
    bundle_path, key_path, bundle = _write_bundle(tmp_path)
    bundle["untrusted_note"] = "ignored by old verifiers"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    with pytest.raises(verifier.VerificationError, match="unexpected bundle schema"):
        verifier.verify_bundle(bundle_path, key_path)


def test_duplicate_json_keys_are_rejected(tmp_path: Path) -> None:
    bundle_path, key_path, bundle = _write_bundle(tmp_path)
    encoded = json.dumps(bundle)
    duplicate = encoded[:-1] + ',"signature":"' + bundle["signature"] + '"}'
    bundle_path.write_text(duplicate, encoding="utf-8")
    with pytest.raises(verifier.VerificationError, match="duplicate JSON key"):
        verifier.verify_bundle(bundle_path, key_path)


def test_symlink_bundle_is_rejected(tmp_path: Path) -> None:
    bundle_path, key_path, _bundle = _write_bundle(tmp_path)
    link = tmp_path / "bundle-link.json"
    link.symlink_to(bundle_path)
    with pytest.raises(verifier.VerificationError, match="symbolic link"):
        verifier.verify_bundle(link, key_path)
