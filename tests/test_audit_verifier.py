"""Regression tests for explicit mixed-format audit verification."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFIER_PATH = (
    REPO_ROOT
    / "files/system/usr/libexec/secure-ai/verify-audit-chains.py"
)

spec = importlib.util.spec_from_file_location("secure_ai_audit_verifier", VERIFIER_PATH)
assert spec and spec.loader
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def test_structured_jsonl_is_not_reported_as_hash_chained(tmp_path):
    path = tmp_path / "airlock-audit.jsonl"
    path.write_text('{"event":"allowed"}\n', encoding="utf-8")

    result = verifier._structured_jsonl(path)

    assert result["valid"] is True
    assert "no tamper-evidence claim" in result["detail"]


def test_structured_jsonl_rejects_invalid_record(tmp_path):
    path = tmp_path / "airlock-audit.jsonl"
    path.write_text('{"event":"allowed"}\nnot-json\n', encoding="utf-8")

    result = verifier._structured_jsonl(path)

    assert result["valid"] is False
    assert result["broken_at"] == 2


def test_manifest_rejects_duplicate_enrollment(monkeypatch, tmp_path):
    manifest = tmp_path / "formats.json"
    manifest.write_text(json.dumps({
        "version": 1,
        "logs": [
            {
                "file": "same-audit.jsonl",
                "format": "structured-jsonl",
                "security_class": "structured-only",
            },
            {
                "file": "same-audit.jsonl",
                "format": "structured-jsonl",
                "security_class": "structured-only",
            },
        ],
    }))
    monkeypatch.setattr(verifier, "MANIFEST_PATH", manifest)

    with pytest.raises(ValueError, match="duplicate"):
        verifier.load_manifest()


def test_repository_manifest_assigns_truthful_classes():
    payload = json.loads(
        (
            REPO_ROOT
            / "files/system/etc/secure-ai/config/audit-log-formats.json"
        ).read_text()
    )
    by_name = {entry["file"]: entry for entry in payload["logs"]}

    assert by_name["agent-audit.jsonl"]["format"] == "python-hmac-chain"
    assert by_name["airlock-audit.jsonl"]["format"] == "structured-jsonl"
    assert by_name["airlock-audit.jsonl"]["security_class"] == "structured-only"
    assert by_name["mcp-firewall-audit.jsonl"]["security_class"] == "unkeyed-hash-linked"


def test_logrotate_does_not_copytruncate_keyed_chains():
    config = (
        REPO_ROOT / "files/system/etc/logrotate.d/secure-ai"
    ).read_text()
    for filename in (
        "agent-audit.jsonl",
        "quarantine-audit.jsonl",
        "search-audit.jsonl",
        "ui-audit.jsonl",
        "mcp-firewall-audit.jsonl",
    ):
        assert f"/var/lib/secure-ai/logs/{filename}" not in config
