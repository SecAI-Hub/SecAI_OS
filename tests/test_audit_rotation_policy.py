"""Keep externally rotated logs disjoint from the declared audit chains."""

from __future__ import annotations

import fnmatch
import json
import shlex
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
FORMAT_MANIFEST = ROOT / "files/system/etc/secure-ai/config/audit-log-formats.json"
ROTATION_POLICY = ROOT / "files/system/etc/logrotate.d/secure-ai"


def _rotation_patterns(config: str) -> list[str]:
    """Read the simple packaged stanzas; unknown syntax fails the check closed."""
    lexer = shlex.shlex(config, posix=True, punctuation_chars="{}")
    lexer.whitespace_split = True
    patterns: list[str] = []
    header: list[str] = []
    inside = False
    for token in lexer:
        if token == "{":
            assert not inside and header, "invalid rotation stanza"
            assert all(path.startswith("/") for path in header), "unsupported rotation directive"
            patterns.extend(header)
            header = []
            inside = True
        elif token == "}":
            assert inside, "unexpected rotation stanza end"
            inside = False
        elif not inside:
            header.append(token)
    assert not inside and not header, "incomplete rotation policy"
    assert patterns, "rotation policy unexpectedly has no log paths"
    return patterns


def _protected_logs() -> list[str]:
    document = json.loads(FORMAT_MANIFEST.read_text())
    assert document["version"] == 2 and document["logs"]
    protected = [
        entry["file"] for entry in document["logs"]
        if entry["format"] != "structured-jsonl"
        or entry["security_class"] != "structured-only"
    ]
    assert protected, "audit format manifest unexpectedly declares no protected logs"
    return protected


@pytest.mark.parametrize("filename", _protected_logs())
def test_declared_audit_chain_is_not_externally_rotated(filename: str) -> None:
    path = f"/var/lib/secure-ai/logs/{filename}"
    patterns = _rotation_patterns(ROTATION_POLICY.read_text())
    matches = [pattern for pattern in patterns if fnmatch.fnmatchcase(path, pattern)]
    assert not matches, f"{filename} is a declared audit chain matched by external rotation: {matches}"


def test_rotation_check_detects_wildcards_and_ignores_comments() -> None:
    patterns = _rotation_patterns('''
# /var/lib/secure-ai/logs/ignored.jsonl
"/var/lib/secure-ai/logs/*-audit.jsonl" /var/lib/secure-ai/logs/other.jsonl {
    daily
    copytruncate
}
''')
    assert len(patterns) == 2
    assert fnmatch.fnmatchcase("/var/lib/secure-ai/logs/panic-audit.jsonl", patterns[0])
    assert not any("ignored" in pattern for pattern in patterns)


def test_rotation_check_rejects_unsupported_includes() -> None:
    with pytest.raises(AssertionError, match="unsupported rotation directive"):
        _rotation_patterns("include /uninspected/policy\n/log.jsonl { daily }")
