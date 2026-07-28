"""Tests for the hash-chained audit log module."""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "services"))

from common.audit_chain import AuditChain, _hash_entry


class TestAuditChainAppend:
    def test_append_creates_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "test-audit.jsonl")
            chain = AuditChain(path)
            chain.append("test_event", {"key": "value"})

            assert Path(path).exists()
            lines = Path(path).read_text().strip().split("\n")
            assert len(lines) == 1

            entry = json.loads(lines[0])
            assert entry["event"] == "test_event"
            assert entry["data"]["key"] == "value"
            assert entry["prev_hash"] == ""
            assert "entry_hash" in entry
            assert "timestamp" in entry

    def test_append_chains_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "test-audit.jsonl")
            chain = AuditChain(path)

            chain.append("event_1", {"n": 1})
            chain.append("event_2", {"n": 2})
            chain.append("event_3", {"n": 3})

            lines = Path(path).read_text().strip().split("\n")
            assert len(lines) == 3

            e1 = json.loads(lines[0])
            e2 = json.loads(lines[1])
            e3 = json.loads(lines[2])

            # First entry has empty prev_hash
            assert e1["prev_hash"] == ""
            # Second entry's prev_hash is first entry's hash
            assert e2["prev_hash"] == e1["entry_hash"]
            # Third entry's prev_hash is second entry's hash
            assert e3["prev_hash"] == e2["entry_hash"]

    def test_append_with_no_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "test-audit.jsonl")
            chain = AuditChain(path)
            chain.append("simple_event")

            entry = json.loads(Path(path).read_text().strip())
            assert entry["data"] == {}

    def test_append_returns_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "test-audit.jsonl")
            chain = AuditChain(path)
            h = chain.append("test", {"x": 1})

            assert isinstance(h, str)
            assert len(h) == 64  # SHA-256 hex

    def test_resume_chain_from_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "test-audit.jsonl")

            # Write some entries
            chain1 = AuditChain(path)
            chain1.append("first", {"n": 1})
            chain1.append("second", {"n": 2})

            # Create a new chain instance (simulates service restart)
            chain2 = AuditChain(path)
            chain2.append("third", {"n": 3})

            # Verify the entire chain is valid
            result = AuditChain.verify(path)
            assert result["valid"] is True
            assert result["entries"] == 3


class TestAuditChainVerify:
    def test_verify_valid_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "test-audit.jsonl")
            chain = AuditChain(path)
            for i in range(10):
                chain.append(f"event_{i}", {"index": i})

            result = AuditChain.verify(path)
            assert result["valid"] is True
            assert result["entries"] == 10
            assert result["broken_at"] is None

    def test_verify_empty_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "test-audit.jsonl")
            Path(path).write_text("")

            result = AuditChain.verify(path)
            assert result["valid"] is True
            assert result["entries"] == 0

    def test_verify_nonexistent_file(self):
        result = AuditChain.verify("/tmp/nonexistent-audit-test.jsonl")
        assert result["valid"] is True
        assert result["entries"] == 0

    def test_verify_detects_tampered_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "test-audit.jsonl")
            chain = AuditChain(path)
            chain.append("event_1", {"ok": True})
            chain.append("event_2", {"ok": True})
            chain.append("event_3", {"ok": True})

            # Tamper with the second entry
            lines = Path(path).read_text().strip().split("\n")
            entry = json.loads(lines[1])
            entry["data"]["ok"] = False  # modify data
            lines[1] = json.dumps(entry, separators=(",", ":"))
            Path(path).write_text("\n".join(lines) + "\n")

            result = AuditChain.verify(path)
            assert result["valid"] is False
            assert result["broken_at"] == 2

    def test_verify_detects_deleted_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "test-audit.jsonl")
            chain = AuditChain(path)
            chain.append("event_1", {})
            chain.append("event_2", {})
            chain.append("event_3", {})

            # Delete the second entry
            lines = Path(path).read_text().strip().split("\n")
            Path(path).write_text(lines[0] + "\n" + lines[2] + "\n")

            result = AuditChain.verify(path)
            assert result["valid"] is False
            assert result["broken_at"] == 2

    def test_verify_detects_inserted_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "test-audit.jsonl")
            chain = AuditChain(path)
            chain.append("event_1", {})
            chain.append("event_2", {})

            # Insert a fake entry between them
            lines = Path(path).read_text().strip().split("\n")
            fake = json.dumps({
                "timestamp": "2026-01-01T00:00:00+00:00",
                "event": "fake",
                "data": {},
                "prev_hash": json.loads(lines[0])["entry_hash"],
                "entry_hash": "deadbeef" * 8,
            })
            Path(path).write_text(lines[0] + "\n" + fake + "\n" + lines[1] + "\n")

            result = AuditChain.verify(path)
            assert result["valid"] is False

    def test_verify_detects_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "test-audit.jsonl")
            chain = AuditChain(path)
            chain.append("event_1", {})

            # Corrupt the file
            content = Path(path).read_text()
            Path(path).write_text(content + "not valid json\n")

            result = AuditChain.verify(path)
            assert result["valid"] is False
            assert "invalid JSON" in result["detail"]


class TestHashEntry:
    def test_deterministic(self):
        h1 = _hash_entry("prev", "event", {"k": "v"}, "2026-01-01T00:00:00")
        h2 = _hash_entry("prev", "event", {"k": "v"}, "2026-01-01T00:00:00")
        assert h1 == h2

    def test_different_inputs_different_hashes(self):
        h1 = _hash_entry("prev", "event_a", {}, "2026-01-01T00:00:00")
        h2 = _hash_entry("prev", "event_b", {}, "2026-01-01T00:00:00")
        assert h1 != h2

    def test_data_order_independent(self):
        h1 = _hash_entry("", "e", {"a": 1, "b": 2}, "ts")
        h2 = _hash_entry("", "e", {"b": 2, "a": 1}, "ts")
        assert h1 == h2


class TestAuditChainRotation:
    def test_rotation_on_size_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "test-audit.jsonl")
            # Use a tiny max size to trigger rotation quickly
            chain = AuditChain(path, max_size_mb=0)  # 0 bytes = always rotate

            chain.append("event_1", {"data": "x" * 100})
            chain.append("event_2", {"data": "y" * 100})

            # Should have rotated — look for archive files
            archives = list(Path(tmp).glob("test-audit.*.jsonl"))
            assert len(archives) >= 1

            # Archives should be read-only
            for a in archives:
                assert not os.access(str(a), os.W_OK)


class TestKeyedAuditChain:
    def test_configured_missing_key_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            try:
                AuditChain(
                    str(Path(tmp) / "keyed.jsonl"),
                    key_path=str(Path(tmp) / "missing.key"),
                )
            except RuntimeError as exc:
                assert "HMAC key" in str(exc)
            else:
                raise AssertionError("configured missing audit key must fail closed")

    def test_hmac_chain_and_checkpoint_survive_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_path = Path(tmp) / "audit.key"
            key_path.write_bytes(os.urandom(32))
            path = str(Path(tmp) / "keyed.jsonl")

            AuditChain(path, key_path=str(key_path)).append("one", {"ok": True})
            AuditChain(path, key_path=str(key_path)).append("two", {"ok": True})

            result = AuditChain.verify(path, key_path=str(key_path))
            assert result["valid"] is True
            assert result["entries"] == 2

    def test_keyed_chain_requires_verification_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_path = Path(tmp) / "audit.key"
            key_path.write_bytes(os.urandom(32))
            path = str(Path(tmp) / "keyed.jsonl")
            AuditChain(path, key_path=str(key_path)).append("one")

            result = AuditChain.verify(path)
            assert result["valid"] is False
            assert "key unavailable" in result["detail"]

    def test_checkpoint_detects_tail_truncation(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_path = Path(tmp) / "audit.key"
            key_path.write_bytes(os.urandom(32))
            log_path = Path(tmp) / "keyed.jsonl"
            chain = AuditChain(str(log_path), key_path=str(key_path))
            chain.append("one")
            chain.append("two")
            log_path.write_text(log_path.read_text().splitlines()[0] + "\n")

            result = AuditChain.verify(
                str(log_path),
                key_path=str(key_path),
            )
            assert result["valid"] is False
            assert "checkpoint" in result["detail"]

    def test_keyed_rotation_verifies_archives_and_current_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_path = Path(tmp) / "audit.key"
            key_path.write_bytes(os.urandom(32))
            path = str(Path(tmp) / "keyed.jsonl")
            chain = AuditChain(path, max_size_mb=0, key_path=str(key_path))
            chain.append("one")
            chain.append("two")
            chain.append("three")

            result = AuditChain.verify(path, key_path=str(key_path))
            assert result["valid"] is True
            assert result["entries"] == 3

    def test_binary_hmac_key_preserves_boundary_whitespace_octets(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_path = Path(tmp) / "audit.key"
            key_path.write_bytes(b"\x20" + b"\x00" * 30 + b"\x0a")
            log_path = Path(tmp) / "keyed.jsonl"

            AuditChain(str(log_path), key_path=str(key_path)).append("one")

            assert AuditChain.verify(
                str(log_path),
                key_path=str(key_path),
            )["valid"] is True

    def test_hmac_key_rejects_symlink_and_group_writable_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target.key"
            target.write_bytes(b"k" * 32)
            link = Path(tmp) / "linked.key"
            link.symlink_to(target)

            with pytest.raises(RuntimeError, match="HMAC key"):
                AuditChain(
                    str(Path(tmp) / "linked.jsonl"),
                    key_path=str(link),
                )

            target.chmod(0o620)
            with pytest.raises(RuntimeError, match="HMAC key"):
                AuditChain(
                    str(Path(tmp) / "writable.jsonl"),
                    key_path=str(target),
                )
