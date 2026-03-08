"""
Hash-chained append-only audit log.

Each log entry includes a SHA-256 hash of the previous entry, forming a
tamper-evident chain. If any entry is modified, deleted, or inserted, the
chain breaks and verification fails.

Format: one JSON object per line (JSONL), each containing:
  - timestamp: ISO 8601 UTC
  - event: event type string
  - data: arbitrary event data dict
  - prev_hash: SHA-256 hex of the previous entry's JSON (empty string for genesis)
  - entry_hash: SHA-256 hex of (prev_hash + event + data + timestamp)

Usage:
    chain = AuditChain("/var/lib/secure-ai/logs/quarantine-audit.jsonl")
    chain.append("promoted", {"model": "phi-3", "sha256": "abc..."})

    result = AuditChain.verify("/var/lib/secure-ai/logs/quarantine-audit.jsonl")
    # result = {"valid": True, "entries": 42, "first": "...", "last": "..."}
"""

import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("audit_chain")


def _hash_entry(prev_hash: str, event: str, data: dict, timestamp: str) -> str:
    """Compute the hash for an audit entry."""
    canonical = json.dumps(
        {"prev_hash": prev_hash, "event": event, "data": data, "timestamp": timestamp},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditChain:
    """Append-only hash-chained audit log."""

    def __init__(self, log_path: str, max_size_mb: int = 50):
        self._path = Path(log_path)
        self._max_size = max_size_mb * 1024 * 1024
        self._lock = threading.Lock()
        self._prev_hash = ""
        self._entry_count = 0

        # Resume chain from existing log
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass  # directory may not be writable in test environments
        if self._path.exists() and self._path.stat().st_size > 0:
            try:
                last_line = ""
                with open(self._path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            last_line = line
                            self._entry_count += 1
                if last_line:
                    entry = json.loads(last_line)
                    self._prev_hash = entry.get("entry_hash", "")
            except (json.JSONDecodeError, OSError) as e:
                log.warning("could not resume chain from %s: %s", self._path, e)

    def append(self, event: str, data: dict = None) -> str:
        """Append a hash-chained entry. Returns the entry hash."""
        if data is None:
            data = {}

        ts = datetime.now(timezone.utc).isoformat()

        with self._lock:
            entry_hash = _hash_entry(self._prev_hash, event, data, ts)

            entry = {
                "timestamp": ts,
                "event": event,
                "data": data,
                "prev_hash": self._prev_hash,
                "entry_hash": entry_hash,
            }

            try:
                # Check if rotation needed
                if self._path.exists() and self._path.stat().st_size >= self._max_size:
                    self._rotate()

                with open(self._path, "a") as f:
                    f.write(json.dumps(entry, separators=(",", ":")) + "\n")

                self._prev_hash = entry_hash
                self._entry_count += 1

            except OSError as e:
                log.error("failed to write audit entry: %s", e)

        return entry_hash

    def _rotate(self):
        """Rotate the log file when it exceeds max size."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        archive = self._path.with_suffix(f".{ts}.jsonl")
        try:
            self._path.rename(archive)
            # Make archive read-only
            os.chmod(str(archive), 0o444)
            log.info("rotated audit log: %s -> %s", self._path, archive)
            # Reset chain for new file (first entry references last hash from old file)
            self._entry_count = 0
        except OSError as e:
            log.error("failed to rotate audit log: %s", e)

    @staticmethod
    def verify(log_path: str) -> dict:
        """Verify the integrity of a hash-chained audit log.

        Returns:
            {
                "valid": bool,
                "entries": int,
                "broken_at": int or None,  # line number of first break
                "detail": str,
            }
        """
        path = Path(log_path)
        if not path.exists():
            return {"valid": True, "entries": 0, "broken_at": None,
                    "detail": "log file does not exist"}

        prev_hash = ""
        count = 0

        try:
            with open(path, "r") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        return {
                            "valid": False,
                            "entries": count,
                            "broken_at": line_num,
                            "detail": f"line {line_num}: invalid JSON",
                        }

                    # Check chain linkage
                    stored_prev = entry.get("prev_hash", "")
                    if stored_prev != prev_hash:
                        return {
                            "valid": False,
                            "entries": count,
                            "broken_at": line_num,
                            "detail": (
                                f"line {line_num}: chain break — "
                                f"expected prev_hash={prev_hash[:16]}..., "
                                f"got {stored_prev[:16]}..."
                            ),
                        }

                    # Verify entry hash
                    expected_hash = _hash_entry(
                        entry.get("prev_hash", ""),
                        entry.get("event", ""),
                        entry.get("data", {}),
                        entry.get("timestamp", ""),
                    )
                    stored_hash = entry.get("entry_hash", "")
                    if stored_hash != expected_hash:
                        return {
                            "valid": False,
                            "entries": count,
                            "broken_at": line_num,
                            "detail": (
                                f"line {line_num}: hash mismatch — "
                                f"computed {expected_hash[:16]}..., "
                                f"stored {stored_hash[:16]}..."
                            ),
                        }

                    prev_hash = stored_hash
                    count += 1

        except OSError as e:
            return {
                "valid": False,
                "entries": count,
                "broken_at": None,
                "detail": f"read error: {e}",
            }

        return {
            "valid": True,
            "entries": count,
            "broken_at": None,
            "detail": f"chain intact: {count} entries verified",
        }
