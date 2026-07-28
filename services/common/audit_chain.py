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
import hmac
import json
import logging
import os
import stat
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("audit_chain")


def _hash_entry(
    prev_hash: str,
    event: str,
    data: dict,
    timestamp: str,
    key: bytes | None = None,
) -> str:
    """Compute the hash for an audit entry."""
    canonical = json.dumps(
        {"prev_hash": prev_hash, "event": event, "data": data, "timestamp": timestamp},
        sort_keys=True,
        separators=(",", ":"),
    )
    encoded = canonical.encode("utf-8")
    if key:
        return hmac.new(key, encoded, hashlib.sha256).hexdigest()
    return hashlib.sha256(encoded).hexdigest()


def _load_key(key_path: str | None) -> bytes | None:
    path = key_path or os.getenv("AUDIT_HMAC_KEY_PATH", "").strip()
    if not path:
        return None
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o022
            or not 32 <= metadata.st_size <= 4096
        ):
            return None
        raw = os.read(descriptor, 4097)
        if len(raw) != metadata.st_size:
            return None
    except OSError:
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    # Provisioned credentials are printable tokens terminated by a newline,
    # while tests and external key managers may provide 32 raw random bytes.
    # Blindly calling bytes.strip() corrupts a binary key whenever its first or
    # last octet happens to be ASCII whitespace.
    stripped = raw.strip(b" \t\r\n")
    key = (
        stripped
        if stripped
        and all(0x21 <= octet <= 0x7E for octet in stripped)
        else raw
    )
    return key if len(key) >= 32 else None


class AuditChain:
    """Append-only hash-chained audit log."""

    def __init__(
        self,
        log_path: str,
        max_size_mb: int = 50,
        *,
        key_path: str | None = None,
    ):
        self._path = Path(log_path)
        self._max_size = max_size_mb * 1024 * 1024
        self._lock = threading.Lock()
        self._prev_hash = ""
        self._entry_count = 0
        self._key_path = key_path
        self._key = _load_key(key_path)
        configured_key_path = key_path or os.getenv(
            "AUDIT_HMAC_KEY_PATH", ""
        ).strip()
        if configured_key_path and self._key is None:
            raise RuntimeError(
                "configured audit HMAC key is missing, unreadable, or shorter than 32 bytes"
            )
        self._checkpoint_path = self._path.with_suffix(
            self._path.suffix + ".checkpoint"
        )

        # Resume chain from existing log
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass  # directory may not be writable in test environments
        if self._path.exists():
            try:
                verification = self.verify(
                    str(self._path),
                    key_path=self._key_path,
                )
                if not verification.get("valid"):
                    raise RuntimeError(
                        "existing audit chain failed verification: "
                        f"{verification.get('detail', 'unknown error')}"
                    )
                last_line = ""
                archives = sorted(
                    self._path.parent.glob(
                        f"{self._path.stem}.*{self._path.suffix}"
                    )
                )
                for current_path in [*archives, self._path]:
                    with open(current_path, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                last_line = line
                                self._entry_count += 1
                if last_line:
                    entry = json.loads(last_line)
                    self._prev_hash = entry.get("entry_hash", "")
            except (json.JSONDecodeError, OSError, RuntimeError) as e:
                raise RuntimeError(
                    f"refusing to append to unverifiable audit chain {self._path}: {e}"
                ) from e

    def append(self, event: str, data: dict | None = None) -> str:
        """Append a hash-chained entry. Returns the entry hash."""
        if data is None:
            data = {}

        ts = datetime.now(timezone.utc).isoformat()

        with self._lock:
            entry_hash = _hash_entry(
                self._prev_hash,
                event,
                data,
                ts,
                self._key,
            )

            entry = {
                "timestamp": ts,
                "event": event,
                "data": data,
                "prev_hash": self._prev_hash,
                "entry_hash": entry_hash,
                "algorithm": "hmac-sha256" if self._key else "sha256",
            }

            try:
                # Check if rotation needed
                if self._path.exists() and self._path.stat().st_size >= self._max_size:
                    self._rotate()

                with open(self._path, "a", encoding="utf-8") as f:
                    # DynamicUser identities may change across activations.
                    # The setgid secure-ai-logs group therefore owns append
                    # continuity; per-log HMAC keys prevent other group
                    # members from forging a valid replacement chain.
                    os.fchmod(f.fileno(), 0o660)
                    f.write(json.dumps(entry, separators=(",", ":")) + "\n")
                    f.flush()
                    os.fsync(f.fileno())

                self._prev_hash = entry_hash
                self._entry_count += 1
                self._write_checkpoint()

            except OSError as e:
                log.error("failed to write audit entry: %s", e)
                raise

        return entry_hash

    def _rotate(self):
        """Rotate the log file when it exceeds max size."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
        archive = self._path.with_suffix(f".{ts}.jsonl")
        try:
            self._path.rename(archive)
            # Make archive read-only
            os.chmod(str(archive), 0o440)
            log.info("rotated audit log: %s -> %s", self._path, archive)
            # The next file continues from the archived tail. Keep the total
            # count so the keyed checkpoint detects archive deletion too.
        except OSError as e:
            log.error("failed to rotate audit log: %s", e)

    def _write_checkpoint(self) -> None:
        """Atomically anchor the current tail and entry count with an HMAC."""
        if not self._key:
            return
        payload = {
            "entries": self._entry_count,
            "last_hash": self._prev_hash,
        }
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        payload["hmac"] = hmac.new(
            self._key,
            canonical,
            hashlib.sha256,
        ).hexdigest()

        self._checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            prefix=f".{self._checkpoint_path.name}.",
            dir=str(self._checkpoint_path.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            # The writer and verifier use separate DynamicUser identities.
            # The shared group must retain append access across restarts;
            # deletion/replacement remains detectable through this keyed
            # checkpoint, even though it cannot be made unavailable to a
            # compromised peer without a dedicated audit broker.
            os.chmod(tmp_path, 0o660)
            os.replace(tmp_path, self._checkpoint_path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    @staticmethod
    def verify(log_path: str, *, key_path: str | None = None) -> dict:
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

        key = _load_key(key_path)
        prev_hash = ""
        count = 0

        try:
            archives = sorted(path.parent.glob(f"{path.stem}.*{path.suffix}"))
            log_paths = [*archives, path]
            line_num = 0
            for current_path in log_paths:
                with open(current_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line_num += 1
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

                        algorithm = entry.get("algorithm", "sha256")
                        if algorithm == "hmac-sha256" and not key:
                            return {
                                "valid": False,
                                "entries": count,
                                "broken_at": line_num,
                                "detail": "HMAC verification key unavailable",
                            }
                        if algorithm not in {"sha256", "hmac-sha256"}:
                            return {
                                "valid": False,
                                "entries": count,
                                "broken_at": line_num,
                                "detail": f"line {line_num}: unsupported hash algorithm",
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

                        expected_hash = _hash_entry(
                            entry.get("prev_hash", ""),
                            entry.get("event", ""),
                            entry.get("data", {}),
                            entry.get("timestamp", ""),
                            key if algorithm == "hmac-sha256" else None,
                        )
                        stored_hash = entry.get("entry_hash", "")
                        if not hmac.compare_digest(stored_hash, expected_hash):
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

        if key and count:
            checkpoint_path = path.with_suffix(path.suffix + ".checkpoint")
            try:
                checkpoint = json.loads(
                    checkpoint_path.read_text(encoding="utf-8")
                )
                checkpoint_hmac = str(checkpoint.pop("hmac", ""))
                canonical = json.dumps(
                    checkpoint,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                expected_checkpoint_hmac = hmac.new(
                    key,
                    canonical,
                    hashlib.sha256,
                ).hexdigest()
                if (
                    not hmac.compare_digest(
                        checkpoint_hmac,
                        expected_checkpoint_hmac,
                    )
                    or checkpoint.get("entries") != count
                    or checkpoint.get("last_hash") != prev_hash
                ):
                    raise ValueError("checkpoint does not match log tail")
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                return {
                    "valid": False,
                    "entries": count,
                    "broken_at": None,
                    "detail": f"checkpoint verification failed: {exc}",
                }

        return {
            "valid": True,
            "entries": count,
            "broken_at": None,
            "detail": f"chain intact: {count} entries verified",
        }
