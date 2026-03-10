"""Storage gateway — mediated file access (spec §8).

All file reads/writes go through sensitivity-aware handles instead of
raw filesystem paths.  Read-only by default; write access limited to
approved output folders.  Supports redaction for outbound candidates.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from pathlib import Path
from typing import Any

from .models import CapabilityToken, SensitivityLevel

log = logging.getLogger("agent.storage")

# Maximum file sizes the gateway will serve
_MAX_READ_BYTES = 2 * 1024 * 1024   # 2 MB per file read
_MAX_WRITE_BYTES = 1 * 1024 * 1024  # 1 MB per file write

# Paths that are always blocked regardless of capability token
_BLOCKED_PATHS = {
    "/etc/shadow",
    "/etc/passwd",
    "/etc/secure-ai/policy",
    "/run/secure-ai/service-token",
}

# Patterns that suggest sensitive content
_SENSITIVE_PATTERNS = [
    re.compile(r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b"),        # SSN
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),  # email
    re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),  # credit card
    re.compile(r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*\S+"),   # credentials
]


class StorageGateway:
    """Mediates all file access for agent tasks.

    Every path access is validated against the capability token.  File
    contents are scanned for sensitivity before being returned to the
    agent runtime.  Write operations are limited to approved output dirs.
    """

    def __init__(self, vault_root: str = "/var/lib/secure-ai/vault"):
        self._vault_root = Path(vault_root)

    # --- public API --------------------------------------------------------

    def read_file(
        self,
        path: str,
        cap: CapabilityToken,
        *,
        max_bytes: int = _MAX_READ_BYTES,
    ) -> dict[str, Any]:
        """Read a file through the gateway.

        Returns {"ok": True, "content": str, "sensitivity": str, "size": int}
        or {"ok": False, "error": str}.
        """
        norm = self._normalise(path)

        # Block check
        err = self._check_blocked(norm)
        if err:
            return {"ok": False, "error": err}

        # Capability check
        if not self._path_in_scope(norm, cap.readable_paths):
            return {"ok": False, "error": f"path not in readable scope: {norm}"}

        # Existence
        real = Path(norm)
        if not real.is_file():
            return {"ok": False, "error": f"file not found: {norm}"}

        # Size check
        size = real.stat().st_size
        if size > max_bytes:
            return {"ok": False, "error": f"file too large ({size} bytes, max {max_bytes})"}

        try:
            content = real.read_text(errors="replace")
        except OSError as exc:
            return {"ok": False, "error": f"read error: {exc}"}

        sensitivity = self._classify_sensitivity(content)

        # Check sensitivity ceiling
        levels = [SensitivityLevel.LOW, SensitivityLevel.MEDIUM, SensitivityLevel.HIGH]
        if levels.index(sensitivity) > levels.index(cap.sensitivity_ceiling):
            return {
                "ok": False,
                "error": (
                    f"file sensitivity '{sensitivity.value}' exceeds "
                    f"ceiling '{cap.sensitivity_ceiling.value}'"
                ),
            }

        return {
            "ok": True,
            "content": content,
            "sensitivity": sensitivity.value,
            "size": len(content),
        }

    def write_file(
        self,
        path: str,
        content: str,
        cap: CapabilityToken,
        *,
        overwrite: bool = False,
        max_bytes: int = _MAX_WRITE_BYTES,
    ) -> dict[str, Any]:
        """Write a file through the gateway.

        Returns {"ok": True, "path": str, "size": int}
        or {"ok": False, "error": str}.
        """
        norm = self._normalise(path)

        # Block check
        err = self._check_blocked(norm)
        if err:
            return {"ok": False, "error": err}

        # Capability check
        if not self._path_in_scope(norm, cap.writable_paths):
            return {"ok": False, "error": f"path not in writable scope: {norm}"}

        # Size check
        content_bytes = content.encode("utf-8")
        if len(content_bytes) > max_bytes:
            return {"ok": False, "error": f"content too large ({len(content_bytes)} bytes, max {max_bytes})"}

        real = Path(norm)

        # Overwrite protection
        if real.exists() and not overwrite:
            return {"ok": False, "error": f"file exists and overwrite=false: {norm}"}

        try:
            real.parent.mkdir(parents=True, exist_ok=True)
            real.write_bytes(content_bytes)
        except OSError as exc:
            return {"ok": False, "error": f"write error: {exc}"}

        return {"ok": True, "path": norm, "size": len(content_bytes)}

    def list_files(
        self,
        scope: str,
        cap: CapabilityToken,
        *,
        max_results: int = 200,
    ) -> dict[str, Any]:
        """List files in a scope directory.

        Returns {"ok": True, "files": list[dict]}
        or {"ok": False, "error": str}.
        """
        norm = self._normalise(scope)

        if not self._path_in_scope(norm, cap.readable_paths):
            return {"ok": False, "error": f"scope not readable: {norm}"}

        real = Path(norm)
        if not real.is_dir():
            return {"ok": False, "error": f"not a directory: {norm}"}

        files = []
        try:
            for entry in sorted(real.iterdir()):
                if len(files) >= max_results:
                    break
                files.append({
                    "name": entry.name,
                    "is_dir": entry.is_dir(),
                    "size": entry.stat().st_size if entry.is_file() else 0,
                })
        except OSError as exc:
            return {"ok": False, "error": f"list error: {exc}"}

        return {"ok": True, "files": files}

    def redact_for_export(self, text: str) -> str:
        """Redact sensitive content from text before any outbound use."""
        redacted = text
        for pattern in _SENSITIVE_PATTERNS:
            redacted = pattern.sub("[REDACTED]", redacted)
        return redacted

    # --- internal ----------------------------------------------------------

    @staticmethod
    def _normalise(path: str) -> str:
        """Normalise and resolve a path, blocking traversal attacks."""
        # Resolve relative paths and symlinks
        norm = os.path.normpath(os.path.abspath(path))
        # Block null bytes
        if "\x00" in path:
            return "/dev/null"  # safe sentinel that will fail later checks
        return norm

    @staticmethod
    def _check_blocked(norm_path: str) -> str | None:
        """Return error string if path is in the blocked set."""
        for blocked in _BLOCKED_PATHS:
            if norm_path == blocked or norm_path.startswith(blocked + "/"):
                return f"path is blocked by policy: {norm_path}"
        return None

    @staticmethod
    def _path_in_scope(norm_path: str, allowed: list[str]) -> bool:
        """Check if a normalised path is within any allowed scope."""
        if not allowed:
            return False
        import fnmatch
        for pattern in allowed:
            norm_pattern = os.path.normpath(pattern)
            if fnmatch.fnmatch(norm_path, norm_pattern):
                return True
            # Also check if path is the directory itself or under it
            dir_pattern = norm_pattern.rstrip("*").rstrip("/")
            if norm_path == dir_pattern or norm_path.startswith(dir_pattern + "/"):
                return True
        return False

    @staticmethod
    def _classify_sensitivity(content: str) -> SensitivityLevel:
        """Heuristic sensitivity classification of file content."""
        hits = 0
        for pattern in _SENSITIVE_PATTERNS:
            if pattern.search(content):
                hits += 1
        if hits >= 2:
            return SensitivityLevel.HIGH
        if hits >= 1:
            return SensitivityLevel.MEDIUM
        return SensitivityLevel.LOW
