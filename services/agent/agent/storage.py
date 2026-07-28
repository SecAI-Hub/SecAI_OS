"""Storage gateway — mediated file access (spec §8).

All file reads/writes go through sensitivity-aware handles instead of
raw filesystem paths.  Read-only by default; write access limited to
approved output folders.  Supports redaction for outbound candidates.
"""

from __future__ import annotations

import logging
import os
import re
import stat
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

        descriptor = -1
        try:
            descriptor = self._open_file_no_symlinks(
                norm,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
            )
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                return {"ok": False, "error": f"file not found: {norm}"}
            if info.st_nlink != 1:
                return {"ok": False, "error": "hard-linked files are not readable"}
            if info.st_size > max_bytes:
                return {
                    "ok": False,
                    "error": f"file too large ({info.st_size} bytes, max {max_bytes})",
                }
            chunks: list[bytes] = []
            remaining = max_bytes + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(remaining, 64 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > max_bytes:
                return {
                    "ok": False,
                    "error": f"file too large (more than {max_bytes} bytes)",
                }
            content = raw.decode("utf-8", errors="replace")
        except FileNotFoundError:
            return {"ok": False, "error": f"file not found: {norm}"}
        except OSError as exc:
            return {"ok": False, "error": f"read error: {exc}"}
        finally:
            if descriptor >= 0:
                os.close(descriptor)

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
            "size": len(raw),
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

        descriptor = -1
        try:
            flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
            if not overwrite:
                flags |= os.O_EXCL
            descriptor = self._open_file_no_symlinks(norm, flags, mode=0o600)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                return {"ok": False, "error": "write target is not a regular file"}
            if info.st_nlink != 1:
                return {"ok": False, "error": "hard-linked files cannot be overwritten"}
            if overwrite:
                os.ftruncate(descriptor, 0)
            view = memoryview(content_bytes)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
            os.fsync(descriptor)
        except FileExistsError:
            return {"ok": False, "error": f"file exists and overwrite=false: {norm}"}
        except OSError as exc:
            return {"ok": False, "error": f"write error: {exc}"}
        finally:
            if descriptor >= 0:
                os.close(descriptor)

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

        files: list[dict[str, object]] = []
        directory_fd = -1
        try:
            directory_fd = self._open_directory_no_symlinks(norm)
            for name in sorted(os.listdir(directory_fd)):
                if len(files) >= max_results:
                    break
                info = os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                files.append({
                    "name": name,
                    "is_dir": stat.S_ISDIR(info.st_mode),
                    "size": info.st_size if stat.S_ISREG(info.st_mode) else 0,
                })
        except OSError as exc:
            return {"ok": False, "error": f"list error: {exc}"}
        finally:
            if directory_fd >= 0:
                os.close(directory_fd)

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
        """Normalise and resolve a path, blocking traversal and symlink attacks."""
        # Block null bytes first
        if not isinstance(path, str) or "\x00" in path:
            return "/dev/null"  # safe sentinel that will fail later checks
        # Resolve relative paths, .., AND symlinks to get the real target
        return os.path.realpath(path)

    @staticmethod
    def _open_directory_no_symlinks(path: str) -> int:
        """Open an absolute directory one component at a time.

        Holding each directory descriptor while opening the next component
        eliminates path re-resolution and symlink-swap races.
        """
        if not os.path.isabs(path):
            raise OSError("path must be absolute")
        parts = Path(path).parts
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(os.sep, flags)
        try:
            for component in parts[1:]:
                if component in {"", ".", ".."}:
                    raise OSError("unsafe path component")
                next_descriptor = os.open(
                    component,
                    flags,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = next_descriptor
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    @classmethod
    def _open_file_no_symlinks(
        cls,
        path: str,
        flags: int,
        *,
        mode: int = 0o600,
    ) -> int:
        parent, name = os.path.split(path)
        if not parent or name in {"", ".", ".."}:
            raise OSError("unsafe file path")
        parent_fd = cls._open_directory_no_symlinks(parent)
        try:
            return os.open(
                name,
                flags | getattr(os, "O_NOFOLLOW", 0),
                mode,
                dir_fd=parent_fd,
            )
        finally:
            os.close(parent_fd)

    @staticmethod
    def _check_blocked(norm_path: str) -> str | None:
        """Return error string if path is in the blocked set."""
        for blocked in _BLOCKED_PATHS:
            # Policy roots must be canonicalised with the requested path.
            # macOS maps /etc -> /private/etc and /var -> /private/var; comparing
            # a realpath only on one side both bypassed deny rules and rejected
            # legitimate capability scopes.
            canonical_blocked = os.path.realpath(blocked)
            if (
                norm_path == canonical_blocked
                or norm_path.startswith(canonical_blocked + os.sep)
            ):
                return f"path is blocked by policy: {norm_path}"
        return None

    @staticmethod
    def _path_in_scope(norm_path: str, allowed: list[str]) -> bool:
        """Check if a normalised path is within any allowed scope."""
        if not allowed:
            return False
        import fnmatch
        for pattern in allowed:
            norm_pattern = StorageGateway._canonicalise_scope_pattern(pattern)
            if fnmatch.fnmatch(norm_path, norm_pattern):
                return True
            # Also check if path is the directory itself or under it
            dir_pattern = norm_pattern.rstrip("*").rstrip("/").rstrip(os.sep)
            if norm_path == dir_pattern or norm_path.startswith(dir_pattern + os.sep):
                return True
        return False

    @staticmethod
    def _canonicalise_scope_pattern(pattern: str) -> str:
        """Canonicalise the literal prefix of a capability glob.

        ``realpath`` cannot be applied to a complete glob because it treats
        wildcard characters as literal path components.  Resolve the path up
        to the first wildcard and then append the normalised glob suffix.
        """
        wildcard_positions = [
            position
            for token in ("*", "?", "[")
            if (position := pattern.find(token)) >= 0
        ]
        if not wildcard_positions:
            return os.path.realpath(os.path.normpath(pattern))

        wildcard_at = min(wildcard_positions)
        separator_at = pattern.rfind(os.sep, 0, wildcard_at)
        if separator_at < 0:
            return os.path.normpath(pattern)

        literal_prefix = pattern[:separator_at] or os.sep
        glob_suffix = pattern[separator_at + 1:]
        canonical_prefix = os.path.realpath(os.path.normpath(literal_prefix))
        return os.path.join(canonical_prefix, glob_suffix)

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
