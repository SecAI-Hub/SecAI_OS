"""SLO compliance tracker — measures runtime adherence to docs/slos.md targets."""

import json
import math
import os
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class SLOResult:
    """A single SLO compliance measurement."""
    name: str
    target: str
    current_value: str
    compliant: bool
    detail: str


class SLOTracker:
    """Periodically records health-check results and computes SLO compliance.

    Thread-safe.  Call record_health_check() from the /api/status handler
    to feed measurements, then call get_all_slos() to read compliance.
    """

    # 7-day rolling window (matches docs/slos.md measurement window)
    WINDOW_SECONDS = 7 * 24 * 3600
    DEFAULT_MAX_SAMPLES_PER_SERVICE = 10_080
    STATE_VERSION = 1

    # SLO targets (from docs/slos.md)
    UPTIME_TARGETS: dict[str, float] = {
        "policy_engine": 99.9,
        "registry": 99.9,
        "tool_firewall": 99.9,
        "attestor": 99.9,
        "integrity_monitor": 99.9,
        "incident_recorder": 99.9,
        "web_ui": 99.5,
        "inference": 99.5,
        "diffusion": 99.5,
    }

    # P95 latency targets in ms (from docs/slos.md)
    LATENCY_P95_TARGETS: dict[str, float] = {
        "policy_engine": 15.0,
        "registry": 30.0,
        "tool_firewall": 30.0,
        "attestor": 150.0,
        "integrity_monitor": 30.0,
        "incident_recorder": 50.0,
    }

    def __init__(
        self,
        state_path: str | Path | None = None,
        *,
        max_samples_per_service: int | None = None,
    ) -> None:
        self._lock = threading.Lock()
        configured_path = (
            os.getenv("SLO_STATE_PATH", "/var/lib/secure-ai/ui/slo-samples.json")
            if state_path is None
            else state_path
        )
        self._state_path = Path(configured_path) if configured_path else None
        if max_samples_per_service is None:
            try:
                max_samples_per_service = int(
                    os.getenv(
                        "SLO_MAX_SAMPLES_PER_SERVICE",
                        str(self.DEFAULT_MAX_SAMPLES_PER_SERVICE),
                    )
                )
            except ValueError:
                max_samples_per_service = self.DEFAULT_MAX_SAMPLES_PER_SERVICE
        self._max_samples = max(1, min(max_samples_per_service, 100_000))
        # service -> [(timestamp, is_healthy)]
        self._health: dict[str, list[tuple[float, bool]]] = {}
        # service -> [(timestamp, latency_ms)]
        self._latency: dict[str, list[tuple[float, float]]] = {}
        self._load()

    @staticmethod
    def _valid_service(value: object) -> bool:
        return isinstance(value, str) and 0 < len(value) <= 128

    @staticmethod
    def _valid_timestamp(value: object, *, cutoff: float, now: float) -> bool:
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
            and cutoff < float(value) <= now + 300
        )

    def _decode_samples(
        self,
        raw: object,
        *,
        health: bool,
        cutoff: float,
        now: float,
    ) -> dict[str, list[tuple[float, Any]]]:
        decoded: dict[str, list[tuple[float, Any]]] = {}
        if not isinstance(raw, dict):
            return decoded
        for service, samples in raw.items():
            if not self._valid_service(service) or not isinstance(samples, list):
                continue
            accepted: list[tuple[float, Any]] = []
            for sample in samples[-self._max_samples :]:
                if not isinstance(sample, list) or len(sample) != 2:
                    continue
                timestamp, value = sample
                if not self._valid_timestamp(timestamp, cutoff=cutoff, now=now):
                    continue
                if health:
                    if not isinstance(value, bool):
                        continue
                elif (
                    not isinstance(value, (int, float))
                    or isinstance(value, bool)
                    or not math.isfinite(value)
                    or value < 0
                ):
                    continue
                accepted.append((float(timestamp), value))
            if accepted:
                decoded[service] = accepted[-self._max_samples :]
        return decoded

    def _load(self) -> None:
        if self._state_path is None:
            return
        try:
            if not self._state_path.exists():
                return
            if self._state_path.is_symlink():
                return
            raw = json.loads(self._state_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or raw.get("version") != self.STATE_VERSION:
                return
            now = time.time()
            cutoff = now - self.WINDOW_SECONDS
            self._health = self._decode_samples(
                raw.get("health"), health=True, cutoff=cutoff, now=now
            )
            self._latency = self._decode_samples(
                raw.get("latency"), health=False, cutoff=cutoff, now=now
            )
            try:
                self._state_path.chmod(0o660)
            except OSError:
                pass
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
            # A corrupt or unreadable state file must not prevent the UI from
            # starting. It is replaced atomically after the next valid sample.
            self._health = {}
            self._latency = {}

    def _persist_locked(self) -> None:
        if self._state_path is None:
            return
        parent = self._state_path.parent
        temporary: Path | None = None
        fd: int | None = None
        try:
            parent.mkdir(mode=0o2770, parents=True, exist_ok=True)
            try:
                parent.chmod(0o2770)
            except OSError:
                pass
            temporary = parent / (
                f".{self._state_path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
            )
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o660,
            )
            payload = {
                "version": self.STATE_VERSION,
                "health": self._health,
                "latency": self._latency,
            }
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                fd = None
                json.dump(payload, handle, separators=(",", ":"), allow_nan=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self._state_path)
            temporary = None
            self._state_path.chmod(0o660)
            try:
                directory_fd = os.open(parent, os.O_RDONLY)
            except OSError:
                directory_fd = None
            if directory_fd is not None:
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except (OSError, TypeError, ValueError):
            # SLO recording is observational and must not make health/status
            # requests fail when the persistence volume is unavailable.
            pass
        finally:
            if fd is not None:
                os.close(fd)
            if temporary is not None:
                try:
                    temporary.unlink()
                except OSError:
                    pass

    def record_health_check(self, service: str, ok: bool, latency_ms: float) -> None:
        """Record a single health-check result."""
        if not self._valid_service(service):
            raise ValueError("service name must be between 1 and 128 characters")
        if not isinstance(ok, bool):
            raise ValueError("health status must be a boolean")
        if (
            not isinstance(latency_ms, (int, float))
            or isinstance(latency_ms, bool)
            or not math.isfinite(latency_ms)
            or latency_ms < 0
        ):
            raise ValueError("latency must be a finite non-negative number")
        now = time.time()
        cutoff = now - self.WINDOW_SECONDS
        with self._lock:
            # Health
            hist = self._health.setdefault(service, [])
            hist.append((now, ok))
            # Trim old entries (keep last window)
            self._health[service] = [
                (t, v) for t, v in hist if t > cutoff
            ][-self._max_samples :]
            # Latency
            lat = self._latency.setdefault(service, [])
            lat.append((now, latency_ms))
            self._latency[service] = [
                (t, v) for t, v in lat if t > cutoff
            ][-self._max_samples :]
            self._persist_locked()

    def _uptime_pct(self, service: str) -> tuple[float, int]:
        """Return (uptime_percentage, sample_count) for a service."""
        with self._lock:
            hist = list(self._health.get(service, []))
        if not hist:
            return 0.0, 0
        ok_count = sum(1 for _, ok in hist if ok)
        return (ok_count / len(hist)) * 100, len(hist)

    def _latency_percentile(self, service: str, percentile: float) -> float:
        """Return the given percentile latency in ms for a service."""
        with self._lock:
            hist = list(self._latency.get(service, []))
        if not hist:
            return 0.0
        values = sorted(v for _, v in hist)
        idx = min(int(len(values) * percentile / 100), len(values) - 1)
        return values[idx]

    def get_all_slos(self) -> list[dict[str, Any]]:
        """Compute all SLO compliance metrics."""
        results: list[dict[str, Any]] = []

        # --- Uptime SLOs ---
        for service, target in self.UPTIME_TARGETS.items():
            uptime, samples = self._uptime_pct(service)
            if samples == 0:
                results.append({
                    "name": f"{service} availability",
                    "target": f"{target}%",
                    "current_value": "N/A",
                    "compliant": True,  # No data yet — don't alarm
                    "detail": "No samples collected yet",
                })
            else:
                results.append({
                    "name": f"{service} availability",
                    "target": f"{target}%",
                    "current_value": f"{uptime:.2f}%",
                    "compliant": uptime >= target,
                    "detail": f"{samples} samples in window",
                })

        # --- Latency SLOs (P95) ---
        for service, target_ms in self.LATENCY_P95_TARGETS.items():
            p95 = self._latency_percentile(service, 95)
            with self._lock:
                samples = len(self._latency.get(service, []))
            if samples == 0:
                results.append({
                    "name": f"{service} P95 latency",
                    "target": f"<{target_ms}ms",
                    "current_value": "N/A",
                    "compliant": True,
                    "detail": "No samples collected yet",
                })
            else:
                results.append({
                    "name": f"{service} P95 latency",
                    "target": f"<{target_ms}ms",
                    "current_value": f"{p95:.1f}ms",
                    "compliant": p95 <= target_ms,
                    "detail": f"{samples} samples in window",
                })

        return results
