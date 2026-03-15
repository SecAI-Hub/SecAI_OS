"""SLO compliance tracker — measures runtime adherence to docs/slos.md targets.

This is an in-process, ephemeral tracker that runs inside the Flask UI service.
Data resets on UI restart (SLOs are informational — actual enforcement is in the
Go security services).  The tracker accumulates health-check results fed by the
existing /api/status route and computes live compliance metrics.
"""

import threading
import time
from dataclasses import dataclass
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

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # service -> [(timestamp, is_healthy)]
        self._health: dict[str, list[tuple[float, bool]]] = {}
        # service -> [(timestamp, latency_ms)]
        self._latency: dict[str, list[tuple[float, float]]] = {}

    def record_health_check(self, service: str, ok: bool, latency_ms: float) -> None:
        """Record a single health-check result."""
        now = time.time()
        cutoff = now - self.WINDOW_SECONDS
        with self._lock:
            # Health
            hist = self._health.setdefault(service, [])
            hist.append((now, ok))
            # Trim old entries (keep last window)
            self._health[service] = [(t, v) for t, v in hist if t > cutoff]
            # Latency
            lat = self._latency.setdefault(service, [])
            lat.append((now, latency_ms))
            self._latency[service] = [(t, v) for t, v in lat if t > cutoff]

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
