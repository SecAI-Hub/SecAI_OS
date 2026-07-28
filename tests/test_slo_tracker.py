import json
import stat
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "services" / "ui"))

from ui.slo_tracker import SLOTracker


def test_slo_samples_survive_restart(tmp_path):
    state_path = tmp_path / "slo.json"
    first = SLOTracker(state_path, max_samples_per_service=10)
    first.record_health_check("registry", True, 4.5)

    restarted = SLOTracker(state_path, max_samples_per_service=10)
    uptime, count = restarted._uptime_pct("registry")

    assert uptime == 100.0
    assert count == 1
    assert restarted._latency_percentile("registry", 95) == 4.5


def test_slo_state_is_bounded_and_group_writable(tmp_path):
    state_path = tmp_path / "private" / "slo.json"
    tracker = SLOTracker(state_path, max_samples_per_service=3)

    for latency in range(8):
        tracker.record_health_check("registry", True, float(latency))

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert len(state["health"]["registry"]) == 3
    assert len(state["latency"]["registry"]) == 3
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o660
    assert stat.S_IMODE(state_path.parent.stat().st_mode) == 0o2770


def test_corrupt_or_stale_slo_state_is_ignored(tmp_path):
    state_path = tmp_path / "slo.json"
    state_path.write_text("{not json", encoding="utf-8")
    tracker = SLOTracker(state_path, max_samples_per_service=2)
    assert tracker._uptime_pct("registry") == (0.0, 0)

    state_path.write_text(
        json.dumps(
            {
                "version": 1,
                "health": {
                    "registry": [[time.time() - SLOTracker.WINDOW_SECONDS - 1, True]]
                },
                "latency": {},
            }
        ),
        encoding="utf-8",
    )
    restarted = SLOTracker(state_path, max_samples_per_service=2)
    assert restarted._uptime_pct("registry") == (0.0, 0)
