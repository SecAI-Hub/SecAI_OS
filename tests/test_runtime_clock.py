"""Suspend-aware lifetime domain, legacy rejection and actual kernel deadline."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/ui"))

from common import runtime_clock
from common.bounded_state import StateUnavailable
from common.session_store import SessionStore, validate_state as validate_sessions
from ui.catalog_jobs import CatalogJobs, validate_state as validate_jobs


def test_actual_suspend_aware_clock_and_independent_kernel_timer():
    assert runtime_clock.clock_id() == time.CLOCK_BOOTTIME
    assert runtime_clock.now() >= time.monotonic() - .1
    command = [sys.executable, "-c", "from common.runtime_clock import now,arm_deadline; import time; arm_deadline(now()+.15); time.sleep(10)"]
    child = subprocess.Popen(command, env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "services")})
    try:
        assert child.wait(timeout=3) == -signal.SIGALRM
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(3)


def test_simulated_suspend_expires_idle_and_absolute_even_if_awake_clock_stops(tmp_path, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(runtime_clock.time, "clock_gettime", lambda domain: clock[0])
    store = SessionStore(tmp_path / "auth", tmp_path / "runtime", idle=30, absolute=60)
    row = {"created": 100.0, "last_active": 100.0, "credential": "a" * 64}
    assert store.valid(row, "a" * 64)
    # No host suspend. Only the explicit suspend-inclusive source advances.
    monkeypatch.setattr(runtime_clock.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(runtime_clock.time, "time", lambda: -100000.0)
    clock[0] = 131
    assert not store.valid(row, "a" * 64)
    row["last_active"] = 159
    clock[0] = 161
    assert not store.valid(row, "a" * 64)


def test_explicit_unavailable_clock_never_falls_back(monkeypatch):
    monkeypatch.delattr(runtime_clock.time, "CLOCK_BOOTTIME")
    with pytest.raises(StateUnavailable):
        runtime_clock.now()


def test_live_schemas_reject_awake_clock_v1_authority(tmp_path):
    sessions = {"version": 1, "epoch": "a" * 64, "sessions": {}, "clients": {}}
    with pytest.raises(ValueError):
        validate_sessions(sessions)
    with pytest.raises(ValueError):
        validate_jobs({"version": 1, "jobs": {}})
    jobs = CatalogJobs(tmp_path / "jobs")
    with jobs.state.transaction(write=True):
        pass
    jobs.state.path.write_text(json.dumps({"version": 1, "jobs": {}}))
    with pytest.raises(StateUnavailable):
        CatalogJobs(tmp_path / "jobs").snapshot()


def test_job_deadline_uses_same_suspend_clock_and_ignores_wall_reversal(tmp_path, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(runtime_clock, "now", lambda: clock[0])
    jobs = CatalogJobs(tmp_path)
    entry = {"filename": "synthetic.gguf", "expected_size_bytes": 1,
             "expected_sha256": "a" * 64, "expected_revision": "b" * 40}
    grant = {"session": "c" * 64, "epoch": "d" * 64, "credential": "e" * 64}
    profile = {"profile": "research", "mode": "appliance", "generation": "", "session": ""}
    identifier = jobs.admit(entry, grant, profile, free_bytes=100, reserve_bytes=0)
    jobs.claim()
    row = jobs.snapshot()[identifier]
    assert row["started"] == 100 and row["deadline"] == 1900
    monkeypatch.setattr(runtime_clock.time, "time", lambda: 1)
    clock[0] = 1901
    from ui.catalog_worker import Attempt
    attempt = Attempt(jobs, identifier, tmp_path, None)
    try:
        with pytest.raises(PermissionError):
            attempt.current()
    finally:
        attempt.http.close()
