"""Synthetic durable queue capacity, authority, recovery and writer boundaries."""
import copy
import errno
import json
import multiprocessing
import os
import stat
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services" / "ui"))

from common.bounded_state import StateBusy, StateCapacity, StateUnavailable, open_directory, stable_lock
from ui import catalog_jobs as module
from ui.catalog_jobs import CatalogJobs, JobConflict, validate_state
from ui.catalog_worker import Attempt, retain_after_stop, recover

GRANT = {"session": "a" * 64, "epoch": "b" * 64, "credential": "c" * 64}
PROFILE = {"profile": "research", "mode": "appliance", "generation": "", "session": ""}


def entry(name="synthetic.gguf"):
    return {"filename": name, "expected_size_bytes": 100, "expected_sha256": "f" * 64,
            "expected_revision": "a" * 40,
            "security_status": "pinned-candidate", "type": "llm"}


def admit(jobs, name="synthetic.gguf"):
    return jobs.admit(entry(name), GRANT, PROFILE, free_bytes=100000, reserve_bytes=1000)


def test_duplicate_intent_and_serialized_claim(tmp_path):
    jobs = CatalogJobs(tmp_path)
    first = admit(jobs)
    assert admit(jobs) == first
    second = admit(jobs, "second.gguf")
    assert jobs.claim() == first
    assert CatalogJobs(tmp_path).claim() is None
    jobs.cancel(first)
    assert jobs.snapshot()[first]["cancel"] is True
    jobs.update(first, status="cancelled", error="cancelled")
    assert CatalogJobs(tmp_path).claim() == second
    with pytest.raises(JobConflict):
        admit(jobs)
    with pytest.raises(JobConflict):
        jobs.retry(first, {**entry(), "expected_sha256": "1" * 64}, GRANT, PROFILE,
                   free_bytes=10000, reserve_bytes=1000)
    with pytest.raises(JobConflict):
        jobs.retry(first, entry(), GRANT, PROFILE, free_bytes=10000, reserve_bytes=1000)
    assert jobs.snapshot()[first]["attempt"] == 1


def _admit_process(directory, index, result):
    try:
        result.put(admit(CatalogJobs(Path(directory)), f"model-{index}.gguf"))
    except Exception as error:
        result.put(type(error).__name__)


def test_concurrent_process_admission_has_no_lost_intents(tmp_path):
    jobs = CatalogJobs(tmp_path)
    admit(jobs)
    context = multiprocessing.get_context("spawn")
    result = context.Queue()
    children = [context.Process(target=_admit_process, args=(str(tmp_path), index, result)) for index in range(8)]
    try:
        for child in children:
            child.start()
        received = [result.get(timeout=10) for _ in children]
        for child in children:
            child.join(5)
            assert child.exitcode == 0
        assert all(len(identifier) == 32 for identifier in received)
        assert len(jobs.snapshot()) == 9
    finally:
        for child in children:
            if child.pid is None:
                continue
            if child.is_alive():
                child.kill()
            child.join(5)
            assert not child.is_alive()
        result.close()


def test_active_capacity_reservation_and_terminal_space(tmp_path):
    jobs = CatalogJobs(tmp_path)
    ids = [admit(jobs, f"{index}.gguf") for index in range(module.MAX_ACTIVE)]
    with pytest.raises(StateCapacity):
        admit(jobs, "over.gguf")
    for identifier in ids:
        jobs.cancel(identifier)
    assert all(row["status"] == "cancelled" for row in jobs.snapshot().values())
    assert admit(jobs, "available.gguf")
    with pytest.raises(StateCapacity):
        jobs.admit(entry("no-space.gguf"), GRANT, PROFILE, free_bytes=1199, reserve_bytes=1000)


def test_actual_worst_case_snapshot_fits_terminal_reservation(tmp_path):
    jobs = CatalogJobs(tmp_path)
    identifier = admit(jobs, "x" * 200)
    row = jobs.snapshot()[identifier]
    row.update(status="handoff_unknown", error="authentication_required", attempt=3,
               size=module.MAX_DOWNLOAD_BYTES, downloaded=module.MAX_DOWNLOAD_BYTES,
               created=10**12, updated=10**12, started=10**12, deadline=10**12)
    row["profile"].update(generation="a" * 64, session="b" * 64)
    row["owned"] = {"." + str(i) + "x" * 253: [2**64 - 1, 2**64 - 1, "directory"] for i in range(6)}
    record_bytes = len(json.dumps(row, separators=(",", ":")).encode())
    assert record_bytes < module.MAX_RECORD_BYTES
    state = {"version": 2, "clock": module.CLOCK_DOMAIN, "jobs": {f"{index:032x}": copy.deepcopy(row) for index in range(module.MAX_JOBS)}}
    validate_state(state)
    assert len((json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode()) < module.MAX_STATE_BYTES
    with jobs.state.transaction(write=True) as current:
        current.update(state)
    with pytest.raises(StateCapacity):
        admit(jobs, "full.gguf")
    jobs.cancel(f"{0:032x}")
    assert jobs.snapshot()[f"{0:032x}"]["status"] == "handoff_unknown"


@pytest.mark.parametrize("status", ["publishing", "quarantined", "handoff_unknown"])
def test_ambiguous_publication_cannot_retry_or_delete(tmp_path, status):
    jobs = CatalogJobs(tmp_path / "jobs")
    root = tmp_path / "incoming"
    root.mkdir()
    identifier = admit(jobs)
    partial = root / ".synthetic.part"
    partial.write_bytes(b"synthetic")
    info = partial.stat()
    jobs.update(identifier, status=status, owned={partial.name: [info.st_dev, info.st_ino, "file"]})
    recover(jobs, root)
    retain_after_stop(jobs, identifier, error="interrupted")
    jobs.cancel(identifier)
    assert partial.exists()
    assert jobs.snapshot()[identifier]["status"] == "handoff_unknown"
    assert not jobs.public()["synthetic.gguf"]["cleanup_required"]
    with pytest.raises(JobConflict):
        jobs.retry(identifier, entry(), GRANT, PROFILE, free_bytes=10000, reserve_bytes=0)


@pytest.mark.parametrize("replacement", ["regular", "symlink", "hardlink"])
def test_recovery_retains_recorded_and_replacement_objects(tmp_path, replacement):
    jobs = CatalogJobs(tmp_path / "jobs")
    root = tmp_path / "incoming"
    root.mkdir()
    identifier = admit(jobs)
    partial = root / ".synthetic.part"
    partial.write_text("old")
    info = partial.stat()
    jobs.update(identifier, status="running", owned={partial.name: [info.st_dev, info.st_ino, "file"]})
    other = root / "unowned"
    if replacement == "hardlink":
        os.link(partial, other)
    else:
        partial.rename(other)
        if replacement == "regular":
            partial.write_text("new")
        else:
            partial.symlink_to(other)
    recover(jobs, root)
    assert partial.exists() and other.exists()
    assert jobs.snapshot()[identifier]["owned"]
    assert not jobs.public()["synthetic.gguf"]["retry_available"]


def test_prepublication_recovery_preserves_partial_bytes_and_inventory(tmp_path):
    jobs = CatalogJobs(tmp_path / "jobs")
    root = tmp_path / "incoming"
    root.mkdir()
    identifier = admit(jobs, "x" * 200)
    partial = root / ("." + "x" * 200 + "." + identifier + ".part")
    partial.write_bytes(b"old")
    info = partial.stat()
    jobs.update(identifier, status="running", owned={partial.name: [info.st_dev, info.st_ino, "file"]})
    unowned = root / ".unowned.part"
    unowned.write_bytes(b"keep")
    recover(jobs, root)
    assert partial.read_bytes() == b"old" and unowned.read_bytes() == b"keep"
    row = jobs.snapshot()[identifier]
    assert row["owned"] == {partial.name: [info.st_dev, info.st_ino, "file"]}
    assert row["status"] == "cleanup_required"
    assert not jobs.public()["x" * 200]["retry_available"]


@pytest.mark.parametrize("kind", ["file", "directory"])
def test_stopped_partial_retention_is_idempotent_and_disables_retry(tmp_path, kind):
    jobs = CatalogJobs(tmp_path / "jobs")
    root = tmp_path / "incoming"
    root.mkdir()
    identifier = admit(jobs)
    assert jobs.claim() == identifier
    partial = root / ".retained.part"
    if kind == "directory":
        (partial / "nested").mkdir(parents=True)
        payload = partial / "nested/inert"
    else:
        payload = partial
    payload.write_bytes(b"synthetic retained bytes")
    info = partial.stat()
    owned = {partial.name: [info.st_dev, info.st_ino, kind]}
    jobs.update(identifier, owned=owned)
    for _ in range(2):
        recover(jobs, root)
        jobs.cancel(identifier)
        assert payload.read_bytes() == b"synthetic retained bytes"
        assert jobs.snapshot()[identifier]["owned"] == owned
        assert jobs.public()["synthetic.gguf"]["cleanup_required"]
        with pytest.raises(JobConflict):
            jobs.retry(identifier, entry(), GRANT, PROFILE, free_bytes=10000, reserve_bytes=0)
    history = module.sanitized_history({"version": 2, "clock": module.CLOCK_DOMAIN, "jobs": jobs.snapshot()})
    assert history["jobs"][identifier]["requires_reconciliation"]


def test_unconfirmed_attempt_also_requires_maintenance_but_unstarted_cancel_can_retry(tmp_path):
    jobs = CatalogJobs(tmp_path)
    first = admit(jobs)
    jobs.claim()
    recover(jobs, tmp_path)
    assert jobs.snapshot()[first]["status"] == "cleanup_required"
    assert not jobs.public()["synthetic.gguf"]["retry_available"]
    second = admit(jobs, "never-started.gguf")
    jobs.cancel(second)
    jobs.retry(second, entry("never-started.gguf"), GRANT, PROFILE, free_bytes=10000, reserve_bytes=0)
    assert jobs.snapshot()[second]["status"] == "queued"
    assert jobs.snapshot()[second]["attempt"] == 0


def test_metadata_failure_retains_written_partial_with_worker_cleanup_disabled(tmp_path, monkeypatch):
    from ui import catalog
    owned = []
    transfer = catalog.Transfer(tmp_path, response=None, fetch=None, check=None, progress=None,
                                owned=owned.append, manage_cleanup=False)
    def fail(*args):
        raise OSError("synthetic publication failure")
    monkeypatch.setattr(catalog, "_publish_noreplace", fail)
    with pytest.raises(OSError):
        transfer._write_quarantine_metadata(tmp_path / ".synthetic.source", b"inert metadata")
    assert len(owned) == 1 and owned[0].read_bytes() == b"inert metadata"


def test_linux_publication_refuses_unlink_fallback(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from ui import catalog
    source, destination = tmp_path / ".source.part", tmp_path / "published"
    source.write_bytes(b"retained")
    monkeypatch.setattr(catalog.sys, "platform", "linux")
    monkeypatch.setattr(catalog.ctypes, "CDLL", lambda *a, **k: SimpleNamespace())
    with pytest.raises(OSError):
        catalog._publish_noreplace(source, destination)
    assert source.read_bytes() == b"retained" and not destination.exists()


@pytest.mark.parametrize("fault", ["short", "space", "file_sync", "directory_sync"])
def test_failed_acceptance_fences_all_live_instances(tmp_path, monkeypatch, fault):
    first, second = CatalogJobs(tmp_path), CatalogJobs(tmp_path)
    identifier = admit(first)
    assert second.snapshot()
    original_write, original_sync = os.write, os.fsync
    def write(fd, data):
        if fault == "short":
            return original_write(fd, data[:1])
        if fault == "space":
            raise OSError(errno.ENOSPC, "synthetic full")
        return original_write(fd, data)
    def sync(fd):
        info = os.fstat(fd)
        if ((fault == "file_sync" and stat.S_ISREG(info.st_mode) and info.st_size > 0)
                or (fault == "directory_sync" and stat.S_ISDIR(info.st_mode))):
            raise OSError(errno.EIO, "synthetic sync failure")
        return original_sync(fd)
    monkeypatch.setattr(os, "write", write)
    monkeypatch.setattr(os, "fsync", sync)
    with pytest.raises(StateUnavailable):
        first.cancel(identifier)
    monkeypatch.undo()
    for instance in (first, second, CatalogJobs(tmp_path)):
        with pytest.raises(StateUnavailable):
            instance.snapshot()


def test_invalid_and_replaced_lock_is_not_chmodded_or_adopted(tmp_path):
    jobs = CatalogJobs(tmp_path)
    admit(jobs)
    path = tmp_path / "jobs.json.lock"
    path.rename(tmp_path / "old.lock")
    path.write_bytes(b"")
    path.chmod(0o664)
    for instance in (jobs, CatalogJobs(tmp_path)):
        with pytest.raises(StateUnavailable):
            instance.snapshot()
    assert stat.S_IMODE(path.stat().st_mode) == 0o664


def _die_mid_transaction(directory):
    jobs = CatalogJobs(Path(directory))
    with jobs.state.transaction(write=True):
        os._exit(0)


def test_writer_crash_requires_explicit_recovery(tmp_path):
    jobs = CatalogJobs(tmp_path)
    admit(jobs)
    child = multiprocessing.get_context("spawn").Process(target=_die_mid_transaction, args=(str(tmp_path),))
    child.start()
    try:
        child.join(5)
        assert child.exitcode == 0
    finally:
        if child.is_alive():
            child.kill()
        child.join(5)
        assert not child.is_alive()
    with pytest.raises(StateUnavailable):
        jobs.snapshot()


def test_process_cases_from_threaded_caller_without_fork(tmp_path, monkeypatch):
    release = threading.Event()
    thread = threading.Thread(target=release.wait, daemon=True)
    thread.start()
    try:
        def forbidden_fork():
            pytest.fail("catalog process fixtures must not fork their threaded caller")
        monkeypatch.setattr(os, "fork", forbidden_fork)
        test_concurrent_process_admission_has_no_lost_intents(tmp_path / "admission")
        test_writer_crash_requires_explicit_recovery(tmp_path / "writer")
        assert thread.is_alive()
    finally:
        release.set()
        thread.join(5)
        assert not thread.is_alive()


def test_busy_reader_does_not_clear_another_writers_fence(tmp_path):
    # Independent open flock descriptions, even in one process, conflict.
    jobs = CatalogJobs(tmp_path)
    identifier = admit(jobs)
    other = CatalogJobs(tmp_path)
    with jobs.state.transaction(write=True):
        with pytest.raises(StateBusy):
            other.cancel(identifier)
        assert (tmp_path / "jobs.json.pending").exists()
    assert other.snapshot()


def test_worker_lock_missing_or_copied_inode_rejected(tmp_path):
    directory = open_directory(tmp_path)
    try:
        fd = stable_lock(directory, "worker.lock", state_name="worker.json")
        os.close(fd)
        payload = (tmp_path / "worker.lock").read_bytes()
        (tmp_path / "worker.lock").rename(tmp_path / "old")
        (tmp_path / "worker.lock").write_bytes(payload)
        (tmp_path / "worker.lock").chmod(0o660)
        with pytest.raises(StateUnavailable):
            stable_lock(directory, "worker.lock", state_name="worker.json")
    finally:
        os.close(directory)


def test_chunk_authority_checks_precede_progress(tmp_path, monkeypatch):
    jobs = CatalogJobs(tmp_path / "jobs")
    identifier = admit(jobs)
    jobs.claim()
    class Auth:
        def validate_grant(self, *args, **kwargs):
            return False
    attempt = Attempt(jobs, identifier, tmp_path, Auth())
    try:
        with pytest.raises(PermissionError):
            attempt.progress("synthetic.gguf", downloaded=1, total=100)
        assert jobs.snapshot()[identifier]["downloaded"] == 0
    finally:
        attempt.http.close()


def test_history_export_preserves_pins_but_cannot_restore_authority(tmp_path):
    jobs = CatalogJobs(tmp_path)
    identifier = admit(jobs)
    jobs.claim()
    source = {"version": 2, "clock": module.CLOCK_DOMAIN, "jobs": jobs.snapshot()}
    history = module.sanitized_history(source)
    row = history["jobs"][identifier]
    assert history["version"] == 1 and history["kind"] == "catalog-history"
    assert row["status"] == "interrupted" and row["requires_reconciliation"]
    assert row["pins"]["sha256"] == entry()["expected_sha256"]
    assert set(row).isdisjoint({"grant", "profile", "cancel", "owned", "deadline", "started"})
    with pytest.raises(ValueError):
        validate_state(history)
    jobs.update(identifier, status="publishing")
    assert module.sanitized_history({"version": 2, "clock": module.CLOCK_DOMAIN, "jobs": jobs.snapshot()})["jobs"][identifier]["status"] == "handoff_unknown"
