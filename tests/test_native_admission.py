"""Native gate state tests; real systemd/cgroup evidence is a separate guest run."""
import importlib.util
import fcntl
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "files/system/usr/libexec/secure-ai/secure-native-admission.py"
spec = importlib.util.spec_from_file_location("native_admission", SOURCE)
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class EmptyCgroup:
    def __init__(self, required):
        pass

    def empty(self):
        return True

    def close(self):
        pass


class NativeAdmissionStateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root, self.runtime = (Path(self.temp.name) / name for name in ("state", "runtime"))
        self.root.mkdir(mode=0o700)
        self.runtime.mkdir(mode=0o700)
        self.patches = [patch.object(native, "ROOT", self.root), patch.object(native, "RUNTIME", self.runtime),
                        patch.object(native, "Cgroup", EmptyCgroup),
                        patch.object(native, "show", return_value={"ActiveState": "inactive", "MainPID": "0", "Job": ""})]
        for item in self.patches:
            item.start()
        native.initialize()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def simulate_boot(self):
        (self.runtime / "ready.json").unlink()

    def test_clean_empty_native_gate_rebinds(self):
        layout = (self.root / "layout.json").read_bytes()
        self.simulate_boot()
        self.assertEqual(native.initialize()["admission"], "open")
        self.assertEqual(layout, (self.root / "layout.json").read_bytes())

    def test_closed_gate_cannot_rebind(self):
        gate = native.NativeGate(self.root, self.runtime)
        operation = gate.operation()
        try:
            native.close_admission(gate, operation)
        finally:
            operation.close()
            gate.close()
        before = (self.root / "gate.json").read_bytes()
        self.simulate_boot()
        with self.assertRaises(native.Error):
            native.initialize()
        self.assertEqual(before, (self.root / "gate.json").read_bytes())
        self.assertFalse((self.runtime / "ready.json").exists())

    def test_transaction_debris_cannot_rebind(self):
        self.simulate_boot()
        (self.root / "transactions" / "unknown").mkdir(mode=0o700)
        with self.assertRaises(native.Error):
            native.initialize()

    def test_active_writer_cannot_rebind(self):
        self.simulate_boot()
        with patch.object(native, "show", return_value={"ActiveState": "active", "MainPID": "20", "Job": ""}):
            with self.assertRaises(native.Error):
                native.initialize()

    def test_unheld_pending_job_cannot_rebind(self):
        self.simulate_boot()
        with patch.object(native, "show", return_value={"ActiveState": "inactive", "MainPID": "0", "Job": "10"}):
            with self.assertRaises(native.Error):
                native.initialize()

    def test_dependency_held_pending_job_rebinds(self):
        self.simulate_boot()
        def show(unit):
            if unit == native.UNIT:
                return {"ActiveState": "inactive", "MainPID": "0", "Job": "10"}
            return {"ActiveState": "activating", "MainPID": str(os.getpid())}
        with patch.object(native, "show", side_effect=show):
            self.assertEqual(native.initialize()["admission"], "open")

    def test_unknown_runtime_metadata_blocks(self):
        (self.runtime / "unknown").write_text("debris")
        with self.assertRaises(native.Error):
            native.initialize()

    def test_stale_boot_ready_is_not_repaired(self):
        ready = self.runtime / "ready.json"
        value = json.loads(ready.read_text())
        value["boot"] = "00000000-0000-0000-0000-000000000000"
        ready.write_text(json.dumps(value))
        with self.assertRaises(native.Error):
            native.initialize()
        self.assertEqual(json.loads(ready.read_text()), value)

    def test_replaced_lock_blocks(self):
        old = self.root / "admission.lock"
        old.rename(Path(self.temp.name) / "retained-old-lock")
        old.write_text("replacement")
        old.chmod(0o600)
        with self.assertRaises(native.Error):
            native.initialize()

    def close_gate(self):
        gate = native.NativeGate(self.root, self.runtime)
        operation = gate.operation()
        try:
            return native.close_admission(gate, operation)
        finally:
            operation.close()
            gate.close()

    def manager_scope(self):
        self.loaded = "masked"
        self.manager_calls = []
        def show(unit):
            return {"Id": unit, "LoadState": self.loaded, "ActiveState": "inactive", "MainPID": "0", "Job": "", "ControlGroup": ""}
        def manager(*args):
            self.manager_calls.append(args)
            if args[0] == "unmask":
                self.loaded = "loaded"
            elif args[0] == "mask":
                self.loaded = "masked"
            return ""
        first = patch.object(native, "show", side_effect=show)
        second = patch.object(native, "manager", side_effect=manager)
        first.start()
        second.start()
        self.addCleanup(first.stop)
        self.addCleanup(second.stop)

    def assert_locked(self, name):
        fd = os.open(self.root / name, os.O_RDONLY | os.O_CLOEXEC)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)

    def test_explicit_cycle_preserves_epoch_and_serializes_decisions(self):
        self.manager_scope()
        epoch = json.loads((self.root / "gate.json").read_text())["epoch"]
        original_manager = native.manager.side_effect
        def manager(*args):
            self.assert_locked("operation.lock")
            if args[0] == "unmask":
                self.assert_locked("admission.lock")
                self.assertEqual(json.loads((self.root / "gate.json").read_text())["state"], "closed")
            return original_manager(*args)
        with patch.object(native, "manager", side_effect=manager):
            closed = native.drain()
            result = native.reopen(closed["closure"])
        self.assertEqual(result["admission"], "open")
        self.assertFalse(result["units_started"])
        self.assertEqual(json.loads((self.root / "gate.json").read_text())["epoch"], epoch)
        self.assertFalse(any(call[0] in ("start", "enable") for call in self.manager_calls))
        self.assertEqual(native.status()["admission"], "open")
        with self.assertRaises(native.Error):
            native.reopen(closed["closure"])

    def test_stale_closure_is_refused_before_manager_changes(self):
        self.close_gate()
        self.manager_scope()
        with self.assertRaises(native.Error):
            native.reopen(str(uuid.uuid4()))
        self.assertEqual(self.manager_calls, [])

    def test_free_flock_does_not_override_live_descendants(self):
        identifier = self.close_gate()
        self.manager_scope()
        with patch.object(EmptyCgroup, "empty", return_value=False):
            with self.assertRaises(native.Error):
                native.reopen(identifier)
        self.assertEqual(self.manager_calls, [])
        self.assertEqual(native.status()["admission"], "closed")

    def test_pending_manager_job_prevents_reopening(self):
        identifier = self.close_gate()
        self.manager_scope()
        with patch.object(native, "show", return_value={"ActiveState": "inactive", "MainPID": "0", "ControlGroup": "", "Job": "22"}):
            with self.assertRaises(native.Error):
                native.reopen(identifier)
        self.assertEqual(self.manager_calls, [])

    def test_conflicting_operation_blocks_reopening(self):
        identifier = self.close_gate()
        self.manager_scope()
        gate = native.NativeGate(self.root, self.runtime)
        operation = gate.operation()
        try:
            with self.assertRaises(native.Error):
                native.reopen(identifier)
        finally:
            operation.close()
            gate.close()
        self.assertEqual(self.manager_calls, [])

    def test_partial_control_metadata_cannot_be_reopened(self):
        identifier = self.close_gate()
        self.manager_scope()
        (self.root / ".next-gate.json").write_text("pending")
        with self.assertRaises(native.Error):
            native.reopen(identifier)
        with self.assertRaises(native.Error):
            native.status()
        self.assertEqual(self.manager_calls, [])

    def test_unknown_ready_is_not_overwritten(self):
        identifier = self.close_gate()
        self.manager_scope()
        ready = self.runtime / "ready.json"
        value = json.loads(ready.read_text())
        value["epoch"] = str(uuid.uuid4())
        ready.write_text(json.dumps(value))
        before = ready.read_bytes()
        with self.assertRaises(native.Error):
            native.reopen(identifier)
        self.assertEqual(before, ready.read_bytes())
        self.assertEqual(self.manager_calls, [])

    def test_status_missing_runtime_is_read_only_explicit_resume_creates_it(self):
        identifier = self.close_gate()
        self.manager_scope()
        self.simulate_boot()
        self.runtime.rmdir()
        value = native.status()
        self.assertEqual((value["admission"], value["boot_binding"]), ("closed", "unbound"))
        self.assertFalse(self.runtime.exists())
        native.reopen(identifier)
        self.assertEqual(native.status()["admission"], "open")
        self.assertEqual(self.runtime.stat().st_mode & 0o777, 0o700)

    def test_status_uninitialized_does_not_provision(self):
        root, runtime = Path(self.temp.name) / "absent-root", Path(self.temp.name) / "absent-runtime"
        with patch.object(native, "ROOT", root), patch.object(native, "RUNTIME", runtime):
            self.assertEqual(native.status()["admission"], "uninitialized")
        self.assertFalse(root.exists() or runtime.exists())

    def fault_resume(self, event):
        identifier = self.close_gate()
        self.manager_scope()
        self.simulate_boot()
        implementation = native.guard.DurableIO
        def fault(actual):
            if actual == event:
                raise RuntimeError("simulated interruption")
        with patch.object(native.guard, "DurableIO", side_effect=lambda: implementation(fault)):
            with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
                native.reopen(identifier)
        return identifier

    def test_interruption_after_ready_before_open_remains_closed_retryable(self):
        identifier = self.fault_resume("native:resume-open:temporary:before-create")
        self.assertEqual(native.status()["admission"], "closed")
        self.assertEqual(native.status()["boot_binding"], "current")
        self.assertEqual(native.reopen(identifier)["admission"], "open")

    def test_interruption_with_pending_open_metadata_fails_closed(self):
        identifier = self.fault_resume("native:resume-open:temporary:after-fsync")
        self.assertEqual(json.loads((self.root / "gate.json").read_text())["state"], "closed")
        with self.assertRaises(native.Error):
            native.status()
        with self.assertRaises(native.Error):
            native.reopen(identifier)

    def test_open_publication_already_has_durable_matching_ready(self):
        self.fault_resume("native:resume-open:after-replace")
        self.assertEqual(native.status()["admission"], "open")
        gate = native.NativeGate(self.root, self.runtime)
        try:
            lease = gate.lease()
            lease.close()
        finally:
            gate.close()

    def test_atomic_replace_refreshes_stale_directory_description_without_filtering(self):
        gate = native.NativeGate(self.root, self.runtime)
        operation = gate.operation()
        original_names = native.guard.names
        stale = False
        def retained_view(fd, maximum):
            names = original_names(fd, maximum)
            # Model the actual Btrfs proof: the retained FD omitted only the
            # replaced gate.json, while a newly opened description saw it.
            return names - {"gate.json"} if stale and fd == gate.root.fd else names
        try:
            with patch.object(native.guard, "names", side_effect=retained_view):
                identifier = native.close_admission(gate, operation)
                stale = True
                self.assertEqual(gate.state()["closure"], identifier)
                (self.root / "unexpected").write_text("must not be filtered")
                with self.assertRaises(native.Error):
                    gate.state()
        finally:
            operation.close()
            gate.close()


if __name__ == "__main__":
    unittest.main()
