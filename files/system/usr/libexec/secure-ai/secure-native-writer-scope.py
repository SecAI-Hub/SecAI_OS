#!/usr/bin/python3 -IB
"""Internal B2 writer coordination; not a recovery adapter or mutation CLI.

Only trusted installed code supplies the complete writer/trigger set and the
durable closed-admission predicate. Archive, journal and command-line data must
never select units. This proves only the selected scope, not global quiescence.
Native metadata, boot rebind and emergency-containment qualification remain
separate prerequisites; nothing here reopens admission or starts services.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import time
from typing import Callable

_spec = importlib.util.spec_from_file_location(
    "native_admission", Path(__file__).with_name("secure-native-admission.py"))
assert _spec and _spec.loader
native = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(native)
Error = native.Error
CGROUP_PARENT = Path("/sys/fs/cgroup/system.slice")
NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,190}\.(service|timer|path)")


class WriterScope:
    """A trusted-code capability with no public arbitrary-unit interface."""

    def __init__(self, writers: tuple[str, ...], triggers: tuple[str, ...],
                 closed: Callable[[], bool]):
        if (type(writers) is not tuple or type(triggers) is not tuple or not writers
                or len(writers) + len(triggers) > 128 or not callable(closed)):
            raise Error("invalid trusted writer scope")
        units = writers + triggers
        if (any(type(name) is not str or not NAME.fullmatch(name) for name in units)
                or len(set(units)) != len(units)
                or any(not name.endswith(".service") for name in writers)
                or any(name.endswith(".service") for name in triggers)):
            raise Error("ambiguous or unsupported writer activation scope")
        self.writers, self.triggers, self.closed = writers, triggers, closed
        self.pins: dict[str, object] = {}
        self.masked = False
        self.finished = False
        self.deadline = None

    def _closed(self) -> None:
        if self.finished or self.closed() is not True:
            raise Error("durable closed admission required")

    def _check(self) -> None:
        self._closed()
        if self.deadline is not None:
            self.deadline.check()

    def _show(self, name: str) -> dict[str, str]:
        self._check()
        value = native.show(name)
        self._check()
        return value

    def _manager(self, *args: str) -> None:
        self._check()
        native.manager(*args)
        self._check()

    def _empty(self, pin) -> bool:
        self._check()
        value = pin.empty()
        self._check()
        return value is True

    def _writer(self, name: str) -> dict[str, str]:
        value = self._show(name)
        path = "/system.slice/" + name
        if value.get("ControlGroup") not in ("", path):
            raise Error("writer escaped its fixed cgroup binding")
        if value["LoadState"] == "loaded":
            expected = {"KillMode": "control-group", "Delegate": "no",
                        "ProtectControlGroups": "yes"}
            if any(value.get(key) != expected_value for key, expected_value in expected.items()):
                raise Error("writer containment properties differ")
        elif not native.inactive(value):
            raise Error("active masked writer containment unavailable")
        return value

    def quiescent(self) -> bool:
        self._check()
        if not self.masked or set(self.pins) != set(self.writers):
            return False
        for name in self.writers:
            value = self._writer(name)
            if (value["LoadState"] != "masked" or not native.inactive(value)
                    or not self._empty(self.pins[name])):
                return False
        for name in self.triggers:
            value = self._show(name)
            if value["LoadState"] != "masked" or not native.inactive(value):
                return False
        self._check()
        return True

    def stop_writers(self, deadline) -> None:
        native.root_only()
        self._closed()
        if self.deadline is not None or self.pins or self.masked:
            raise Error("writer scope closure is single-use")
        self.deadline = deadline
        self._check()
        for name in self.writers:
            self._writer(name)
        for name in self.triggers:
            self._show(name)
        # Preserve loaded stop policy until all processes and jobs are gone.
        self._manager("mask", "--runtime", "--no-reload", *self.triggers, *self.writers)
        self.masked = True
        self._closed()
        for name in self.writers:
            self._check()
            self.pins[name] = native.Cgroup(required=False, trusted_path=CGROUP_PARENT / name)
            self._check()
        self._manager("stop", "--no-block", *self.triggers, *self.writers)
        while True:
            deadline.check()
            self._check()
            writers = [self._writer(name) for name in self.writers]
            triggers = [self._show(name) for name in self.triggers]
            if (all(native.inactive(value) for value in writers + triggers)
                    and all(self._empty(pin) for pin in self.pins.values())):
                break
            time.sleep(0.05)
        self._manager("daemon-reload")
        if not self.quiescent():
            raise Error("writer or activation reappeared after closure")
        self._check()

    def close(self) -> None:
        # Closing handles is not reopening authority; runtime masks remain.
        for pin in self.pins.values():
            pin.close()
        self.pins.clear()
        self.finished = True


if __name__ == "__main__":
    raise SystemExit("internal B2 coordination library; native restore remains unavailable")
