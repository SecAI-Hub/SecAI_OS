"""B2 coordination tests; these do not qualify native activation or restore."""
import importlib.util
from pathlib import Path

import pytest

SOURCE = Path(__file__).parents[1] / "files/system/usr/libexec/secure-ai/secure-native-writer-scope.py"
SPEC = importlib.util.spec_from_file_location("writer_scope", SOURCE)
assert SPEC and SPEC.loader
scope = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scope)


class Deadline:
    def __init__(self, maximum=100):
        self.calls, self.maximum = 0, maximum

    def check(self):
        self.calls += 1
        if self.calls > self.maximum:
            raise scope.Error("fixture deadline")


class Pin:
    def __init__(self):
        self.idle = True
        self.closed = False

    def empty(self):
        return self.idle

    def close(self):
        self.closed = True


class Manager:
    WRITERS = ("fixture-a.service", "fixture-b.service")
    TRIGGERS = ("fixture-a.timer", "fixture-b.path")

    def __init__(self):
        self.actions, self.pins = [], {}
        self.closed = True
        self.reappear = None
        self.values = {
            name: {
                **{key: "" for key in scope.native.PROPERTIES},
                "Id": name, "LoadState": "loaded", "ActiveState": "active",
                "MainPID": "42" if name in self.WRITERS else "0", "Job": "0",
                "ControlGroup": "/system.slice/" + name if name in self.WRITERS else "",
                "KillMode": "control-group", "Delegate": "no", "ProtectControlGroups": "yes",
            }
            for name in self.WRITERS + self.TRIGGERS
        }

    def manager(self, *args):
        command = args[0]
        if command == "show":
            return "\n".join(f"{key}={value}" for key, value in self.values[args[1]].items())
        self.actions.append(args)
        if command == "stop":
            assert set(self.pins) == set(self.WRITERS), "stop occurred before kernel pins"
            for value in self.values.values():
                value.update(ActiveState="inactive", MainPID="0", Job="0")
        elif command == "daemon-reload":
            for value in self.values.values():
                value["LoadState"] = "masked"
            if self.reappear:
                self.values[self.reappear]["Job"] = "7"
        return ""

    def pin(self, required, *, trusted_path):
        assert required is False
        assert trusted_path.parent == scope.CGROUP_PARENT
        pin = self.pins.setdefault(trusted_path.name, Pin())
        return pin


@pytest.fixture
def manager(monkeypatch):
    manager = Manager()
    monkeypatch.setattr(scope.native, "manager", manager.manager)
    monkeypatch.setattr(scope.native, "root_only", lambda: None)
    monkeypatch.setattr(scope.native, "Cgroup", manager.pin)
    return manager


def make_scope(manager):
    return scope.WriterScope(manager.WRITERS, manager.TRIGGERS, lambda: manager.closed)


def test_masks_pins_stops_then_rechecks_without_reopening(manager):
    controller = make_scope(manager)
    controller.stop_writers(Deadline())
    assert controller.quiescent() is True
    assert [call[0] for call in manager.actions] == ["mask", "stop", "daemon-reload"]
    assert manager.actions[0] == (
        "mask", "--runtime", "--no-reload", *manager.TRIGGERS, *manager.WRITERS)
    pins = list(manager.pins.values())
    controller.close()
    assert all(pin.closed for pin in pins)
    assert manager.closed is True
    assert not any(call[0] in {"unmask", "start", "restart"} for call in manager.actions)
    with pytest.raises(scope.Error):
        controller.quiescent()


@pytest.mark.parametrize("closed", [False, 1, {}, None])
def test_durable_closure_is_required_before_manager_changes(manager, closed):
    manager.closed = closed
    with pytest.raises(scope.Error, match="durable closed"):
        make_scope(manager).stop_writers(Deadline())
    assert manager.actions == []


@pytest.mark.parametrize("property,value", [
    ("ControlGroup", "/other.slice/escaped.service"), ("KillMode", "process"),
    ("Delegate", "yes"), ("ProtectControlGroups", "no"), ("Id", "alias.service"),
])
def test_ambiguous_or_uncontained_writer_is_never_stopped(manager, property, value):
    manager.values[manager.WRITERS[0]][property] = value
    with pytest.raises(scope.Error):
        make_scope(manager).stop_writers(Deadline())
    assert manager.actions == []


def test_inactive_manager_cannot_hide_surviving_descendant(manager):
    manager.pins[manager.WRITERS[0]] = Pin()
    manager.pins[manager.WRITERS[0]].idle = False
    controller = make_scope(manager)
    with pytest.raises(scope.Error, match="deadline"):
        controller.stop_writers(Deadline(35))
    with pytest.raises(scope.Error, match="deadline"):
        controller.quiescent()
    assert manager.actions[-1][0] == "stop"
    controller.close()
    assert manager.closed is True


@pytest.mark.parametrize("unit", Manager.WRITERS + Manager.TRIGGERS)
def test_queued_activation_after_reload_prevents_quiescence(manager, unit):
    manager.reappear = unit
    controller = make_scope(manager)
    with pytest.raises(scope.Error):
        controller.stop_writers(Deadline())
    controller.close()
    assert manager.closed is True


@pytest.mark.parametrize("writers,triggers", [
    ((), ()), (("a.service", "a.service"), ()), (("../a.service",), ()),
    (("a@instance.service",), ()), (("a.service",), ("a.service",)),
    (("a.service",), ("a.socket",)),
])
def test_unsupported_authority_names_are_rejected(writers, triggers):
    with pytest.raises(scope.Error):
        scope.WriterScope(writers, triggers, lambda: True)


@pytest.mark.parametrize("phase", ["preflight", "final-scan"])
def test_expiration_during_manager_query_cannot_mutate_or_succeed(manager, monkeypatch, phase):
    class ExpiringDeadline:
        expired = False

        def check(self):
            if self.expired:
                raise scope.Error("fixture deadline")

    deadline = ExpiringDeadline()
    original = manager.manager

    def slow_manager(*args):
        result = original(*args)
        if args[0] == "show" and (
            phase == "preflight" or any(call[0] == "daemon-reload" for call in manager.actions)
        ):
            deadline.expired = True
        return result

    monkeypatch.setattr(scope.native, "manager", slow_manager)
    controller = make_scope(manager)
    with pytest.raises(scope.Error, match="deadline"):
        controller.stop_writers(deadline)
    if phase == "preflight":
        assert manager.actions == []
    else:
        assert manager.actions[-1][0] == "daemon-reload"
    controller.close()
    assert manager.closed is True
