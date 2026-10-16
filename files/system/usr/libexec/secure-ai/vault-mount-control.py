"""Fixed PID1 vault mount/consumer control; not a namespace or recovery broker."""
from __future__ import annotations

import importlib.util
import re
import subprocess
import time
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "vault_native_manager", Path(__file__).with_name("secure-native-admission.py"))
assert _spec and _spec.loader
native = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(native)

UNIT = r"var-lib-secure\x2dai-vault.mount"
WHERE = "/var/lib/secure-ai/vault"
WHAT = "/dev/mapper/secure-ai-vault"
TYPE = "ext4"
SOURCE_PATH = "/etc/fstab"
FRAGMENT_PATH = "/run/systemd/generator/" + UNIT
CONSUMERS = (
    "secure-ai-inference.service", "secure-ai-diffusion.service", "secure-ai-agent.service",
    "secure-ai-mcp-firewall.service", "secure-ai-tool-firewall.service",
    "secure-ai-integrity-monitor.service", "secure-ai-quarantine-watcher.service",
    "secure-ai-registry.service", "secure-ai-vault-mounted.service",
)
CGROUP_PARENT = Path("/sys/fs/cgroup/system.slice")
_SECONDS = 30.0
_DRAIN_SECONDS = 10.0
_PROPERTIES = {"Id", "LoadState", "ActiveState", "SubState", "Job", "ControlPID",
               "What", "Where", "Type", "Options", "SourcePath", "FragmentPath"}


class MountControlError(RuntimeError):
    """PID1 state/job completion is unconfirmed; never authorize mapper close."""


def _check(end):
    if time.monotonic() >= end:
        raise MountControlError("vault manager deadline exceeded")


def _call(end, *args):
    _check(end)
    try:
        value = native.manager(*args)
    except (native.Error, OSError, ValueError, subprocess.SubprocessError) as exc:
        raise MountControlError("vault manager operation failed") from exc
    _check(end)
    return value


def _job(value):
    job = value.get("Job")
    if job in ("", "0"):
        return None
    if not isinstance(job, str) or not re.fullmatch(r"[1-9][0-9]{0,9}", job):
        raise MountControlError("ambiguous vault manager job")
    return job


def _show(end):
    rows = {}
    for line in _call(end, "show", UNIT, "--property=" + ",".join(sorted(_PROPERTIES))).splitlines():
        key, sep, value = line.partition("=")
        if not sep or key not in _PROPERTIES or key in rows:
            raise MountControlError("invalid mount manager response")
        rows[key] = value
    if (rows.get("Id") != UNIT or rows.get("LoadState") not in ("loaded", "not-found")
            or not {"ActiveState", "SubState", "Job"} <= rows.keys()):
        raise MountControlError("unknown fixed vault mount unit")
    _job(rows)
    return rows


def _contract(value):
    if value["LoadState"] == "not-found":
        if not _absent(value):
            raise MountControlError("unknown active vault mount")
        return
    expected = {"What": WHAT, "Where": WHERE, "Type": TYPE,
                "SourcePath": SOURCE_PATH, "FragmentPath": FRAGMENT_PATH}
    options = value.get("Options", "").split(",")
    if (any(value.get(key) != item for key, item in expected.items())
            or not {"nodev", "nosuid", "noexec"} <= set(options)
            or set(options) & {"dev", "suid", "exec", "bind", "rbind", "move", "remount"}
            or any(not item or any(char.isspace() for char in item) for item in options)
            or not re.fullmatch(r"[0-9]+", value.get("ControlPID", ""))):
        raise MountControlError("generated vault mount contract differs")


def _absent(value):
    return (_job(value) is None and value.get("ActiveState") == "inactive"
            and value.get("SubState") == "dead" and value.get("ControlPID", "0") == "0")


def _mounted(value):
    return (_job(value) is None and value.get("ActiveState") == "active"
            and value.get("SubState") == "mounted" and value.get("ControlPID") == "0")


def state() -> tuple[str, str]:
    value = _show(time.monotonic() + _DRAIN_SECONDS)
    try:
        _contract(value)
    except MountControlError:
        return "unexpected", value.get("What", "")
    if _absent(value):
        return "absent", ""
    if _mounted(value):
        return "expected", value["What"]
    return "error", value.get("What", "")


def _service(end, name):
    _check(end)
    try:
        value = native.show(name)
    except (native.Error, OSError, ValueError, subprocess.SubprocessError) as exc:
        raise MountControlError("consumer manager state unavailable") from exc
    _check(end)
    if (value.get("ControlGroup") not in ("", "/system.slice/" + name)
            or value["LoadState"] == "loaded" and any(value.get(key) != expected for key, expected in
               {"KillMode": "control-group", "Delegate": "no", "ProtectControlGroups": "yes"}.items())):
        raise MountControlError("vault consumer escaped installed containment")
    _job(value)
    return value


def _cancel_settle(end, name, show):
    while True:
        value = show(end)
        job = _job(value)
        if job is not None:
            # Reconfirm the ID still belongs to this exact fixed unit.
            if _job(show(end)) != job:
                continue
            try:
                _call(end, "cancel", job)
            except MountControlError:
                if _job(show(end)) == job:
                    raise
            continue
        if (value.get("ActiveState") in ("active", "inactive", "failed")
                and value.get("ControlPID", "0") == "0"):
            return value
        time.sleep(0.05)


def _mount(action):
    end = time.monotonic() + _SECONDS
    value = _show(end)
    _contract(value)
    if value["LoadState"] == "not-found":
        if action == "stop":
            return
        raise MountControlError("generated vault mount unit is unavailable")
    try:
        _contract(_cancel_settle(end, UNIT, _show))
        _call(end, action, "--no-block", UNIT)
        while True:
            value = _show(end)
            _contract(value)
            if (_mounted(value) if action == "start" else _absent(value)):
                return
            if _job(value) is None and value["ActiveState"] == "failed":
                raise MountControlError("vault mount job failed")
            time.sleep(0.05)
    except BaseException:
        # A client failure/timeout does not cancel a PID1 job. Attempt bounded
        # cancellation and settling, but preserve failure even if it settles.
        _cancel_settle(time.monotonic() + _DRAIN_SECONDS, UNIT, _show)
        raise


def start() -> None:
    native.root_only()
    _mount("start")


def stop() -> None:
    native.root_only()
    _mount("stop")


def _pins(end):
    pins = {}
    try:
        for name in CONSUMERS:
            _service(end, name)
            pins[name] = native.Cgroup(required=False, trusted_path=CGROUP_PARENT / name)
            _check(end)
        return pins
    except BaseException:
        for pin in pins.values():
            pin.close()
        raise


def _empty(end, pins):
    for name, pin in pins.items():
        if not native.inactive(_service(end, name)):
            return False
        _check(end)
        if pin.empty() is not True:
            return False
        _check(end)
    return True


def consumers_idle() -> bool:
    end = time.monotonic() + _DRAIN_SECONDS
    pins = _pins(end)
    try:
        return _empty(end, pins)
    finally:
        for pin in pins.values():
            pin.close()


def stop_consumers() -> None:
    native.root_only()
    end = time.monotonic() + _SECONDS
    pins = _pins(end)
    try:
        _call(end, "stop", "--no-block", *CONSUMERS)
        while not _empty(end, pins):
            time.sleep(0.05)
    except BaseException:
        cleanup = time.monotonic() + _DRAIN_SECONDS
        for name in CONSUMERS:
            _cancel_settle(cleanup, name, lambda end, name=name: _service(end, name))
        raise
    finally:
        for pin in pins.values():
            pin.close()


def start_consumer(name: str) -> None:
    if name not in CONSUMERS:
        raise MountControlError("unsupported vault consumer")
    native.root_only()
    end = time.monotonic() + _SECONDS
    try:
        _service(end, name)
        _call(end, "start", "--no-block", name)
        while True:
            value = _service(end, name)
            ready = (value.get("SubState") == "exited" and name == "secure-ai-vault-mounted.service"
                     or value.get("SubState") == "running" and value.get("MainPID", "0").isdigit()
                     and int(value["MainPID"]) > 0)
            if _job(value) is None and value["ActiveState"] == "active" and ready:
                return
            if _job(value) is None and value["ActiveState"] == "failed":
                raise MountControlError("vault consumer start failed")
            time.sleep(0.05)
    except BaseException:
        _cancel_settle(time.monotonic() + _DRAIN_SECONDS, name, lambda end: _service(end, name))
        raise


if __name__ == "__main__":
    raise SystemExit("internal fixed vault mount control; no command interface")
