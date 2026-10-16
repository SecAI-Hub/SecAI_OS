"""Fixed helper tests: real private flocks/SCM_RIGHTS; no apps/units/devices.

NativeDataGate itself is real; installed policy and PID1/cgroup metadata are
fixtures. Expected root file ownership is substituted for ordinary-user runs.
"""

from array import array
from dataclasses import dataclass
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
from types import SimpleNamespace

import pytest

SCRIPTS = Path(__file__).parents[1] / "files/system/usr/libexec/secure-ai"
SPEC = importlib.util.spec_from_file_location(
    "data_admission_test", SCRIPTS / "secure-data-admission.py"
)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
INVOCATION = "a" * 32
BOOT = "54d24c30-e965-4d5c-939e-a78b58372c4e"


def available(path):
    with path.open("rb") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
    return True


@dataclass(frozen=True)
class Policy:
    key: str

    def profile(self):
        return {"fixture_class": self.key}


@pytest.fixture
def authority(tmp_path, monkeypatch):
    root, runtime = tmp_path / "state", tmp_path / "runtime"
    root.mkdir(mode=0o700)
    runtime.mkdir(mode=0o700)

    class Clock(module.transaction.guard.LinuxClock):
        def boot_id(self):
            return BOOT

    module.transaction.guard.Gate.initialize(root, runtime, clock=Clock())
    monkeypatch.setattr(module, "_ROOT", root)
    monkeypatch.setattr(module, "_RUNTIME", runtime)
    monkeypatch.setattr(
        module.transaction.native_metadata, "installed_incoming_policy", Policy
    )
    monkeypatch.setenv("INVOCATION_ID", INVOCATION)
    monkeypatch.delenv("LISTEN_FDS", raising=False)
    checks = []
    capability = SimpleNamespace(
        clock=Clock(),
        check=lambda: checks.append("checked"),
        close=lambda: checks.append("closed"),
        trusted_root_rebind=lambda *a: pytest.fail("fixture mount ID did not change"),
    )
    monkeypatch.setattr(module.namespace, "prehook_namespace", lambda role: capability)
    store = {"count": "0", "fd": -1}

    def manager(*args):
        assert args[0] == "show"
        rows = {
            "Id": module.namespace._UNITS["agent"],
            **module._STORE,
            "NFileDescriptorStore": store["count"],
        }
        return "\n".join(k + "=" + v for k, v in rows.items())

    monkeypatch.setattr(module.native, "manager", manager)
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)

    def transfer(fd, name):
        assert name == module._NAME_PREFIX + INVOCATION
        assert not available(root / "admission.lock")
        left.sendmsg(
            [b"lease"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", [fd]))]
        )
        data, ancillary, flags, _ = right.recvmsg(
            16, socket.CMSG_SPACE(array("i").itemsize), socket.MSG_CMSG_CLOEXEC
        )
        assert data == b"lease" and not flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC)
        received = array("i")
        received.frombytes(ancillary[0][2])
        assert len(received) == 1
        store.update(fd=received[0], count="1")

    monkeypatch.setattr(module, "_notify", transfer)
    try:
        yield root, runtime, store, checks
    finally:
        if store["fd"] >= 0:
            os.close(store["fd"])
        left.close()
        right.close()


def test_actual_native_gate_lease_transfer_survives_pre_close(authority):
    root, _runtime, store, checks = authority
    assert module.prehook("agent") == 0
    assert checks[-1] == "closed" and store["count"] == "1"
    assert not available(root / "admission.lock")
    assert os.pread(store["fd"], 8, 0) == b"stable\n"
    os.close(store["fd"])
    store["fd"] = -1
    assert available(root / "admission.lock")


@pytest.mark.parametrize("bad", ["closed", "stale", "history", "missing", "metadata"])
def test_prehook_fails_without_bypassing_native_gate(authority, monkeypatch, bad):
    root, runtime, store, checks = authority
    if bad == "closed":
        state = json.loads((root / "gate.json").read_text())
        state.update(state="closed", transaction="96cd9fe0-d12d-4e1f-a882-95cb4504836d")
        (root / "gate.json").write_text(json.dumps(state))
    elif bad == "stale":
        state = json.loads((runtime / "ready.json").read_text())
        state["boot"] = "ad6fb891-9ae2-49cb-9a54-e42d68b08986"
        (runtime / "ready.json").write_text(json.dumps(state))
    elif bad == "history":
        (root / "transactions/unknown").mkdir(mode=0o700)
    elif bad == "missing":
        (root / "layout.json").unlink()
    else:

        def unavailable(_key):
            raise RuntimeError("installed policy unavailable")

        monkeypatch.setattr(
            module.transaction.native_metadata, "installed_incoming_policy", unavailable
        )
    before = {
        path: path.read_bytes()
        for directory in (root, runtime)
        for path in directory.iterdir()
        if path.is_file()
    }
    with pytest.raises((RuntimeError, OSError)):
        module.prehook("agent")
    assert store["count"] == "0" and checks[-1] == "closed"
    assert all(path.read_bytes() == data for path, data in before.items())
    assert available(root / "admission.lock")


@pytest.mark.parametrize("when", ["notification", "acknowledgement"])
def test_notification_failures_release_only_own_reference(authority, monkeypatch, when):
    root, _runtime, store, _checks = authority
    real = module._notify

    def fail(fd, name):
        if when == "acknowledgement":
            real(fd, name)
        raise module.Error("fixture notification failure")

    monkeypatch.setattr(module, "_notify", fail)
    with pytest.raises(module.Error):
        module.prehook("agent")
    assert available(root / "admission.lock") is (when == "notification")
    if when == "acknowledgement":
        assert store["fd"] >= 0  # Never LOCK_UN PID1's duplicate.


@pytest.mark.parametrize(
    "role", ["diffusion", "", "other", "agent.service", "../agent", None]
)
def test_unknown_or_diffusion_modes_fail_before_effects(monkeypatch, role):
    def forbidden(*a):
        pytest.fail("unsupported role reached an effect")

    monkeypatch.setattr(module.namespace, "prehook_namespace", forbidden)
    monkeypatch.setattr(module, "_binding", forbidden)
    with pytest.raises(module.Error):
        module.prehook(role)
    with pytest.raises(module.Error):
        module.supervise(role)


@pytest.fixture
def handed(tmp_path, monkeypatch):
    path = tmp_path / "admission.lock"
    path.write_bytes(b"stable\n")
    path.chmod(0o600)
    source = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    fcntl.flock(source, fcntl.LOCK_SH)
    fd = os.dup(source)
    monkeypatch.setattr(module, "_LEASE_FD", fd)
    monkeypatch.setattr(module, "_OWNER_UID", os.geteuid())
    monkeypatch.setattr(module, "_OWNER_GID", os.getegid())
    monkeypatch.setenv("LISTEN_PID", str(os.getpid()))
    monkeypatch.setenv("LISTEN_FDS", "1")
    monkeypatch.setenv("LISTEN_FDNAMES", module._NAME_PREFIX + INVOCATION)
    monkeypatch.setenv("INVOCATION_ID", INVOCATION)
    try:
        yield path, fd
    finally:
        try:
            os.fstat(fd)
        except OSError:
            pass
        else:
            os.close(fd)
        os.close(source)


@pytest.mark.parametrize(
    "name,value",
    [("LISTEN_PID", "0"), ("LISTEN_FDS", "2"), ("LISTEN_FDNAMES", "old-invocation")],
)
def test_wrong_activation_envelope_denied(handed, monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(module.Error):
        module._Lease(INVOCATION)


@pytest.mark.parametrize("bad", ["mode", "bytes", "hardlink", "writable-fd"])
def test_wrong_descriptor_identity_denied(handed, tmp_path, monkeypatch, bad):
    path, fd = handed
    if bad == "mode":
        path.chmod(0o644)
    elif bad == "bytes":
        path.write_bytes(b"bad!\n")
    elif bad == "hardlink":
        os.link(path, tmp_path / "linked")
    else:
        os.close(fd)
        fd2 = os.open(path, os.O_RDWR)
        assert fd2 == fd
    with pytest.raises(module.Error):
        module._Lease(INVOCATION)
    with pytest.raises(OSError):
        os.fstat(fd)


@pytest.fixture
def supervisor(handed, tmp_path, monkeypatch):
    _path, fd = handed
    unit = module.namespace._UNITS["agent"]
    rows = {
        **module.namespace._COMMON,
        **module.namespace._ROLES["agent"],
        **module._STORE,
        "Id": unit,
        "MainPID": str(os.getpid()),
        "ControlPID": "0",
        "ActiveState": "active",
        "SubState": "running",
        "NFileDescriptorStore": "1",
        "InvocationID": INVOCATION,
        "ControlGroup": "/system.slice/" + unit,
        "FragmentPath": module.namespace._FRAGMENTS["agent"],
        "PrivateTmp": "yes",
    }
    group = tmp_path / "cgroup"
    group.write_text("0::/system.slice/" + unit + "\n")
    monkeypatch.setattr(module, "_SELF_CGROUP", group)
    monkeypatch.setattr(
        module, "_credentials", lambda: (1001, 1001, 1001, 1001, (1001,))
    )

    def manager(*args):
        assert args[0] == "show"
        return "\n".join(k + "=" + v for k, v in rows.items())

    monkeypatch.setattr(module.native, "manager", manager)
    child = SimpleNamespace(code=7, signals=[], poll=lambda: 7, wait=lambda: 7)
    child.send_signal = lambda value: child.signals.append(value)
    populations = iter([True, True, False])
    pin = SimpleNamespace(other_processes=lambda: next(populations), close=lambda: None)
    monkeypatch.setattr(module.native, "Cgroup", lambda *a, **kw: pin)
    calls = []

    def spawn(command, **kwargs):
        calls.append((command, kwargs))
        return child

    monkeypatch.setattr(module.subprocess, "Popen", spawn)
    monkeypatch.setattr(module.time, "sleep", lambda *_: None)
    return rows, calls, child, pin, fd


def test_supervisor_waits_residual_population_and_preserves_exit_status(
    supervisor, handed
):
    _rows, calls, _child, _pin, fd = supervisor
    assert module.supervise("agent") == 7
    assert calls[0][0] == module._COMMANDS["agent"]
    assert calls[0][1]["close_fds"] is True
    assert not any(
        key in calls[0][1]["env"]
        for key in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "NOTIFY_SOCKET")
    )
    with pytest.raises(OSError):
        os.fstat(fd)


@pytest.mark.parametrize(
    "key,value",
    [
        ("MainPID", "0"),
        ("InvocationID", "b" * 32),
        ("ControlGroup", "/other"),
        ("Id", "alias.service"),
        ("NotifyAccess", "all"),
        ("FileDescriptorStorePreserve", "yes"),
        ("NFileDescriptorStore", "0"),
        ("KillMode", "process"),
    ],
)
def test_supervisor_binding_failure_never_launches(supervisor, key, value):
    rows, calls, _child, _pin, _fd = supervisor
    rows[key] = value
    with pytest.raises(module.Error):
        module.supervise("agent")
    assert not calls


def test_unproven_cgroup_failure_is_failure_not_success(supervisor):
    _rows, _calls, child, pin, _fd = supervisor

    def ambiguous():
        raise module.Error("cgroup rebound")

    pin.other_processes = ambiguous
    with pytest.raises(module.Error):
        module.supervise("agent")
    assert child.signals == [signal.SIGTERM]


@pytest.mark.parametrize(
    "code,received,expected", [(0, 0, 0), (9, 0, 9), (-15, 0, 143), (0, 15, 143)]
)
def test_signal_and_exit_status_convention(code, received, expected):
    assert module._status(code, received) == expected


PRIVATE_SUPERVISOR = r'''
import importlib.util,json,os,pathlib,signal,subprocess,sys,time
source,fd,work,mode=sys.argv[1:];fd=int(fd);work=pathlib.Path(work)
spec=importlib.util.spec_from_file_location('private_data_supervisor',source)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m._LEASE_FD=fd;m._OWNER_UID=os.geteuid();m._OWNER_GID=os.getegid();m._POLL_SECONDS=.01
invocation='a'*32;unit=m.namespace._UNITS['agent']
os.environ.update(INVOCATION_ID=invocation,LISTEN_PID=str(os.getpid()),LISTEN_FDS='1',LISTEN_FDNAMES=m._NAME_PREFIX+invocation)
rows={**m.namespace._COMMON,**m.namespace._ROLES['agent'],**m._STORE,'Id':unit,'MainPID':str(os.getpid()),'ControlPID':'0','ActiveState':'active','SubState':'running','NFileDescriptorStore':'1','InvocationID':invocation,'ControlGroup':'/system.slice/'+unit,'FragmentPath':m.namespace._FRAGMENTS['agent'],'PrivateTmp':'yes'}
m.native.manager=lambda *a:'\n'.join(k+'='+v for k,v in rows.items())
group=work/'self-cgroup';group.write_text('0::/system.slice/'+unit+'\n');m._SELF_CGROUP=group
identity=os.fstat(fd)
childcode="""
import json,os,pathlib,signal,sys,time
work=pathlib.Path(sys.argv[1]);mode=sys.argv[2];device,inode=map(int,sys.argv[3:])
for path in pathlib.Path('/proc/self/fd').iterdir():
    try:s=os.fstat(int(path.name))
    except OSError:continue
    assert (s.st_dev,s.st_ino)!=(device,inode),'workload inherited lease'
assert not any(k in os.environ for k in ('LISTEN_PID','LISTEN_FDS','LISTEN_FDNAMES','NOTIFY_SOCKET'))
if mode=='orphan':
    read,write=os.pipe()
    if os.fork()==0:
        os.close(read);(work/'residual-pid').write_text(json.dumps({'pid':os.getpid(),'start':pathlib.Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]}));os.write(write,b'x');os.close(write)
        print('residual-ready',flush=True);time.sleep(.4);(work/'done').write_text('done');os._exit(0)
    os.close(write);assert os.read(read,1)==b'x';os.close(read);os._exit(7)
def terminate(number,_frame):
    print('child-signal-'+str(number),flush=True);raise SystemExit(0)
signal.signal(signal.SIGTERM,terminate)
print('child-ready',flush=True);time.sleep(5)
"""
command=(sys.executable,'-I','-B','-c',childcode,str(work),mode,str(identity.st_dev),str(identity.st_ino))
m._COMMANDS={'agent':command}
real_spawn=subprocess.Popen;children=[]
def spawn(args,**kwargs):
    assert args==command
    child=real_spawn(args,**kwargs);children.append(child);return child
m.subprocess.Popen=spawn
class Pin:
    def __init__(self,*a,**kw):pass
    def other_processes(self):
        if any(child.poll() is None for child in children):return True
        if mode=='orphan':
            pid=json.loads((work/'residual-pid').read_text())['pid']
            try:return pathlib.Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[0]!='Z'
            except FileNotFoundError:return False
        return False
    def close(self):pass
m.native.Cgroup=Pin
raise SystemExit(m.supervise('agent'))
'''


@pytest.mark.parametrize("mode,expected", [("orphan", 7), ("signal", 143)])
def test_real_private_supervisor_holds_fd_through_residual_or_signal(
    tmp_path, mode, expected
):
    import select

    path = tmp_path / "lease"
    path.write_bytes(b"stable\n")
    path.chmod(0o600)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    fcntl.flock(fd, fcntl.LOCK_SH)
    child = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            PRIVATE_SUPERVISOR,
            str(SCRIPTS / "secure-data-admission.py"),
            str(fd),
            str(tmp_path),
            mode,
        ],
        pass_fds=(fd,),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    os.close(fd)  # Only the supervisor owns the original shared OFD now.
    try:
        assert select.select([child.stdout], [], [], 5)[0]
        first = child.stdout.readline().strip()
        assert first == ("residual-ready" if mode == "orphan" else "child-ready")
        assert not available(path)
        if mode == "signal":
            child.send_signal(signal.SIGTERM)
        output, errors = child.communicate(timeout=5)
        assert child.returncode == expected, errors
        if mode == "orphan":
            assert (tmp_path / "done").read_text() == "done"
        else:
            assert "child-signal-15" in output
        assert available(path)
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=5)
        # Any finite residual test process is ours; only signal a pinned PID FD.
        residual = tmp_path / "residual-pid"
        if residual.exists():
            try:
                record = json.loads(residual.read_text())
                owned = os.pidfd_open(record["pid"])
            except ProcessLookupError:
                pass
            else:
                try:
                    current = (
                        Path("/proc/" + str(record["pid"]) + "/stat")
                        .read_text()
                        .rsplit(")", 1)[1]
                        .split()[19]
                    )
                    if current == record["start"]:
                        signal.pidfd_send_signal(owned, signal.SIGKILL)
                except (ProcessLookupError, FileNotFoundError):
                    pass
                finally:
                    os.close(owned)
