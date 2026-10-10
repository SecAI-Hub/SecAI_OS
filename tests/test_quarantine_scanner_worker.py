"""Tests for the credentialless quarantine scanner boundary."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "services" / "quarantine"))

from quarantine import scanner_worker


def _private_worker(tmp_path, script, *, timeout=20):
    package_root = Path(__file__).resolve().parents[1] / "services/quarantine"
    bootstrap = f"import sys; sys.path.insert(0, {str(package_root)!r});\n"
    completed = subprocess.run(
        [sys.executable, "-I", "-c", bootstrap + script],
        cwd=tmp_path, stdin=subprocess.DEVNULL, capture_output=True, text=True,
        timeout=timeout, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return completed


def test_scanner_worker_rejects_artifact_outside_quarantine(tmp_path, monkeypatch):
    quarantine = tmp_path / "quarantine"
    quarantine.mkdir()
    outside = tmp_path / "outside.gguf"
    outside.write_bytes(b"GGUF")
    monkeypatch.setenv("QUARANTINE_DIR", str(quarantine))

    with pytest.raises(ValueError, match="direct child"):
        scanner_worker._validated_artifact_path(str(outside))


def test_scanner_worker_detects_artifact_mutation(tmp_path, monkeypatch):
    quarantine = tmp_path / "quarantine"
    quarantine.mkdir()
    artifact = quarantine / "model.gguf"
    artifact.write_bytes(b"original")
    expected_hash = hashlib.sha256(b"original").hexdigest()

    calls = {"count": 0}

    def mutate_during_first_stage(*_args, **_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            artifact.write_bytes(b"modified")
        return {"passed": True}

    monkeypatch.setattr(scanner_worker, "_run_stage", mutate_during_first_stage)

    result = scanner_worker.scan(
        artifact,
        expected_hash,
        {},
        source_url="",
        directory=False,
    )

    assert result["passed"] is False
    assert result["reason"] == "artifact_changed_during_scan"


def test_scanner_worker_rejects_malformed_source_metadata(tmp_path, monkeypatch):
    artifact = tmp_path / "model.gguf"
    artifact.write_bytes(b"original")
    expected_hash = hashlib.sha256(b"original").hexdigest()
    with pytest.raises(ValueError, match="control characters"):
        scanner_worker.scan(
            artifact,
            expected_hash,
            {},
            source_url="https://example.invalid/model\ninjected",
            directory=False,
        )


def test_parser_exception_is_a_normal_rejection_not_restart(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "quarantine-scanner",
            "--artifact",
            "/claim/snapshot/poison.gguf",
            "--sha256",
            "a" * 64,
            "--policy",
            "/etc/policy.yaml",
        ],
    )
    monkeypatch.setattr(
        scanner_worker,
        "_validated_artifact_path",
        lambda _path: Path("/claim/snapshot/poison.gguf"),
    )
    monkeypatch.setattr(
        scanner_worker,
        "_policy_bundle_evidence",
        lambda _path: {"version": 1, "sha256": "b" * 64, "components": {}},
    )
    # This unit test isolates result classification; actual bootstrap refusal
    # and child lifetime behavior are exercised in private-process tests below.
    monkeypatch.setattr(scanner_worker, "_establish_coordinator_domain", lambda: object())
    monkeypatch.setattr(scanner_worker, "_close_coordinator_domain", lambda _domain: None)
    monkeypatch.setattr(scanner_worker, "_load_policy", lambda _path: {})
    monkeypatch.setattr(
        scanner_worker,
        "scan",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ValueError("deterministic parser poison")
        ),
    )

    scanner_worker.main()

    output = json.loads(capsys.readouterr().out)
    assert output["passed"] is False
    assert output["reason"] == "artifact_parser_rejected"
    assert output["details"]["failure_class"] == "ValueError"
    assert "deterministic parser poison" not in json.dumps(output)


def test_coordinator_runs_each_required_stage_in_a_fresh_assignment(
    tmp_path,
    monkeypatch,
):
    artifact = tmp_path / "model.gguf"
    artifact.write_bytes(b"GGUF")
    expected_hash = hashlib.sha256(b"GGUF").hexdigest()
    stages = []

    def passed_stage(stage, *_args, **_kwargs):
        stages.append(stage)
        return {
            "passed": True,
            # A compromised stage can only place this inside its own result.
            "provenance": {"passed": True},
        }

    monkeypatch.setattr(scanner_worker, "_run_stage", passed_stage)
    result = scanner_worker.scan(
        artifact,
        expected_hash,
        {"models": {"require_behavior_tests": True}},
        source_url="",
        directory=False,
        policy_path=tmp_path / "policy.yaml",
    )

    assert stages == [
        "source_policy",
        "format_gate",
        "hash_pin",
        "provenance",
        "static_scan",
        "smoke_test",
    ]
    assert result["passed"] is True
    assert set(result["details"]) == {
        *stages,
        "hash",
    }
    assert result["details"]["source_policy"]["provenance"] == {"passed": True}
    assert result["details"]["provenance"] is not result["details"]["source_policy"]


def test_coordinator_disables_ptrace_and_core_dumps(monkeypatch):
    calls = []

    class FakeLibC:
        def prctl(self, *args):
            calls.append(("prctl", args))
            return 0

    monkeypatch.setattr(scanner_worker.sys, "platform", "linux")
    monkeypatch.setattr(
        scanner_worker.ctypes,
        "CDLL",
        lambda *_args, **_kwargs: FakeLibC(),
    )
    monkeypatch.setattr(
        scanner_worker.resource,
        "setrlimit",
        lambda resource_id, limits: calls.append(
            ("setrlimit", resource_id, limits)
        ),
    )

    assert scanner_worker._protect_coordinator_from_stage_processes() is True
    assert (
        "setrlimit",
        scanner_worker.resource.RLIMIT_CORE,
        (0, 0),
    ) in calls
    assert (
        "prctl",
        (scanner_worker.PR_SET_DUMPABLE, 0, 0, 0, 0),
    ) in calls


@pytest.mark.parametrize("source,expected", [("", True), ("--directory", False)])
def test_real_stage_subprocess_boundary_in_exclusive_worker(tmp_path, source, expected):
    artifact = tmp_path / "model.gguf"
    artifact.write_bytes(b"GGUF")
    policy_path = Path(__file__).resolve().parents[1] / "files/system/etc/secure-ai/policy/policy.yaml"
    completed = _private_worker(tmp_path, f"""
import json
from pathlib import Path
from quarantine import scanner_worker as worker
owner = worker._establish_coordinator_domain()
try:
    result = worker._run_stage("source_policy", Path({str(artifact)!r}),
        {hashlib.sha256(b"GGUF").hexdigest()!r}, Path({str(policy_path)!r}),
        source_url={source!r}, directory=False)
    assert owner.stage is None and worker._coordinator_children() == []
    print(json.dumps(result))
finally:
    worker._close_coordinator_domain(owner)
""")
    result = json.loads(completed.stdout)
    assert result["passed"] is expected
    assert result.get("reason") != "stage_boundary_failed"


def test_poison_artifact_cli_exits_normally_with_rejection(tmp_path):
    artifact = tmp_path / "poison.gguf"
    artifact.write_bytes(b"not-a-valid-gguf")
    repo_root = Path(__file__).parent.parent
    policy_root = repo_root / "files/system/etc/secure-ai/policy"
    package_root = repo_root / "services/quarantine"
    environment = {
        **os.environ,
        "PYTHONPATH": str(package_root),
        "QUARANTINE_DIR": str(tmp_path),
        "MODELS_LOCK_PATH": str(policy_root / "models.lock.yaml"),
        "DIFFUSION_MODELS_LOCK_PATH": str(
            policy_root / "diffusion-models.lock.yaml"
        ),
        "SOURCES_ALLOWLIST_PATH": str(policy_root / "sources.allowlist.yaml"),
        "YARA_RULES_DIR": str(
            package_root / "quarantine/yara_rules"
        ),
    }
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "quarantine.scanner_worker",
            "--artifact",
            str(artifact),
            "--sha256",
            hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "--policy",
            str(policy_root / "policy.yaml"),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
        check=False,
    )

    assert completed.returncode == 0
    result = json.loads(completed.stdout)
    assert result["passed"] is False
    assert result["reason"] == "format_gate"


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Linux prctl/proc descendant reaping test",
)
def test_stage_subreaper_kills_setsid_escape(tmp_path):
    package_root = Path(__file__).parent.parent / "services/quarantine"
    pid_path = tmp_path / "escaped.pid"
    script = f"""\
import os
import subprocess
import sys
import time
from pathlib import Path
from quarantine import scanner_worker

owner = scanner_worker._establish_coordinator_domain()
child_code = '''\
import os
import time
from pathlib import Path
pid = os.fork()
if pid:
    os._exit(0)
os.setsid()
Path({str(pid_path)!r}).write_text(str(os.getpid()), encoding="ascii")
time.sleep(30)
'''
child = subprocess.Popen(
    [sys.executable, "-c", child_code],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    close_fds=True,
)
owner.stage = child
owner.stage_pid = child.pid
owner.stage_starttime = scanner_worker._process_identity(child.pid)[2]
child.wait(timeout=5)
deadline = time.monotonic() + 5
while (
    (
        not Path({str(pid_path)!r}).exists()
        or not Path({str(pid_path)!r}).read_text(encoding="ascii")
    )
    and time.monotonic() < deadline
):
    time.sleep(0.01)
escaped_pid = int(Path({str(pid_path)!r}).read_text(encoding="ascii"))
scanner_worker._reap_reparented_stage_descendants(owner)
assert owner.stage is None
scanner_worker._close_coordinator_domain(owner)
try:
    os.kill(escaped_pid, 0)
except ProcessLookupError:
    raise SystemExit(0)
raise SystemExit("escaped scanner descendant survived reaping")
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=15,
        env={**os.environ, "PYTHONPATH": str(package_root)},
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux process ownership")
def test_preexisting_tracker_and_sentinel_survive_all_ambient_cleanup_refusals(tmp_path):
    _private_worker(tmp_path, r"""
import multiprocessing.resource_tracker as rt
import os
import subprocess
import sys
from pathlib import Path
from quarantine import scanner_worker as worker
rt.ensure_running()
tracker_pid = rt._resource_tracker._pid
tracker_fd = rt._resource_tracker._fd
tracker_birth = worker._process_identity(tracker_pid)[2]
sentinel = subprocess.Popen([sys.executable, '-I', '-c',
    'import sys;print("ready",flush=True);sys.stdin.buffer.read(1)'],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
assert sentinel.stdout.readline() == b'ready\n'
birth = worker._process_identity(sentinel.pid)[2]
try:
    os.environ['SCANNER_COORDINATOR_ENABLED'] = '1'
    calls = [
        lambda: worker._run_stage('source_policy', Path('unused'), 'a' * 64, Path('unused'), source_url='', directory=False),
        worker._reap_reparented_stage_descendants,
        lambda: worker._kill_stage_process_group(sentinel),
        worker._establish_coordinator_domain,
    ]
    for call in calls:
        try:
            call()
        except worker.CoordinatorIsolationError:
            pass
        else:
            raise AssertionError('ambient process acquired cleanup authority')
        assert worker._process_identity(tracker_pid)[2] == tracker_birth
        assert worker._process_identity(sentinel.pid)[2] == birth
        assert sentinel.poll() is None
        assert os.write(tracker_fd, b'PROBE:0:noop\n') == 13
finally:
    sentinel.communicate(input=b'x', timeout=5)
    assert sentinel.returncode == 0
# Tracker receives its normal interpreter-lifetime close; no reset or warning filter.
""")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux process ownership")
def test_foreign_stale_closed_and_fork_inherited_domains_are_rejected(tmp_path):
    _private_worker(tmp_path, r"""
import os
from quarantine import scanner_worker as worker
owner = worker._establish_coordinator_domain()
foreign = worker._CoordinatorDomain(owner.owner_pid, owner.owner_starttime)
def reject(domain):
    try:
        worker._require_domain(domain)
    except worker.CoordinatorIsolationError:
        return
    raise AssertionError('invalid domain accepted')
reject(foreign)
owner.owner_starttime -= 1
reject(owner)
owner.owner_starttime += 1
pid = os.fork()
if pid == 0:
    try:
        reject(owner)
        os._exit(0)
    except BaseException:
        os._exit(1)
assert os.waitpid(pid, 0)[1] == 0
worker._close_coordinator_domain(owner)
reject(owner)
""")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux process ownership")
def test_new_preexisting_child_and_mismatched_process_are_never_cleaned(tmp_path):
    _private_worker(tmp_path, r"""
import subprocess
import sys
from pathlib import Path
from quarantine import scanner_worker as worker
owner = worker._establish_coordinator_domain()
children = []
try:
    for _ in range(2):
        child = subprocess.Popen([sys.executable, '-I', '-c',
            'import sys;print("ready",flush=True);sys.stdin.buffer.read(1)'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        assert child.stdout.readline() == b'ready\n'
        children.append(child)
    births = [worker._process_identity(c.pid)[2] for c in children]
    try:
        worker._run_stage('source_policy', Path('unused'), 'a' * 64, Path('unused'), source_url='', directory=False)
    except worker.CoordinatorIsolationError:
        pass
    else:
        raise AssertionError('stage started with preexisting children')
    owner.stage = children[0]
    owner.stage_pid = children[0].pid
    owner.stage_starttime = births[0]
    try:
        worker._kill_stage_process_group(children[1])
    except worker.CoordinatorIsolationError:
        pass
    else:
        raise AssertionError('foreign process cleaned')
    assert [worker._process_identity(c.pid)[2] for c in children] == births
    assert all(c.poll() is None for c in children)
finally:
    for c in children:
        c.communicate(input=b'x', timeout=5)
        assert c.returncode == 0
    worker._close_coordinator_domain(owner)
""")


def test_child_enumeration_failure_is_not_empty_success(monkeypatch):
    original = Path.read_text
    def denied(path, *args, **kwargs):
        if path.name == "children":
            raise PermissionError("synthetic proc denial")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "read_text", denied)
    with pytest.raises(scanner_worker.CoordinatorIsolationError, match="enumeration"):
        scanner_worker._coordinator_children()


def test_reaped_stage_never_signals_recycled_process_group(monkeypatch):
    from types import SimpleNamespace
    process = SimpleNamespace(pid=123, returncode=0)
    owner = SimpleNamespace(stage=process)
    monkeypatch.setattr(scanner_worker, "_require_stage", lambda *_a, **_k: owner)
    monkeypatch.setattr(scanner_worker.os, "killpg", lambda *_a: pytest.fail("reaped group must not be signaled"))
    drained = []
    monkeypatch.setattr(scanner_worker, "_reap_reparented_stage_descendants", lambda *a, **k: drained.append((a, k)))
    scanner_worker._kill_stage_process_group(process)
    assert len(drained) == 1


def test_stage_post_kill_wait_has_a_fixed_deadline(monkeypatch):
    from types import SimpleNamespace
    waits = []
    def stuck(*, timeout):
        waits.append(timeout)
        raise subprocess.TimeoutExpired("synthetic stage", timeout)
    process = SimpleNamespace(pid=123, returncode=None, wait=stuck)
    owner = SimpleNamespace(owner_pid=99, stage_starttime=44, stage=process)
    monkeypatch.setattr(scanner_worker, "_require_stage", lambda *_a, **_k: owner)
    monkeypatch.setattr(scanner_worker, "_process_identity", lambda _pid: (99, 123, 44))
    monkeypatch.setattr(scanner_worker.os, "killpg", lambda *_a: None)
    with pytest.raises(scanner_worker.CoordinatorIsolationError, match="deadline"):
        scanner_worker._kill_stage_process_group(process)
    assert len(waits) == 1 and 0 <= waits[0] <= scanner_worker.STAGE_CLEANUP_TIMEOUT


def test_undrainable_owned_descendants_fail_within_deadline(monkeypatch):
    from types import SimpleNamespace
    owner = SimpleNamespace(owner_pid=99, stage=SimpleNamespace(returncode=0))
    ticks = iter([0.0, 0.0, 0.01, 0.1])
    monkeypatch.setattr(scanner_worker, "_require_stage", lambda *_a, **_k: owner)
    monkeypatch.setattr(scanner_worker, "_coordinator_children", lambda: [123])
    monkeypatch.setattr(scanner_worker, "_process_identity", lambda _pid: (99, 123, 44))
    monkeypatch.setattr(scanner_worker.os, "kill", lambda *_a: None)
    monkeypatch.setattr(scanner_worker.os, "waitpid", lambda *_a: (0, 0))
    monkeypatch.setattr(scanner_worker.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(scanner_worker.time, "sleep", lambda *_a: None)
    with pytest.raises(scanner_worker.CoordinatorIsolationError, match="deadline"):
        scanner_worker._reap_reparented_stage_descendants(deadline=0.05)


def test_isolation_failure_is_operational_not_artifact_rejection(monkeypatch, capsys):
    from types import SimpleNamespace
    monkeypatch.setattr(scanner_worker, "_validated_artifact_path", lambda p: Path(p))
    monkeypatch.setattr(scanner_worker, "_policy_bundle_evidence", lambda _p: {})
    monkeypatch.setattr(scanner_worker, "_load_policy", lambda _p: {})
    def isolation_failure(*_a, **_k):
        raise scanner_worker.CoordinatorIsolationError("synthetic incomplete drain")
    monkeypatch.setattr(scanner_worker, "scan", isolation_failure)
    args = SimpleNamespace(artifact="unused", policy="unused", sha256="a" * 64, source_url="", directory=False)
    with pytest.raises(SystemExit) as error:
        scanner_worker._main_in_domain(args)
    assert error.value.code == 2
    assert capsys.readouterr().out == ""


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux thread ownership")
def test_bootstrap_refuses_extra_os_thread_before_process_controls(tmp_path):
    _private_worker(tmp_path, r"""
import threading
from quarantine import scanner_worker as worker
release = threading.Event()
thread = threading.Thread(target=release.wait)
thread.start()
try:
    def no_controls():
        raise AssertionError('controls changed before ownership validation')
    worker._enable_child_subreaper = no_controls
    try:
        worker._establish_coordinator_domain()
    except worker.CoordinatorIsolationError:
        pass
    else:
        raise AssertionError('multithreaded coordinator admitted')
    assert thread.is_alive()
finally:
    release.set()
    thread.join(5)
    assert not thread.is_alive()
""")


def test_child_enumeration_failure_precedes_stage_spawn_and_drain_effects(monkeypatch):
    from types import SimpleNamespace
    domain = SimpleNamespace(stage=None)
    def unavailable():
        raise scanner_worker.CoordinatorIsolationError("enumeration denied")
    monkeypatch.setattr(scanner_worker, "_require_domain", lambda *_a: domain)
    monkeypatch.setattr(scanner_worker, "_require_stage", lambda *_a, **_k: domain)
    monkeypatch.setattr(scanner_worker, "_coordinator_children", unavailable)
    monkeypatch.setattr(scanner_worker.subprocess, "Popen", lambda *_a, **_k: pytest.fail("spawn after failed enumeration"))
    monkeypatch.setattr(scanner_worker.os, "kill", lambda *_a: pytest.fail("signal after failed enumeration"))
    monkeypatch.setattr(scanner_worker.os, "waitpid", lambda *_a: pytest.fail("reap after failed enumeration"))
    with pytest.raises(scanner_worker.CoordinatorIsolationError, match="enumeration"):
        scanner_worker._run_stage("source_policy", Path("unused"), "a" * 64, Path("unused"), source_url="", directory=False)
    domain.stage = SimpleNamespace(returncode=0)
    with pytest.raises(scanner_worker.CoordinatorIsolationError, match="enumeration"):
        scanner_worker._reap_reparented_stage_descendants()


def test_proc_identity_ignores_untrusted_comm_bytes(monkeypatch):
    # Linux process names can contain non-ASCII bytes and closing parentheses.
    fields = [b"S", b"7", b"8"] + [b"0"] * 16 + [b"99"]
    monkeypatch.setattr(Path, "read_bytes", lambda _p: b"123 (bad\xff)name)) " + b" ".join(fields))
    assert scanner_worker._process_identity(123) == (7, 8, 99)


@pytest.mark.parametrize("deadline", [True, "unbounded", float("inf"), float("nan")])
def test_invalid_cleanup_deadline_cannot_expand_authority(monkeypatch, deadline):
    from types import SimpleNamespace
    monkeypatch.setattr(scanner_worker, "_require_stage", lambda *_a, **_k: SimpleNamespace(stage=SimpleNamespace(returncode=0)))
    monkeypatch.setattr(scanner_worker, "_coordinator_children", lambda: pytest.fail("enumerated with invalid deadline"))
    with pytest.raises(scanner_worker.CoordinatorIsolationError, match="deadline"):
        scanner_worker._reap_reparented_stage_descendants(deadline=deadline)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux process ownership")
def test_post_popen_identity_failure_reaps_registered_child_and_exits_operationally(tmp_path):
    _private_worker(tmp_path, r"""
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from quarantine import scanner_worker as worker
owner = worker._establish_coordinator_domain()
original_popen = subprocess.Popen
original_identity = worker._process_identity
launched = []
def create(_command, **kwargs):
    process = original_popen([sys.executable, '-I', '-c', 'import time;time.sleep(30)'], **kwargs)
    launched.append((process, original_identity(process.pid)))
    return process
def identity(pid):
    if launched and pid == launched[0][0].pid:
        raise worker.CoordinatorIsolationError('synthetic post-Popen identity denial')
    return original_identity(pid)
def no_group(*_args):
    raise AssertionError('unverified registration cannot signal a group')
worker.subprocess.Popen = create
worker._process_identity = identity
worker.os.killpg = no_group
worker._validated_artifact_path = lambda _path: Path('unused')
worker._policy_bundle_evidence = lambda _path: {}
worker._load_policy = lambda _path: {}
worker.scan = lambda *_args, **_kwargs: worker._run_stage('source_policy', Path('unused'),
    'a' * 64, Path('unused'), source_url='', directory=False)
args = SimpleNamespace(artifact='unused', policy='unused', sha256='a' * 64, source_url='', directory=False)
try:
    try:
        worker._main_in_domain(args)
    except SystemExit as error:
        assert error.code == 2
    else:
        raise AssertionError('isolation failure became an artifact result')
    assert len(launched) == 1 and launched[0][0].returncode is not None
    assert owner.stage is None and owner.stage_pid is None
    assert worker._coordinator_children() == []
finally:
    # The production cleanup must have finished; this is verification, not a
    # fallback test cleanup that could conceal a leaked worker.
    assert all(process.returncode is not None for process, _identity in launched)
    worker._close_coordinator_domain(owner)
""")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux kernel policy qualification")
def test_coordinator_proc_identity_under_inherited_filter_and_proc_grant(tmp_path):
    import ctypes.util
    import shutil
    if (os.uname().machine not in {"x86_64", "aarch64"}
            or not shutil.which("systemd-analyze") or not ctypes.util.find_library("seccomp")):
        pytest.skip("native systemd/libseccomp policy tools unavailable")
    root = Path(__file__).resolve().parents[1]
    denied = tmp_path / "ungranted"
    denied.write_bytes(b"synthetic")
    completed = _private_worker(tmp_path, f"""
import ctypes
import ctypes.util
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import yaml
from quarantine import scanner_worker as worker
root = Path({str(root)!r})
sys.path.insert(0, str(root / 'tests'))
from test_landlock_service_filters import effective
unit = root / 'files/system/usr/lib/systemd/system/secure-ai-quarantine-watcher.service'
calls = sorted(effective(unit.read_text()))
policy = yaml.safe_load((root / 'files/system/etc/secure-ai/policy/landlock.yaml').read_text())
for service in ('quarantine', 'quarantine_scanner'):
    assert next(p for p in policy['services'][service]['paths'] if p['path'] == '/proc')['access'] == 'ro'
spec = importlib.util.spec_from_file_location('fixture_landlock', root / 'files/system/usr/libexec/secure-ai/landlock-apply.py')
landlock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(landlock)
abi = landlock.check_landlock_available()
assert abi > 0
# The full profiles grant the installed Python runtime. Preload its lazy ASCII
# codec before this deliberately narrower /proc-only filesystem fixture.
import encodings.ascii
libc = ctypes.CDLL(None, use_errno=True)
seccomp = ctypes.CDLL(ctypes.util.find_library('seccomp'), use_errno=True)
seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
seccomp.seccomp_init.restype = ctypes.c_void_p
seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
seccomp.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
context = seccomp.seccomp_init(0x50000 | 1)
for name in calls:
    number = seccomp.seccomp_syscall_resolve_name(name.encode())
    if number >= 0:
        assert seccomp.seccomp_rule_add(context, 0x7fff0000, number, 0) == 0
create, add, restrict = landlock._syscall_numbers()
reader, writer = os.pipe()
assert libc.prctl(38, 1, 0, 0, 0) == 0
assert seccomp.seccomp_load(context) == 0
# Exercise a strict filesystem subset of the inherited profiles: their exact
# /proc ro grant, no added path grant. This does not qualify packaged exec paths.
attr = ctypes.create_string_buffer(struct.pack('Q', landlock._handled_access_for_abi(abi)))
ruleset = libc.syscall(create, attr, 8, 0)
assert ruleset >= 0
proc = os.open('/proc', os.O_PATH | os.O_CLOEXEC)
rule = ctypes.create_string_buffer(struct.pack('Qi', landlock._access_for_mode('ro', abi), proc))
assert libc.syscall(add, ruleset, 1, rule, 0) == 0
assert libc.syscall(restrict, ruleset, 0) == 0
os.close(proc)
os.close(ruleset)
try:
    Path({str(denied)!r}).read_bytes()
except PermissionError:
    pass
else:
    raise AssertionError('Landlock did not deny ungranted sibling')
owner = worker._establish_coordinator_domain()
pid = os.fork()
if pid == 0:
    os.close(writer)
    os.read(reader, 1)
    os.close(reader)
    os._exit(0)
os.close(reader)
try:
    child = worker._process_identity(pid)
    assert child[0] == owner.owner_pid and child[2] >= owner.owner_starttime
    assert worker._coordinator_children() == [pid]
finally:
    os.write(writer, b'x')
    os.close(writer)
    assert os.waitpid(pid, 0)[1] == 0
assert worker._coordinator_children() == []
worker._close_coordinator_domain(owner)
print(json.dumps({{'landlock_abi': abi, 'proc_read': True, 'ungranted_read_denied': True,
 'seccomp_filter_sha256': hashlib.sha256(json.dumps(calls).encode()).hexdigest(),
 'registered_owner_pid': owner.owner_pid, 'child_pid': pid, 'child_reaped': True}}))
""")
    report = json.loads(completed.stdout)
    assert report["proc_read"] and report["ungranted_read_denied"] and report["child_reaped"]
