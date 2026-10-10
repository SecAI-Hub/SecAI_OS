"""Run B1 fork scenarios in a clean interpreter, never the pytest process.

This support file is test-only. The child imports pytest's assertions without
starting pytest or its plugins. Forked fixture children retain their existing
pidfd ownership, private sessions and 8/10/15-second lifetime limits.
"""

from __future__ import annotations

import functools
import inspect
import json
import os
import signal
import stat
import subprocess
import sys
import threading
from pathlib import Path


def kernel_thread_count():
    return len(os.listdir("/proc/self/task"))


def isolated_case(*, seconds=45):
    assert type(seconds) is int and 1 <= seconds <= 600

    def decorate(function):
        @functools.wraps(function)
        def invoke(*args, **kwargs):
            bound = inspect.signature(function).bind(*args, **kwargs)
            arguments = {key: str(value) if isinstance(value, Path) else value
                         for key, value in bound.arguments.items()}
            run_isolated_case(function.__name__, arguments, seconds)

        invoke.b1_case_body = function
        invoke.b1_case_seconds = seconds
        return invoke

    return decorate


def run_isolated_case(name, arguments, seconds):
    from test_backup_transaction import signal_evidence

    request = {"name": name, "arguments": arguments, "seconds": seconds,
               "caller_pid": os.getpid(), "caller_pgid": os.getpgrp(),
               "caller_threads": kernel_thread_count()}
    encoded = json.dumps(request, separators=(",", ":"))
    assert len(encoded) <= 8192
    # No preexec_fn: Python's subprocess exec boundary is safe from a threaded
    # caller. -I excludes caller import paths and user startup customization.
    with subprocess.Popen(
        [sys.executable, "-I", "-W", "error::DeprecationWarning", str(Path(__file__).resolve()), encoded],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True, close_fds=True,
    ) as process:
        descriptor = os.pidfd_open(process.pid)
        try:
            try:
                stdout, stderr = process.communicate(timeout=seconds + 3)
            except subprocess.TimeoutExpired:
                signal_evidence({"kind": "clean-runner-pidfd", "sender_pid": os.getpid(),
                                 "sender_pgid": os.getpgrp(), "target_pid": process.pid,
                                 "signal": int(signal.SIGKILL)})
                signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
                process.communicate(timeout=3)
                raise AssertionError("clean B1 fixture interpreter exceeded lifetime") from None
        finally:
            os.close(descriptor)
    assert process.returncode == 0, (name, process.returncode, stdout.decode(errors="replace"),
                                    stderr.decode(errors="replace"))
    proof = json.loads(stdout)
    assert proof == {"case": name, "pid": process.pid, "ppid": os.getpid(),
                     "pgid": process.pid, "sid": process.pid, "threads": 1,
                     "caller_threads": request["caller_threads"]}
    assert process.pid != request["caller_pgid"]
    assert not stderr, stderr.decode(errors="replace")
    return proof


def main():
    request = json.loads(sys.argv[1])
    assert len(sys.argv) == 2 and len(sys.argv[1]) <= 8192
    assert os.getpid() == os.getpgrp() == os.getsid(0)
    assert os.getppid() == request["caller_pid"]
    assert os.getpgrp() != request["caller_pgid"]
    assert kernel_thread_count() == threading.active_count() == 1
    # The sole added path is this repository's test support, not a caller path.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import test_backup_quiescence as cases
    import test_backup_transaction as fixture

    scenario = getattr(cases, request["name"])
    body = scenario.b1_case_body
    assert request["seconds"] == scenario.b1_case_seconds
    arguments = request["arguments"]
    root = Path(arguments["tmp_path"])
    metadata = root.lstat()
    assert root.is_absolute() and stat.S_ISDIR(metadata.st_mode)
    assert metadata.st_uid == os.getuid() and not metadata.st_mode & 0o077
    arguments["tmp_path"] = root
    inspect.signature(body).bind(**arguments)
    fixture._FORK_RUNNER_PID = os.getpid()
    assert kernel_thread_count() == threading.active_count() == 1
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(request["seconds"])
    fixture.signal_evidence({"kind": "clean-interpreter", "sender_pid": os.getpid(),
                             "sender_pgid": os.getpgrp(), "caller_pid": os.getppid(),
                             "caller_pgid": request["caller_pgid"], "threads": 1,
                             "caller_threads": request["caller_threads"], "case": request["name"]})
    try:
        body(**arguments)
        assert not fixture._CHILDREN, "scenario left an unreaped fixture child"
    finally:
        # Only descriptors registered by this runner may be used for cleanup.
        for pid in list(fixture._CHILDREN):
            try:
                fixture.signal_child(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            fixture.wait_child(pid, 3)
    assert kernel_thread_count() == threading.active_count() == 1
    print(json.dumps({"case": request["name"], "pid": os.getpid(), "ppid": os.getppid(),
                      "pgid": os.getpgrp(), "sid": os.getsid(0), "threads": 1,
                      "caller_threads": request["caller_threads"]}))


if __name__ == "__main__":
    main()
