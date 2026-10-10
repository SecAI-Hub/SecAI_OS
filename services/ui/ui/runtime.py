"""Supervise Gunicorn and one catalog queue owner in the existing UI service."""
from __future__ import annotations

import ctypes
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
for _candidate in (_root, _root.parent, _root / "services"):
    if (_candidate / "common" / "auth.py").is_file() or (_candidate / "ui" / "catalog.py").is_file():
        sys.path.insert(0, str(_candidate))

from ui.catalog_worker import auth_manager, parent_death


def post_fork(server, worker):
    """Gunicorn config hook: blocked HTTP workers die with their master."""
    parent_death(server.pid)


def on_starting(server):
    if server.cfg.workers != 1:
        raise RuntimeError("one HTTP worker is required for the shared audit writer")


def _terminate(child):
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "--":
        argv.pop(0)
    if not argv or not Path(argv[0]).is_absolute():
        raise RuntimeError("an absolute Gunicorn executable is required")
    if not sys.platform.startswith("linux"):
        raise RuntimeError("supervised UI runtime requires Linux")
    # Adopt/reap descendant transfers if their coordinator exits unexpectedly.
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise RuntimeError("UI process supervision unavailable")
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["CATALOG_WORKER_ENABLED"] = "1"
    auth_manager()._store.require_current_epoch()
    children = []
    stopping = False
    def stop(signum, frame):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        children.append(subprocess.Popen([sys.executable, "-I", "-B", str(Path(__file__).with_name("catalog_worker.py")),
                                          "coordinator", str(os.getpid())], start_new_session=True))
        supervisor_pid = os.getpid()
        children.append(subprocess.Popen([*argv, "--config", str(Path(__file__).resolve())],
                                         start_new_session=True,
                                         preexec_fn=lambda: parent_death(supervisor_pid)))
        while not stopping and all(child.poll() is None for child in children):
            time.sleep(.1)
        if not stopping:
            raise RuntimeError("a supervised UI component exited")
    finally:
        for child in children:
            _terminate(child)
        deadline = time.monotonic() + 5
        for child in children:
            try:
                child.wait(timeout=max(.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait(timeout=5)
        # Any adopted attempt has a kernel parent-death kill. Reap it here.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if not pid:
                time.sleep(.01)


if __name__ == "__main__":
    main()
