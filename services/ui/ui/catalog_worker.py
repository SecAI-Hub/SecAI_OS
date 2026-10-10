"""Single durable queue owner and isolated, deadline-bounded transfer attempts."""
from __future__ import annotations

import ctypes
import fcntl
import os
import re
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

# -I excludes CWD/PYTHONPATH. These roots are derived only from this trusted file.
_root = Path(__file__).resolve().parent.parent
for _candidate in (_root, _root.parent, _root / "services"):
    if (_candidate / "common" / "auth.py").is_file() or (_candidate / "ui" / "catalog.py").is_file():
        sys.path.insert(0, str(_candidate))

import requests
from common.auth import AuthManager
from common import runtime_clock
from common.bounded_state import BoundedState, StateUnavailable, open_directory, stable_lock
from ui import catalog, runtime_policy
from ui.catalog_jobs import CatalogJobs, JobConflict, PUBLISHED, entry_digest


def paths():
    root = Path(os.getenv("SECURE_AI_ROOT", "/var/lib/secure-ai"))
    return (Path(os.getenv("CATALOG_JOBS_DIR", str(root / "ui" / "catalog-jobs"))),
            Path(os.getenv("QUARANTINE_DIR", str(root / "quarantine" / "incoming"))))


def auth_manager():
    return AuthManager(os.getenv("AUTH_DATA_DIR", "/var/lib/secure-ai/auth"),
                       session_timeout=int(os.getenv("SESSION_TIMEOUT", "1800")),
                       runtime_dir=os.getenv("SESSION_RUNTIME_DIR", "/run/secure-ai-ui/session-state"))


def parent_death(expected_parent: int):
    if not sys.platform.startswith("linux"):
        raise RuntimeError("supervised catalog execution requires Linux")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != expected_parent:
        raise RuntimeError("catalog supervisor disappeared")


def _credential_headers():
    path = Path(os.getenv("AIRLOCK_TOKEN_PATH", ""))
    if not path.is_absolute():
        raise PermissionError("Airlock credential unavailable")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        mode = stat.S_IMODE(info.st_mode)
        sandbox_ro = (os.getenv("SECURE_AI_DEPLOYMENT_MODE") == "sandbox" and mode in {0o444, 0o644}
                      and os.fstatvfs(fd).f_flag & os.ST_RDONLY)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size not in {64, 65}
                or (mode not in {0o400, 0o600} and not sandbox_ro)):
            raise PermissionError("Airlock credential unavailable")
        raw = os.read(fd, 66)
        def identity(item):
            return (item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_nlink, item.st_ctime_ns, item.st_mtime_ns)
        if not re.fullmatch(rb"[0-9a-f]{64}\n?", raw) or identity(info) != identity(os.fstat(fd)) or identity(info) != identity(path.lstat()):
            raise PermissionError("Airlock credential unavailable")
        return {"Authorization": "Bearer " + raw[:64].decode("ascii"), "X-SecAI-Service": "ui", "Accept-Encoding": "identity"}
    finally:
        os.close(fd)


class Attempt:
    def __init__(self, jobs, identifier, root, auth):
        self.jobs, self.identifier, self.root, self.auth = jobs, identifier, Path(root), auth
        self.last_progress = 0.0
        self.http = requests.Session()
        self.http.trust_env = False

    def current(self):
        row = self.jobs.snapshot()[self.identifier]
        if row["cancel"] or runtime_clock.now() >= row["deadline"]:
            raise PermissionError("catalog attempt cancelled or expired")
        grant = row["grant"]
        if not self.auth.validate_grant(grant["session"], epoch=grant["epoch"], credential=grant["credential"]):
            raise PermissionError("authentication required")
        return row

    def authorize(self):
        row = self.current()
        if runtime_policy.binding() != row["profile"]:
            raise PermissionError("catalog policy changed")
        entry = next((item for item in catalog.load_model_catalog() if item.get("filename") == row["filename"]), None)
        if entry is None or entry.get("blocked") or entry.get("security_status") != "pinned-candidate" or entry_digest(entry) != row["catalog_digest"]:
            raise PermissionError("catalog entry changed")
        return entry

    def fetch(self, destination, *, method="GET", body="", upstream_headers=None, stream=False, timeout=30):
        self.authorize()  # Executor-bound immediately before each new Airlock RPC.
        headers = _credential_headers()
        self.http.cookies.clear()
        response = self.http.post(os.getenv("AIRLOCK_URL", "http://127.0.0.1:8490").rstrip("/") + "/v1/fetch",
                                  json={"destination": destination, "method": method, "body": body,
                                        "headers": dict(upstream_headers or {})}, headers=headers,
                                  stream=True, timeout=(5, min(timeout, 30)), allow_redirects=False)
        try:
            if response.status_code != 200 or response.headers.get("Content-Encoding", "identity").lower() not in {"", "identity"}:
                raise ValueError("Airlock fetch failed")
            final_url = response.headers.get("X-SecAI-Upstream-URL", destination)
            if not final_url.startswith("https://") or len(final_url) > 4096:
                raise ValueError("Airlock upstream identity invalid")
            response.url = final_url
            return response
        except BaseException:
            response.close()
            raise

    def response(self, url):
        return self.fetch(url, upstream_headers=catalog._huggingface_headers() if catalog._is_huggingface_url(url) else {}, stream=True)

    def check(self, url, **kwargs):
        # /v1/fetch independently enforces the actual egress decision. The
        # current profile and session remain prerequisites to every fetch.
        self.authorize()
        return True, 200, ""

    def owned(self, path):
        info = path.lstat()
        if path.parent != self.root or stat.S_ISLNK(info.st_mode):
            raise ValueError("invalid owned catalog inode")
        row = self.jobs.snapshot()[self.identifier]
        owned = dict(row["owned"])
        owned[path.name] = [info.st_dev, info.st_ino, "directory" if stat.S_ISDIR(info.st_mode) else "file"]
        self.jobs.update(self.identifier, owned=owned)

    def progress(self, filename, *, downloaded, total, message=None):
        self.authorize()
        now = time.monotonic()
        if now - self.last_progress >= 1 or downloaded == total:
            self.jobs.update(self.identifier, downloaded=downloaded)
            self.last_progress = now

    def before_publish(self):
        self.authorize()
        self.jobs.update(self.identifier, statuses={"running", "verified", "publishing"}, status="publishing")

    def published(self, destination):
        self.jobs.update(self.identifier, statuses={"publishing"}, status="quarantined", error="", owned={},
                         downloaded=self.jobs.snapshot()[self.identifier]["size"])

    def run(self):
        try:
            entry = self.authorize()
            attempt_number = self.jobs.snapshot()[self.identifier]["attempt"]
            transfer = catalog.Transfer(self.root, response=self.response, fetch=self.fetch, check=self.check,
                                        progress=self.progress, partial=lambda name: self.root / f".{name}.{self.identifier}.a{attempt_number}.part",
                                        owned=self.owned, before_publish=self.before_publish, published=self.published,
                                        manage_cleanup=False)
            if entry["type"] == "diffusion":
                transfer._download_diffusion_model(entry["url"], entry["filename"], catalog_entry=entry)
            else:
                transfer._download_single_file(entry["url"], entry["filename"], entry)
        finally:
            self.http.close()


def retain_after_stop(jobs, identifier, *, error):
    """Record containment after reaping; never mutate artifact paths here.

    Even an empty inventory cannot prove that a killed attempt did not create
    an unrecorded partial. Maintenance is required after any started attempt.
    """
    row = jobs.snapshot()[identifier]
    if row["status"] in PUBLISHED:
        return
    jobs.update(identifier, status="cleanup_required", error=error)


def recover(jobs, root):
    for identifier, row in jobs.snapshot().items():
        if row["status"] in {"publishing", "quarantined"}:
            jobs.update(identifier, status="handoff_unknown", error="handoff_unknown")
        elif row["status"] in {"running", "verified"}:
            retain_after_stop(jobs, identifier, error="interrupted")
        elif row["status"] in {"paused", "failed", "cancelled"} and (row["attempt"] or row["owned"]):
            retain_after_stop(jobs, identifier, error=row["error"] or "interrupted")


def _heartbeat_store(directory):
    def valid(value):
        if not isinstance(value, dict) or set(value) != {"pid", "updated"} or any(type(v) is not int or v < 0 for v in value.values()):
            raise ValueError("invalid worker readiness")
    return BoundedState(directory / "worker.json", lambda: {"pid": os.getpid(), "updated": 0}, valid, max_bytes=256)


def ready(directory):
    """A recent heartbeat and the original held owner lock are both required."""
    fd = open_directory(directory)
    lock = None
    try:
        # Never initialize authority from the health reader.
        os.stat("worker.lock", dir_fd=fd, follow_symlinks=False)
        lock = stable_lock(fd, "worker.lock", state_name="worker.json")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            return False
        with _heartbeat_store(directory).transaction() as state:
            return state["pid"] > 0 and 0 <= time.time() - state["updated"] <= 5
    finally:
        if lock is not None:
            os.close(lock)
        os.close(fd)


def coordinator():
    directory, root = paths()
    jobs = CatalogJobs(directory)
    auth = auth_manager()
    directory_fd = open_directory(directory, create=True)
    lock = stable_lock(directory_fd, "worker.lock", state_name="worker.json")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    heartbeat = _heartbeat_store(directory)
    child = None
    stopping = False
    def stop(signum, frame):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    def check_owner():
        previous = os.fstat(lock)
        current = os.stat("worker.lock", dir_fd=directory_fd, follow_symlinks=False)
        reopened = open_directory(directory)
        try:
            before, after = os.fstat(directory_fd), os.fstat(reopened)
            if ((previous.st_dev, previous.st_ino) != (current.st_dev, current.st_ino)
                    or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)):
                raise StateUnavailable("catalog owner path changed")
        finally:
            os.close(reopened)
    try:
        check_owner()
        recover(jobs, root)
        while not stopping:
            check_owner()
            for job_id, row in jobs.snapshot().items():
                if row["status"] == "quarantined" and not os.path.lexists(root / row["filename"]):
                    jobs.update(job_id, statuses={"quarantined"}, status="handoff_unknown", error="handoff_unknown")
            with heartbeat.transaction(write=True) as state:
                state.update(pid=os.getpid(), updated=int(time.time()))
            identifier = jobs.claim()
            if identifier is None:
                time.sleep(.5)
                continue
            child = subprocess.Popen([sys.executable, "-I", str(Path(__file__).resolve()), "attempt", identifier, str(os.getpid())],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            error = "transfer_failed"
            try:
                while child.poll() is None:
                    check_owner()
                    row = jobs.snapshot()[identifier]
                    grant = row["grant"]
                    if stopping or row["cancel"]:
                        error = "cancelled"
                        break
                    if runtime_clock.now() >= row["deadline"]:
                        error = "deadline"
                        break
                    if not auth.validate_grant(grant["session"], epoch=grant["epoch"], credential=grant["credential"]):
                        error = "authentication_required"
                        break
                    try:
                        same_profile = runtime_policy.binding() == row["profile"]
                    except PermissionError:
                        same_profile = False
                    if not same_profile:
                        error = "policy_changed"
                        break
                    with heartbeat.transaction(write=True) as state:
                        state.update(pid=os.getpid(), updated=int(time.time()))
                    time.sleep(.25)
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
                child = None
            row = jobs.snapshot()[identifier]
            if row["status"] != "quarantined":
                if row["status"] in PUBLISHED:
                    jobs.update(identifier, status="handoff_unknown", error="handoff_unknown")
                else:
                    retain_after_stop(jobs, identifier, error=error)
    finally:
        if child is not None:
            child.kill()
            child.wait(timeout=5)
        try:
            with heartbeat.transaction(write=True) as state:
                state["updated"] = 0
        finally:
            os.close(lock)
            os.close(directory_fd)


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "attempt":
        parent_death(int(sys.argv[3]))
        directory, root = paths()
        jobs = CatalogJobs(directory)
        row = jobs.snapshot()[sys.argv[2]]
        remaining = row["deadline"] - runtime_clock.now()
        if remaining <= 0:
            raise RuntimeError("attempt deadline expired")
        # Independent kernel timer survives disappearance of the caller's
        # watchdog; SIGALRM terminates even a blocked network/IPC consumer.
        runtime_clock.arm_deadline(row["deadline"])
        Attempt(jobs, sys.argv[2], root, auth_manager()).run()
    elif len(sys.argv) == 3 and sys.argv[1] == "coordinator":
        parent_death(int(sys.argv[2]))
        coordinator()
    else:
        raise RuntimeError("invalid catalog worker invocation")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, JobConflict, StateUnavailable) as error:
        # Never log upstream bodies, URLs, authentication metadata or keys.
        print(f"catalog worker unavailable ({type(error).__name__}, errno={getattr(error, 'errno', None)}); inspect durable job status", file=sys.stderr)
        sys.exit(1)
