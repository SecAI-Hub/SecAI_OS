"""Actual Gunicorn/queue/attempt processes with a private synthetic Airlock.

The filesystem is a read-only bubblewrap view with only the synthetic fixture
writable. No host service, profile, credentials or firewall is changed.
"""
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "services/ui"))

from common.auth import AuthManager
from common import runtime_clock
from ui.catalog_jobs import CatalogJobs


def until(check, timeout=12):
    end = time.monotonic() + timeout
    last = None
    while time.monotonic() < end:
        try:
            last = check()
            if last:
                return last
        except (OSError, requests.RequestException):
            pass
        time.sleep(.05)
    raise AssertionError(f"bounded condition not reached; last={last!r}")


def children(pid):
    try:
        return [int(value) for value in Path(f"/proc/{pid}/task/{pid}/children").read_text().split()]
    except FileNotFoundError:
        return []


def descendants(pid):
    result = []
    pending = children(pid)
    while pending:
        current = pending.pop()
        result.append(current)
        pending.extend(children(current))
    return result


def running(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0] != "Z"
    except FileNotFoundError:
        return False


class Runtime:
    def __init__(self, root, *, idle=1800):
        self.root = root
        self.data = root / "data"
        for name in ("state", "auth", "ui/catalog-jobs", "quarantine/incoming", "logs"):
            (self.data / name).mkdir(parents=True, exist_ok=True)
        (self.data / "state/profile.json").write_text('{"active":"research"}')
        self.runtime = root / "runtime"
        self.runtime.mkdir()
        self.auth = AuthManager(str(self.data / "auth"), runtime_dir=str(self.runtime / "session-state"), session_timeout=idle)
        assert self.auth.setup_passphrase("synthetic-runtime-passphrase")
        self.token = self.auth.login("synthetic-runtime-passphrase")["token"]
        self.jobs = CatalogJobs(self.data / "ui/catalog-jobs")
        self.payload = b"inert-catalog-fixture\n" * 131072
        self.entry = {"name": "Synthetic", "type": "llm", "filename": "synthetic.gguf",
                      "url": "https://huggingface.co/synthetic/fixture/resolve/" + "a" * 40 + "/synthetic.gguf",
                      "expected_revision": "a" * 40, "expected_size_bytes": len(self.payload),
                      "expected_sha256": hashlib.sha256(self.payload).hexdigest(), "security_status": "pinned-candidate"}
        self.catalog = root / "catalog.yaml"
        self.catalog.write_text(json.dumps({"models": [self.entry]}))
        self.airlock_token = root / "airlock.token"
        self.airlock_token.write_text("d" * 64)
        self.airlock_token.chmod(0o600)
        self.flask_key = root / "flask.key"
        self.flask_key.write_text("e" * 64)
        self.flask_key.chmod(0o600)
        self.started = threading.Event()
        self.release = threading.Event()
        self.fetches = 0
        self.failures = []
        fixture = self
        class Airlock(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                try:
                    assert self.headers.get("Authorization") == "Bearer " + "d" * 64
                    body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    assert body["destination"] == fixture.entry["url"]
                    if self.path == "/v1/egress/check":
                        payload = b'{"allowed":true}'
                        self.send_response(200)
                        self.send_header("Content-Length", str(len(payload)))
                        self.end_headers()
                        self.wfile.write(payload)
                        return
                    assert self.path == "/v1/fetch"
                    fixture.fetches += 1
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(fixture.payload)))
                    self.end_headers()
                    self.wfile.write(fixture.payload[:1048576])
                    self.wfile.flush()
                    fixture.started.set()
                    if not fixture.release.wait(20):
                        return
                    self.wfile.write(fixture.payload[1048576:])
                except (BrokenPipeError, ConnectionResetError):
                    pass
                except Exception as error:
                    fixture.failures.append(type(error).__name__)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Airlock)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.http = requests.Session()
        self.http.trust_env = False
        self.http.headers["Authorization"] = "Bearer " + self.token
        self.log = (root / "runtime.log").open("wb")
        self.env = {**os.environ, "SECURE_AI_ROOT": "/var/lib/secure-ai", "SECURE_AI_DEPLOYMENT_MODE": "appliance",
                    "AUTH_DATA_DIR": "/var/lib/secure-ai/auth", "SESSION_RUNTIME_DIR": "/run/secure-ai-ui/session-state",
                    "CATALOG_JOBS_DIR": "/var/lib/secure-ai/ui/catalog-jobs", "QUARANTINE_DIR": "/var/lib/secure-ai/quarantine/incoming",
                    "AUDIT_LOG_PATH": "/var/lib/secure-ai/logs/ui-audit.jsonl", "AIRLOCK_TOKEN_PATH": str(self.airlock_token),
                    "AIRLOCK_URL": f"http://127.0.0.1:{self.server.server_port}", "MODEL_CATALOG_PATH": str(self.catalog),
                    "FLASK_SECRET_KEY_PATH": str(self.flask_key), "BIND_ADDR": f"127.0.0.1:{self.port}",
                    "SESSION_TIMEOUT": str(idle), "PYTHONPATH": str(ROOT / "services") + ":" + str(ROOT / "services/ui"),
                    "VAULT_ACTIVITY_FILE": str(root / "activity"), "PYTHONDONTWRITEBYTECODE": "1"}
        self.command = [shutil.which("bwrap"), "--die-with-parent", "--ro-bind", "/", "/", "--dev", "/dev",
                        "--bind", str(root), str(root), "--tmpfs", "/var/lib", "--dir", "/var/lib/secure-ai",
                        "--bind", str(self.data), "/var/lib/secure-ai", "--tmpfs", "/etc", "--dir", "/etc/secure-ai",
                        "--tmpfs", "/run", "--dir", "/run/secure-ai-ui", "--bind", str(self.runtime), "/run/secure-ai-ui",
                        sys.executable, "-I", str(ROOT / "services/ui/ui/runtime.py"), "--",
                        str(Path(sys.executable).with_name("gunicorn")), "--bind", f"127.0.0.1:{self.port}",
                        "--workers", "1", "--threads", "2", "--max-requests", "8", "--max-requests-jitter", "0",
                        "--no-control-socket", "--worker-tmp-dir", str(root), "ui.app:app"]
        self.process = subprocess.Popen(self.command, env=self.env, stdout=self.log, stderr=self.log, start_new_session=True)
        self.seen = set()
        try:
            until(lambda: self.http.get(self.url + "/health", timeout=.5).status_code == 200)
        except BaseException:
            self.close()
            raise AssertionError((root / "runtime.log").read_text()[-4000:])

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def submit(self):
        response = self.http.post(self.url + "/api/catalog/download", json={
            "url": self.entry["url"], "filename": self.entry["filename"]}, timeout=5)
        assert response.status_code == 202, response.text
        self.identifier = response.json()["job_id"]
        assert self.started.wait(8), (self.root / "runtime.log").read_text()[-3000:]
        # Select the blocked-read boundary after the durable ownership/progress
        # transaction, not a random kill while that transaction is committing.
        until(lambda: self.status()["downloaded"] == 1048576, timeout=8)
        self.seen.update(descendants(self.process.pid))
        return self.identifier

    def status(self):
        return self.jobs.snapshot()[self.identifier]

    def close(self):
        self.release.set()
        if hasattr(self, "process"):
            self.seen.update(descendants(self.process.pid))
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
            until(lambda: all(not running(pid) for pid in self.seen), timeout=8)
        self.http.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        self.log.close()
        assert not self.failures


@pytest.fixture
def runtime(tmp_path):
    if not sys.platform.startswith("linux") or not shutil.which("bwrap"):
        pytest.skip("actual Linux bubblewrap runtime required")
    instance = Runtime(tmp_path)
    try:
        yield instance
    finally:
        instance.close()


def test_gunicorn_recycles_without_losing_session_or_transfer(runtime):
    runtime.submit()
    before = set(descendants(runtime.process.pid))
    for _ in range(20):
        assert runtime.http.get(runtime.url + "/api/auth/status", timeout=3).json()["authenticated"]
    until(lambda: set(descendants(runtime.process.pid)) != before)
    assert runtime.status()["status"] == "running"
    assert runtime.fetches == 1
    runtime.release.set()
    until(lambda: runtime.status()["status"] == "quarantined")
    assert (runtime.data / "quarantine/incoming/synthetic.gguf").read_bytes() == runtime.payload
    assert runtime.fetches == 1
    assert runtime.token.encode() not in (runtime.data / "ui/catalog-jobs/jobs.json").read_bytes()


@pytest.mark.parametrize("action", ["cancel", "logout", "credential", "profile", "deadline"])
def test_blocked_transfer_stops_and_reaps_on_revocation(runtime, action):
    runtime.submit()
    inventory = runtime.status()["owned"]
    original = {name: (runtime.data / "quarantine/incoming" / name).read_bytes() for name in inventory}
    if action == "cancel":
        response = runtime.http.post(runtime.url + f"/api/catalog/jobs/{runtime.identifier}/cancel", json={}, timeout=3)
        assert response.status_code == 202
    elif action == "logout":
        runtime.auth.logout(runtime.token)
    elif action == "credential":
        assert runtime.auth.change_passphrase("synthetic-runtime-passphrase", "synthetic-runtime-replacement")["success"]
    elif action == "profile":
        (runtime.data / "state/profile.json").write_text('{"active":"offline_private"}')
    else:
        runtime.jobs.update(runtime.identifier, deadline=int(runtime_clock.now()) - 1)
    until(lambda: runtime.status()["status"] == "cleanup_required")
    assert runtime.status()["owned"]
    assert runtime.status()["owned"] == inventory
    assert all((runtime.data / "quarantine/incoming" / name).read_bytes() == data for name, data in original.items())
    assert not (runtime.data / "quarantine/incoming/synthetic.gguf").exists()
    assert runtime.fetches == 1


def test_idle_expiry_stops_stream_without_passive_refresh(tmp_path):
    instance = Runtime(tmp_path, idle=4)
    try:
        instance.submit()
        until(lambda: instance.status()["status"] == "cleanup_required", timeout=9)
        assert instance.status()["error"] == "authentication_required"
        assert instance.status()["owned"]
    finally:
        instance.close()


@pytest.mark.parametrize("component", ["coordinator", "supervisor"])
def test_abrupt_parent_death_leaves_no_running_descendants(runtime, component):
    runtime.submit()
    processes = descendants(runtime.process.pid)
    runtime.seen.update(processes)
    target = next(pid for pid in processes if
                  ((b"catalog_worker.py\x00coordinator" in Path(f"/proc/{pid}/cmdline").read_bytes())
                   if component == "coordinator" else b"ui/runtime.py" in Path(f"/proc/{pid}/cmdline").read_bytes()))
    os.kill(target, signal.SIGKILL)
    runtime.process.wait(timeout=10)
    until(lambda: all(not running(pid) for pid in processes), timeout=8)
    assert runtime.fetches == 1


def test_attempt_death_retains_data_and_blocks_retry(runtime):
    runtime.submit()
    pid = next(pid for pid in descendants(runtime.process.pid)
               if b"catalog_worker.py\x00attempt" in Path(f"/proc/{pid}/cmdline").read_bytes())
    os.kill(pid, signal.SIGKILL)
    until(lambda: runtime.status()["status"] == "cleanup_required")
    assert runtime.status()["owned"] and not running(pid)
    assert runtime.fetches == 1
    response = runtime.http.post(runtime.url + f"/api/catalog/jobs/{runtime.identifier}/retry", json={}, timeout=4)
    assert response.status_code == 409
    assert runtime.fetches == 1
    assert runtime.status()["attempt"] == 1
    assert all((runtime.data / "quarantine/incoming" / name).read_bytes() == runtime.payload[:1048576]
               for name in runtime.status()["owned"])


def test_supervisor_restart_preserves_stopped_partial_and_inventory(runtime):
    runtime.submit()
    inventory = runtime.status()["owned"]
    original = {name: (runtime.data / "quarantine/incoming" / name).read_bytes() for name in inventory}
    pid = next(pid for pid in descendants(runtime.process.pid)
               if b"ui/runtime.py" in Path(f"/proc/{pid}/cmdline").read_bytes())
    os.kill(pid, signal.SIGTERM)
    runtime.process.wait(timeout=8)
    until(lambda: all(not running(pid) for pid in runtime.seen))
    runtime.process = subprocess.Popen(runtime.command, env=runtime.env, stdout=runtime.log, stderr=runtime.log,
                                       start_new_session=True)
    until(lambda: runtime.http.get(runtime.url + "/health", timeout=.5).status_code == 200)
    assert runtime.status()["status"] == "cleanup_required"
    assert runtime.status()["owned"] == inventory
    assert all((runtime.data / "quarantine/incoming" / name).read_bytes() == data for name, data in original.items())
    assert runtime.fetches == 1
    assert runtime.http.post(runtime.url + f"/api/catalog/jobs/{runtime.identifier}/retry", json={}, timeout=3).status_code == 409


def test_competing_supervisor_cannot_take_over_owned_queue(runtime):
    runtime.submit()
    other = subprocess.Popen(runtime.command, env=runtime.env, stdout=runtime.log, stderr=runtime.log,
                             start_new_session=True)
    seen = []
    try:
        seen = descendants(other.pid)
        assert other.wait(timeout=8) != 0
        until(lambda: all(not running(pid) for pid in seen))
        assert runtime.status()["status"] == "running"
        assert runtime.fetches == 1
        assert runtime.http.get(runtime.url + "/health", timeout=3).status_code == 200
    finally:
        if other.poll() is None:
            os.killpg(other.pid, signal.SIGKILL)
            other.wait(5)


def test_owner_path_replacement_stops_attempt_without_takeover(runtime):
    runtime.submit()
    lock = runtime.data / "ui/catalog-jobs/worker.lock"
    lock.rename(lock.with_name("original-worker.lock"))
    lock.write_bytes(b"")
    lock.chmod(0o660)
    runtime.process.wait(timeout=8)
    until(lambda: all(not running(pid) for pid in runtime.seen))
    assert runtime.fetches == 1


def test_cookie_and_csrf_survive_worker_recycling(runtime):
    runtime.submit()
    runtime.http.headers.pop("Authorization")
    login = runtime.http.post(runtime.url + "/api/auth/login", json={"passphrase": "synthetic-runtime-passphrase"}, timeout=5)
    assert login.status_code == 200
    for _ in range(18):
        response = runtime.http.get(runtime.url + "/api/auth/status", timeout=3)
        assert response.json()["authenticated"]
    csrf = runtime.http.cookies.get("csrf_token")
    assert csrf
    endpoint = runtime.url + f"/api/catalog/jobs/{runtime.identifier}/cancel"
    assert runtime.http.post(endpoint, json={}, timeout=3).status_code == 403
    assert runtime.http.post(endpoint, json={}, headers={"X-CSRF-Token": csrf}, timeout=3).status_code == 202
    until(lambda: runtime.status()["status"] == "cleanup_required")
