"""Real helper processes and inert loopback peers; no model or external RPC."""

import ctypes
import gzip
import os
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services"))

from common import inference_client as client
from common import inference_transport as transport


@pytest.fixture
def peer(tmp_path, monkeypatch):
    key = tmp_path / "synthetic-key"
    key.write_text("a" * 64)
    key.chmod(0o600)
    monkeypatch.setenv("INFERENCE_TOKEN_PATH", str(key))
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.do_GET()

        def do_GET(self):
            self.server.calls += 1
            assert self.headers.get("Authorization") == "Bearer " + "a" * 64
            assert self.headers.get("Accept-Encoding") == "identity"
            mode = self.server.mode
            try:
                if mode == "slow-headers":
                    for byte in b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n":
                        self.connection.sendall(bytes([byte]))
                        time.sleep(.04)
                    return
                if mode == "chunk-metadata":
                    self.connection.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;" + b"x" * 32768 + b"\r\na\r\n0\r\n\r\n")
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream" if mode == "stream" else "application/json")
                if mode == "large-length":
                    self.send_header("Content-Length", str(transport.MAX_BODY_BYTES + 1))
                elif mode == "bad-length":
                    self.send_header("Content-Length", "invalid")
                elif mode == "compressed":
                    self.send_header("Content-Encoding", "gzip")
                self.end_headers()
                if mode == "json":
                    self.wfile.write(b'{"data":[]}')
                elif mode == "deep-json":
                    self.wfile.write(b'{"x":' + b'[' * 65 + b'0' + b']' * 65 + b'}')
                elif mode in {"positive-overflow", "negative-overflow"}:
                    self.wfile.write(b'{"usage":{"cost":' + (b'-' if mode == "negative-overflow" else b'') + b'1e999}}')
                elif mode == "malformed":
                    self.wfile.write(b'{private-invalid')
                elif mode == "compressed":
                    self.wfile.write(gzip.compress(b"x" * (transport.MAX_BODY_BYTES + 1)))
                elif mode == "blocked-consumer":
                    self.wfile.write(b"x" * (256 * 1024))
                    self.wfile.flush()
                    time.sleep(2)
                elif mode == "large-no-length":
                    self.wfile.write(b"x" * (transport.MAX_BODY_BYTES + 1))
                elif mode in {"slow-body", "stream"}:
                    if mode == "stream":
                        self.wfile.write(b'data: {"choices":[{"delta":{"role":"assistant","content":null}}]}\n\n')
                        self.wfile.flush()
                    for _ in range(120):
                        self.wfile.write(b" ")
                        self.wfile.flush()
                        time.sleep(.04)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.mode = "json"
    server.calls = 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, f"http://127.0.0.1:{server.server_port}/v1/models", key
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def test_real_worker_json_and_private_credentials(peer):
    server, url, key = peer
    response = client.get(url, timeout=3)
    pid = response.operation.process.pid
    assert key.read_bytes() not in Path(f"/proc/{pid}/cmdline").read_bytes()
    environment = Path(f"/proc/{pid}/environ").read_bytes()
    assert key.read_bytes() not in environment and b"INFERENCE_TOKEN_PATH=" not in environment
    assert client.read_json(response) == {"data": []}
    assert response.operation.process.poll() is not None
    assert server.calls == 1


@pytest.mark.parametrize("mode", ["slow-headers", "slow-body"])
def test_absolute_deadline_stops_continuous_drip(peer, mode):
    server, url, _ = peer
    server.mode = mode
    started = time.monotonic()
    with pytest.raises(transport.TransportFailure) as failure:
        client.read_json(client.get(url, timeout=.6))
    assert client.backend_error(failure.value).status_code == 504
    assert time.monotonic() - started < 1.8


@pytest.mark.parametrize("mode", ["large-length", "bad-length", "large-no-length",
                                  "compressed", "malformed", "deep-json", "chunk-metadata",
                                  "positive-overflow", "negative-overflow"])
def test_oversized_compressed_and_malformed_responses_fail(peer, mode):
    server, url, _ = peer
    server.mode = mode
    with pytest.raises((transport.TransportFailure, client.InferenceBackendError)):
        client.read_json(client.get(url, timeout=3))
    assert transport._admission._value == transport.MAX_IN_FLIGHT


def test_stopped_consumer_is_killed_and_admission_returns(peer):
    server, url, _ = peer
    server.mode = "blocked-consumer"
    response = client.get(url, timeout=.6)
    process = response.operation.process
    time.sleep(.8)  # Never consume or close: the independent deadline must act.
    assert process.poll() is not None
    assert response.operation.closed
    assert transport._admission._value == transport.MAX_IN_FLIGHT
    response.close()
    server.mode = "json"
    assert client.read_json(client.get(url, timeout=3)) == {"data": []}


def test_admission_is_nonblocking_and_release_is_idempotent(peer):
    server, url, _ = peer
    server.mode = "stream"
    held = [client.get(url, timeout=5) for _ in range(transport.MAX_IN_FLIGHT)]
    try:
        before = server.calls
        with pytest.raises(transport.TransportFailure) as failure:
            client.get(url, timeout=3)
        assert failure.value.kind == "busy" and server.calls == before
        closers = [threading.Thread(target=held[0].close) for _ in range(5)]
        for thread in closers:
            thread.start()
        for thread in closers:
            thread.join(timeout=2)
        server.mode = "json"
        assert client.read_json(client.get(url, timeout=3)) == {"data": []}
    finally:
        for response in held:
            response.close()
    assert transport._admission._value == transport.MAX_IN_FLIGHT


def test_auth_and_request_limits_precede_process_creation(peer, monkeypatch):
    _server, url, key = peer
    def forbidden(*args, **kwargs):
        pytest.fail("helper must not be created")
    monkeypatch.setattr(transport.subprocess, "Popen", forbidden)
    with pytest.raises(transport.TransportFailure):
        client.post(url.replace("/v1/models", "/completion"), timeout=3,
                    json={"prompt": "x" * (transport.MAX_REQUEST_BYTES + 1)})
    key.unlink()
    with pytest.raises(client.InferenceCredentialUnavailable):
        client.get(url, timeout=3)


def test_blocked_request_pipe_obeys_deadline_and_releases_slot(peer, monkeypatch):
    _server, url, _key = peer
    original = subprocess.Popen
    spawned = []
    def not_reading(argv, **kwargs):
        process = original([sys.executable, "-I", "-c", "import time; time.sleep(10)"], **kwargs)
        spawned.append(process)
        return process
    monkeypatch.setattr(transport.subprocess, "Popen", not_reading)
    started = time.monotonic()
    with pytest.raises(transport.TransportFailure) as failure:
        client.post(url.replace("/v1/models", "/completion"), timeout=.4,
                    json={"prompt": "x" * (512 * 1024)})
    assert failure.value.kind == "timeout"
    assert time.monotonic() - started < 1.8
    assert all(process.poll() is not None for process in spawned)
    assert transport._admission._value == transport.MAX_IN_FLIGHT


def test_event_work_and_unterminated_line_limits():
    import requests
    for content in (b": comment\n\n" * 8193, b"x" * 65537):
        response = requests.Response()
        response._content = content
        response._content_consumed = True
        with pytest.raises(ValueError):
            list(client.chat_events(response))


@pytest.mark.parametrize("mode", ["slow-body", "blocked-consumer"])
def test_parent_death_does_not_leave_live_worker(peer, mode):
    server, url, key = peer
    server.mode = mode
    libc = ctypes.CDLL(None)
    old = ctypes.c_int()
    assert libc.prctl(37, ctypes.byref(old), 0, 0, 0) == 0
    assert libc.prctl(36, 1, 0, 0, 0) == 0  # Adopt/reap this test's orphan only.
    code = (
        "import sys,time;sys.path.insert(0,sys.argv[1]);"
        "from common import inference_client as c;"
        "r=c.get(sys.argv[2],timeout=1.5);"
        "print(r.operation.process.pid,flush=True);time.sleep(10)"
    )
    parent = subprocess.Popen([sys.executable, "-I", "-c", code,
                               str(Path(__file__).resolve().parents[1] / "services"), url],
                              env={**os.environ, "INFERENCE_TOKEN_PATH": str(key)},
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    worker = None
    try:
        worker = int(parent.stdout.readline())
        parent.kill()
        parent.wait(timeout=2)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            exited, status = os.waitpid(worker, os.WNOHANG)
            if exited:
                worker = None
                # A closed stdout exits immediately; a waiting HTTP read must
                # be stopped by the independent timer after the parent dies.
                expected = {124} if mode == "slow-body" else {1, 120, 124}
                assert os.waitstatus_to_exitcode(status) in expected
                break
            time.sleep(.03)
        else:
            pytest.fail("orphan helper survived its own deadline")
    finally:
        if parent.poll() is None:
            parent.kill()
        parent.communicate(timeout=2)
        if worker:
            try:
                os.kill(worker, signal.SIGKILL)
                os.waitpid(worker, 0)
            except ProcessLookupError:
                pass
        assert libc.prctl(36, old.value, 0, 0, 0) == 0


def test_buffered_json_and_sse_cannot_succeed_after_deadline(peer, monkeypatch):
    _server, url, _key = peer
    response = client.get(url, timeout=3)
    response.operation.deadline = time.monotonic() - 1
    with pytest.raises(transport.TransportFailure) as failure:
        client.read_json(response)
    assert failure.value.kind == "timeout"
    # Two events in one IPC chunk must still re-check between downstream yields.
    class Buffered:
        deadline = time.monotonic() + 3
        def close(self):
            pass
    response = object.__new__(client.BoundedResponse)
    response.operation = Buffered()
    response.iter_content = lambda **kwargs: iter([b'data: {"choices":[{"delta":{"content":"x"}}]}\n\ndata: [DONE]\n\n'])
    events = client.chat_events(response)
    assert '"content": "x"' in next(events)
    response.operation.deadline = time.monotonic() - 1
    with pytest.raises(transport.TransportFailure) as failure:
        next(events)
    assert failure.value.kind == "timeout"


@pytest.mark.parametrize("number", [b"1e999", b"-1e999"])
def test_nested_json_exponent_overflow_is_rejected_at_parse_time(number):
    with pytest.raises(ValueError, match="nonfinite JSON number"):
        transport.decode_json(b'{"usage":[{"cost":' + number + b'}]}')


def test_finite_json_exponents_remain_valid():
    assert transport.decode_json(b'{"usage":[{"cost":1e307},{"cost":-1e307}]}') == {
        "usage": [{"cost": 1e307}, {"cost": -1e307}],
    }
