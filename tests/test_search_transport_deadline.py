import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/search-mediator"))
import search_transport as transport


@pytest.fixture
def origin():
    class Handler(BaseHTTPRequestHandler):
        calls = 0
        behavior = "json"
        received_headers = {}

        def log_message(self, *args):
            pass

        def do_GET(self):
            type(self).calls += 1
            type(self).received_headers = dict(self.headers)
            behavior = type(self).behavior
            if behavior == "slow":
                time.sleep(2)
            if behavior == "redirect":
                self.send_response(302)
                self.send_header("Location", "/redirect-target")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if behavior == "gzip":
                self.send_header("Content-Encoding", "gzip")
            if behavior == "large":
                self.send_header("Content-Length", str(transport.MAX_BODY_BYTES + 1))
            self.end_headers()
            try:
                self.wfile.write(json.dumps({"results": []}).encode())
            except BrokenPipeError:
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=.01), daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", Handler
    server.shutdown()
    server.server_close()
    thread.join(timeout=1)


def test_worker_ignores_proxy_environment_and_uses_only_fixed_origin(origin, monkeypatch):
    url, handler = origin
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    result = transport.request_bounded(url, "/search", params={"q": "public facts"}, timeout=2, expect_json=True)
    assert result == {"results": []}
    assert handler.calls == 1
    assert handler.received_headers["Accept-Encoding"] == "identity"
    assert handler.received_headers["User-Agent"] == transport.HEADERS["User-Agent"]
    assert handler.received_headers["X-Forwarded-For"] == "127.0.0.1"
    assert "Authorization" not in handler.received_headers
    assert "Cookie" not in handler.received_headers


@pytest.mark.parametrize("behavior", ["redirect", "gzip", "large"])
def test_worker_rejects_unsafe_responses(origin, behavior):
    url, handler = origin
    handler.behavior = behavior
    with pytest.raises(requests.RequestException):
        transport.request_bounded(url, "/search", timeout=2, expect_json=True)
    assert handler.calls == 1


def test_wall_clock_deadline_kills_a_worker_waiting_for_headers(origin):
    url, handler = origin
    handler.behavior = "slow"
    started = time.monotonic()
    with pytest.raises(requests.Timeout):
        transport.request_bounded(url, "/search", timeout=.35, expect_json=True)
    assert time.monotonic() - started < 1.5


@pytest.mark.parametrize("url", ["http://user:secret@localhost", "http://localhost/extra", "http://localhost/?secret", "http://localhost/#secret", "http://localhost/\n", "http://localhost\\@example.invalid"])
def test_invalid_origins_rejected_before_worker_start(url, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("invalid origin started a worker")
    monkeypatch.setattr(transport.subprocess, "run", forbidden)
    with pytest.raises(ValueError):
        transport.request_bounded(url, "/search", timeout=1, expect_json=True)
