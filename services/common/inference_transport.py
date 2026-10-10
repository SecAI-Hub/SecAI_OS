"""Killable inference I/O with bounded private IPC; no credentials in argv/env.

The helper is executed as a file under -I so it needs no package import path.
Admission is local to each caller process, not a backend authorization policy.
"""

import http.client
import json
import logging
import math
import os
import select
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

MAX_REQUEST_BYTES = 1024 * 1024
MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_WIRE_BYTES = MAX_BODY_BYTES + 256 * 1024
MAX_FRAME_BYTES = 16384
MAX_SECONDS = 300.0
MAX_IN_FLIGHT = 4
CHUNK_BYTES = 4096

# Start the independent deadline before third-party imports or stdin reads.
# The only argv datum is a monotonic timestamp; all request data stays in IPC.
if __name__ == "__main__":
    try:
        _child_deadline = float(sys.argv[1])
        _remaining_seconds = _child_deadline - time.monotonic()
        if not math.isfinite(_remaining_seconds) or not 0 < _remaining_seconds <= MAX_SECONDS:
            os._exit(124)
        _watchdog = threading.Timer(_remaining_seconds, lambda: os._exit(124))
        _watchdog.daemon = True
        _watchdog.start()
    except (IndexError, ValueError):
        os._exit(124)

import requests
from urllib3.exceptions import ReadTimeoutError

_admission = threading.BoundedSemaphore(MAX_IN_FLIGHT)


class TransportFailure(requests.RequestException):
    def __init__(self, kind):
        super().__init__("bounded inference transport failed")
        self.kind = kind


def check_json_work(raw):
    """Bound structural work before decoding; strings remain opaque data."""
    depth = 0
    nodes = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
            nodes += 1
        elif byte in (91, 123):
            depth += 1
            nodes += 1
            if depth > 64:
                raise TransportFailure("protocol")
        elif byte in (93, 125):
            depth -= 1
        elif byte in (44, 58):
            nodes += 1
        if nodes > 65536:
            raise TransportFailure("protocol")


def decode_json(raw):
    check_json_work(raw)
    def invalid_constant(value):
        raise ValueError("non-JSON constant")
    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("nonfinite JSON number")
        return number
    return json.loads(raw.decode("utf-8"), parse_constant=invalid_constant,
                      parse_float=finite_float)


def encode_request(payload):
    pending = [(payload, 0)]
    nodes = characters = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > 65536 or depth > 64:
            raise TransportFailure("size")
        if isinstance(item, str):
            characters += len(item)
            if characters > MAX_REQUEST_BYTES:
                raise TransportFailure("size")
        elif isinstance(item, dict):
            if nodes + len(pending) + 2 * len(item) > 65536:
                raise TransportFailure("size")
            pending.extend((value, depth + 1) for pair in item.items() for value in pair)
        elif isinstance(item, (list, tuple)):
            if nodes + len(pending) + len(item) > 65536:
                raise TransportFailure("size")
            pending.extend((value, depth + 1) for value in item)
    raw = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode()
    if len(raw) > MAX_REQUEST_BYTES:
        raise TransportFailure("size")
    return raw


def validate_request(method, url, timeout, body):
    if (not isinstance(timeout, (int, float)) or isinstance(timeout, bool)
            or not math.isfinite(timeout) or not 0 < timeout <= MAX_SECONDS):
        raise TransportFailure("timeout")
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 33 for c in url):
        raise TransportFailure("protocol")
    parsed = urlsplit(url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or "\\" in url
            or (method, parsed.path) not in {
                ("GET", "/v1/models"), ("POST", "/completion"),
                ("POST", "/v1/chat/completions"),
            }):
        raise TransportFailure("protocol")
    _ = parsed.port
    if body is not None and not isinstance(body, dict):
        raise TransportFailure("protocol")


class _WireReader:
    """Bound bytes and metadata lines before HTTP/chunk parsers allocate them."""
    def __init__(self, wrapped):
        self.wrapped = wrapped
        self.total = 0

    def _read(self, method, size=-1):
        limit = min(MAX_WIRE_BYTES - self.total + 1,
                    8193 if method == "readline" else MAX_WIRE_BYTES + 1)
        if size >= 0:
            limit = min(limit, size)
        data = getattr(self.wrapped, method)(limit)
        self.total += len(data)
        if self.total > MAX_WIRE_BYTES or (method == "readline" and len(data) > 8192):
            raise TransportFailure("size")
        return data

    def read(self, size=-1):
        return self._read("read", size)

    def read1(self, size=-1):
        return self._read("read1", size)

    def readline(self, size=-1):
        return self._read("readline", size)

    def readinto(self, buffer):
        data = self.read(len(buffer))
        buffer[:len(data)] = data
        return len(data)

    def __getattr__(self, name):
        return getattr(self.wrapped, name)


def exchange(payload):
    """Worker-only exchange; yields bounded (kind, bytes) protocol frames."""
    try:
        validate_request(payload["method"], payload["url"], payload["timeout"], payload.get("json"))
        headers = dict(payload["headers"], **{"Accept-Encoding": "identity"})
        with requests.Session() as session:
            session.trust_env = False
            with session.request(
                payload["method"], payload["url"], json=payload.get("json"), headers=headers,
                proxies={}, allow_redirects=False, stream=True,
                timeout=(min(5, payload["timeout"]), payload["timeout"]),
            ) as response:
                selected = {name: response.headers[name] for name in (
                    "Content-Type", "Content-Length", "Content-Encoding",
                ) if name in response.headers}
                metadata = json.dumps({"status": response.status_code, "headers": selected}).encode()
                if len(metadata) > MAX_FRAME_BYTES:
                    raise TransportFailure("size")
                if response.status_code == 200:
                    if response.headers.get("Content-Encoding", "identity").strip().lower() not in {"", "identity"}:
                        raise TransportFailure("protocol")
                    length = response.headers.get("Content-Length")
                    if length is not None and (not length.isascii() or not length.isdigit()
                                               or len(length) > 10 or int(length) > MAX_BODY_BYTES):
                        raise TransportFailure("size")
                yield b"H", metadata
                if response.status_code == 200:
                    total = 0
                    for chunk in response.iter_content(chunk_size=CHUNK_BYTES):
                        total += len(chunk)
                        if total > MAX_BODY_BYTES:
                            raise TransportFailure("size")
                        if chunk:
                            yield b"B", chunk
                yield b"D", b""
    except requests.Timeout:
        yield b"E", b"timeout"
    except TransportFailure as exc:
        yield b"E", exc.kind.encode("ascii")
    except requests.RequestException as exc:
        timeout = isinstance(exc, requests.ConnectionError) and any(
            isinstance(cause, ReadTimeoutError) for cause in exc.args)
        yield b"E", b"timeout" if timeout else b"upstream"
    except Exception:  # noqa: BLE001 -- never disclose library/request diagnostics
        yield b"E", b"protocol"


class Operation:
    """One child, one absolute deadline and one held admission slot."""
    def __init__(self, payload, deadline):
        self.deadline = deadline
        self.closed = False
        self.expired = False
        self._lock = threading.Lock()
        self._buffer = bytearray()
        self._released = False
        self.process = None
        self.timer = None
        if not _admission.acquire(blocking=False):
            raise TransportFailure("busy")
        try:
            if time.monotonic() >= deadline:
                raise TransportFailure("timeout")
            self.process = subprocess.Popen(
                [sys.executable, "-I", str(Path(__file__).resolve()), str(deadline)],
                # A private bounded pipe avoids opening /dev/null, which the
                # native UI Landlock policy does not grant. Never log its data.
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True, bufsize=0,
                env={key: value for key, value in os.environ.items()
                     if key in {"PATH", "LANG", "LC_ALL", "SYSTEMROOT", "WINDIR"}},
            )
            self.timer = threading.Timer(max(0, deadline - time.monotonic()), self._expire)
            self.timer.daemon = True
            self.timer.start()
            os.set_blocking(self.process.stdin.fileno(), False)
            os.set_blocking(self.process.stdout.fileno(), False)
            offset = 0
            while offset < len(payload):
                self._wait(self.process.stdin, writing=True)
                try:
                    offset += os.write(self.process.stdin.fileno(), payload[offset:])
                except BlockingIOError:
                    continue
            self.process.stdin.close()
        except Exception:
            self.close()
            if self.expired or time.monotonic() >= deadline:
                raise TransportFailure("timeout") from None
            raise

    def _remaining(self):
        if self.expired or time.monotonic() >= self.deadline:
            raise TransportFailure("timeout")
        if self.closed:
            raise TransportFailure("closed")
        return self.deadline - time.monotonic()

    def _wait(self, pipe, *, writing=False):
        try:
            ready = select.select([] if writing else [pipe], [pipe] if writing else [], [], self._remaining())
            if not (ready[1] if writing else ready[0]):
                raise TransportFailure("timeout")
            self._remaining()
        except (ValueError, OSError):
            self._remaining()
            raise TransportFailure("upstream") from None

    def _read(self, size):
        while len(self._buffer) < size:
            self._wait(self.process.stdout)
            try:
                chunk = os.read(self.process.stdout.fileno(), min(CHUNK_BYTES, size - len(self._buffer)))
            except BlockingIOError:
                continue
            if not chunk:
                self._remaining()
                raise TransportFailure("protocol")
            self._buffer.extend(chunk)
        result = bytes(self._buffer[:size])
        del self._buffer[:size]
        return result

    def receive(self):
        try:
            header = self._read(5)
            kind, length = header[:1], struct.unpack("!I", header[1:])[0]
            if kind not in {b"H", b"B", b"D", b"E"} or length > MAX_FRAME_BYTES:
                raise TransportFailure("protocol")
            return kind, self._read(length)
        except Exception:
            self.close()
            raise

    def _expire(self):
        self.expired = True
        self.close()

    def _release(self):
        if not self._released:
            self._released = True
            _admission.release()

    def close(self):
        with self._lock:
            if self.closed:
                return
            self.closed = True
            if self.timer is not None:
                self.timer.cancel()
            process = self.process
            if process is None:
                self._release()
                return
            if process.poll() is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                # Never admit a replacement while a child still exists. This
                # bounded reaper retains its slot until the OS completes exit.
                def reap():
                    process.wait()
                    self._release()
                threading.Thread(target=reap, daemon=True).start()
            else:
                self._release()


def _worker():
    logging.disable(logging.CRITICAL)
    # Limits affect only this isolated helper, never the caller's HTTP library.
    original = socket.socket.makefile
    def bounded_makefile(sock, *args, **kwargs):
        return _WireReader(original(sock, *args, **kwargs))
    socket.socket.makefile = bounded_makefile
    http.client._MAXLINE = 8192
    http.client._MAXHEADERS = 32
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        return 1
    try:
        payload = decode_json(raw)
        if payload["deadline"] != _child_deadline or time.monotonic() >= _child_deadline:
            return 124
        for kind, data in exchange(payload):
            if len(data) > MAX_FRAME_BYTES:
                return 1
            sys.stdout.buffer.write(kind + struct.pack("!I", len(data)) + data)
            sys.stdout.buffer.flush()
    except Exception:  # noqa: BLE001 -- private worker failures are sanitized
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_worker())
