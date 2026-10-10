"""Authenticated local inference transport and sanitized protocol failures."""
import json
import time

import requests
from urllib3.exceptions import ReadTimeoutError

from . import inference_transport as transport
from .inference_auth import InferenceCredentialUnavailable, inference_headers


class InferenceBackendError(requests.RequestException):
    """A service failure, never evidence that a model failed its integrity check."""

    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


def backend_error(error: Exception) -> InferenceBackendError:
    if isinstance(error, InferenceBackendError):
        return error
    if isinstance(error, InferenceCredentialUnavailable):
        return InferenceBackendError("local inference authentication is unavailable", 503)
    if isinstance(error, transport.TransportFailure):
        if error.kind == "timeout":
            return InferenceBackendError("inference worker exceeded its operation deadline", 504)
        if error.kind in {"busy", "upstream", "closed"}:
            return InferenceBackendError("inference worker is temporarily unavailable", 503)
        return InferenceBackendError("inference worker returned an invalid or oversized response")
    # requests wraps urllib3 read timeouts as ConnectionError while consuming
    # response bodies (including SSE), rather than its Timeout subclass.
    if isinstance(error, requests.Timeout) or (
        isinstance(error, requests.ConnectionError)
        and any(isinstance(cause, ReadTimeoutError) for cause in error.args)
    ):
        return InferenceBackendError("inference worker timed out", 504)
    if isinstance(error, requests.RequestException):
        return InferenceBackendError("inference worker not available", 503)
    return InferenceBackendError("inference worker returned an invalid response")


class BoundedResponse(requests.Response):
    """Response facade whose owner must consume or close the bounded operation."""
    def __init__(self, operation):
        super().__init__()
        self.operation = operation
        self.closed = False
        try:
            kind, raw = self._receive()
            if kind != b"H":
                raise transport.TransportFailure("protocol")
            metadata = transport.decode_json(raw)
            self.status_code = metadata["status"]
            self.headers.update(metadata["headers"])
            self.check_deadline()
        except Exception:
            self.close()
            raise

    def check_deadline(self):
        if time.monotonic() >= self.operation.deadline:
            raise transport.TransportFailure("timeout")

    def _receive(self):
        kind, raw = self.operation.receive()
        if kind == b"E":
            raise transport.TransportFailure(raw.decode("ascii"))
        return kind, raw

    def iter_content(self, chunk_size=4096, decode_unicode=False):
        total = 0
        try:
            while True:
                kind, raw = self._receive()
                if kind == b"D":
                    if raw:
                        raise transport.TransportFailure("protocol")
                    return
                if kind != b"B":
                    raise transport.TransportFailure("protocol")
                total += len(raw)
                if total > transport.MAX_BODY_BYTES:
                    raise transport.TransportFailure("size")
                self.check_deadline()
                yield raw
        finally:
            self.close()

    def json(self, **kwargs):
        payload = transport.decode_json(b"".join(self.iter_content()))
        self.check_deadline()
        return payload

    def close(self):
        if not self.closed:
            self.closed = True
            self.operation.close()


def _request(method: str, url: str, *, timeout, json_body=None) -> requests.Response:
    # Authenticate before any helper exists or RPC can occur. Credentials are
    # transferred only through a private stdin pipe, never argv/environment.
    headers = inference_headers()
    started = time.monotonic()
    transport.validate_request(method, url, timeout, json_body)
    deadline = started + timeout
    try:
        # The existing HTTP callers already bound request bodies. This limit
        # also covers helper IPC and protects direct internal client callers.
        payload = transport.encode_request({"method": method, "url": url, "headers": headers,
                                            "json": json_body, "timeout": timeout,
                                            "deadline": deadline})
        return BoundedResponse(transport.Operation(payload, deadline))
    except (TypeError, RecursionError):
        raise InferenceBackendError("inference request exceeds client limits") from None
    except transport.TransportFailure:
        raise
    except OSError:
        raise InferenceBackendError("inference transport is unavailable", 503) from None


def get(url: str, *, timeout: float) -> requests.Response:
    return _request("GET", url, timeout=timeout)


def post(url: str, *, json: dict, timeout: float, stream: bool = False) -> requests.Response:
    # Always stream from the backend; nonstreaming callers decode bounded bytes.
    return _request("POST", url, json_body=json, timeout=timeout)


def check_status(response: requests.Response) -> None:
    status = response.status_code
    if status == 200:
        return
    if status in (401, 403):
        raise InferenceBackendError("inference service authentication failed", 503)
    if 300 <= status < 400:
        raise InferenceBackendError("inference worker returned an unexpected redirect")
    if status in (429, 503):
        raise InferenceBackendError("inference worker is temporarily unavailable", 503)
    raise InferenceBackendError("inference worker rejected the request")


def read_json(response: requests.Response) -> dict:
    try:
        check_status(response)
        payload = response.json()
        if not isinstance(payload, dict) or "error" in payload:
            raise ValueError("invalid inference response")
        return payload
    except ValueError:
        raise InferenceBackendError("inference worker returned an invalid response") from None
    finally:
        response.close()


def validate_chat(payload: dict, *, streaming: bool = False) -> dict:
    choices = payload.get("choices")
    # A final streamed usage record may have an empty choices array.
    if not isinstance(choices, list) or (not streaming and not choices) or "error" in payload:
        raise InferenceBackendError("inference worker returned an invalid response")
    for choice in choices:
        if not isinstance(choice, dict):
            raise InferenceBackendError("inference worker returned an invalid response")
        message = choice.get("delta" if streaming else "message")
        if not isinstance(message, dict):
            raise InferenceBackendError("inference worker returned an invalid response")
        content = message.get("content", "" if streaming else None)
        # llama's first role-only delta explicitly uses content:null; final
        # chunks use an empty delta. Neither is a non-text completion body.
        if not isinstance(content, str) and not (streaming and content is None):
            raise InferenceBackendError("inference worker returned an invalid response")
    return payload


def chat_events(response: requests.Response):
    """Forward complete, bounded SSE data frames; require a terminal marker.

    The caller owns the response, including closing it on a downstream disconnect.
    Never forward upstream error bodies or malformed JSON as successful events.
    """
    pending = b""
    lines: list[str] = []
    frame_bytes = 0
    total_bytes = 0
    frames = 0
    for chunk in response.iter_content(chunk_size=4096):
        total_bytes += len(chunk)
        if total_bytes > transport.MAX_BODY_BYTES:
            raise ValueError("inference stream too large")
        pending += chunk
        while b"\n" in pending:
            raw, pending = pending.split(b"\n", 1)
            frame_bytes += len(raw) + 1
            if frame_bytes > 65536:
                raise ValueError("inference event too large")
            line = raw.rstrip(b"\r").decode("utf-8")
            if line:
                if line.startswith("data:"):
                    lines.append(line[5:].removeprefix(" "))
                elif not line.startswith(":"):
                    raise ValueError("invalid inference event field")
                continue
            frame_bytes = 0
            frames += 1
            if frames > 8192:
                raise ValueError("too many inference events")
            if not lines:
                continue
            data = "\n".join(lines)
            lines = []
            if isinstance(response, BoundedResponse):
                response.check_deadline()
            if data == "[DONE]":
                yield "data: [DONE]\n\n"
                return
            payload = transport.decode_json(data.encode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("invalid inference event")
            validate_chat(payload, streaming=True)
            if isinstance(response, BoundedResponse):
                response.check_deadline()
            yield "data: " + json.dumps(payload, ensure_ascii=True) + "\n\n"
        if len(pending) + frame_bytes > 65536:
            raise ValueError("inference event too large")
    raise ValueError("incomplete inference stream")
