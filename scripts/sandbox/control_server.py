#!/usr/bin/env python3
"""Loopback control API for the Docker sandbox launcher.

The UI container intentionally does not get the Docker socket. This helper runs
on the host, listens on loopback, and only accepts token-authenticated requests
for a small allowlist of sandbox start profiles.
"""

from __future__ import annotations

import argparse
import contextlib
import hmac
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


VALID_PROFILES = {"offline_private", "research", "full_lab"}
PROFILE_ARGS = {
    "offline_private": (),
    "research": ("--with-search",),
    "full_lab": ("--with-search", "--with-diffusion"),
}
PS_SWITCHES = {
    "--with-search": "-WithSearch",
    "--with-airlock": "-WithAirlock",
    "--with-inference": "-WithInference",
    "--with-diffusion": "-WithDiffusion",
}
SAFE_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+=:-]{0,254}\.gguf$", re.IGNORECASE)
MAX_BODY_BYTES = 8192

_state_lock = threading.Lock()
_active_thread: threading.Thread | None = None
_server: ThreadingHTTPServer | None = None


class ControlConfig:
    def __init__(self, repo_root: Path, runtime_dir: Path, token_path: Path) -> None:
        self.repo_root = repo_root
        self.runtime_dir = runtime_dir
        self.token_path = token_path
        self.status_path = runtime_dir / "state" / "control-status.json"
        self.pid_path = runtime_dir / "control-server.pid"
        self.env_path = repo_root / "deploy" / "sandbox" / ".env"


CONFIG: ControlConfig | None = None


def _now() -> float:
    return round(time.time(), 3)


def _read_token() -> str:
    if CONFIG is None:
        return ""
    try:
        return CONFIG.token_path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _current_profile() -> str:
    if CONFIG is None:
        return "offline_private"
    state = _read_json(CONFIG.runtime_dir / "state" / "profile.json")
    profile = str(state.get("active") or "offline_private")
    return profile if profile in VALID_PROFILES else "offline_private"


def _status(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    if CONFIG is None:
        return {"status": "unconfigured", "profile": "offline_private"}
    data = _read_json(CONFIG.status_path)
    if not data:
        data = {"status": "idle"}
    data.update({
        "profile": _current_profile(),
        "valid_profiles": sorted(VALID_PROFILES),
        "controller": "secai-sandbox-control",
    })
    if extra:
        data.update(extra)
    return data


def _display_command(profile: str, *, inference: bool) -> str:
    args = list(PROFILE_ARGS[profile])
    if inference:
        args.append("--with-inference")
    return ".\\secai-sandbox.cmd start" + ((" " + " ".join(args)) if args else "")


def _command_args(profile: str, *, inference: bool) -> list[str]:
    args = list(PROFILE_ARGS[profile])
    if inference and "--with-inference" not in args:
        args.append("--with-inference")
    if os.name == "nt":
        if CONFIG is None:
            raise RuntimeError("controller is not configured")
        start_script = CONFIG.repo_root / "scripts" / "sandbox" / "start.ps1"
        return [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(start_script),
            *[PS_SWITCHES[arg] for arg in args],
        ]
    if CONFIG is None:
        raise RuntimeError("controller is not configured")
    start_script = CONFIG.repo_root / "scripts" / "sandbox" / "start.sh"
    return [str(start_script), *args]


def _validate_model_filename(value: object) -> str:
    if value in (None, ""):
        return ""
    filename = str(value)
    if "/" in filename or "\\" in filename or filename in {".", ".."}:
        raise ValueError("invalid model filename")
    if not SAFE_MODEL_RE.match(filename):
        raise ValueError("model filename must be a single .gguf registry filename")
    return filename


def _set_env_value(path: Path, key: str, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    replacement = f"{key}={value}"
    for idx, line in enumerate(lines):
        if line.startswith(f"{key}="):
            lines[idx] = replacement
            break
    else:
        lines.append(replacement)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def _tail(text: str, limit: int = 6000) -> str:
    if len(text) <= limit:
        return text
    return text[-limit:]


def _run_apply(
    *,
    profile: str,
    inference: bool,
    model_filename: str,
    requested_by: str,
) -> None:
    if CONFIG is None:
        return
    command = _command_args(profile, inference=inference)
    display = _display_command(profile, inference=inference)
    started = _now()
    _write_json_atomic(CONFIG.status_path, {
        "status": "running",
        "profile": profile,
        "inference": inference,
        "model_filename": model_filename,
        "requested_by": requested_by,
        "command": display,
        "started_at": started,
        "updated_at": started,
    })
    if inference and model_filename:
        _set_env_value(
            CONFIG.env_path,
            "SECAI_INFERENCE_MODEL_PATH",
            f"/var/lib/secure-ai/registry/{model_filename}",
        )
    try:
        proc = subprocess.run(
            command,
            cwd=str(CONFIG.repo_root),
            check=False,
            capture_output=True,
            text=True,
            timeout=3600,
        )
        finished = _now()
        output = "\n".join(
            part for part in (proc.stdout.strip(), proc.stderr.strip()) if part
        )
        _write_json_atomic(CONFIG.status_path, {
            "status": "complete" if proc.returncode == 0 else "failed",
            "profile": profile,
            "inference": inference,
            "model_filename": model_filename,
            "requested_by": requested_by,
            "command": display,
            "exit_code": proc.returncode,
            "output_tail": _tail(output),
            "started_at": started,
            "finished_at": finished,
            "updated_at": finished,
        })
    except Exception as exc:
        finished = _now()
        _write_json_atomic(CONFIG.status_path, {
            "status": "failed",
            "profile": profile,
            "inference": inference,
            "model_filename": model_filename,
            "requested_by": requested_by,
            "command": display,
            "error": str(exc),
            "started_at": started,
            "finished_at": finished,
            "updated_at": finished,
        })


def _start_apply(payload: dict[str, Any], requested_by: str) -> tuple[dict[str, Any], int]:
    global _active_thread
    profile = str(payload.get("profile") or _current_profile())
    if profile not in VALID_PROFILES:
        return {"error": f"invalid profile: {profile}"}, 400
    inference = bool(payload.get("inference", False))
    try:
        model_filename = _validate_model_filename(payload.get("model_filename"))
    except ValueError as exc:
        return {"error": str(exc)}, 400

    with _state_lock:
        if _active_thread is not None and _active_thread.is_alive():
            return {"status": "already_in_progress", **_status()}, 409
        _active_thread = threading.Thread(
            target=_run_apply,
            kwargs={
                "profile": profile,
                "inference": inference,
                "model_filename": model_filename,
                "requested_by": requested_by,
            },
            daemon=True,
        )
        _active_thread.start()

    return {
        "status": "accepted",
        "profile": profile,
        "inference": inference,
        "model_filename": model_filename,
        "command": _display_command(profile, inference=inference),
    }, 202


class Handler(BaseHTTPRequestHandler):
    server_version = "SecAISandboxControl/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        expected = _read_token()
        header = self.headers.get("Authorization", "")
        supplied = header[7:] if header.startswith("Bearer ") else ""
        return bool(expected and supplied and hmac.compare_digest(expected, supplied))

    def _read_body(self) -> tuple[dict[str, Any], str | None]:
        raw_len = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_len)
        except ValueError:
            return {}, "invalid content length"
        if length > MAX_BODY_BYTES:
            return {}, "request too large"
        data = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(data.decode("utf-8") or "{}")
        except ValueError:
            return {}, "invalid json"
        if not isinstance(payload, dict):
            return {}, "json body must be an object"
        return payload, None

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json({"status": "ok", "controller": "secai-sandbox-control"})
            return
        if self.path == "/v1/status":
            if not self._authorized():
                self._send_json({"error": "unauthorized"}, 401)
                return
            self._send_json(_status())
            return
        self._send_json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        if self.path not in {"/v1/apply", "/v1/shutdown"}:
            self._send_json({"error": "not found"}, 404)
            return
        if not self._authorized():
            self._send_json({"error": "unauthorized"}, 401)
            return
        if self.path == "/v1/shutdown":
            self._send_json({"status": "stopping"})
            threading.Thread(target=_shutdown_server, daemon=True).start()
            return
        payload, error = self._read_body()
        if error:
            self._send_json({"error": error}, 400 if error != "request too large" else 413)
            return
        result, status = _start_apply(payload, requested_by=self.client_address[0])
        self._send_json(result, status)


def _shutdown_server() -> None:
    time.sleep(0.1)
    if _server is not None:
        _server.shutdown()


def _stop_existing(runtime_dir: Path, token_path: Path, host: str, port: int) -> int:
    try:
        token = token_path.read_text(encoding="utf-8").strip()
    except OSError:
        token = ""
    if token:
        req = urllib.request.Request(
            f"http://{host}:{port}/v1/shutdown",
            method="POST",
            headers={"Authorization": f"Bearer {token}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=2):
                pass
        except (urllib.error.URLError, TimeoutError):
            pass
    pid_path = runtime_dir / "control-server.pid"
    with contextlib.suppress(OSError):
        pid_path.unlink()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--runtime-dir", required=True)
    parser.add_argument("--token-path")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8498)
    parser.add_argument("--stop", action="store_true")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    runtime_dir = Path(args.runtime_dir).resolve()
    token_path = Path(args.token_path).resolve() if args.token_path else runtime_dir / "control-token"

    if args.stop:
        return _stop_existing(runtime_dir, token_path, args.host, args.port)

    global CONFIG, _server
    CONFIG = ControlConfig(repo_root, runtime_dir, token_path)
    CONFIG.pid_path.parent.mkdir(parents=True, exist_ok=True)
    CONFIG.pid_path.write_text(str(os.getpid()), encoding="utf-8")

    _server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        _server.serve_forever()
    finally:
        with contextlib.suppress(OSError):
            CONFIG.pid_path.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
