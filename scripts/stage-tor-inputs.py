#!/usr/bin/env python3
"""Stage only checksum-pinned, signed Tor source inputs; never install packages."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import tempfile
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

CONTRACT_ROOT = Path(__file__).resolve().parents[1] / "build/tor"
spec = importlib.util.spec_from_file_location("tor_source_verify", CONTRACT_ROOT / "verify.py")
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlsplit(newurl)
        if parsed.scheme != "https" or parsed.username or parsed.password:
            raise ValueError("source download redirected outside HTTPS")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def stage_inputs(output: Path, offline_cache: Path | None = None) -> dict:
    lock, raw = verify.load_contract(CONTRACT_ROOT / "source.lock.json")
    if output.exists() or output.is_symlink():
        raise ValueError("staging destination already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + 300
    opener = urllib.request.build_opener(HTTPSRedirect()) if offline_cache is None else None
    with tempfile.TemporaryDirectory(prefix=".tor-stage-", dir=output.parent) as temporary:
        stage = Path(temporary) / "inputs"
        stage.mkdir(mode=0o755)
        for name, row in lock["remote_inputs"].items():
            if offline_cache is not None:
                data = verify.check_input(offline_cache / name, row)
            else:
                with opener.open(row["url"], timeout=min(45, max(1, deadline - time.monotonic()))) as response:
                    if urlsplit(response.url).scheme != "https":
                        raise ValueError("source download is not HTTPS")
                    chunks, size = [], 0
                    while True:
                        if time.monotonic() >= deadline:
                            raise ValueError("source staging deadline exceeded")
                        chunk = response.read(min(1 << 20, row["bytes"] + 1 - size))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        size += len(chunk)
                        if size > row["bytes"]:
                            raise ValueError("source download exceeds pinned size")
                    data = b"".join(chunks)
                if len(data) != row["bytes"] or verify.digest(data) != row["sha256"]:
                    raise ValueError("source download checksum mismatch: " + name)
            (stage / name).write_bytes(data)
        for name, row in lock["local_inputs"].items():
            data = verify.check_input(CONTRACT_ROOT / row["path"], row)
            (stage / name).write_bytes(data)
        (stage / "source.lock.json").write_bytes(raw)
        manifest = {"schema_version": 1, "version": lock["version"], "contract_sha256": verify.digest(raw), "inputs": {p.name: {"sha256": verify.digest(p.read_bytes()), "bytes": p.stat().st_size} for p in sorted(stage.iterdir())}}
        (stage / "TOR_SOURCE_MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        verify.verify_stage(stage, CONTRACT_ROOT / "source.lock.json")
        for path in stage.iterdir():
            path.chmod(0o444)
        os.rename(stage, output)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(".source-prep/tor"))
    parser.add_argument("--offline-cache", type=Path, help="Require all exact approved inputs from this local cache; no network fallback")
    args = parser.parse_args()
    manifest = stage_inputs(args.output, args.offline_cache)
    print(json.dumps({"output": str(args.output), "version": manifest["version"], "contract_sha256": manifest["contract_sha256"], "inputs": len(manifest["inputs"])}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, OSError, TimeoutError) as error:
        raise SystemExit("Tor input staging failed: " + str(error))
