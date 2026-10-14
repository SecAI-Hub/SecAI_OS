"""Special-file reads must not occupy an agent worker waiting for a peer."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != "linux", reason="Linux FIFO and procfs checks required")
def test_fifo_read_without_writer_is_rejected_without_blocking(tmp_path):
    fifo = tmp_path / "waiting-for-writer"
    os.mkfifo(fifo, 0o600)
    program = """
import json, os, sys
from agent.agent.models import CapabilityToken
from agent.agent.storage import StorageGateway
path = sys.argv[1]
count = len(os.listdir('/proc/self/fd'))
result = StorageGateway().read_file(path, CapabilityToken(readable_paths=[path]))
assert len(os.listdir('/proc/self/fd')) == count
print(json.dumps(result))
"""
    # An owned, bounded child makes the pre-fix blocking open safe to reproduce.
    child = subprocess.run(
        [sys.executable, "-c", program, str(fifo)],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "PYTHONPATH": "services"},
        capture_output=True, text=True, timeout=5, check=True,
    )
    result = json.loads(child.stdout)
    assert result["ok"] is False
    assert "file not found" in result["error"]
