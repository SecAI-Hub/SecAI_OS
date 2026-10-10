"""Guard the native/container launch contract that the live smoke exercises."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_native_search_installs_its_flat_entrypoint_and_worker_modules():
    builder = (ROOT / "files/scripts/build-services.sh").read_text()
    block = builder.split("SEARCH_DIR=", 1)[1].split("# Hugging Face", 1)[0]
    assert '"/tmp/services/search-mediator"' in block
    assert "/tmp/upstreams" not in block
    assert '"${SRC_DIR}/llm-search-mediator/"*.py' in block
    assert "app:app" in block and "search_mediator.app:app" not in block
    for name in ("search_transport.py", "search_boundary.py", "search_privacy.py"):
        assert (ROOT / "services/search-mediator" / name).is_file()


def test_search_launchers_preserve_single_writer_and_private_access_logs():
    builder = (ROOT / "files/scripts/build-services.sh").read_text()
    block = builder.split("SEARCH_DIR=", 1)[1].split("# Hugging Face", 1)[0]
    container = (ROOT / "services/search-mediator/entrypoint.py").read_text()
    sandbox = (ROOT / "scripts/sandbox/search-mediator-entrypoint.sh").read_text()
    for launcher in (block, container, sandbox):
        assert "--no-control-socket" in launcher
        assert "%(m)s %(s)s %(L)s" in launcher
    assert "--workers 1" in block and "--workers 1" in sandbox
    assert '"--workers",\n        "1"' in container
    system = ROOT / "files/system/usr/lib"
    unit = (system / "systemd/system/secure-ai-search-mediator.service").read_text()
    assert "User=secure-ai-search" in unit
    assert "UMask=0077" in unit
    assert "u secure-ai-search " in (system / "sysusers.d/secure-ai.conf").read_text()
    assert "search-audit.jsonl 0660 secure-ai-search secure-ai-logs" in (system / "tmpfiles.d/secure-ai.conf").read_text()


def test_seccomp_permits_deadline_worker_and_durable_audit_lifecycle():
    policy = json.loads((ROOT / "files/system/etc/secure-ai/seccomp/search-mediator.json").read_text())
    allowed = {name for rule in policy["syscalls"] if rule["action"] == "SCMP_ACT_ALLOW" for name in rule["names"]}
    assert policy["defaultAction"] == "SCMP_ACT_ERRNO"
    assert {"execve", "wait4", "kill", "chdir", "uname", "utimensat", "fchmod", "mkdir", "rename", "unlink", "fsync"} <= allowed
    assert not {"mount", "ptrace", "bpf", "setns"} & allowed
