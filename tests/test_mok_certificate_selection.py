"""Review-pinned module certificates cannot change between validation and import."""

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "files/system/usr/libexec/secure-ai/enroll-secureboot.sh"
SOURCE = SCRIPT.read_text()
STAGING = SOURCE.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
MAIN = SOURCE.split("# --- Main ---\n", 1)[1]


@pytest.fixture(scope="module")
def certificate_bytes(tmp_path_factory):
    if not shutil.which("openssl"):
        pytest.skip("OpenSSL unavailable")
    root = tmp_path_factory.mktemp("public-certificate")
    cert = root / "public.der"
    result = subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                             "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
                             "-subj", "/CN=SecAI-test-fixture", "-keyout", str(root / "fixture.key"),
                             "-outform", "DER", "-out", str(cert)],
                            capture_output=True, timeout=5, check=False)
    assert result.returncode == 0
    return cert.read_bytes()


def stage(path, digest, *, root_owned=True, env=None):
    # Exercise the product's original Python body with root metadata simulated
    # only in this subprocess. No firmware or privileged operation is performed.
    preamble = '''
import os
from types import SimpleNamespace
os.geteuid = lambda: 0
original_fstat = os.fstat
def fixture_fstat(descriptor):
    actual = original_fstat(descriptor)
    value = {key: getattr(actual, key) for key in
             ("st_mode", "st_uid", "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")}
    value["st_uid"] = 0
    return SimpleNamespace(**value)
'''
    if root_owned:
        preamble += "os.fstat = fixture_fstat\n"
    return subprocess.run([sys.executable, "-c", preamble + STAGING, str(path), digest],
                          env={**os.environ, **(env or {})}, capture_output=True,
                          text=True, timeout=8, check=False)


def test_staged_cert_is_exact_and_survives_source_replacement(tmp_path, certificate_bytes):
    source = tmp_path / "source.der"
    source.write_bytes(certificate_bytes)
    source.chmod(0o644)
    result = stage(source, hashlib.sha256(certificate_bytes).hexdigest(),
                   env={"TMPDIR": str(tmp_path / "untrusted-temp")})
    assert result.returncode == 0, result.stderr
    staged = Path(result.stdout.strip())
    try:
        assert str(staged).startswith("/tmp/secai-mok-")
        assert staged.parent.stat().st_mode & 0o777 == 0o700
        assert staged.stat().st_mode & 0o777 == 0o400
        source.unlink()
        source.write_bytes(b"replacement")
        assert staged.read_bytes() == certificate_bytes
    finally:
        staged.unlink()
        staged.parent.rmdir()


@pytest.mark.parametrize("kind", ["hash", "symlink", "writable", "not_root", "private_or_invalid",
                                  "trailing_data", "oversized", "noncanonical_hash"])
def test_unsafe_or_unpinned_certificate_never_stages(tmp_path, certificate_bytes, kind):
    path = tmp_path / "certificate.der"
    data = certificate_bytes
    if kind == "private_or_invalid":
        data = b"not a public certificate"
    elif kind == "trailing_data":
        data += b"extra data"
    elif kind == "oversized":
        data = b"x" * 131073
    path.write_bytes(data)
    path.chmod(0o644)
    digest = hashlib.sha256(data).hexdigest()
    if kind == "hash":
        digest = "0" * 64
    elif kind == "noncanonical_hash":
        digest = "X" * 64
    elif kind == "writable":
        path.chmod(0o666)
    elif kind == "symlink":
        target = tmp_path / "target.der"
        path.rename(target)
        path.symlink_to(target)
    result = stage(path, digest, root_owned=kind != "not_root")
    assert result.returncode != 0
    assert result.stdout == ""


@pytest.mark.parametrize("args", [
    ["--certificate"], ["--certificate", "/tmp/cert.der"], ["--sha256", "a" * 64],
    ["--sha256", "bad"], ["--certificate", "relative.der", "--sha256", "a" * 64],
    ["--check-only", "--enroll"], ["--enroll", "unexpected"],
])
def test_bad_certificate_cli_never_dispatches_enrollment(args):
    stubs = '''
set -euo pipefail
cmd_check() { echo DISPATCHED; }
cmd_enroll() { echo DISPATCHED; }
stage_reviewed_certificate() { echo DISPATCHED; return 1; }
'''
    result = subprocess.run(["bash", "-c", stubs + MAIN, "enroll-secureboot", *args],
                            capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode != 0
    assert "DISPATCHED" not in result.stdout


def test_enrollment_uses_staged_cert_and_cleans_it(tmp_path):
    directory = tmp_path / "owned-stage"
    directory.mkdir(mode=0o700)
    cert = directory / "certificate.der"
    cert.write_bytes(b"public fixture")
    stubs = '''
set -euo pipefail
stage_reviewed_certificate() { printf '%s\\n' "$TEST_STAGE/certificate.der"; }
cmd_check() { exit 99; }
cmd_enroll() { printf 'IMPORT %s\\n' "$MOK_DER"; }
'''
    result = subprocess.run(["bash", "-c", stubs + MAIN, "enroll-secureboot",
                             "--enroll", "--certificate", "/reviewed/release.der", "--sha256", "a" * 64],
                            env={**os.environ, "TEST_STAGE": str(directory)}, capture_output=True,
                            text=True, timeout=5, check=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"IMPORT {cert}"
    assert not directory.exists()
