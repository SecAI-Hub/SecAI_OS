"""Native unit syscall filters must permit their required Landlock boundary."""
import ctypes
import ctypes.util
import functools
import inspect
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading

import pytest

ROOT = Path(__file__).resolve().parents[1]
UNITS = ROOT / "files/system/usr/lib/systemd/system"
CALLS = {"landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self"}


def restrict_suid_sgid():
    """Native-architecture mode checks from systemd255 seccomp_restrict_sxid."""
    class Compare(ctypes.Structure):
        _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int),
                    ("mask", ctypes.c_uint64), ("value", ctypes.c_uint64)]
    library = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    library.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                              ctypes.c_uint, ctypes.POINTER(Compare)]
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    context = library.seccomp_init(0x7FFF0000)
    for name, mode_arg in {"chmod": 1, "fchmod": 1, "fchmodat": 2, "fchmodat2": 2,
                           "mkdir": 1, "mkdirat": 2, "mknod": 1, "mknodat": 2, "creat": 1,
                           "open": 2, "openat": 3}.items():
        number = library.seccomp_syscall_resolve_name(name.encode())
        if number < 0:
            continue
        for bit in (0o4000, 0o2000):
            comparisons = [Compare(mode_arg, 7, bit, bit)]  # SCMP_CMP_MASKED_EQ
            if name in {"open", "openat"}:
                comparisons.append(Compare(mode_arg - 1, 7, os.O_CREAT, os.O_CREAT))
            values = (Compare * len(comparisons))(*comparisons)
            assert library.seccomp_rule_add_array(context, 0x50000 | 1, number, len(comparisons), values) == 0
    number = library.seccomp_syscall_resolve_name(b"openat2")
    if number >= 0:
        assert library.seccomp_rule_add_array(context, 0x50000 | 38, number, 0, None) == 0
    assert ctypes.CDLL(None).prctl(38, 1, 0, 0, 0) == 0
    assert library.seccomp_load(context) == 0


def test_catalog_and_state_creation_under_restrict_suid_sgid(tmp_path):
    if not sys.platform.startswith("linux") or not ctypes.util.find_library("seccomp"):
        pytest.skip("Linux libseccomp required")
    code = "import ctypes,os,hashlib,sys\nfrom pathlib import Path\n" + inspect.getsource(restrict_suid_sgid) + '''
from common.bounded_state import BoundedState
from ui import catalog
root=Path(sys.argv[1]);incoming=root/'incoming';incoming.mkdir();incoming.chmod(0o2770)
restrict_suid_sgid()
for action in (lambda: os.mkdir(root/'forbidden',0o2770),lambda: incoming.chmod(0o2770)):
    try: action()
    except PermissionError: pass
    else: raise AssertionError('RestrictSUIDSGID negative control did not deny')
store=BoundedState(root/'state/value.json',lambda:{'value':0},lambda state:None,max_bytes=100)
with store.transaction(write=True) as state: state['value']=1
class Response:
    headers={'content-length':'3'}
    def iter_content(self,**kwargs): yield b'abc'
    def close(self): pass
url='https://huggingface.co/synthetic/fixture';revision='a'*40
files=[{'path':'nested/model.safetensors','size':3,'oid_type':'sha256','oid':hashlib.sha256(b'abc').hexdigest()}]
selected,variant=catalog._select_diffusion_repo_files(files)
manifest=catalog._huggingface_manifest_payload(source_url=url,repo_id='synthetic/fixture',revision=revision,variant=variant,files=selected)
entry={'expected_revision':revision,'expected_size_bytes':3,'expected_manifest_sha256':catalog._canonical_manifest_sha256(manifest)}
transfer=catalog.Transfer(incoming,response=lambda url:Response(),fetch=None,check=lambda *a,**k:(True,200,''),progress=lambda *a,**k:None,manage_cleanup=False)
transfer._huggingface_tree=lambda *a,**k:files
transfer._download_diffusion_model(url,'synthetic',catalog_entry=entry)
assert (incoming/'synthetic/nested/model.safetensors').read_bytes()==b'abc'
assert (incoming/'synthetic').stat().st_mode & 0o2000
'''
    result = subprocess.run([sys.executable, "-c", code, str(tmp_path)],
                            env={**os.environ, "PYTHONPATH": str(ROOT / "services") + ":" + str(ROOT / "services/ui")},
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_required_native_landlock_units_explicitly_allow_initialization():
    checked = []
    for path in sorted(UNITS.glob("*.service")):
        source = path.read_text()
        if "landlock-apply.py --require" not in source:
            continue
        lines = re.findall(r"^SystemCallFilter=([^~].*)$", source, re.M)
        if not lines:
            continue
        assert CALLS <= set(" ".join(lines).split()), path.name
        checked.append(path.name)
    assert len(checked) == 14


@functools.lru_cache(maxsize=None)
def expand(group):
    output = subprocess.check_output(["systemd-analyze", "syscall-filter", group], text=True,
                                     env={**os.environ, "SYSTEMD_COLORS": "0"})
    result = set()
    for line in output.splitlines()[1:]:
        line = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
        if line and not line.startswith("#"):
            result.update(expand(line) if line.startswith("@") else {line})
    return result


def effective(source):
    result = set()
    for line in re.findall(r"^SystemCallFilter=(.+)$", source, re.M):
        names = set().union(*(expand(part) if part.startswith("@") else {part}
                              for part in line.lstrip("~").split()))
        result = result - names if line.startswith("~") else result | names
    return result


def test_every_distinct_effective_filter_initializes_and_enforces_landlock(tmp_path):
    if (not sys.platform.startswith("linux") or os.uname().machine not in {"x86_64", "aarch64"}
            or not shutil.which("systemd-analyze") or not ctypes.util.find_library("seccomp")):
        pytest.skip("native syscall-filter qualification requires Linux systemd/libseccomp")
    allowed, denied = tmp_path / "allowed", tmp_path / "denied"
    allowed.write_bytes(b"synthetic")
    denied.write_bytes(b"synthetic")
    groups = {}
    for path in sorted(UNITS.glob("*.service")):
        source = path.read_text()
        if "landlock-apply.py --require" in source and "SystemCallFilter=" in source:
            groups.setdefault(frozenset(effective(source)), []).append(path.name)
    assert groups
    for calls, names in groups.items():
        assert CALLS <= calls, names
        raw_calls = json.dumps(sorted(calls))
        result = subprocess.run(
            [sys.executable, "-I", str(Path(__file__).with_name("landlock_filter_fixture.py")),
             ctypes.util.find_library("seccomp"), raw_calls, str(allowed), str(denied)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            start_new_session=True, timeout=10,
        )
        assert result.returncode == 0, (names, result.stdout, result.stderr)
        report = json.loads(result.stdout)
        assert report["threads"] == 1 and report["session"] == report["pid"]
        assert (report["uid"], report["gid"], report["groups"]) == (os.getuid(), os.getgid(), os.getgroups())
        capabilities = {key: value.strip() for key, value in
                        (line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
                        if key in {"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"}}
        assert report["capabilities"] == capabilities
        assert report["calls_sha256"] == hashlib.sha256(raw_calls.encode()).hexdigest()
        assert report["landlock_abi"] > 0
        assert all(report[key] for key in ("no_new_privs", "seccomp_loaded", "allowed_read", "sibling_denied"))


def test_native_filters_from_threaded_caller_without_fork(tmp_path, monkeypatch):
    release = threading.Event()
    thread = threading.Thread(target=release.wait, daemon=True)
    thread.start()
    try:
        def forbidden_fork():
            pytest.fail("native filter fixtures must not fork their threaded caller")
        monkeypatch.setattr(os, "fork", forbidden_fork)
        test_every_distinct_effective_filter_initializes_and_enforces_landlock(tmp_path)
        assert thread.is_alive()
    finally:
        release.set()
        thread.join(5)
        assert not thread.is_alive()
