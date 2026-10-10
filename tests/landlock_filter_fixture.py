"""Fresh single-thread native seccomp/Landlock fixture; never imported by pytest."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import sys


def probe(library, calls, allowed, denied):
    libc = ctypes.CDLL(None, use_errno=True)
    seccomp = ctypes.CDLL(library, use_errno=True)
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
    seccomp.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    context = seccomp.seccomp_init(0x50000 | 1)
    for name in calls:
        number = seccomp.seccomp_syscall_resolve_name(name.encode())
        if number >= 0:
            assert seccomp.seccomp_rule_add(context, 0x7FFF0000, number, 0) == 0
    assert libc.prctl(38, 1, 0, 0, 0) == 0
    assert libc.prctl(39, 0, 0, 0, 0) == 1  # PR_GET_NO_NEW_PRIVS
    assert seccomp.seccomp_load(context) == 0
    # x86_64 and aarch64 are the appliance helper's explicit supported ABIs.
    abi = libc.syscall(444, None, 0, 1)
    assert abi > 0
    attr = ctypes.create_string_buffer(struct.pack("Q", 4))  # handle READ_FILE
    ruleset = libc.syscall(444, attr, 8, 0)
    assert ruleset >= 0
    descriptor = os.open(allowed, os.O_PATH | os.O_CLOEXEC)
    rule = ctypes.create_string_buffer(struct.pack("Qi", 4, descriptor))
    assert libc.syscall(445, ruleset, 1, rule, 0) == 0
    assert libc.syscall(446, ruleset, 0) == 0
    os.close(descriptor)
    os.close(ruleset)
    assert allowed.read_bytes() == b"synthetic"
    try:
        denied.read_bytes()
    except PermissionError:
        pass
    else:
        raise AssertionError("Landlock did not deny the ungranted sibling")

    return abi


def main():
    library, raw_calls, raw_allowed, raw_denied = sys.argv[1:]
    calls = json.loads(raw_calls)
    assert isinstance(calls, list) and all(isinstance(name, str) for name in calls)
    report = {
        "pid": os.getpid(), "session": os.getsid(0),
        "uid": os.getuid(), "gid": os.getgid(), "groups": os.getgroups(),
        "threads": len(list(Path("/proc/self/task").iterdir())),
        "calls_sha256": hashlib.sha256(raw_calls.encode()).hexdigest(),
        "capabilities": {key: value.strip() for key, value in
                         (line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
                         if key in {"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"}},
    }
    assert report["threads"] == 1 and report["session"] == report["pid"]
    report["landlock_abi"] = probe(library, calls, Path(raw_allowed), Path(raw_denied))
    report.update(no_new_privs=True, seccomp_loaded=True, allowed_read=True, sibling_denied=True)
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
