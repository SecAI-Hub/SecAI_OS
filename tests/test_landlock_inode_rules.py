"""Opened-inode rule masks and real Linux fail-closed confinement."""
import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

SOURCE = Path(__file__).resolve().parents[1] / "files/system/usr/libexec/secure-ai/landlock-apply.py"


def module():
    spec = importlib.util.spec_from_file_location("landlock_inode", SOURCE)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


@pytest.mark.parametrize("abi", [1, 2, 3, 4, 5, 8])
@pytest.mark.parametrize("mode", ["ro", "rw", "exe"])
def test_inode_mask_only_removes_directory_rights(abi, mode):
    loaded = module()
    requested = loaded._access_for_mode(mode, abi) & loaded._handled_access_for_abi(abi)
    assert loaded._access_for_inode(mode, stat.S_IFDIR, abi) == requested
    file_mask = (loaded.LANDLOCK_ACCESS_FS_EXECUTE | loaded.LANDLOCK_ACCESS_FS_READ_FILE
                 | loaded.LANDLOCK_ACCESS_FS_WRITE_FILE | loaded.LANDLOCK_ACCESS_FS_TRUNCATE
                 | loaded.LANDLOCK_ACCESS_FS_IOCTL_DEV)
    for inode in (stat.S_IFREG, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK):
        assert loaded._access_for_inode(mode, inode, abi) == requested & file_mask
    assert not loaded._access_for_inode(mode, stat.S_IFREG, abi) & loaded.LANDLOCK_ACCESS_FS_READ_DIR


def test_real_file_directory_permissions_and_required_failure(tmp_path):
    loaded = module()
    if not loaded.check_landlock_available():
        pytest.skip("kernel Landlock unavailable")
    ro = tmp_path / "read-only"
    ro.write_text("synthetic")
    rw = tmp_path / "writable"
    rw.mkdir()
    secret = tmp_path / "outside"
    secret.write_text("unrelated synthetic")
    executable = tmp_path / "no-execute"
    executable.write_bytes(Path("/usr/bin/true").read_bytes())
    executable.chmod(0o755)
    policy = tmp_path / "policy.yaml"
    paths = [{"path": str(ro), "access": "ro", "required": True},
             {"path": str(rw), "access": "rw", "required": True},
             {"path": str(executable), "access": "ro", "required": True}]
    # Runtime executable and libraries only support this isolated test process.
    paths += [{"path": str(Path(sys.base_prefix).resolve()), "access": "exe"},
              {"path": "/usr", "access": "exe"}]
    policy.write_text(yaml.safe_dump({"services": {"probe": {"include_common_paths": False, "paths": paths}}}))
    code = '''import importlib.util,json,os,pathlib,subprocess,sys
spec=importlib.util.spec_from_file_location('ll',sys.argv[1]);ll=importlib.util.module_from_spec(spec);spec.loader.exec_module(ll)
assert ll.apply_landlock('probe')
ro,rw,secret,executable=map(pathlib.Path,sys.argv[2:])
assert ro.read_text()=='synthetic'
(rw/'new').write_text('allowed');assert (rw/'new').read_text()=='allowed';(rw/'new').unlink()
for operation in (lambda: ro.write_text('denied'),lambda: secret.read_text(),lambda: subprocess.run([str(executable)],check=True)):
 try: operation()
 except PermissionError: pass
 else: raise AssertionError('out-of-policy access permitted')
print(json.dumps({'confinement':'pass'}))
'''
    result = subprocess.run([sys.executable, "-c", code, str(SOURCE), str(ro), str(rw), str(secret), str(executable)],
                            env={**os.environ, "LANDLOCK_POLICY_PATH": str(policy)},
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"confinement": "pass"}
    paths.append({"path": str(tmp_path / "missing-required"), "access": "ro", "required": True})
    policy.write_text(yaml.safe_dump({"services": {"probe": {"include_common_paths": False, "paths": paths}}}))
    refused = subprocess.run([sys.executable, str(SOURCE), "--require", "probe", "--", "/usr/bin/true"],
                             env={**os.environ, "LANDLOCK_POLICY_PATH": str(policy)},
                             capture_output=True, text=True, timeout=10)
    assert refused.returncode != 0 and "refusing" in refused.stderr
