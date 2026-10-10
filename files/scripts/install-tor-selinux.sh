#!/usr/bin/env bash
# Build-root only: never reload the build host's running SELinux policy.
set -euo pipefail

tor_policy_store=/etc/selinux
tor_policy_file=/usr/share/selinux/packages/secure-ai-tor.cil

[[ "${EUID}" -eq 0 ]] || { echo 'Tor policy installation requires the image build root' >&2; exit 1; }
[[ ! -e /run/ostree-booted ]] || { echo 'Refusing to change a booted OSTree deployment' >&2; exit 1; }
/usr/bin/python3 - <<'PY'
from pathlib import Path
import shlex
import stat

values = {}
for line in Path('/etc/os-release').read_text().splitlines():
    if '=' in line:
        key, value = line.split('=', 1)
        words = shlex.split(value)
        values[key] = words[0] if words else ''
if values.get('ID') != 'fedora' or values.get('VERSION_ID') != '44':
    raise SystemExit('Tor policy requires the reviewed Fedora 44 image base')
config = [line.replace(' ', '') for line in Path('/etc/selinux/semanage.conf').read_text().splitlines() if not line.lstrip().startswith('#')]
if 'store-root=/etc/selinux' not in config:
    raise SystemExit('Unexpected SELinux store; refusing a mutable /var-store fallback')
store = Path('/etc/selinux/targeted/active/modules')
if not store.is_dir() or store.is_symlink():
    raise SystemExit('The image SELinux module store is unavailable')
policy = Path('/usr/share/selinux/packages/secure-ai-tor.cil')
info = policy.lstat()
if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
    raise SystemExit('The packaged Tor policy must be a protected root-owned file')
PY

/usr/sbin/semodule --noreload --store targeted --store-path "${tor_policy_store}" --install "${tor_policy_file}"

/usr/bin/python3 - <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess

contexts = Path('/etc/selinux/targeted/contexts/files/file_contexts')
expected = {
    '/etc/secure-ai/tor/torrc': 'tor_etc_t',
    '/var/lib/secure-ai/tor/state': 'tor_var_lib_t',
    '/var/lib/secure-ai/logs/tor.log': 'tor_var_log_t',
    '/etc/secure-ai/tor-other/test': 'etc_t',
    '/var/lib/secure-ai/tor-other/state': 'var_lib_t',
    '/var/lib/secure-ai/logs/torXlog': 'var_lib_t',
    '/var/lib/secure-ai/logs/tor.log.extra': 'var_lib_t',
}
matches = {}
for path, wanted in expected.items():
    label = subprocess.check_output(['/usr/sbin/matchpathcon', '-n', '-f', str(contexts), path], text=True).strip()
    if label.split(':')[2] != wanted:
        raise SystemExit('Tor file-context boundary does not match the packaged policy')
    matches[path] = label
files = [Path('/usr/share/selinux/packages/secure-ai-tor.cil'), contexts]
files.extend(sorted(Path('/etc/selinux/targeted/policy').glob('policy.[0-9]*')))
if len(files) < 3:
    raise SystemExit('Compiled image policy is unavailable')
report = {'store_root': '/etc/selinux', 'kernel_policy_reloaded': False,
          'sha256': {str(path): hashlib.file_digest(path.open('rb'), 'sha256').hexdigest() for path in files},
          'contexts': matches}
Path('/usr/share/selinux/packages/secure-ai-tor-build.json').write_text(json.dumps(report, indent=2) + '\n')
print('Tor policy installed into the image store without a kernel reload')
PY
