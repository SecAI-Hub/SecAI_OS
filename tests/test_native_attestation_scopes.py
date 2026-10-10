"""Exercise the installed shell gate's schema/scope predicate with private peers."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT/'files/system/usr/libexec/secure-ai/attestation-gate.sh'


@pytest.mark.parametrize('scope,change,accepted', [
    ('bootstrap', {}, True), ('runtime', {}, True),
    ('bootstrap', {'verification_scope': 'runtime'}, False),
    ('runtime', {'verification_scope': 'bootstrap'}, False),
    ('runtime', {'schema_version': 1}, False),
    ('runtime', {'gpu_policy_satisfied': False}, False),
    ('runtime', {'gpu_mode': 'auto'}, False),
    ('runtime', {'policy_satisfied': False}, False),
    ('runtime', {'assurance_mode': 'hardware'}, False),
    ('runtime', {'assurance_mode': 'hardware', 'verified': True, 'evidence_verified': True}, True),
])
def test_native_gate_requires_exact_approved_scope(tmp_path, scope, change, accepted):
    if not shutil.which('jq'):
        pytest.skip('native jq unavailable')
    peer = tmp_path/'bin'
    peer.mkdir()
    scripts = {'curl': '#!/bin/sh\ncat >/dev/null\ncat "$GATE_REPLY"\n',
               'seq': '#!/bin/sh\nprintf "1\\n"\n', 'sleep': '#!/bin/sh\nexit 0\n'}
    for name, source in scripts.items():
        path = peer/name
        path.write_text(source)
        path.chmod(0o700)
    token = tmp_path/'token'
    token.write_text('a'*64)
    token.chmod(0o600)
    response = tmp_path/'response.json'
    response.write_text(json.dumps({'schema_version': 2, 'verification_scope': scope,
                                   'gpu_mode': 'no_gpu', 'gpu_policy_satisfied': True,
                                   'policy_satisfied': True, 'assurance_mode': 'evaluation',
                                   'verified': False, 'evidence_verified': False, **change}))
    result = subprocess.run(['bash', str(GATE), str(token), scope],
                            env={**os.environ, 'PATH': str(peer)+':/usr/bin:/bin', 'GATE_REPLY': str(response)},
                            capture_output=True, timeout=5, check=False)
    assert (result.returncode == 0) is accepted, result.stderr.decode()
