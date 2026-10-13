"""Exercise the installed shell gate's schema/scope predicate with private peers."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT/'files/system/usr/libexec/secure-ai/attestation-gate.sh'


def test_native_gpu_bootstrap_uses_dedicated_service_port():
    config = ROOT / 'files/system/etc/secure-ai'
    policy = yaml.safe_load((config / 'policy/attestation.yaml').read_text())
    bootstrap = yaml.safe_load((config / 'gpu-integrity/bootstrap-profile.yaml').read_text())
    runtime = yaml.safe_load((ROOT / 'services/gpu-integrity-watch/profiles/default-profile.yaml').read_text())
    profile = json.loads((config / 'config/service-profile.json').read_text())
    bootstrap_address = bootstrap['daemon']['bind_addr']
    assert policy['gpu']['bootstrap']['origin'] == f'http://{bootstrap_address}'
    assert policy['gpu']['runtime']['origin'] == f"http://{runtime['daemon']['bind_addr']}"
    # Both daemons must coexist with the declared native control-plane services.
    occupied = {item['health_url'].split('/')[2] for item in profile['services']
                if item['health_url'].startswith('http://')}
    assert bootstrap_address not in occupied
    assert bootstrap_address != runtime['daemon']['bind_addr']
    mcp_unit = (ROOT / 'files/system/usr/lib/systemd/system/secure-ai-mcp-firewall.service').read_text()
    assert f'Environment=BIND_ADDR={bootstrap_address}\n' not in mcp_unit


def test_rtx5080_profiles_require_exact_supported_probe_coverage():
    config = ROOT / 'files/system/etc/secure-ai'
    policy = yaml.safe_load((config / 'policy/attestation.yaml').read_text())
    assert policy['gpu']['mode'] == 'required'
    paths = {'bootstrap': config / 'gpu-integrity/bootstrap-profile.yaml',
             'runtime': ROOT / 'services/gpu-integrity-watch/profiles/default-profile.yaml'}
    for scope, path in paths.items():
        probes = yaml.safe_load(path.read_text())['probes']
        enabled = {probe['name']: probe['type'] for probe in probes if probe['enabled']}
        assert enabled == policy['gpu'][scope]['required_probes']
        assert 'ecc-status' not in enabled
        assert enabled['driver-fingerprint'] == 'driver_fingerprint'
        assert enabled['device-allowlist'] == 'device_allowlist'
        driver = next(probe for probe in probes if probe['name'] == 'driver-fingerprint')
        assert driver['settings'] == {'driver_version_path': '/sys/module/nvidia/version', 'kernel_module': 'nvidia'}
        # Observing the Ubuntu development GPU is never Fedora release approval.
        assert policy['gpu'][scope]['profile_sha256'] == ''
        assert policy['gpu'][scope]['baseline_sha256'] == ''
    assert policy['gpu']['runtime']['required_probes']['tensor-hash-check'] == 'tensor_hash'
    assert policy['gpu']['runtime']['required_probes']['sentinel-inference'] == 'sentinel_inference'


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
