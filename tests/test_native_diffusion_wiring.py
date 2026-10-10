"""Native optional generation obeys the measured execution policy and runtime."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "files/scripts/secai-enable-diffusion.sh"


@pytest.fixture
def backend_selection(tmp_path):
    text = INSTALLER.read_text()
    code = text.split('# Step 2: Detect GPU backend', 1)[1].split(
        '# Validate backend exists in manifest', 1)[0]
    python = tmp_path / 'policy-reader'
    python.write_text(
        f'#!{sys.executable}\nimport os, sys\n'
        "assert sys.argv[1:] == ['/usr/libexec/secure-ai/apply-inference-model.py', 'gpu-layers', '-1']\n"
        "if os.environ['POLICY_RESPONSE'] == 'fail': sys.exit(1)\n"
        "print(os.environ['POLICY_RESPONSE'])\n"
    )
    python.chmod(0o700)
    lspci = tmp_path / 'lspci'
    lspci.write_text('#!/bin/sh\nprintf "NVIDIA device\\n"\n')
    lspci.chmod(0o700)
    script = ('_progress() { :; }\nrollback() { echo "$1" >&2; exit 23; }\n'
              + code + '\nprintf "selected=%s\\n" "$GPU_BACKEND"\n')

    def run(policy, override=''):
        env = {**os.environ, 'PYTHON_BIN': str(python), 'POLICY_RESPONSE': policy,
               'BACKEND_OVERRIDE': override, 'PATH': str(tmp_path) + os.pathsep + os.environ['PATH']}
        return subprocess.run(['bash', '-c', script], env=env, capture_output=True,
                              text=True, timeout=10, check=False)
    return run


@pytest.mark.parametrize('override', ['', 'cpu'])
def test_cpu_release_overrides_detected_nvidia(backend_selection, override):
    result = backend_selection('0', override)
    assert result.returncode == 0, result.stderr
    assert 'selected=cpu' in result.stdout


@pytest.mark.parametrize('override', ['cuda', 'rocm'])
def test_cpu_release_rejects_explicit_gpu_backend(backend_selection, override):
    result = backend_selection('0', override)
    assert result.returncode == 23
    assert 'CPU-only release' in result.stderr
    assert 'selected=' not in result.stdout


@pytest.mark.parametrize('response', ['fail', '', 'cuda', '00', '0\n-1'])
def test_missing_or_invalid_policy_never_reaches_backend(backend_selection, response):
    result = backend_selection(response)
    assert result.returncode == 23
    assert 'selected=' not in result.stdout


def test_gpu_release_preserves_explicit_cpu_choice(backend_selection):
    result = backend_selection('-1', 'cpu')
    assert result.returncode == 0, result.stderr
    assert 'selected=cpu' in result.stdout


def test_optional_sources_are_in_release_measurement(tmp_path):
    path = ROOT / 'files/scripts/generate-release-baseline.py'
    spec = importlib.util.spec_from_file_location('diffusion_baseline', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Execute the real enumerator against a filesystem containing only the
    # optional worker and shared policy client, rather than restating its roots.
    worker = tmp_path / 'usr/lib/secure-ai/services/diffusion-worker/app.py'
    worker.parent.mkdir(parents=True)
    worker.write_text('worker fixture\n')
    client = tmp_path / 'usr/lib/secure-ai/services/common/runtime_assurance.py'
    client.parent.mkdir()
    client.write_text('admission fixture\n')
    search = tmp_path / 'usr/lib/secure-ai/services/search-mediator/app.py'
    search.parent.mkdir()
    search.write_text('search fixture\n')
    module.Path = lambda value: tmp_path / str(value).lstrip('/')
    assert {worker, client, search} <= set(module.candidate_paths())


def test_native_unit_loads_separate_attestor_identity():
    unit = (ROOT / 'files/system/usr/lib/systemd/system/secure-ai-diffusion.service').read_text()
    assert 'Environment=SECURE_AI_DEPLOYMENT_MODE=appliance' in unit
    assert 'Environment=ATTESTOR_TOKEN_PATH=%d/attestor-token' in unit
    assert 'LoadCredential=attestor-token:/var/lib/secure-ai/credentials/runtime-attestor.token' in unit
    assert 'LoadCredential=service-token:/var/lib/secure-ai/credentials/diffusion.token' in unit
    assert 'Environment=ATTESTOR_TOKEN_PATH=%d/service-token' not in unit
