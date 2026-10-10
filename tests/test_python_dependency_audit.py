"""Regression tests for backend-local Python advisory coverage."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AUDIT_SCRIPT = REPO_ROOT / ".github" / "scripts" / "audit-python-deps.py"
SPEC = importlib.util.spec_from_file_location("audit_python_deps", AUDIT_SCRIPT)
assert SPEC and SPEC.loader
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def test_local_torch_versions_are_audited_as_canonical_releases(tmp_path):
    lock = tmp_path / "diffusion.lock"
    lock.write_text(
        "--index-url https://pypi.org/simple\n"
        "--find-links https://download.pytorch.org/whl/cu129/torch/\n"
        "torch==2.13.0+cu129 \\\n"
        "    --hash=sha256:" + "a" * 64 + "\n"
        "    # via test\n"
        "torchvision==0.28.0+cu129 \\\n"
        "    --hash=sha256:" + "b" * 64 + "\n"
        "    # via test\n"
        "urllib3==2.7.0 \\\n"
        "    --hash=sha256:" + "c" * 64 + "\n",
        encoding="utf-8",
    )

    original = lock.read_bytes()
    expected = AUDIT.expected_requirements(lock, frozenset({"torch", "torchvision"}))
    assert expected == {"torch": "2.13.0", "torchvision": "0.28.0", "urllib3": "2.7.0"}
    assert lock.read_bytes() == original


def _lock(tmp_path, entries=("setuptools==84.0.0", "wheel==0.48.0"), name="test.lock"):
    path = tmp_path / name
    path.write_text("\n".join(f"{entry} --hash=sha256:{'a' * 64}" for entry in entries) + "\n")
    return path


def _report():
    return {"dependencies": [
        {"name": "setuptools", "version": "84.0.0", "vulns": []},
        {"name": "wheel", "version": "0.48.0", "vulns": []},
    ]}


@pytest.mark.parametrize("name,selected", [
    ("test.lock", "linux-old"), ("diffusion-cpu-py314.lock", "linux-new"),
    ("requirements-windows-sandbox.lock", "windows"),
])
def test_markers_use_lock_target_not_auditor_host(tmp_path, name, selected):
    path = _lock(tmp_path, (
        'linux-old==1.0; sys_platform == "linux" and python_version < "3.14"',
        'linux-new==2.0; sys_platform == "linux" and python_full_version == "3.14.8"',
        'windows==3.0; sys_platform == "win32" and platform_machine == "AMD64"',
    ), name)
    expected = AUDIT.expected_requirements(path)
    assert list(expected) == [selected]


@pytest.mark.parametrize("entry", [
    "thing>=1.0", "thing==1.*", "thing[extra]==1.0",
    "thing @ https://example.com/arbitrary.whl", "thing==1.0+unmapped",
    'thing==1.0; platform_release == "6.0"', '-r other.lock',
    "--extra-index-url https://unreviewed.invalid/", "thing==broken",
])
def test_unbounded_or_unsupported_lock_entries_fail(tmp_path, entry):
    with pytest.raises(ValueError):
        AUDIT.expected_requirements(_lock(tmp_path, (entry,)))


def test_missing_hash_and_duplicate_selected_names_fail(tmp_path):
    path = tmp_path / "nohash.lock"
    path.write_text("setuptools==84.0.0\n")
    with pytest.raises(ValueError, match="hash"):
        AUDIT.expected_requirements(path)
    with pytest.raises(ValueError, match="duplicate"):
        AUDIT.expected_requirements(_lock(tmp_path, ("Some_Name==1.0", "some-name==1.0")))


def test_inactive_local_mapping_does_not_drop_marker_or_claim_coverage(tmp_path):
    path = _lock(tmp_path, ('torch==2.13.0+cu129; sys_platform == "win32"', 'wheel==0.48.0'))
    assert AUDIT.expected_requirements(path, frozenset({"torch"})) == {"wheel": "0.48.0"}
    with pytest.raises(ValueError, match="missing"):
        AUDIT.expected_requirements(path, frozenset({"torch", "triton-rocm"}))
    with pytest.raises(ValueError, match="duplicate"):
        AUDIT.expected_requirements(_lock(tmp_path, ("triton-rocm==3.7.1", "triton==3.7.1")),
                                    frozenset({"triton-rocm"}))


@pytest.mark.parametrize("mutation", [
    "empty", "wrong-root", "omitted", "extra", "duplicate", "wrong-version",
    "skipped", "bad-vulns", "bad-dep", "bad-version", "bad-name", "bad-vuln-id",
])
def test_report_must_prove_every_exact_pair(mutation):
    data = _report()
    if mutation == "empty":
        data = {}
    elif mutation == "wrong-root":
        data = []
    elif mutation == "omitted":
        data["dependencies"].pop()
    elif mutation == "extra":
        data["dependencies"].append({"name": "unexpected", "version": "1", "vulns": []})
    elif mutation == "duplicate":
        data["dependencies"].append(data["dependencies"][0])
    elif mutation == "bad-dep":
        data["dependencies"][0] = None
    else:
        field, value = {
            "wrong-version": ("version", "83.0.0"), "skipped": ("skip_reason", "unavailable"),
            "bad-vulns": ("vulns", None), "bad-version": ("version", "invalid"),
            "bad-name": ("name", "bad/name"), "bad-vuln-id": ("vulns", [{"id": ""}]),
        }[mutation]
        data["dependencies"][0][field] = value
    with pytest.raises(ValueError):
        AUDIT.validate_coverage(data, {"setuptools": "84.0.0", "wheel": "0.48.0"}, 0)


@pytest.mark.parametrize("code,findings,valid", [(0, False, True), (1, True, True),
                                              (1, False, False), (0, True, False),
                                              (2, False, False), (2, True, False)])
def test_exit_status_must_agree_with_findings(code, findings, valid):
    data = _report()
    if findings:
        data["dependencies"][0]["vulns"] = [{"id": "TEST-1", "description": "inert"}]
    if valid:
        assert bool(AUDIT.validate_coverage(data, {"setuptools": "84.0.0", "wheel": "0.48.0"}, code)) == findings
    else:
        with pytest.raises(ValueError, match="exit code"):
            AUDIT.validate_coverage(data, {"setuptools": "84.0.0", "wheel": "0.48.0"}, code)


def test_waivers_never_hide_bad_coverage_or_tool_failure(tmp_path, monkeypatch):
    data = _report()
    data["dependencies"][0]["vulns"] = [{"id": "TEST-1"}]
    path = _lock(tmp_path)
    monkeypatch.setattr(AUDIT, "run_audit", lambda expected: (1, data, ""))
    assert AUDIT.audit_one(path, set()) == 1
    assert AUDIT.audit_one(path, {"TEST-1"}) == 0
    data["dependencies"].pop()
    assert AUDIT.audit_one(path, {"TEST-1"}) == 1
    monkeypatch.setattr(AUDIT, "run_audit", lambda expected: (1, {"dependencies": []}, "failure"))
    assert AUDIT.audit_one(path, {"TEST-1"}) == 1


@pytest.mark.parametrize("output", [json.dumps(_report()), '{"dependencies":[],"dependencies":[]}', '{"dependencies":[],"extra":NaN}', "not-json"])
def test_real_fake_tool_gets_only_exact_advisory_input_and_cleanup(tmp_path, monkeypatch, output):
    fake = tmp_path / "fake_audit.py"
    record = tmp_path / "input-path.txt"
    fake.write_text(
        "import pathlib,sys\n"
        "assert '--disable-pip' in sys.argv and '--no-deps' in sys.argv\n"
        "p=pathlib.Path(sys.argv[sys.argv.index('-r')+1])\n"
        "assert p.read_text() == 'setuptools==84.0.0\\nwheel==0.48.0\\n'\n"
        f"pathlib.Path({str(record)!r}).write_text(str(p))\n"
        f"print({output!r})\n"
    )
    monkeypatch.setattr(AUDIT, "pip_audit_cmd", lambda: [sys.executable, str(fake)])
    code, data, _stderr = AUDIT.run_audit({"setuptools": "84.0.0", "wheel": "0.48.0"})
    assert code == 0
    assert (data is not None) == (output == json.dumps(_report()))
    assert not Path(record.read_text()).exists()


def test_tool_timeout_is_failure(tmp_path, monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("fake", 180)
    monkeypatch.setattr(AUDIT.subprocess, "run", timeout)
    assert AUDIT.audit_one(_lock(tmp_path), set()) == 1


def test_every_committed_lock_family_is_selected():
    selected = {path.as_posix() for path in AUDIT.REQUIREMENT_FILES}
    selected.update(path.as_posix() for path, _mapping in AUDIT.NO_DEPS_REQUIREMENT_FILES)
    actual = {path.relative_to(REPO_ROOT).as_posix() for pattern in
              ("requirements-ci.lock", ".github/requirements-*.lock", "services/*/requirements.lock",
               "vendor/application-requirements.lock", "files/scripts/diffusion-*.lock")
              for path in REPO_ROOT.glob(pattern)}
    assert selected == actual


def test_torch_advisory_finding_is_not_silently_dropped():
    findings = AUDIT.validate_coverage(
        {
            "dependencies": [
                {
                    "name": "torch",
                    "version": "2.13.0",
                    "vulns": [
                        {
                            "id": "PYSEC-TEST-TORCH",
                            "description": "regression sentinel",
                        }
                    ],
                }
            ]
        },
        {"torch": "2.13.0"},
        1,
    )
    assert findings == [
        ("torch", "PYSEC-TEST-TORCH", "regression sentinel")
    ]


def test_rocm_triton_uses_upstream_advisory_proxy(tmp_path):
    lock = tmp_path / "diffusion-rocm.lock"
    lock.write_text(
        "--index-url https://pypi.org/simple\n"
        "--find-links https://download.pytorch.org/whl/rocm7.1/triton-rocm/\n"
        "triton-rocm==3.7.1 \\\n"
        "    --hash=sha256:" + "d" * 64 + "\n"
        "urllib3==2.7.0 \\\n"
        "    --hash=sha256:" + "e" * 64 + "\n",
        encoding="utf-8",
    )

    original = lock.read_bytes()
    expected = AUDIT.expected_requirements(lock, frozenset({"triton-rocm"}))
    assert expected == {"triton": "3.7.1", "urllib3": "2.7.0"}
    assert lock.read_bytes() == original
