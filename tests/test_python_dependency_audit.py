"""Regression tests for backend-local Python advisory coverage."""

from __future__ import annotations

import importlib.util
from pathlib import Path


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

    audit_copy, advisory_copy = AUDIT.split_local_advisory_requirements(
        lock,
        frozenset({"torch", "torchvision"}),
    )
    try:
        content = audit_copy.read_text(encoding="utf-8")
        advisory = advisory_copy.read_text(encoding="utf-8")
    finally:
        audit_copy.unlink(missing_ok=True)
        advisory_copy.unlink(missing_ok=True)

    assert "torch" not in content
    assert "torch==2.13.0\n" in advisory
    assert "torchvision==0.28.0\n" in advisory
    assert "+cu129" not in advisory
    assert "--hash=" not in advisory
    assert "urllib3==2.7.0 \\" in content
    assert "c" * 64 in content
    assert "--find-links https://download.pytorch.org/" not in content


def test_torch_advisory_finding_is_not_silently_dropped():
    findings = AUDIT.extract_findings(
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
        }
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

    audit_copy, advisory_copy = AUDIT.split_local_advisory_requirements(
        lock,
        frozenset({"triton-rocm"}),
    )
    try:
        content = audit_copy.read_text(encoding="utf-8")
        advisory = advisory_copy.read_text(encoding="utf-8")
    finally:
        audit_copy.unlink(missing_ok=True)
        advisory_copy.unlink(missing_ok=True)

    assert "triton-rocm" not in content
    assert "triton==3.7.1\n" in advisory
    assert "urllib3==2.7.0 \\" in content
