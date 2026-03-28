"""Tests for Epic 1 — Release Artifact Consistency.

Validates that the release workflow, sample-release-bundle docs, and
release-artifacts.json are all consistent with each other.
"""

import json
import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
RELEASE_YML = REPO_ROOT / ".github" / "workflows" / "release.yml"
ARTIFACTS_JSON = REPO_ROOT / "docs" / "release-artifacts.json"
SAMPLE_BUNDLE = REPO_ROOT / "docs" / "sample-release-bundle.md"
VERIFY_RELEASE = REPO_ROOT / "files" / "scripts" / "verify-release.sh"


def _load_artifacts_json():
    return json.loads(ARTIFACTS_JSON.read_text(encoding="utf-8"))


def _read_release_yml():
    return RELEASE_YML.read_text(encoding="utf-8")


class TestReleaseArtifactsJson:
    def test_file_exists(self):
        assert ARTIFACTS_JSON.exists()

    def test_valid_json(self):
        data = _load_artifacts_json()
        assert "schema_version" in data

    def test_canonical_image_ref(self):
        data = _load_artifacts_json()
        assert data["canonical_image_ref"] == "ghcr.io/secai-hub/secai_os"

    def test_go_services_match_release_matrix(self):
        """Go services in artifacts.json must match release.yml matrix."""
        data = _load_artifacts_json()
        release_content = _read_release_yml()

        # Extract matrix services from release.yml
        match = re.search(r"service: \[([^\]]+)\]", release_content)
        assert match, "Cannot find service matrix in release.yml"
        release_services = sorted(s.strip() for s in match.group(1).split(","))
        artifact_services = sorted(data["go_services"])

        assert release_services == artifact_services, (
            f"Mismatch: release.yml has {release_services}, "
            f"artifacts.json has {artifact_services}"
        )

    def test_all_nine_go_services(self):
        data = _load_artifacts_json()
        assert len(data["go_services"]) == 9

    def test_all_six_python_services(self):
        data = _load_artifacts_json()
        assert len(data["python_services"]) == 6

    def test_both_architectures(self):
        data = _load_artifacts_json()
        assert "linux-amd64" in data["architectures"]
        assert "linux-arm64" in data["architectures"]


class TestReleaseWorkflowStructure:
    def test_has_build_iso_job(self):
        content = _read_release_yml()
        assert "build-iso:" in content

    def test_has_build_vm_images_job(self):
        content = _read_release_yml()
        assert "build-vm-images:" in content

    def test_vm_images_gated_on_kvm_runner(self):
        content = _read_release_yml()
        assert "HAS_KVM_RUNNER" in content

    def test_provenance_needs_build_iso(self):
        content = _read_release_yml()
        # Provenance job should depend on build-iso
        assert "build-iso" in content

    def test_release_files_include_iso(self):
        content = _read_release_yml()
        assert "secai-os-*.iso" in content

    def test_release_files_include_vm(self):
        content = _read_release_yml()
        assert "secai-os-*.qcow2" in content
        assert "secai-os-*.ova" in content

    def test_release_files_include_signatures(self):
        content = _read_release_yml()
        assert "*.iso.sig" in content

    def test_manifest_includes_install_artifacts(self):
        content = _read_release_yml()
        assert "install_artifacts" in content


class TestSampleReleaseBundle:
    def test_mentions_iso(self):
        content = SAMPLE_BUNDLE.read_text(encoding="utf-8")
        assert ".iso" in content

    def test_mentions_qcow2(self):
        content = SAMPLE_BUNDLE.read_text(encoding="utf-8")
        assert ".qcow2" in content

    def test_mentions_ova(self):
        content = SAMPLE_BUNDLE.read_text(encoding="utf-8")
        assert ".ova" in content

    def test_mentions_optional_vm_artifacts(self):
        """Docs must note that QCOW2/OVA may be absent."""
        content = SAMPLE_BUNDLE.read_text(encoding="utf-8")
        assert "absent" in content.lower() or "optional" in content.lower()

    def test_references_artifacts_json(self):
        content = SAMPLE_BUNDLE.read_text(encoding="utf-8")
        assert "release-artifacts.json" in content


class TestVerifyReleaseScript:
    def test_has_step5_install_artifacts(self):
        content = VERIFY_RELEASE.read_text(encoding="utf-8")
        assert "Step 5" in content
        assert "install artifact" in content.lower()

    def test_handles_missing_artifacts_gracefully(self):
        content = VERIFY_RELEASE.read_text(encoding="utf-8")
        # Must skip gracefully when no install artifacts present
        assert "SKIP" in content or "skipping" in content.lower()

    def test_verifies_cosign_blob(self):
        content = VERIFY_RELEASE.read_text(encoding="utf-8")
        # Step 5 should use cosign verify-blob for install artifacts
        assert "cosign verify-blob" in content


class TestBuildQcow2Script:
    def test_supports_ci_flag(self):
        content = (REPO_ROOT / "scripts" / "vm" / "build-qcow2.sh").read_text(
            encoding="utf-8"
        )
        assert "--ci" in content

    def test_supports_image_ref_flag(self):
        content = (REPO_ROOT / "scripts" / "vm" / "build-qcow2.sh").read_text(
            encoding="utf-8"
        )
        assert "--image-ref" in content
