"""Tests for Epic 1 — Release Artifact Consistency.

Validates that the release workflow, sample-release-bundle docs, and
release-artifacts.json are all consistent with each other.
"""

import json
import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
RELEASE_YML = REPO_ROOT / ".github" / "workflows" / "release.yml"
CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"
ARTIFACTS_JSON = REPO_ROOT / "docs" / "release-artifacts.json"
SAMPLE_BUNDLE = REPO_ROOT / "docs" / "sample-release-bundle.md"
VERIFY_RELEASE = REPO_ROOT / "files" / "scripts" / "verify-release.sh"
BOOTSTRAP = REPO_ROOT / "files" / "scripts" / "secai-bootstrap.sh"
MAKEFILE = REPO_ROOT / "Makefile"
QUARANTINE_PYPROJECT = REPO_ROOT / "services" / "quarantine" / "pyproject.toml"
BUILD_USB = REPO_ROOT / "scripts" / "build-usb-image.sh"


def _load_artifacts_json():
    return json.loads(ARTIFACTS_JSON.read_text(encoding="utf-8"))


def _read_release_yml():
    return RELEASE_YML.read_text(encoding="utf-8")


def _read_ci_yml():
    return CI_YML.read_text(encoding="utf-8")


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

    def test_release_files_include_portable_usb(self):
        content = _read_release_yml()
        assert "secai-os-*-usb.raw.xz" in content

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

    def test_release_files_include_openvex(self):
        content = _read_release_yml()
        assert ".vex.json" in content

    def test_has_sandbox_vex_job(self):
        content = _read_release_yml()
        assert "build-sandbox-vex:" in content

    def test_preflight_requires_sandbox_openvex_ci_check(self):
        content = _read_release_yml()
        assert "Sandbox OpenVEX Smoke" in content

    def test_release_go_build_creates_dist_directory(self):
        content = _read_release_yml()
        assert "mkdir -p ../../dist" in content

    def test_release_python_sboms_use_pinned_action(self):
        content = _read_release_yml()
        assert "raw.githubusercontent.com/anchore/syft/main/install.sh" not in content
        assert "anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610" in content
        assert "dist/search-mediator-sbom.cdx.json" in content

    def test_release_sandbox_vex_build_retries(self):
        content = _read_release_yml()
        assert "for attempt in 1 2 3" in content
        assert "Sandbox image build failed after" in content


class TestCiWorkflowStructure:
    def test_ci_has_sandbox_openvex_smoke_job(self):
        content = _read_ci_yml()
        assert "sandbox-vex-smoke:" in content

    def test_ci_generates_custom_python_vex(self):
        content = _read_ci_yml()
        assert "generate_custom_python_vex.py" in content

    def test_python_dependency_audit_uses_project_requirements(self):
        content = _read_ci_yml()
        audit_script = REPO_ROOT / ".github" / "scripts" / "audit-python-deps.py"
        script_content = audit_script.read_text(encoding="utf-8")
        assert "python .github/scripts/audit-python-deps.py" in content
        assert "requirements-ci.txt" in script_content
        assert "services/ui/requirements.lock" in script_content
        assert "services/quarantine/requirements.lock" in script_content

    def test_quarantine_scan_extra_keeps_garak_opt_in(self):
        data = tomllib.loads(QUARANTINE_PYPROJECT.read_text(encoding="utf-8"))
        optional = data["project"]["optional-dependencies"]
        scan_deps = optional["scan"]
        dependencies = data["project"]["dependencies"]
        assert "garak" in optional
        assert all(not dep.startswith("garak") for dep in scan_deps)
        for package in ("modelscan", "fickling", "modelaudit"):
            matches = [dep for dep in scan_deps if "==" in dep and dep.split("==", 1)[0] == package]
            assert len(matches) == 1
        assert "yara-python==4.5.4" in dependencies

    def test_quarantine_container_scanners_are_pinned(self):
        for rel_path in (
            "services/quarantine/Containerfile",
            "services/quarantine/Containerfile.sandbox",
        ):
            content = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
            assert "ARG ENABLE_GARAK_SCANNER=false" in content
            assert "ARG MODELSCAN_PACKAGE=" in content
            assert "ARG FICKLING_PACKAGE=" in content
            assert "ARG MODELAUDIT_PACKAGE=" in content
            assert "ARG GARAK_PACKAGE=" in content
            assert "tomllib.load" in content
            assert "missing pinned scanner dependency" in content
            assert 'scanners="modelscan fickling modelaudit"' in content

    def test_appsec_scanners_are_wired_into_ci(self):
        content = _read_ci_yml()
        assert "Hadolint & Semgrep" in content
        assert ".github/scripts/check-hadolint.sh" in content
        assert ".github/scripts/run-semgrep.sh" in content

    def test_ci_syft_usage_comes_from_pinned_action(self):
        content = _read_ci_yml()
        assert "raw.githubusercontent.com/anchore/syft/main/install.sh" not in content
        assert "anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610" in content

    def test_ci_govulncheck_install_is_pinned(self):
        content = _read_ci_yml()
        assert "golang.org/x/vuln/cmd/govulncheck@latest" not in content
        assert "golang.org/x/vuln/cmd/govulncheck@v1.3.0" in content


class TestSampleReleaseBundle:
    def test_mentions_iso(self):
        content = SAMPLE_BUNDLE.read_text(encoding="utf-8")
        assert ".iso" in content

    def test_mentions_qcow2(self):
        content = SAMPLE_BUNDLE.read_text(encoding="utf-8")
        assert ".qcow2" in content

    def test_mentions_portable_usb(self):
        content = SAMPLE_BUNDLE.read_text(encoding="utf-8")
        assert ".raw.xz" in content

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

    def test_mentions_openvex(self):
        content = SAMPLE_BUNDLE.read_text(encoding="utf-8")
        assert "custom-python.vex.json" in content


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

    def test_handles_portable_usb_artifacts(self):
        content = VERIFY_RELEASE.read_text(encoding="utf-8")
        assert "usb.raw.xz" in content

    def test_validates_openvex_when_present(self):
        content = VERIFY_RELEASE.read_text(encoding="utf-8")
        assert "custom-python.vex.json" in content
        assert "openvex_structure" in content

    def test_supports_key_archive_directory(self):
        content = VERIFY_RELEASE.read_text(encoding="utf-8")
        assert "COSIGN_PUB_KEYS_DIR" in content
        assert "release-keys" in content


class TestBootstrapScript:
    def test_dry_run_does_not_install_policy_before_rebase(self):
        content = BOOTSTRAP.read_text(encoding="utf-8")
        assert 'VERIFY_KEY="$TEMP_KEY"' in content
        assert "would install cosign via dnf" in content
        assert "DRY RUN — would install public key" in content
        policy_section = content.split('step "Configuring container signing policy"', 1)[1]
        dry_run_block = policy_section.split('if [ "$DRY_RUN" = true ]; then', 1)[1].split("else", 1)[0]
        assert "cp \"$TEMP_KEY\" \"$COSIGN_PUB_DEST\"" not in dry_run_block
        assert "cat > \"$REGISTRIES_YAML\"" not in dry_run_block

    def test_fresh_policy_fails_closed_and_digest_is_validated(self):
        content = BOOTSTRAP.read_text(encoding="utf-8")
        assert "^sha256:[0-9A-Fa-f]{64}$" in content
        assert "'default': [{'type': 'reject'}]" in content


class TestMakefileTargets:
    def test_has_sandbox_vex_target(self):
        content = MAKEFILE.read_text(encoding="utf-8")
        assert "sandbox-vex:" in content


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

    def test_vm_rebase_is_signed_first(self):
        content = (REPO_ROOT / "scripts" / "vm" / "build-qcow2.sh").read_text(
            encoding="utf-8"
        )
        assert "ostree-unverified-registry" not in content
        assert "ostree-image-signed:docker://${CONTAINER_IMAGE}" in content
        assert "secai-cosign.pub" in content
        assert "use-sigstore-attachments: true" in content

    def test_vm_ci_runs_installer_and_protects_kickstart_secrets(self):
        content = (REPO_ROOT / "scripts" / "vm" / "build-qcow2.sh").read_text(
            encoding="utf-8"
        )
        assert 'if [ "$CI_MODE" = true ]; then' in content
        assert 'virt-install "${VIRT_INSTALL_ARGS[@]}"' in content
        assert 'chmod 0600 "${OUTPUT_DIR}/secai-ks.cfg"' in content


class TestBuildUsbScript:
    def test_builder_image_is_digest_pinned(self):
        content = BUILD_USB.read_text(encoding="utf-8")
        assert "bootc-image-builder:latest@sha256:" in content

    def test_user_supplied_options_are_validated(self):
        content = BUILD_USB.read_text(encoding="utf-8")
        assert "validate_image_ref" in content
        assert "Unsupported --rootfs value" in content
        assert "Unsupported --xz-level value" in content
