"""Tests for Epic 1 — Release Artifact Consistency.

Validates that the release workflow, sample-release-bundle docs, and
release-artifacts.json are all consistent with each other.
"""

import json
import os
import re
import subprocess
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
RELEASE_YML = REPO_ROOT / ".github" / "workflows" / "release.yml"
BUILD_YML = REPO_ROOT / ".github" / "workflows" / "build.yml"
CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"
ARTIFACTS_JSON = REPO_ROOT / "docs" / "release-artifacts.json"
SAMPLE_BUNDLE = REPO_ROOT / "docs" / "sample-release-bundle.md"
VERIFY_RELEASE = REPO_ROOT / "files" / "scripts" / "verify-release.sh"
BOOTSTRAP = REPO_ROOT / "files" / "scripts" / "secai-bootstrap.sh"
MAKEFILE = REPO_ROOT / "Makefile"
QUARANTINE_PYPROJECT = REPO_ROOT / "services" / "quarantine" / "pyproject.toml"
BUILD_USB = REPO_ROOT / "scripts" / "build-usb-image.sh"
RELEASE_HELPERS = [
    REPO_ROOT / "scripts" / "release" / "secai-os-build-iso.sh",
    REPO_ROOT / "scripts" / "release" / "secai-os-build-usb.sh",
    REPO_ROOT / "scripts" / "release" / "secai-os-run-docker.sh",
    REPO_ROOT / "scripts" / "release" / "secai-os-run-docker.ps1",
]


def _load_artifacts_json():
    return json.loads(ARTIFACTS_JSON.read_text(encoding="utf-8"))


def _read_release_yml():
    return RELEASE_YML.read_text(encoding="utf-8")


def _read_ci_yml():
    return CI_YML.read_text(encoding="utf-8")


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _fake_vm_builder_environment(tmp_path: Path) -> dict[str, str]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_executable(fake_bin / "cosign", "#!/bin/sh\nexit 0\n")
    _write_executable(
        fake_bin / "qemu-img",
        '#!/bin/sh\n[ "$1" = create ] || exit 2\n: > "$4"\n',
    )
    _write_executable(fake_bin / "virt-install", "#!/bin/sh\nexit 0\n")
    _write_executable(
        fake_bin / "virsh",
        '#!/bin/sh\n[ "$1" = dominfo ] && exit 1\nexit 0\n',
    )
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:/usr/bin:/bin:/usr/sbin:/sbin"
    env.pop("SECAI_VM_PASSWORD", None)
    env.pop("SECAI_HOST_STATE_PASSWORD", None)
    return env


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

    def test_release_does_not_publish_shared_credential_vm_images(self):
        content = _read_release_yml()
        assert "dist/secai-os-*.qcow2" not in content
        assert "dist/secai-os-*.ova" not in content
        assert "Qualify Local VM Builders (Not Published)" in content
        assert "VM builders qualified; ephemeral images will now be destroyed." in content

    def test_release_files_include_signatures(self):
        content = _read_release_yml()
        assert "*.iso.sig" in content

    def test_manifest_includes_install_artifacts(self):
        content = _read_release_yml()
        assert "install_artifacts" in content

    def test_release_files_include_openvex(self):
        content = _read_release_yml()
        assert ".vex.json" in content

    def test_release_files_include_helper_scripts(self):
        content = _read_release_yml()
        for helper in (
            "secai-os-build-iso.sh",
            "secai-os-build-usb.sh",
            "secai-os-run-docker.sh",
            "secai-os-run-docker.ps1",
        ):
            assert helper in content

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


class TestBuildWorkflowTrustBoundary:
    def test_pull_request_build_has_no_write_permissions_or_signing_secret(self):
        content = BUILD_YML.read_text(encoding="utf-8")
        pr_job = content.split("\n  bluebuild_pr:", 1)[1].split(
            "\n  bluebuild_publish:", 1
        )[0]
        assert "permissions:\n      contents: read" in pr_job
        assert "packages: write" not in pr_job
        assert "id-token: write" not in pr_job
        assert "SIGNING_SECRET" not in pr_job
        assert 'cosign_private_key: ""' in pr_job
        assert "push: false" in pr_job

    def test_publish_build_is_non_pr_and_environment_protected(self):
        content = BUILD_YML.read_text(encoding="utf-8")
        publish_job = content.split("\n  bluebuild_publish:", 1)[1].split(
            "\n  bluebuild:", 1
        )[0]
        assert "if: github.event_name != 'pull_request'" in publish_job
        assert "environment: release" in publish_job
        assert "packages: write" in publish_job
        assert "id-token: write" in publish_job
        assert "cosign_private_key: ${{ secrets.SIGNING_SECRET }}" in publish_job
        assert "push: true" in publish_job

    def test_release_image_tag_promotion_is_environment_protected(self):
        content = RELEASE_YML.read_text(encoding="utf-8")
        resolve_job = content.split("\n  resolve-image:", 1)[1].split(
            "\n  build-go:", 1
        )[0]
        assert "environment: release" in resolve_job
        assert "packages: write" in resolve_job

    def test_final_image_rejects_build_only_packages(self):
        content = BUILD_YML.read_text(encoding="utf-8")
        assert (
            "for package in golang golang-bin golang-src go-filesystem "
            "cmake cmake-data gcc-c++ gcc git git-core"
        ) in content
        assert "for command_name in go cmake gcc g++ git pip pip3" in content


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
        assert "requirements-ci.lock" in script_content
        assert "requirements-ci.txt" not in script_content
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
        lock = (
            REPO_ROOT / "services/quarantine/requirements.lock"
        ).read_text(encoding="utf-8")
        for package, version in (
            ("modelscan", "0.8.8"),
            ("fickling", "0.1.12"),
            ("modelaudit", "0.2.42"),
        ):
            assert f"{package}=={version} \\" in lock
        for rel_path in (
            "services/quarantine/Dockerfile",
            "services/quarantine/Dockerfile.sandbox",
        ):
            content = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
            assert "ARG ENABLE_GARAK_SCANNER=false" in content
            assert "--require-hashes -r requirements.lock" in content
            assert "garak is not present in the reviewed default scanner lock" in content
            assert "for scanner in modelscan fickling modelaudit" in content
            assert "ARG MODELSCAN_PACKAGE=" not in content

    def test_appsec_scanners_are_wired_into_ci(self):
        content = _read_ci_yml()
        assert "Hadolint & Semgrep" in content
        assert ".github/scripts/check-hadolint.sh" in content
        assert ".github/scripts/run-semgrep.sh" in content

    def test_release_helper_smoke_is_wired_into_ci(self):
        content = _read_ci_yml()
        assert "Release Helper Script Smoke" in content
        assert ".github/scripts/check-release-installers.sh" in content

    def test_ci_syft_usage_comes_from_pinned_action(self):
        content = _read_ci_yml()
        assert "raw.githubusercontent.com/anchore/syft/main/install.sh" not in content
        assert "anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610" in content

    def test_ci_govulncheck_install_is_pinned(self):
        content = _read_ci_yml()
        assert "golang.org/x/vuln/cmd/govulncheck@latest" not in content
        assert "golang.org/x/vuln/cmd/govulncheck@v1.3.0" in content

    def test_semgrep_uses_repo_owned_posix_wrapper(self):
        content = _read_ci_yml()
        wrapper = REPO_ROOT / ".github" / "scripts" / "run-semgrep.sh"
        assert "--network=none" in content
        assert "--entrypoint /bin/sh" in content
        assert ".github/scripts/run-semgrep.sh" in content
        wrapper_content = wrapper.read_text(encoding="utf-8")
        assert wrapper_content.startswith("#!/bin/sh\n")
        assert "--no-git-ignore" in wrapper_content


class TestSampleReleaseBundle:
    def test_mentions_iso(self):
        content = SAMPLE_BUNDLE.read_text(encoding="utf-8")
        assert ".iso" in content

    def test_mentions_qcow2(self):
        content = SAMPLE_BUNDLE.read_text(encoding="utf-8")
        assert "QCOW2" in content

    def test_mentions_portable_usb(self):
        content = SAMPLE_BUNDLE.read_text(encoding="utf-8")
        assert ".raw.xz" in content

    def test_mentions_ova(self):
        content = SAMPLE_BUNDLE.read_text(encoding="utf-8")
        assert "OVA" in content

    def test_mentions_local_only_vm_images(self):
        """Docs must make clear that QCOW2/OVA are not release artifacts."""
        content = SAMPLE_BUNDLE.read_text(encoding="utf-8")
        assert "not release artifacts" in content.lower()
        assert "build them locally" in content.lower()

    def test_references_artifacts_json(self):
        content = SAMPLE_BUNDLE.read_text(encoding="utf-8")
        assert "release-artifacts.json" in content

    def test_mentions_openvex(self):
        content = SAMPLE_BUNDLE.read_text(encoding="utf-8")
        assert "custom-python.vex.json" in content

    def test_mentions_release_helper_scripts(self):
        content = SAMPLE_BUNDLE.read_text(encoding="utf-8")
        for helper in (
            "secai-os-build-iso.sh",
            "secai-os-build-usb.sh",
            "secai-os-run-docker.sh",
            "secai-os-run-docker.ps1",
        ):
            assert helper in content


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
        assert "^sha256:[0-9a-f]{64}$" in content
        assert "--digest is required" in content
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
        assert "repository@sha256:<64 lowercase hex>" in content
        assert 'cosign verify --key "$COSIGN_PUB_SRC" "$CONTAINER_IMAGE"' in content
        assert "secai_os:latest" not in content

    def test_vm_ci_runs_installer_and_protects_kickstart_secrets(self):
        content = (REPO_ROOT / "scripts" / "vm" / "build-qcow2.sh").read_text(
            encoding="utf-8"
        )
        assert 'if [ "$CI_MODE" = true ]; then' in content
        assert 'virt-install "${VIRT_INSTALL_ARGS[@]}"' in content
        assert 'chmod 0600 "$KICKSTART_TMP"' in content
        assert 'ln "$KICKSTART_TMP" "$KICKSTART_PATH"' in content

    def test_vm_uses_current_fedora_and_separates_host_state_from_vault(self):
        content = (REPO_ROOT / "scripts" / "vm" / "build-qcow2.sh").read_text(
            encoding="utf-8"
        )
        assert "releases/44/Silverblue" in content
        assert "--os-variant fedora44" in content
        assert (
            "part /var/lib/secure-ai --fstype=ext4 --size=8192 "
            "--encrypted"
        ) in content
        assert "part /var/tmp/secai-vault-staging --fstype=ext4 --grow" in content
        assert "--vault-device /dev/sda5" in content

    def test_vm_credentials_are_not_printed_to_build_logs(self):
        content = (REPO_ROOT / "scripts" / "vm" / "build-qcow2.sh").read_text(
            encoding="utf-8"
        )
        assert "secai-first-boot-secrets.txt" in content
        assert 'chmod 0600 "$SECRETS_TMP"' in content
        assert 'ln "$SECRETS_TMP" "$SECRETS_FILE"' in content
        assert "password: ${SECAI_VM_PASSWORD}" not in content
        assert "current: ${SECAI_" not in content

    def test_vm_ci_credentials_are_explicit_and_images_are_qualification_only(self):
        content = (REPO_ROOT / "scripts" / "vm" / "build-qcow2.sh").read_text(
            encoding="utf-8"
        )
        assert "--ci requires caller-provided SECAI_VM_PASSWORD" in content
        assert "--qualification-ssh-key is restricted to --ci builds" in content
        assert "This CI output is qualification-only and must not be distributed." in content

    def test_vm_release_catalog_marks_images_local_only(self):
        data = _load_artifacts_json()
        optional = data["artifacts"]["optional"]
        local_only = data["artifacts"]["local_only"]
        assert "qcow2" not in optional
        assert "ova" not in optional
        assert set(local_only) == {"qcow2", "ova"}
        assert all(
            "never" in definition["description"].lower()
            or "never" in definition.get("required_when", "").lower()
            for definition in local_only.values()
        )

    def test_local_vm_builder_protects_generated_credentials(
        self, tmp_path: Path
    ):
        env = _fake_vm_builder_environment(tmp_path)
        output = tmp_path / "output"
        image_ref = f"example.test/secai/os@sha256:{'a' * 64}"
        result = subprocess.run(
            [
                "bash",
                str(REPO_ROOT / "scripts" / "vm" / "build-qcow2.sh"),
                "--image-ref",
                image_ref,
                str(output),
            ],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        secrets = output / "secai-first-boot-secrets.txt"
        kickstart = output / "secai-ks.cfg"
        qcow2 = output / "secai-os.qcow2"
        assert secrets.stat().st_mode & 0o777 == 0o600
        assert kickstart.stat().st_mode & 0o777 == 0o600
        assert qcow2.stat().st_mode & 0o777 == 0o600
        combined_output = result.stdout + result.stderr
        for line in secrets.read_text(encoding="utf-8").splitlines():
            credential = line.split(": ", maxsplit=1)[1]
            assert credential not in combined_output

    def test_ci_vm_builder_requires_explicit_ephemeral_credentials(
        self, tmp_path: Path
    ):
        env = _fake_vm_builder_environment(tmp_path)
        output = tmp_path / "ci-output"
        image_ref = f"example.test/secai/os@sha256:{'b' * 64}"
        result = subprocess.run(
            [
                "bash",
                str(REPO_ROOT / "scripts" / "vm" / "build-qcow2.sh"),
                "--ci",
                "--image-ref",
                image_ref,
                str(output),
            ],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        assert result.returncode == 2
        assert "--ci requires caller-provided" in result.stderr
        assert not (output / "secai-os.qcow2").exists()

    def test_ci_vm_builder_does_not_persist_plaintext_credentials(
        self, tmp_path: Path
    ):
        env = _fake_vm_builder_environment(tmp_path)
        env["SECAI_VM_PASSWORD"] = "a" * 32
        env["SECAI_HOST_STATE_PASSWORD"] = "b" * 32
        output = tmp_path / "ci-output"
        image_ref = f"example.test/secai/os@sha256:{'c' * 64}"
        result = subprocess.run(
            [
                "bash",
                str(REPO_ROOT / "scripts" / "vm" / "build-qcow2.sh"),
                "--ci",
                "--image-ref",
                image_ref,
                str(output),
            ],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert (output / "secai-os.qcow2").stat().st_mode & 0o777 == 0o600
        assert not (output / "secai-ks.cfg").exists()
        assert not (output / "secai-first-boot-secrets.txt").exists()
        combined_output = result.stdout + result.stderr
        assert env["SECAI_VM_PASSWORD"] not in combined_output
        assert env["SECAI_HOST_STATE_PASSWORD"] not in combined_output


class TestBuildUsbScript:
    def test_builder_image_is_digest_pinned(self):
        content = BUILD_USB.read_text(encoding="utf-8")
        assert "release/secai-os-build-usb.sh" in content
        release_helper = RELEASE_HELPERS[1].read_text(encoding="utf-8")
        assert "bootc-image-builder:latest@sha256:" in release_helper

    def test_user_supplied_options_are_validated(self):
        content = RELEASE_HELPERS[1].read_text(encoding="utf-8")
        assert "validate_image_ref" in content
        assert "Unsupported --rootfs value" in content
        assert "Unsupported --xz-level value" in content


class TestReleaseHelperScripts:
    def test_release_helpers_exist(self):
        for helper in RELEASE_HELPERS:
            assert helper.exists()

    def test_release_helpers_are_documented_as_artifacts(self):
        data = _load_artifacts_json()
        files = data["artifacts"]["required"]["release_scripts"]["files"]
        for helper in RELEASE_HELPERS:
            assert helper.name in files
        assert data["artifacts"]["required"]["trust_root"]["files"] == ["cosign.pub"]

    def test_iso_and_usb_helpers_pin_builder_image(self):
        for helper in RELEASE_HELPERS[:2]:
            content = helper.read_text(encoding="utf-8")
            assert "bootc-image-builder:latest@sha256:" in content

    def test_iso_and_usb_require_verified_immutable_source_image(self):
        for helper in RELEASE_HELPERS[:2]:
            content = helper.read_text(encoding="utf-8")
            assert "an immutable --image-ref or --digest is required" in content
            assert "@sha256:" in content
            verify_at = content.index('cosign verify --key "$COSIGN_KEY" "$IMAGE_REF"')
            pull_at = content.index('podman pull "$IMAGE_REF"')
            assert verify_at < pull_at

    def test_docker_helpers_support_profiles(self):
        for helper in RELEASE_HELPERS[2:]:
            content = helper.read_text(encoding="utf-8")
            assert "offline-private" in content
            assert "research" in content
            assert "full-lab" in content
