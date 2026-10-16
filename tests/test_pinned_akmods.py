"""Read-only preflight/unit checks; never execute the installer positive path."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "modules/pinned-akmods/pinned-akmods.sh"
CONFIG = {
    "type": "pinned-akmods",
    "source": "local",
    "base": "main",
    "install": [],
    "nvidia-driver": "nvidia-open",
}
KERNEL = "7.2.10-200.fc44.x86_64"
GUARD_END = '# All following installation commands are unreachable until these checks pass.'


@pytest.fixture
def guard_runner(tmp_path):
    """All commands except real JSON parsing are inert stubs; no installer run."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    mutations = tmp_path / "mutations"
    stub = bindir / "stub"
    stub.write_text(
        "#!/usr/bin/python3\n"
        "import os, sys\n"
        "from pathlib import Path\n"
        "name = Path(sys.argv[0]).name\n"
        "args = sys.argv[1:]\n"
        "if name == 'rpm':\n"
        "    if args == ['-E', '%{?fedora}']: print(os.environ['FEDORA'])\n"
        "    elif args == ['-E', '%{_arch}']: print(os.environ['ARCH'])\n"
        "    elif args[-1] == 'kernel-core':\n"
        "        if os.environ.get('RPM_FAIL'): sys.exit(2)\n"
        "        print(os.environ['KERNEL'])\n"
        "    elif args[-1] == 'kmod-nvidia': print(os.environ['KMOD'])\n"
        "    elif args[-1] == 'nvidia-driver': print(os.environ['DRIVER'])\n"
        "    else: sys.exit(3)\n"
        "elif name == 'modinfo':\n"
        "    if os.environ.get('MODINFO_FAIL'): sys.exit(2)\n"
        "    assert args[:3] == ['-k', '7.2.10-200.fc44.x86_64', '-F']\n"
        "    if os.environ.get('BAD_MODULE') == args[-1]: print('wrong-kernel SMP')\n"
        "    else: print(os.environ['MODULE_VERSION'] if args[3] == 'version' else os.environ['VERMAGIC'])\n"
        "else:\n"
        "    with open(os.environ['MUTATIONS'], 'a') as log: log.write(name + '\\n')\n"
        "    sys.exit(99)\n"
    )
    stub.chmod(0o755)
    for name in (
        "rpm", "modinfo", "skopeo", "tar", "mv", "curl", "sed", "rpm-ostree",
        "dnf5", "rm", "ln", "mkdir", "find", "grep", "tr",
    ):
        (bindir / name).symlink_to(stub)
    (bindir / "jq").symlink_to("/usr/bin/jq")
    env = {
        "PATH": str(bindir), "OS_VERSION": "44", "MULTILIB": "0",
        "FEDORA": "44", "ARCH": "x86_64", "KERNEL": KERNEL,
        "KMOD": "590.48.01", "DRIVER": "590.48.01", "MODULE_VERSION": "590.48.01",
        "VERMAGIC": KERNEL + " SMP preempt mod_unload ", "MUTATIONS": str(mutations),
    }

    def run(config=CONFIG, overrides=None, *, full_script=False, post=False):
        current_env = env | (overrides or {})
        value = config if isinstance(config, str) else json.dumps(config)
        if full_script:
            command = ["/bin/bash", str(SCRIPT), value]
        else:
            # Function definitions only: the installer and call site are omitted.
            prefix = SCRIPT.read_text().split(GUARD_END)[0]
            calls = '\nvalidate_pinned_inputs "$1"\n'
            if post:
                calls += 'KERNEL="${POST_KERNEL:-$KERNEL}"\nvalidate_installed_modules\n'
            command = ["/bin/bash", "-c", prefix + calls, "guard-test", value]
        result = subprocess.run(command, env=current_env, text=True, capture_output=True, timeout=10, check=False)
        assert not mutations.exists(), "preflight reached an external/mutating command"
        return result

    return run


@pytest.mark.parametrize("config", [
    CONFIG | {"type": "akmods"}, CONFIG | {"source": "remote"},
    CONFIG | {"base": "bazzite"}, CONFIG | {"install": ["xone"]},
    CONFIG | {"install": None}, CONFIG | {"nvidia-driver": "nvidia"},
    CONFIG | {"extra": True}, {k: v for k, v in CONFIG.items() if k != "install"},
    "{broken", "[]", "null",
])
def test_invalid_configuration_stops_before_mutation(guard_runner, config):
    result = guard_runner(config, full_script=True)
    assert result.returncode != 0
    assert "unsupported module configuration" in result.stderr


@pytest.mark.parametrize("overrides, error", [
    ({"OS_VERSION": "43"}, "OS_VERSION must be 44"),
    ({"MULTILIB": "1"}, "MULTILIB must be disabled"),
    ({"FEDORA": "43"}, "Fedora 44 is required"),
    ({"FEDORA": ""}, "Fedora 44 is required"),
    ({"ARCH": "aarch64"}, "amd64 is required"),
    ({"KERNEL": "7.2.9-200.fc44.x86_64"}, "installed kernel mismatch"),
    ({"KERNEL": KERNEL + "\n7.2.8-200.fc44.x86_64"}, "installed kernel mismatch"),
    ({"RPM_FAIL": "1"}, "kernel-core query failed"),
])
def test_wrong_platform_stops_before_mutation(guard_runner, overrides, error):
    result = guard_runner(overrides=overrides, full_script=True)
    assert result.returncode != 0
    assert error in result.stderr


def test_valid_read_only_guards(guard_runner):
    result = guard_runner(post=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("overrides, error", [
    ({"KMOD": "different"}, "kernel/userspace NVIDIA version mismatch"),
    ({"MODULE_VERSION": "different"}, "NVIDIA module version mismatch"),
    ({"VERMAGIC": "7.2.8-200.fc44.x86_64 SMP"}, "NVIDIA module kernel mismatch"),
    ({"MODINFO_FAIL": "1"}, "installed NVIDIA module missing"),
    ({"BAD_MODULE": "nvidia_drm"}, "NVIDIA module kernel mismatch: nvidia_drm"),
    ({"POST_KERNEL": "7.2.8-200.fc44.x86_64"}, "installed kernel mismatch"),
])
def test_post_install_module_mismatch_rejected(guard_runner, overrides, error):
    result = guard_runner(overrides=overrides, post=True)
    assert result.returncode != 0
    assert error in result.stderr


def test_local_routing_and_exact_inputs():
    recipe = yaml.safe_load((ROOT / "recipes/recipe.yml").read_text())
    assert recipe["image-version"] == "44@sha256:7f829bceba48df411642833d9f3c2b8d6ed49d89ce8a1963f686a7f57b74c612"
    modules = recipe["modules"]
    module = next(m for m in modules if m["type"] == "pinned-akmods")
    assert module == CONFIG
    assert not any(m["type"] == "akmods" for m in modules)
    script = SCRIPT.read_text()
    refs = [line.split("docker://", 1)[1].split()[0] for line in script.splitlines() if line.startswith("skopeo copy")]
    assert refs == [
        "ghcr.io/ublue-os/akmods@sha256:606ec67c9f5d6a1f738ba1b3d5bb1b0b1d1b9b6358a192112ed7dfc12049f225",
        "ghcr.io/ublue-os/akmods-nvidia-open@sha256:355ad2f68ee9547979ff5aa2c67311636b968e3dc3f6290a06bc4ca82f9471c3",
    ]
    assert script.index('validate_pinned_inputs "$@"') < script.index("INSTALL_NVIDIA_DRIVER()")
    assert 'nvidia-install.sh\nvalidate_installed_modules' in script
    assert SCRIPT.stat().st_mode & 0o111
    provenance = json.loads((SCRIPT.parent / "UPSTREAM_SOURCE.json").read_text())
    assert provenance["upstream_script_sha256"] == "315fac949da2c24fda68dc20e2bcb2068135c628a568737c9ab8fcc52e9b6b80"
    assert provenance["source_layer"]["bytes"] == 4186
    assert hashlib.sha256(SCRIPT.read_bytes()).hexdigest() == provenance["local_script_sha256"]
    review_path = ROOT / provenance["input_review_receipt"]
    assert hashlib.sha256(review_path.read_bytes()).hexdigest() == provenance["input_review_receipt_sha256"]
    review = json.loads(review_path.read_text())
    expected_inputs = {
        "base": "ghcr.io/ublue-os/silverblue-main@" + recipe["image-version"].split("@", 1)[1],
        "common": refs[0], "nvidia_open": refs[1], "kernel": KERNEL,
    }
    assert provenance["reviewed_inputs"] == review["reviewed_inputs"] == expected_inputs
    assert review["trusted_ublue_key_sha256"] == provenance["trusted_ublue_key_sha256"]
    assert {row["subject"] for row in review["signatures"]} == {expected_inputs[key] for key in ("base", "common", "nvidia_open")}
    assert all(row["exit_code"] == 0 and row["default_transparency_verification"] is True for row in review["signatures"])
    assert review["qualification"]["installed_image"] is False
