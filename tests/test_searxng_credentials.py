"""Security tests for SearXNG's ephemeral credential-backed settings."""

from __future__ import annotations

import stat
import subprocess
import sys
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
HELPER = (
    REPO_ROOT
    / "files"
    / "system"
    / "usr"
    / "libexec"
    / "secure-ai"
    / "prepare-searxng-settings.py"
)
BASE_SETTINGS = (
    REPO_ROOT / "files" / "system" / "etc" / "secure-ai" / "searxng" / "settings.yml"
)
WRAPPER = (
    REPO_ROOT
    / "files"
    / "system"
    / "usr"
    / "libexec"
    / "secure-ai"
    / "start-searxng.sh"
)
UNIT = (
    REPO_ROOT
    / "files"
    / "system"
    / "usr"
    / "lib"
    / "systemd"
    / "system"
    / "secure-ai-searxng.service"
)


def _run(base: Path, credential: Path, output: Path):
    return subprocess.run(
        [
            sys.executable,
            str(HELPER),
            "--base",
            str(base),
            "--credential",
            str(credential),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_runtime_settings_inject_credential_without_mutating_base(tmp_path: Path):
    base = tmp_path / "base.yml"
    base.write_bytes(BASE_SETTINGS.read_bytes())
    credential = tmp_path / "credential"
    credential.write_text("0" * 64 + "\n", encoding="ascii")
    credential.chmod(0o600)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    output = runtime / "settings.yml"

    result = _run(base, credential, output)

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    rendered = yaml.safe_load(output.read_text(encoding="utf-8"))
    original = yaml.safe_load(base.read_text(encoding="utf-8"))
    assert rendered["server"]["secret_key"] == "0" * 64
    assert original["server"]["secret_key"] == "required-runtime-credential"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_runtime_settings_reject_linked_credential(tmp_path: Path):
    credential = tmp_path / "credential"
    real_credential = tmp_path / "real-credential"
    real_credential.write_text("0" * 64, encoding="ascii")
    credential.symlink_to(real_credential)
    output = tmp_path / "settings.yml"

    result = _run(BASE_SETTINGS, credential, output)

    assert result.returncode != 0
    assert not output.exists()


def test_runtime_settings_reject_duplicate_yaml_keys(tmp_path: Path):
    base = tmp_path / "base.yml"
    base.write_text(
        "server:\n  secret_key: required-runtime-credential\n"
        "server:\n  secret_key: required-runtime-credential\n",
        encoding="utf-8",
    )
    credential = tmp_path / "credential"
    credential.write_text("0" * 64, encoding="ascii")
    output = tmp_path / "settings.yml"

    result = _run(base, credential, output)

    assert result.returncode != 0
    assert "duplicate settings key" in result.stderr
    assert not output.exists()


def test_runtime_settings_refuse_linked_output(tmp_path: Path):
    credential = tmp_path / "credential"
    credential.write_text("0" * 64, encoding="ascii")
    protected = tmp_path / "protected"
    protected.write_text("unchanged\n", encoding="utf-8")
    output = tmp_path / "settings.yml"
    output.symlink_to(protected)

    result = _run(BASE_SETTINGS, credential, output)

    assert result.returncode != 0
    assert protected.read_text(encoding="utf-8") == "unchanged\n"


def test_searxng_unit_uses_owner_only_ephemeral_settings():
    unit = UNIT.read_text(encoding="utf-8")
    wrapper = WRAPPER.read_text(encoding="utf-8")

    assert "RuntimeDirectory=secure-ai-searxng" in unit
    assert "RuntimeDirectoryMode=0700" in unit
    assert "UMask=0077" in unit
    assert "ReadWritePaths=/run/secure-ai-searxng" in unit
    assert "prepare-searxng-settings.py" in wrapper
    assert 'export SEARXNG_SETTINGS_PATH="$runtime_settings_path"' in wrapper
    assert "export SEARXNG_SECRET=" not in wrapper


def test_pinned_settings_use_current_privacy_and_tor_schema():
    settings = yaml.safe_load(BASE_SETTINGS.read_text(encoding="utf-8"))

    assert settings["search"]["autocomplete"] == ""
    assert settings["outgoing"]["using_tor_proxy"] is True
    assert settings["outgoing"]["proxies"] == {"all://": ["socks5h://127.0.0.1:9050"]}
    assert settings["plugins"] == {
        "searx.plugins.hash_plugin.SXNGPlugin": {"active": True},
        "searx.plugins.hostnames.SXNGPlugin": {"active": True},
        "searx.plugins.tracker_url_remover.SXNGPlugin": {"active": True},
    }
    assert "enabled_plugins" not in settings
    engines = {engine["name"]: engine for engine in settings["engines"]}
    assert engines["stackoverflow"]["engine"] == "stackexchange"
    assert engines["stackoverflow"]["api_site"] == "stackoverflow"
    assert {"google", "bing", "yahoo", "brave"}.isdisjoint(engines)
