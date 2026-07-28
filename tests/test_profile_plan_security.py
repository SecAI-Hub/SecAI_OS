"""Fail-closed profile planning and atomic state tests."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = (
    REPO_ROOT
    / "files/system/usr/libexec/secure-ai/secure-profile-plan.py"
)
CONFIG_PATH = (
    REPO_ROOT
    / "files/system/etc/secure-ai/config/appliance.yaml"
)
UNIT_ROOT = REPO_ROOT / "files/system/usr/lib/systemd/system"
SPEC = importlib.util.spec_from_file_location("secure_profile_plan", HELPER_PATH)
assert SPEC and SPEC.loader
profiles = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(profiles)


def test_repository_profile_model_is_complete_and_explicit() -> None:
    definitions = profiles.load_definitions(CONFIG_PATH, UNIT_ROOT)
    assert set(definitions) == profiles.VALID_PROFILES
    controlled = {
        name: set(definition["services_enabled"])
        | set(definition["services_disabled"])
        for name, definition in definitions.items()
    }
    assert len({frozenset(units) for units in controlled.values()}) == 1


def test_duplicate_yaml_key_is_rejected(tmp_path: Path) -> None:
    config = tmp_path / "appliance.yaml"
    config.write_text(
        "profile:\n"
        "  default: offline_private\n"
        "profile:\n"
        "  default: offline_private\n",
        encoding="utf-8",
    )
    with pytest.raises(profiles.ProfileError, match="duplicate YAML key"):
        profiles.load_definitions(config, UNIT_ROOT)


def test_profiles_must_control_the_same_complete_unit_set(tmp_path: Path) -> None:
    data = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    data["profile"]["definitions"]["research"]["services_disabled"].pop()
    config = tmp_path / "appliance.yaml"
    config.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(profiles.ProfileError, match="same controlled unit set"):
        profiles.load_definitions(config, UNIT_ROOT)


def test_offline_profile_must_disable_network_stack(tmp_path: Path) -> None:
    data = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    offline = data["profile"]["definitions"]["offline_private"]
    offline["services_disabled"].remove("secure-ai-airlock.service")
    offline["services_enabled"].append("secure-ai-airlock.service")
    config = tmp_path / "appliance.yaml"
    config.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(profiles.ProfileError, match="network-capable"):
        profiles.load_definitions(config, UNIT_ROOT)


def test_malformed_operator_override_fails_closed(tmp_path: Path) -> None:
    override = tmp_path / "profile.yaml"
    override.write_text("profile: full_lab\nunexpected: true\n", encoding="utf-8")
    state = tmp_path / "state.json"
    state.write_text('{"active":"offline_private"}\n', encoding="utf-8")
    with pytest.raises(profiles.ProfileError, match="exactly one profile field"):
        profiles.read_current_profile(state, override)


def test_malformed_runtime_state_uses_safe_default(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    state = tmp_path / "state.json"
    state.write_text('{"active":"full_lab","active":"research"}\n', encoding="utf-8")
    current = profiles.read_current_profile(state, tmp_path / "no-override")
    assert current == {
        "profile": "offline_private",
        "locked": False,
        "source": "safe_default",
    }
    assert "invalid runtime state" in capsys.readouterr().err


def test_request_must_be_one_exact_allowlisted_name(tmp_path: Path) -> None:
    request = tmp_path / "request"
    request.write_text("full_lab;reboot", encoding="utf-8")
    with pytest.raises(profiles.ProfileError, match="invalid profile name"):
        profiles.read_request(request)
    request.write_text("research\nfull_lab\n", encoding="utf-8")
    with pytest.raises(profiles.ProfileError, match="exactly one line"):
        profiles.read_request(request)


def test_request_symlink_is_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.write_text("offline_private", encoding="utf-8")
    request = tmp_path / "request"
    request.symlink_to(real)
    with pytest.raises(profiles.ProfileError, match="symbolic link"):
        profiles.read_request(request)


def test_state_and_result_writes_are_atomic_and_bounded(tmp_path: Path) -> None:
    state = tmp_path / "state/profile.json"
    profiles.write_state(state, "research", "test")
    parsed_state = json.loads(state.read_text(encoding="utf-8"))
    assert parsed_state["active"] == "research"
    assert parsed_state["changed_by"] == "test"
    assert not list(state.parent.glob(".profile.json.*"))

    result = tmp_path / "run/profile-result.json"
    profiles.write_result(
        result,
        "success",
        "research",
        "offline_private",
        "",
    )
    parsed_result = json.loads(result.read_text(encoding="utf-8"))
    assert parsed_result["status"] == "success"
    assert os.stat(result).st_mode & 0o777 == 0o640
    assert not list(result.parent.glob(".profile-result.json.*"))


def _profile_shell_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    initial_profile: str = "offline_private",
) -> tuple[dict[str, str], Path]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    python_path = Path(os.environ.get("VIRTUAL_ENV", "")) / "bin/python"
    if not python_path.is_file():
        python_path = Path(os.sys.executable)
    (fake_bin / "python3").write_text(
        f"#!/bin/sh\nexec {python_path!s} \"$@\"\n",
        encoding="utf-8",
    )

    (fake_bin / "id").write_text(
        "#!/bin/sh\n[ \"${1:-}\" = -u ] && { echo 0; exit 0; }\nexit 1\n",
        encoding="utf-8",
    )
    (fake_bin / "install").write_text(
        "#!/bin/sh\nfor target do :; done\nmkdir -p -- \"$target\"\n",
        encoding="utf-8",
    )
    (fake_bin / "flock").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    systemctl = fake_bin / "systemctl"
    systemctl.write_text(
        """#!/bin/sh
set -eu
command=$1
shift
[ "${1:-}" = "--quiet" ] && shift
unit=${1:-}
state=${FAKE_SYSTEMD_STATE:?}
enabled="$state/$unit.enabled"
active="$state/$unit.active"
case "$command" in
  is-enabled)
    value=disabled
    [ ! -f "$enabled" ] || value=$(cat "$enabled")
    echo "$value"
    [ "$value" = enabled ]
    ;;
  is-active)
    value=inactive
    [ ! -f "$active" ] || value=$(cat "$active")
    echo "$value"
    [ "$value" = active ]
    ;;
  enable) printf 'enabled\\n' > "$enabled" ;;
  disable) printf 'disabled\\n' > "$enabled" ;;
  start)
    if [ "${FAIL_START_UNIT:-}" = "$unit" ]; then exit 1; fi
    printf 'active\\n' > "$active"
    ;;
  stop) printf 'inactive\\n' > "$active" ;;
  *) exit 2 ;;
esac
""",
        encoding="utf-8",
    )
    for executable in fake_bin.iterdir():
        executable.chmod(0o755)

    state_dir = tmp_path / "systemd"
    state_dir.mkdir()
    definitions = profiles.load_definitions(CONFIG_PATH, UNIT_ROOT)
    initial = definitions[initial_profile]
    for unit in initial["services_enabled"]:
        (state_dir / f"{unit}.enabled").write_text("enabled\n", encoding="utf-8")
        (state_dir / f"{unit}.active").write_text("active\n", encoding="utf-8")
    for unit in initial["services_disabled"]:
        (state_dir / f"{unit}.enabled").write_text("disabled\n", encoding="utf-8")
        (state_dir / f"{unit}.active").write_text("inactive\n", encoding="utf-8")

    runtime = tmp_path / "runtime"
    runtime.mkdir()
    state_file = tmp_path / "state/profile.json"
    state_file.parent.mkdir()
    profiles.write_state(state_file, initial_profile, "test")
    environment = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "APPLIANCE_CONFIG": str(CONFIG_PATH),
        "PROFILE_STATE": str(state_file),
        "OPERATOR_OVERRIDE": str(tmp_path / "no-override.yaml"),
        "REQUEST_FILE": str(tmp_path / "no-request"),
        "RESULT_FILE": str(runtime / "result.json"),
        "AUDIT_LOG": str(tmp_path / "logs/audit.jsonl"),
        "UNIT_ROOT": str(UNIT_ROOT),
        "PROFILE_HELPER": str(HELPER_PATH),
        "WORK_ROOT": str(runtime / "work"),
        "LOCK_FILE": str(runtime / "profile.lock"),
        "FAKE_SYSTEMD_STATE": str(state_dir),
    }
    monkeypatch.setenv("VIRTUAL_ENV", str(Path(os.sys.executable).parents[1]))
    return environment, state_dir


def test_profile_shell_commits_only_after_full_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment, state_dir = _profile_shell_environment(tmp_path, monkeypatch)
    script = REPO_ROOT / "files/system/usr/libexec/secure-ai/apply-profile.sh"
    completed = subprocess.run(
        [str(script), "research", "test"],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    state = json.loads(Path(environment["PROFILE_STATE"]).read_text(encoding="utf-8"))
    result = json.loads(Path(environment["RESULT_FILE"]).read_text(encoding="utf-8"))
    assert state["active"] == "research"
    assert result["status"] == "success"
    research = profiles.load_definitions(CONFIG_PATH, UNIT_ROOT)["research"]
    for unit in research["services_enabled"]:
        assert (state_dir / f"{unit}.enabled").read_text().strip() == "enabled"
        assert (state_dir / f"{unit}.active").read_text().strip() == "active"
    for unit in research["services_disabled"]:
        assert (state_dir / f"{unit}.enabled").read_text().strip() == "disabled"
        assert (state_dir / f"{unit}.active").read_text().strip() == "inactive"


def test_profile_shell_restores_exact_snapshot_on_start_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment, state_dir = _profile_shell_environment(tmp_path, monkeypatch)
    environment["FAIL_START_UNIT"] = "secure-ai-airlock.service"
    before = {
        path.name: path.read_text(encoding="utf-8")
        for path in state_dir.iterdir()
    }
    script = REPO_ROOT / "files/system/usr/libexec/secure-ai/apply-profile.sh"
    completed = subprocess.run(
        [str(script), "research", "test"],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 1
    after = {
        path.name: path.read_text(encoding="utf-8")
        for path in state_dir.iterdir()
    }
    assert after == before
    state = json.loads(Path(environment["PROFILE_STATE"]).read_text(encoding="utf-8"))
    result = json.loads(Path(environment["RESULT_FILE"]).read_text(encoding="utf-8"))
    assert state["active"] == "offline_private"
    assert result["status"] == "rolled_back"
