"""Functional authenticity tests for canary placement and checking."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "files/system/usr/libexec/secure-ai/secure-canary.py"
SPEC = importlib.util.spec_from_file_location("secure_canary", HELPER_PATH)
assert SPEC and SPEC.loader
canary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(canary)


def _layout(tmp_path: Path) -> tuple[Path, Path, list[Path], Path]:
    key = tmp_path / "canary.key"
    key.write_bytes(b"k" * 32)
    key.chmod(0o600)
    vault = tmp_path / "vault"
    registry = tmp_path / "registry"
    keys = tmp_path / "keys"
    etc = tmp_path / "etc"
    for directory in (vault, registry, keys, etc):
        directory.mkdir()
    locations = [
        vault / ".canary",
        registry / ".canary",
        keys / ".canary",
        etc / ".canary",
    ]
    database = tmp_path / "state/canary-db.json"
    database.parent.mkdir()
    return key, database, locations, vault


def test_authenticated_round_trip(tmp_path: Path) -> None:
    key, database, locations, vault = _layout(tmp_path)
    result = canary.place_canaries(
        database,
        key,
        locations,
        vault,
        mount_checker=lambda _path: True,
    )
    assert result == {"status": "ok", "enrolled": 4, "pending_locations": []}
    assert database.stat().st_mode & 0o777 == 0o600
    assert all(path.stat().st_mode & 0o777 == 0o400 for path in locations)
    check = canary.check_canaries(database, key)
    assert check["status"] == "ok"
    assert check["violations"] == []


def test_unmounted_vault_is_truthfully_pending_then_enrolled(tmp_path: Path) -> None:
    key, database, locations, vault = _layout(tmp_path)
    first = canary.place_canaries(
        database,
        key,
        locations,
        vault,
        mount_checker=lambda _path: False,
    )
    assert first["status"] == "pending"
    assert first["pending_locations"] == [str(locations[0])]
    assert not locations[0].exists()
    assert all(path.exists() for path in locations[1:])
    assert canary.check_canaries(database, key)["status"] == "pending"

    second = canary.place_canaries(
        database,
        key,
        locations,
        vault,
        mount_checker=lambda _path: True,
    )
    assert second["status"] == "ok"
    assert second["enrolled"] == 4
    assert locations[0].exists()
    assert canary.check_canaries(database, key)["status"] == "ok"


def test_canary_content_tamper_is_detected(tmp_path: Path) -> None:
    key, database, locations, vault = _layout(tmp_path)
    canary.place_canaries(
        database,
        key,
        locations,
        vault,
        mount_checker=lambda _path: True,
    )
    locations[1].chmod(0o600)
    locations[1].write_text("replacement\n", encoding="utf-8")
    locations[1].chmod(0o400)
    result = canary.check_canaries(database, key)
    assert result["status"] == "violation"
    assert result["violations"][0]["path"] == str(locations[1])
    assert "mismatch" in result["violations"][0]["reason"]


def test_canary_dac_tamper_is_detected(tmp_path: Path) -> None:
    key, database, locations, vault = _layout(tmp_path)
    canary.place_canaries(
        database,
        key,
        locations,
        vault,
        mount_checker=lambda _path: True,
    )
    locations[2].chmod(0o444)
    result = canary.check_canaries(database, key)
    assert result["status"] == "violation"
    assert "private file" in result["violations"][0]["reason"]


def test_database_tamper_is_detected_and_cannot_be_rebaselined(tmp_path: Path) -> None:
    key, database, locations, vault = _layout(tmp_path)
    canary.place_canaries(
        database,
        key,
        locations,
        vault,
        mount_checker=lambda _path: True,
    )
    envelope = json.loads(database.read_text(encoding="utf-8"))
    envelope["payload"]["canaries"][0]["sha256"] = "0" * 64
    database.write_text(json.dumps(envelope), encoding="utf-8")
    database.chmod(0o600)
    result = canary.check_canaries(database, key)
    assert result["status"] == "violation"
    assert "HMAC" in result["violations"][0]["reason"]
    with pytest.raises(canary.CanaryError, match="HMAC"):
        canary.place_canaries(
            database,
            key,
            locations,
            vault,
            mount_checker=lambda _path: True,
        )


def test_existing_untracked_canary_is_never_blessed(tmp_path: Path) -> None:
    key, database, locations, vault = _layout(tmp_path)
    locations[1].write_text("attacker-selected\n", encoding="utf-8")
    locations[1].chmod(0o400)
    with pytest.raises(canary.CanaryError, match="untracked canary"):
        canary.place_canaries(
            database,
            key,
            locations,
            vault,
            mount_checker=lambda _path: True,
        )


def test_symlink_canary_is_never_followed(tmp_path: Path) -> None:
    key, database, locations, vault = _layout(tmp_path)
    outside = tmp_path / "outside"
    outside.write_text("outside\n", encoding="utf-8")
    locations[3].symlink_to(outside)
    with pytest.raises(canary.CanaryError, match="untracked canary"):
        canary.place_canaries(
            database,
            key,
            locations,
            vault,
            mount_checker=lambda _path: True,
        )
    assert outside.read_text(encoding="utf-8") == "outside\n"
