"""Security invariants for the UI-to-root runtime request boundary."""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "services" / "ui"))
sys.path.insert(0, str(REPO_ROOT / "services"))

from ui import app as ui_app


def test_activity_update_is_atomic_and_group_shared(tmp_path, monkeypatch):
    activity = tmp_path / "last-activity"
    monkeypatch.setattr(ui_app, "VAULT_ACTIVITY_FILE", activity)

    assert ui_app._touch_vault_activity() is True
    assert float(activity.read_text(encoding="ascii")) > 0
    assert stat.S_IMODE(activity.stat().st_mode) == 0o660
    assert not list(tmp_path.glob(".last-activity.*"))


def test_runtime_request_is_complete_and_no_replace(tmp_path):
    request = tmp_path / "profile-request"

    ui_app._publish_runtime_request(request, b"research")

    assert request.read_bytes() == b"research"
    assert stat.S_IMODE(request.stat().st_mode) == 0o640
    try:
        ui_app._publish_runtime_request(request, b"full_lab")
    except FileExistsError:
        pass
    else:
        raise AssertionError("an existing root-broker request was overwritten")
    assert request.read_bytes() == b"research"
    assert not list(tmp_path.glob(".profile-request.*"))


def test_vault_status_rejects_non_finite_activity(tmp_path, monkeypatch):
    activity = tmp_path / "last-activity"
    activity.write_text("NaN", encoding="ascii")
    monkeypatch.setattr(ui_app, "VAULT_ACTIVITY_FILE", activity)
    monkeypatch.setattr(
        ui_app,
        "_read_vault_state",
        lambda: {"state": "unlocked", "detail": ""},
    )
    monkeypatch.setattr(ui_app._auth, "is_configured", lambda: True)
    monkeypatch.setattr(
        ui_app._auth,
        "validate_session",
        lambda _token, refresh=False: True,
    )

    with ui_app.app.test_client() as client:
        response = client.get("/api/vault/status")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["last_activity"] == 0.0
    assert payload["idle_seconds"] == 0
    assert json.dumps(payload, allow_nan=False)
