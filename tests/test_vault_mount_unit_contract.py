"""Bind fixed consumer containment checks to the installed unit declarations."""

import importlib.util
from pathlib import Path
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "files/system/usr/libexec/secure-ai/vault-mount-control.py"
SPEC = importlib.util.spec_from_file_location("vault_installed_unit_contract", SOURCE)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


@pytest.mark.parametrize("name", module.CONSUMERS)
def test_installed_consumer_satisfies_controller_containment(name, monkeypatch):
    # systemd defaults for absent properties are part of the installed contract.
    values = {"KillMode": "control-group", "Delegate": "no", "ProtectControlGroups": "no"}
    section = ""
    text = (ROOT / "files/system/usr/lib/systemd/system" / name).read_text()
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            section = line
        if section == "[Service]" and "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            if key in values:
                values[key] = value
    record = {**values, "Id": name, "LoadState": "loaded", "ActiveState": "inactive",
              "SubState": "dead", "Job": "", "MainPID": "0", "ControlGroup": ""}
    monkeypatch.setattr(module.native, "show", lambda unit: record if unit == name else {})
    assert module._service(time.monotonic() + 1, name) == record
