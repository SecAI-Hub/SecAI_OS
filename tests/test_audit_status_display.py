"""Execute the audit status presentation logic against mixed and stale evidence."""
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'services/ui'))
from ui import assurance

TEMPLATE = Path(__file__).resolve().parents[1] / "services/ui/ui/templates/security.html"


@pytest.fixture(scope="module")
def summarize():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is needed to execute the browser status logic")
    source = TEMPLATE.read_text()
    start = source.index("    function auditStatusSummary(")
    end = source.index("    async function loadAuditStatus", start)
    function = "function evidenceObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }\n" + source[start:end]
    def run(payload, now=1700000000000):
        payload = assurance.audit(payload, now / 1000)
        payload["basis"] = "root_owned_local_report"
        if payload.get("passing") is True:
            payload["valid_until"] = now / 1000 + 30
        script = function + "\nprocess.stdout.write(JSON.stringify(auditStatusSummary(" + json.dumps(payload) + "," + str(now) + ")));"
        completed = subprocess.run([node, "-e", script], capture_output=True, text=True, check=True, timeout=10)
        return json.loads(completed.stdout)
    return run


def report():
    return {"status": "ok", "ready": True, "logs_checked": 4, "failures": 0, "checked_at": "2023-11-14T22:13:20Z", "details": [
        {"status": "ok", "valid": True, "security_class": "keyed-tamper-evident"},
        {"status": "ok", "valid": True, "security_class": "unkeyed-hash-linked"},
        {"status": "ok", "valid": True, "security_class": "structured-only"},
        {"status": "not_applicable", "valid": True, "security_class": "structured-only"}]}


def test_mixed_coverage_retains_assurance_distinctions(summarize):
    result = summarize(report())
    assert result["label"] == "Checked"
    assert "1 keyed chains, 1 unkeyed chains, 1 syntax-only logs; 1 not applicable" in result["text"]
    assert "do not prove authenticity" in result["text"]
    assert "Chain verified" not in result["text"]


@pytest.mark.parametrize("change", ["stale", "future", "missing_date", "legacy_valid", "not_ready", "empty", "unknown_class", "unknown_status"])
def test_incomplete_or_old_report_never_displays_success(summarize, change):
    data = report()
    if change == "stale":
        data["checked_at"] = "2023-11-14T21:00:00Z"
    elif change == "future":
        data["checked_at"] = "2023-11-14T23:00:00Z"
    elif change == "missing_date":
        data.pop("checked_at")
    elif change == "legacy_valid":
        data = {"valid": True}
    elif change == "not_ready":
        data["ready"] = False
    elif change == "empty":
        data["details"] = []
    elif change == "unknown_class":
        data["details"][0]["security_class"] = "trusted"
    else:
        data["details"][0]["status"] = "missing"
    assert summarize(data)["label"] == "Unknown"


@pytest.mark.parametrize("status, expected", [("failed", "Degraded"), ("checking", "Checking"), ("unknown", "Unknown")])
def test_nonready_states_are_explicit(summarize, status, expected):
    data = report()
    data["status"] = status
    data["ready"] = False
    assert summarize(data)["label"] == expected


def test_false_detail_overrides_top_level_success(summarize):
    data = report()
    data["details"][0]["valid"] = False
    assert summarize(data)["label"] == "Degraded"
