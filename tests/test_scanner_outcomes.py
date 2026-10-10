"""Admission must require complete evidence from the pinned scanner protocols."""
import copy
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "services" / "quarantine"))
from quarantine import pipeline


def audit_report():
    return {"issues": [], "has_errors": False, "success": True, "files_scanned": 1,
            "bytes_scanned": 128, "total_checks": 4, "file_metadata": {}, "checks": []}


def scan_report():
    return {"issues": [], "errors": [], "summary": {
        "modelscan_version": "0.8.8", "scanned": {"total_scanned": 1},
        "skipped": {"total_skipped": 0}}}


@pytest.mark.parametrize("report", [None, [], {}, {"issues": []},
    {**audit_report(), "has_errors": True}, {**audit_report(), "success": False},
    {**audit_report(), "files_scanned": 0}, {**audit_report(), "files_scanned": True},
    {**audit_report(), "bytes_scanned": 0}, {**audit_report(), "total_checks": 0},
    {**audit_report(), "dry_run": True},
    {**audit_report(), "file_metadata": {"a": {"analysis_incomplete": True}}},
    {**audit_report(), "checks": [{"details": {"scan_outcome": "inconclusive"}}]},
    {**audit_report(), "issues": [{"severity": "warning"}]},
    {**audit_report(), "issues": [{"severity": "unrecognized"}]}])
def test_modelaudit_never_accepts_invalid_incomplete_or_failed_report(report, monkeypatch):
    monkeypatch.setattr(pipeline.subprocess, "run", lambda *a, **kw:
                        SimpleNamespace(returncode=0, stdout=json.dumps(report), stderr=""))
    assert not pipeline._run_modelaudit(Path("model.gguf"))["passed"]


def test_modelaudit_requires_exit_success_and_positive_evidence(monkeypatch):
    for code, expected in [(0, True), (2, False)]:
        monkeypatch.setattr(pipeline.subprocess, "run", lambda *a, **kw:
                            SimpleNamespace(returncode=code, stdout=json.dumps(audit_report()), stderr=""))
        assert pipeline._run_modelaudit(Path("model.gguf"))["passed"] is expected


@pytest.mark.parametrize("report", [None, [], {}, {"issues": []},
    {**scan_report(), "errors": [{"message": "partial parser failure"}]},
    {**scan_report(), "errors": None}, {**scan_report(), "issues": {}},
    {**scan_report(), "summary": {"scanned": {"total_scanned": None}}},
    {**scan_report(), "summary": {"scanned": {"total_scanned": True}}},
    {**scan_report(), "summary": {"scanned": {"total_scanned": 0}}},
    {**scan_report(), "summary": {"scanned": {"total_scanned": 2}, "skipped": {"total_skipped": 1}}}])
@pytest.mark.parametrize("adapter", ["api", "cli"])
def test_modelscan_adapters_reject_empty_errors_and_partial_coverage(report, adapter, monkeypatch):
    if adapter == "api":
        monkeypatch.setitem(sys.modules, "modelscan", SimpleNamespace(__version__="0.8.8"))
        monkeypatch.setitem(sys.modules, "modelscan.modelscan", SimpleNamespace(
            ModelScan=lambda: SimpleNamespace(scan=lambda path: report)))
    else:
        monkeypatch.setitem(sys.modules, "modelscan", SimpleNamespace())
        monkeypatch.delitem(sys.modules, "modelscan.modelscan", raising=False)
        monkeypatch.setattr(pipeline.subprocess, "run", lambda *a, **kw:
                            SimpleNamespace(returncode=0, stdout=json.dumps(report), stderr=""))
    assert pipeline._run_modelscan(Path("model.pkl"))["passed"] is False


@pytest.mark.parametrize("ext", ["gguf", "safetensors"])
def test_unsupported_format_is_explicit_and_cannot_mask_scanner_errors(ext):
    report = copy.deepcopy(scan_report())
    report["summary"]["scanned"]["total_scanned"] = 0
    for code in (0, 3):
        result = pipeline._modelscan_outcome(report, Path(f"model.{ext}"), "modelscan-cli", "0.8.8", code)
        assert result["passed"] and result["status"] == "not_applicable"
    report["errors"] = [{"message": "read failure"}]
    assert not pipeline._modelscan_outcome(report, Path(f"model.{ext}"), "modelscan-api", "0.8.8")["passed"]


def test_modelscan_accepts_complete_report():
    result = pipeline._modelscan_outcome(scan_report(), Path("model.pkl"), "modelscan-api", "0.8.8")
    assert result["passed"] and result["status"] == "pass" and result["files_scanned"] == 1
