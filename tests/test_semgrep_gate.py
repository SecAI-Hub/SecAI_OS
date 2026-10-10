"""Exercise the real shell gate against scanner status/report boundary failures."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / ".github/scripts/run-semgrep.sh"


@pytest.fixture
def checkout(tmp_path):
    (tmp_path / ".github/scripts").mkdir(parents=True)
    (tmp_path / "services").mkdir()
    (tmp_path / "scripts").mkdir()
    shutil.copyfile(GATE, tmp_path / ".github/scripts/run-semgrep.sh")
    shutil.copyfile(ROOT / ".semgrep.yml", tmp_path / ".semgrep.yml")
    (tmp_path / "services/example.py").write_text("value = 1\n")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    scanner = bindir / "semgrep"
    scanner.write_text(f'''#!{sys.executable}
import json, pathlib, sys
root=pathlib.Path(__file__).parent.parent
plan=json.loads((root/'plan.json').read_text())
(root/'scanner-argv.json').write_text(json.dumps(sys.argv[1:]))
output=pathlib.Path(sys.argv[sys.argv.index('--json-output')+1])
(root/'report-path.txt').write_text(str(output))
if plan.get('output', True):
 output.write_text(plan.get('raw', json.dumps(plan['report'])))
sys.exit(plan.get('exit', 0))
''')
    scanner.chmod(0o755)
    return tmp_path


def good_report():
    return {"version": "1.176.0", "results": [], "errors": [], "skipped_rules": [],
            "engine_requested": "OSS", "paths": {"scanned": ["services/example.py"], "skipped": []}}


def run_gate(root, plan, *, missing_tool=False):
    (root / "plan.json").write_text(json.dumps(plan))
    env = {**os.environ, "PATH": str(root / "bin") + ":/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}
    if missing_tool:
        env["PATH"] = str(root / "missing-tools")
    result = subprocess.run(["/bin/sh", str(root / ".github/scripts/run-semgrep.sh")],
                            env=env, capture_output=True, text=True, timeout=15)
    report = root / "report-path.txt"
    if report.exists():
        assert not Path(report.read_text()).exists(), "temporary scanner report leaked"
    return result


@pytest.mark.parametrize("case", ["valid", "finding-exit", "operational-exit", "missing-report", "invalid-json",
                                  "duplicate-json-key", "not-object", "missing-errors", "wrong-errors-type",
                                  "partial-parse", "timeout", "out-of-memory", "skipped-rule", "hidden-finding",
                                  "wrong-engine", "missing-paths", "empty-paths", "duplicate-paths", "missing-file",
                                  "missing-eligible-coverage", "size-skip", "unexpected-policy-skip", "unknown-skip",
                                  "contradictory-skip", "missing-skips", "missing-version", "fixpoint-timeout", "report-size-limit"])
def test_scan_gate_refuses_failed_or_incomplete_reports(checkout, case):
    root = checkout
    report = good_report()
    plan = {"report": report}
    expected = 0 if case == "valid" else 2
    if case in {"finding-exit", "operational-exit"}:
        expected = plan["exit"] = 1 if case == "finding-exit" else 3
    elif case == "missing-report":
        plan["output"] = False
    elif case == "invalid-json":
        plan["raw"] = "{broken"
    elif case == "duplicate-json-key":
        plan["raw"] = json.dumps(report).replace('"errors": []', '"errors": [], "errors": []')
    elif case == "not-object":
        plan["report"] = []
    elif case == "missing-errors":
        del report["errors"]
    elif case == "wrong-errors-type":
        report["errors"] = {}
    elif case in {"partial-parse", "timeout", "out-of-memory"}:
        report["errors"] = [{"code": 3, "level": "warn", "type": {"partial-parse": "PartialParsing", "timeout": "Timeout", "out-of-memory": "OutOfMemory"}[case], "path": "services/example.py"}]
    elif case == "skipped-rule":
        report["skipped_rules"] = [{"rule_id": "rule", "reason": "unsupported"}]
    elif case == "hidden-finding":
        report["results"] = [{"check_id": "finding"}]
    elif case == "wrong-engine":
        report["engine_requested"] = "PRO"
    elif case == "missing-paths":
        del report["paths"]
    elif case == "empty-paths":
        report["paths"]["scanned"] = []
    elif case == "duplicate-paths":
        report["paths"]["scanned"] *= 2
    elif case == "missing-file":
        report["paths"]["scanned"] = ["services/absent.py"]
    elif case == "missing-eligible-coverage":
        (root / "services/omitted.py").write_text("value = 2\n")
    elif case in {"size-skip", "unexpected-policy-skip", "unknown-skip"}:
        (root / "services/omitted.py").write_text("value = 2\n")
        reason = {"size-skip": "exceeded_size_limit", "unexpected-policy-skip": "semgrepignore_patterns_match",
                  "unknown-skip": "future_reason"}[case]
        report["paths"]["skipped"] = [{"path": "services/omitted.py", "reason": reason}]
    elif case == "contradictory-skip":
        report["paths"]["skipped"] = [{"path": "services/example.py", "reason": "exceeded_size_limit"}]
    elif case == "missing-skips":
        del report["paths"]["skipped"]
    elif case == "missing-version":
        del report["version"]
    elif case == "fixpoint-timeout":
        report["time"] = {"fixpoint_timeouts": ["services/example.py"]}
    elif case == "report-size-limit":
        plan["raw"] = " " * (16 * 1024 * 1024 + 1)
    result = run_gate(root, plan)
    assert result.returncode == expected, result.stdout + result.stderr
    if case == "valid":
        assert "coverage verified: 1 eligible source files" in result.stdout
        args = json.loads((root / "scanner-argv.json").read_text())
        for flag in ["--error", "--strict", "--verbose", "--json-output", "--metrics=off",
                     "--disable-version-check", "--no-git-ignore", "--oss-only"]:
            assert flag in args
        assert args[-3:] == ["services", "scripts", ".github"]
    elif expected == 2:
        assert "FATAL: invalid or incomplete Semgrep scan" in result.stderr


def test_existing_go_test_policy_is_reported_without_counting_as_scan(checkout):
    (checkout / "services/example_test.go").write_text("package example\n")
    report = good_report()
    report["paths"]["skipped"] = [{"path": "services/example_test.go", "reason": "semgrepignore_patterns_match"}]
    result = run_gate(checkout, {"report": report})
    assert result.returncode == 0, result.stderr
    assert "1 eligible source files; 1 Go test files remain excluded" in result.stdout


def test_go_test_operational_skip_is_not_accepted_as_policy(checkout):
    (checkout / "services/example_test.go").write_text("package example\n")
    report = good_report()
    report["paths"]["skipped"] = [{"path": "services/example_test.go", "reason": "exceeded_size_limit"}]
    result = run_gate(checkout, {"report": report})
    assert result.returncode == 2


def test_missing_scanner_is_fatal(checkout):
    result = run_gate(checkout, {"report": good_report()}, missing_tool=True)
    assert result.returncode == 1
    assert "FATAL: semgrep is required" in result.stderr
    assert not (checkout / "scanner-argv.json").exists()


def test_inventory_scope_matches_the_configured_rule_consumer(checkout):
    import ast

    import yaml

    # Read the actual inventory expression, so changing the wrapper or rule
    # language/path scope requires a matching change in the other consumer.
    code = GATE.read_text().split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    loops = [node for node in ast.walk(ast.parse(code)) if isinstance(node, ast.For)
             and isinstance(node.target, ast.Tuple)
             and [getattr(value, "id", None) for value in node.target.elts] == ["relative", "suffixes"]]
    assert len(loops) == 1
    inventory = dict(ast.literal_eval(loops[0].iter))
    result = run_gate(checkout, {"report": good_report()})
    assert result.returncode == 0, result.stderr
    argv = json.loads((checkout / "scanner-argv.json").read_text())
    targets = argv[argv.index("--oss-only") + 1:]
    languages = {"python": ".py", "go": ".go"}
    configured = {}
    rules = yaml.safe_load((ROOT / ".semgrep.yml").read_text())["rules"]
    for rule in rules:
        assert set(rule["languages"]) <= languages.keys(), "new language needs coverage inventory support"
        assert not rule["paths"].get("exclude"), "rule exclusions need explicit coverage review"
        for pattern in rule["paths"]["include"]:
            assert pattern.startswith("/") and pattern.count("/**/*") == 1
            scope, suffix = pattern[1:].split("/**/*")
            assert not any(character in scope for character in "*?[]")
            assert suffix in {languages[language] for language in rule["languages"]}
            if any(scope == target or scope.startswith(target + "/") for target in targets):
                configured.setdefault(scope, set()).add(suffix)
    assert configured == inventory, "configured rule paths and expected coverage must agree"
