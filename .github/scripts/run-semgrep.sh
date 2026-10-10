#!/bin/sh
# Run repo-owned Semgrep rules without uploading code or metrics.
set -eu

if ! command -v semgrep >/dev/null 2>&1; then
    echo "FATAL: semgrep is required for application security linting." >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "FATAL: python3 is required to validate Semgrep scan coverage." >&2
    exit 1
fi

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

REPORT="$(mktemp)"
trap 'rm -f -- "$REPORT"' EXIT
trap 'exit 2' HUP INT TERM
status=0
semgrep scan \
    --config .semgrep.yml \
    --error \
    --strict \
    --verbose \
    --json-output "$REPORT" \
    --metrics=off \
    --disable-version-check \
    --no-git-ignore \
    --oss-only \
    services scripts .github || status=$?
[ "$status" -eq 0 ] || exit "$status"

# Exit zero alone does not establish coverage: Semgrep may skip oversized
# targets without an error. Match the report against the Python/Go paths in
# the project rules. Revisit this inventory if their language/path scope changes.
python3 - "$REPORT" <<'PY'
import json
import os
from pathlib import Path
import sys


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate report key")
        result[key] = value
    return result


def walk_error(error):
    raise error


try:
    root = Path.cwd().resolve()
    expected = set()
    for relative, suffixes in (("services", {".py", ".go"}),
                               ("scripts", {".py"}),
                               (".github/scripts", {".py"})):
        base = root / relative
        if not base.is_dir() or base.is_symlink():
            raise ValueError(f"missing or ambiguous scan root: {relative}")
        for directory, directories, filenames in os.walk(base, onerror=walk_error):
            if any((Path(directory) / name).is_symlink() for name in directories):
                raise ValueError("source directory symlinks prevent complete coverage")
            for name in filenames:
                path = Path(directory) / name
                if path.suffix in suffixes:
                    if path.is_symlink() or not path.is_file():
                        raise ValueError("source is not a regular file")
                    expected.add(path.relative_to(root).as_posix())
    if not expected:
        raise ValueError("no eligible project source files")

    with open(sys.argv[1], "rb") as stream:
        raw = stream.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError("scan report exceeds 16 MiB")
    report = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(report, dict) or not isinstance(report.get("version"), str) or not report["version"]:
        raise ValueError("invalid report version or object")
    for field in ("results", "errors", "skipped_rules"):
        if not isinstance(report.get(field), list) or report[field]:
            raise ValueError(f"scan has findings, errors, skipped rules, or invalid {field}")
    if report.get("engine_requested") != "OSS":
        raise ValueError("scan did not establish the requested OSS engine")
    timing = report.get("time", {})
    if not isinstance(timing, dict) or not isinstance(timing.get("fixpoint_timeouts", []), list) or timing.get("fixpoint_timeouts", []):
        raise ValueError("scan reports fixpoint timeouts or invalid timing metadata")
    paths = report.get("paths")
    if not isinstance(paths, dict) or not isinstance(paths.get("scanned"), list) or not isinstance(paths.get("skipped"), list):
        raise ValueError("missing or invalid scan coverage")

    def source_path(value):
        if not isinstance(value, str) or not value:
            raise ValueError("invalid reported path")
        path = root / value
        if path.is_symlink() or not path.is_file():
            raise ValueError("reported path is not a regular source file")
        relative = path.resolve(strict=True).relative_to(root)
        if relative.parts[0] not in {"services", "scripts", ".github"}:
            raise ValueError("reported path is outside the requested roots")
        return relative.as_posix()

    scanned = [source_path(value) for value in paths["scanned"]]
    if not scanned or len(scanned) != len(set(scanned)):
        raise ValueError("empty or duplicate scanned paths")
    intentional = set()
    seen_skips = set()
    for item in paths["skipped"]:
        if not isinstance(item, dict) or not isinstance(item.get("reason"), str):
            raise ValueError("invalid skipped-path record")
        path = source_path(item.get("path"))
        if path in seen_skips or path in scanned:
            raise ValueError("duplicate or contradictory skipped path")
        seen_skips.add(path)
        # Preserve Semgrep's existing Go-test policy, without adding exclusions.
        # These files are explicitly reported as unscanned, never counted as passes.
        if (path in expected and path.startswith("services/") and path.endswith("_test.go")
                and item["reason"] == "semgrepignore_patterns_match"):
            intentional.add(path)
        else:
            raise ValueError(f"incomplete scan: {path} ({item['reason']})")
    missing = expected - set(scanned) - intentional
    if missing:
        raise ValueError(f"missing eligible source coverage: {', '.join(sorted(missing)[:8])}")
    print(f"Semgrep coverage verified: {len(expected - intentional)} eligible source files; "
          f"{len(intentional)} Go test files remain excluded by the existing default policy.")
except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
    print(f"FATAL: invalid or incomplete Semgrep scan: {error}", file=sys.stderr)
    raise SystemExit(2)
PY
