#!/usr/bin/env bash
# Run govulncheck for every Go service and require every reported finding to
# match a specific, unexpired OSV/CVE waiver. Scanner failures fail closed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WAIVERS="${REPO_ROOT}/.github/vuln-waivers.json"
GO_SERVICES="airlock registry tool-firewall gpu-integrity-watch mcp-firewall policy-engine runtime-attestor integrity-monitor incident-recorder ui-ingress"

if ! command -v govulncheck >/dev/null 2>&1; then
    echo "FATAL: govulncheck is required" >&2
    exit 1
fi
if [ ! -s "$WAIVERS" ]; then
    echo "FATAL: vulnerability waiver file is missing or empty: $WAIVERS" >&2
    exit 1
fi

AUDIT_DIR="$(mktemp -d)"
trap 'rm -rf -- "$AUDIT_DIR"' EXIT
FINDINGS_FILE="${AUDIT_DIR}/findings.jsonl"
: > "$FINDINGS_FILE"

for svc in ${GO_SERVICES}; do
    echo "--- govulncheck: ${svc} ---"
    OUTPUT_FILE="${AUDIT_DIR}/${svc}.json"
    STDERR_FILE="${AUDIT_DIR}/${svc}.stderr"

    if ! (
        cd "${REPO_ROOT}/services/${svc}"
        govulncheck -json ./... > "$OUTPUT_FILE" 2> "$STDERR_FILE"
    ); then
        echo "::error::${svc}: govulncheck failed to complete" >&2
        sed -n '1,80p' "$STDERR_FILE" >&2
        exit 1
    fi

    # govulncheck emits adjacent, sometimes pretty-printed JSON objects rather
    # than JSONL. Decode the complete stream and fail closed on any trailing or
    # malformed content.
    python3 "${REPO_ROOT}/.github/scripts/normalize-govulncheck.py" \
        "$svc" "$OUTPUT_FILE" >> "$FINDINGS_FILE"
done

python3 - "$WAIVERS" "$FINDINGS_FILE" <<'PY'
import datetime as dt
import json
import sys
from pathlib import Path

waivers_path = Path(sys.argv[1])
findings_path = Path(sys.argv[2])
today = dt.date.today()

try:
    waiver_doc = json.loads(waivers_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f"FATAL: invalid vulnerability waiver file: {exc}")

active_waivers: dict[str, dict] = {}
errors = 0
for index, waiver in enumerate(waiver_doc.get("go", []), 1):
    missing = [
        key
        for key in ("id", "reason", "reviewer", "expires")
        if not isinstance(waiver.get(key), str) or not waiver[key].strip()
    ]
    if missing:
        print(f"::error::Go waiver #{index} lacks required fields: {', '.join(missing)}")
        errors += 1
        continue
    try:
        expiry = dt.date.fromisoformat(waiver["expires"])
    except ValueError:
        print(f"::error::Go waiver #{index} has invalid expiry: {waiver['expires']}")
        errors += 1
        continue
    if expiry < today:
        continue
    if waiver["id"] in active_waivers:
        print(f"::error::duplicate active Go waiver: {waiver['id']}")
        errors += 1
        continue
    active_waivers[waiver["id"]] = waiver

findings = []
for line_number, line in enumerate(
    findings_path.read_text(encoding="utf-8").splitlines(), 1
):
    if not line.strip():
        continue
    try:
        findings.append(json.loads(line))
    except json.JSONDecodeError as exc:
        print(f"::error::invalid normalized finding at line {line_number}: {exc}")
        errors += 1

used_waivers: set[str] = set()
unwaived: list[dict] = []
for finding in findings:
    identifiers = set(finding.get("identifiers", []))
    matches = sorted(identifiers.intersection(active_waivers))
    if matches:
        used_waivers.update(matches)
        print(
            f"WAIVED: {finding['service']} {finding['primary_id']} "
            f"via {', '.join(matches)}"
        )
    else:
        print(
            f"::error::{finding['service']}: {finding['primary_id']} "
            f"({', '.join(sorted(identifiers))}) is unwaived"
        )
        unwaived.append(finding)

for waiver_id in sorted(set(active_waivers) - used_waivers):
    print(f"::warning::active Go waiver is not used by this scan: {waiver_id}")

if errors or unwaived:
    unique = {finding["primary_id"] for finding in unwaived}
    print(
        f"FAIL: {len(unique)} unwaived Go vulnerability ID(s), "
        f"{errors} waiver/output validation error(s)"
    )
    raise SystemExit(1)

print(
    f"PASS: strict Go vulnerability scan completed "
    f"({len(findings)} finding(s), {len(used_waivers)} waiver(s) used)"
)
PY
