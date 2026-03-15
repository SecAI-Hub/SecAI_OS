#!/usr/bin/env bash
# govulncheck-strict.sh — Release-branch govulncheck with CVE-ID-level waivers.
#
# Unlike the regular dependency-audit job (which subtracts waiver counts),
# this matches by specific CVE ID — same approach as the Python pip-audit gate.
# Only used by the release-gate job on release/* and stable branches.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WAIVERS="${REPO_ROOT}/.github/vuln-waivers.json"
GO_SERVICES="airlock registry tool-firewall gpu-integrity-watch mcp-firewall policy-engine runtime-attestor integrity-monitor incident-recorder"

# Collect all vulnerability IDs across services
FINDINGS_FILE=$(mktemp)
trap 'rm -f "$FINDINGS_FILE"' EXIT

for svc in ${GO_SERVICES}; do
    echo "--- govulncheck: ${svc} ---"
    OUTPUT_FILE=$(mktemp)
    (cd "${REPO_ROOT}/services/${svc}" && govulncheck -json ./... > "$OUTPUT_FILE" 2>&1) || true

    # Extract OSV/CVE IDs from govulncheck JSON stream
    python3 -c "
import json, sys
ids = set()
for line in open('${OUTPUT_FILE}'):
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        continue
    osv = obj.get('osv', {})
    if osv:
        vid = osv.get('id', '')
        if vid:
            ids.add(vid)
        for a in osv.get('aliases', []):
            ids.add(a)
    finding = obj.get('finding', {})
    if finding and finding.get('osv'):
        ids.add(finding['osv'])
for vid in sorted(ids):
    print('${svc}:' + vid)
" >> "$FINDINGS_FILE" 2>/dev/null || true

    rm -f "$OUTPUT_FILE"
done

# Compare findings against waivers
python3 -c "
import json, sys, datetime

with open('${WAIVERS}') as f:
    waivers = json.load(f)
today = datetime.date.today().isoformat()
waived_ids = {w['id'] for w in waivers.get('go', []) if w.get('expires', '') >= today}

unwaived = []
with open('${FINDINGS_FILE}') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        svc, vid = line.split(':', 1)
        if vid in waived_ids:
            print(f'WAIVED: {svc} {vid}')
        else:
            print(f'::error::{svc}: {vid} — unwaived vulnerability')
            unwaived.append(f'{svc}:{vid}')

# Deduplicate (same CVE in multiple services)
unique = set(v.split(':', 1)[1] for v in unwaived)
if unique:
    print(f'RELEASE GATE FAIL: {len(unique)} unwaived Go CVE(s) across {len(unwaived)} service finding(s)')
    print('To waive, add CVE IDs to .github/vuln-waivers.json with reason + expiry.')
    sys.exit(1)
print(f'OK: Go strict vuln check passed ({len(waived_ids)} waiver(s) active)')
"
