#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# check-test-counts.sh — Detect test-count drift against docs/test-counts.json
#
# Exits non-zero if any per-service count is LOWER than the documented count.
# Counts that EXCEED the documented value are fine (docs just need updating).
###############################################################################

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COUNTS_FILE="${REPO_ROOT}/docs/test-counts.json"

if [[ ! -f "${COUNTS_FILE}" ]]; then
  echo "FATAL: ${COUNTS_FILE} not found."
  exit 1
fi

# JSON helper — Python is already set up in CI.
read_json() {
  python3 -c "import json,sys; d=json.load(open('${COUNTS_FILE}')); print(d$1)"
}

###############################################################################
# 1. Count Go tests per service
###############################################################################

GO_SERVICES="airlock registry tool-firewall gpu-integrity-watch mcp-firewall policy-engine runtime-attestor integrity-monitor incident-recorder"

go_total_actual=0
drift_found=0

echo "=============================================="
echo "  Test-Count Drift Check"
echo "=============================================="
echo ""
echo "--- Go services ---"

# Store results in temp files (bash 3 compatible, no associative arrays)
results_dir=$(mktemp -d)
trap 'rm -rf "${results_dir}"' EXIT

for svc in ${GO_SERVICES}; do
  svc_dir="${REPO_ROOT}/services/${svc}"
  if [[ ! -d "${svc_dir}" ]]; then
    echo "WARNING: services/${svc} directory not found, skipping."
    echo "0" > "${results_dir}/${svc}.actual"
  else
    count=$(cd "${svc_dir}" && go test -v -count=1 ./... 2>&1 | grep -c "^--- PASS" || true)
    echo "${count}" > "${results_dir}/${svc}.actual"
    go_total_actual=$((go_total_actual + count))
  fi

  expected=$(read_json "['go']['${svc}']" 2>/dev/null || echo 0)
  echo "${expected}" > "${results_dir}/${svc}.expected"
done

###############################################################################
# 2. Count Python tests
###############################################################################

echo "--- Python tests ---"

python_actual=$(cd "${REPO_ROOT}" && \
  PYTHONPATH=services python3 -m pytest tests/ --co -q 2>&1 | tail -1 | \
  grep -oE '^[0-9]+' || echo 0)

python_expected=$(read_json "['python_total']" 2>/dev/null || echo 0)

###############################################################################
# 3. Compute totals
###############################################################################

go_total_expected=$(read_json "['go_total']" 2>/dev/null || echo 0)
grand_expected=$(read_json "['grand_total']" 2>/dev/null || echo 0)
grand_actual=$((go_total_actual + python_actual))

###############################################################################
# 4. Print summary table
###############################################################################

echo ""
echo "=============================================="
printf "  %-22s %8s %8s %8s\n" "Component" "Expected" "Actual" "Status"
echo "----------------------------------------------"

for svc in ${GO_SERVICES}; do
  exp=$(cat "${results_dir}/${svc}.expected")
  act=$(cat "${results_dir}/${svc}.actual")
  if [ "${act}" -lt "${exp}" ]; then
    status="DRIFT!"
    drift_found=1
  elif [ "${act}" -gt "${exp}" ]; then
    status="ABOVE (update docs)"
  else
    status="OK"
  fi
  printf "  %-22s %8d %8d   %s\n" "go/${svc}" "${exp}" "${act}" "${status}"
done

# Python row
if [ "${python_actual}" -lt "${python_expected}" ]; then
  py_status="DRIFT!"
  drift_found=1
elif [ "${python_actual}" -gt "${python_expected}" ]; then
  py_status="ABOVE (update docs)"
else
  py_status="OK"
fi
printf "  %-22s %8d %8d   %s\n" "python" "${python_expected}" "${python_actual}" "${py_status}"

echo "----------------------------------------------"
printf "  %-22s %8d %8d\n" "Go subtotal" "${go_total_expected}" "${go_total_actual}"
printf "  %-22s %8d %8d\n" "Python subtotal" "${python_expected}" "${python_actual}"
printf "  %-22s %8d %8d\n" "Grand total" "${grand_expected}" "${grand_actual}"
echo "=============================================="
echo ""

###############################################################################
# 5. Exit with appropriate code
###############################################################################

if [ "${drift_found}" -eq 1 ]; then
  echo "FAIL: One or more test counts drifted DOWN from documented values."
  echo "      This means tests were removed or broken without updating docs/test-counts.json."
  exit 1
else
  echo "PASS: All test counts meet or exceed documented values."
  if [ "${grand_actual}" -gt "${grand_expected}" ]; then
    echo "NOTE: Grand total exceeds documented count (${grand_actual} > ${grand_expected})."
    echo "      Consider updating docs/test-counts.json to reflect the new counts."
  fi
  exit 0
fi
