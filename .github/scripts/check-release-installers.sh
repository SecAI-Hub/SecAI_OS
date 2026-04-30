#!/usr/bin/env bash
#
# Smoke-test release helper scripts without building large images.
#
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

shell_scripts=(
    scripts/release/secai-os-build-iso.sh
    scripts/release/secai-os-build-usb.sh
    scripts/release/secai-os-run-docker.sh
)

for script in "${shell_scripts[@]}"; do
    echo "=== ${script} ==="
    test -f "$script"
    bash -n "$script"
    bash "$script" --help >/dev/null
done

if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -s bash "${shell_scripts[@]}" .github/scripts/check-release-installers.sh
fi

bash scripts/release/secai-os-build-iso.sh \
    --dry-run \
    --tag v0.0.0 \
    --output-dir /tmp/secai-os-iso-smoke >/dev/null

bash scripts/release/secai-os-build-usb.sh \
    --dry-run \
    --tag v0.0.0 \
    --output-dir /tmp/secai-os-usb-smoke >/dev/null

bash scripts/release/secai-os-run-docker.sh \
    --dry-run \
    --tag v0.0.0 \
    --install-dir /tmp/secai-os-docker-smoke \
    --profile full-lab \
    --with-inference >/dev/null

pwsh_bin=""
if command -v pwsh >/dev/null 2>&1; then
    pwsh_bin="pwsh"
elif command -v powershell >/dev/null 2>&1; then
    pwsh_bin="powershell"
fi

if [[ -n "$pwsh_bin" ]]; then
    # shellcheck disable=SC2016
    "$pwsh_bin" -NoProfile -Command \
        '$null = [scriptblock]::Create((Get-Content scripts/release/secai-os-run-docker.ps1 -Raw)); Write-Output "PowerShell parse OK"'
    "$pwsh_bin" -NoProfile -File scripts/release/secai-os-run-docker.ps1 \
        -DryRun \
        -Tag v0.0.0 \
        -InstallDir /tmp/secai-os-docker-ps-smoke \
        -Profile full-lab \
        -WithInference >/dev/null
else
    echo "WARN: PowerShell not available; skipped .ps1 parse smoke"
fi

echo "OK: release helper scripts passed smoke checks"
