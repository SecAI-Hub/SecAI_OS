#!/usr/bin/env bash
#
# Refresh the committed Python wheelhouse.
#
# Usage: scripts/refresh-wheels.sh
#
# This script:
#   1. Collects all requirements.lock files from services/
#   2. Downloads wheels into vendor/wheels/
#   3. Regenerates vendor/wheels/SHA256SUMS
#   4. Reports size delta vs previous state
#
# IMPORTANT: This is the ONLY supported way to update vendor/wheels/.
# Ad hoc wheel drops directly into vendor/wheels/ without updating lockfiles
# will be caught by CI and rejected.
#
# After running this script, review the changes and include:
#   - License review for any new packages
#   - Size-delta note in the PR description
#
set -euo pipefail

WHEELS_DIR="vendor/wheels"
LOCKFILES=()

echo "=== Refreshing Python wheelhouse ==="

# Collect all lockfiles
for lockfile in services/*/requirements.lock; do
    if [ -f "$lockfile" ]; then
        LOCKFILES+=("$lockfile")
        echo "  Found: $lockfile"
    fi
done

if [ ${#LOCKFILES[@]} -eq 0 ]; then
    echo "WARNING: No requirements.lock files found in services/*/"
    echo "Create per-service lockfiles first:"
    echo "  pip-compile --generate-hashes -o services/<svc>/requirements.lock services/<svc>/pyproject.toml"
    exit 1
fi

# Record previous size for delta reporting
PREV_SIZE=0
if [ -d "$WHEELS_DIR" ]; then
    PREV_SIZE=$(du -sb "$WHEELS_DIR" 2>/dev/null | awk '{print $1}')
fi

# Clean and rebuild
rm -rf "${WHEELS_DIR:?}/"*.whl "${WHEELS_DIR:?}/SHA256SUMS"
mkdir -p "$WHEELS_DIR"

# Download wheels from all lockfiles
for lockfile in "${LOCKFILES[@]}"; do
    echo "Downloading wheels for: $lockfile"
    pip download \
        --require-hashes \
        --dest "$WHEELS_DIR" \
        -r "$lockfile" || {
            echo "FATAL: Failed to download wheels for $lockfile" >&2
            exit 1
        }
done

# Deduplicate (pip download may fetch the same wheel from multiple lockfiles)
echo "Deduplicating wheels..."
# Just keep unique filenames (pip download names them deterministically)

# Generate SHA256SUMS
echo "Generating SHA256SUMS..."
cd "$WHEELS_DIR"
if find . -maxdepth 1 -name '*.whl' -print -quit | grep -q .; then
    find . -maxdepth 1 -name '*.whl' -exec sha256sum -- {} + > SHA256SUMS
else
    echo "WARNING: No wheel files found in $WHEELS_DIR"
    touch SHA256SUMS
fi
cd - > /dev/null

# Report size delta
NEW_SIZE=$(du -sb "$WHEELS_DIR" 2>/dev/null | awk '{print $1}')
DELTA=$((NEW_SIZE - PREV_SIZE))
DELTA_MB=$(echo "scale=2; $DELTA / 1048576" | bc 2>/dev/null || echo "?")
TOTAL_MB=$(echo "scale=2; $NEW_SIZE / 1048576" | bc 2>/dev/null || echo "?")

echo ""
echo "=== Wheelhouse refreshed ==="
echo "  Total size:  ${TOTAL_MB} MB"
echo "  Size delta:  ${DELTA_MB} MB"
echo "  Wheel count: $(find "$WHEELS_DIR" -maxdepth 1 -name '*.whl' | wc -l)"
echo ""
echo "Next steps:"
echo "  1. Review new/updated packages for license compliance"
echo "  2. Note size delta in your PR description"
echo "  3. git add vendor/wheels/ && git commit"
