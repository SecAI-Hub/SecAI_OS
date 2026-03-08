#!/usr/bin/env bash
# Verify all GitHub Actions use SHA-pinned versions
set -euo pipefail
ERRORS=0
for f in .github/workflows/*.yml .github/workflows/*.yaml; do
    [ -f "$f" ] || continue
    while IFS= read -r line; do
        # Match "uses: owner/repo@" lines that don't have a 40-char hex SHA
        if echo "$line" | grep -qE '^\s*-?\s*uses:\s+[^/]+/[^@]+@' && \
           ! echo "$line" | grep -qE '@[0-9a-f]{40}(\s|$)'; then
            echo "ERROR: $f has unpinned action: $(echo "$line" | sed 's/^[[:space:]]*//')"
            ERRORS=$((ERRORS + 1))
        fi
    done < "$f"
done
if [ $ERRORS -gt 0 ]; then
    echo "FAIL: $ERRORS unpinned action(s) found"
    exit 1
fi
echo "OK: All actions are SHA-pinned"
