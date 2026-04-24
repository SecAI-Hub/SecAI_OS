#!/usr/bin/env bash
# Verify all Containerfiles use digest-pinned base images.
# Usage: .github/scripts/check-container-pins.sh
set -euo pipefail

ERRORS=0
WARNINGS=0

for f in $(find services/ -name 'Containerfile' -o -name 'Dockerfile'); do
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue

        if echo "$line" | grep -qE '^FROM '; then
            image_ref="$(echo "$line" | awk '{for (i = 2; i <= NF; i++) if ($i !~ /^--/) {print $i; break}}')"

            if [ "$image_ref" = "scratch" ]; then
                continue
            fi

            # Allow ARG-interpolated tags (e.g. ${COMPUTE}) with a warning
            if echo "$line" | grep -q '\${'; then
                if ! echo "$line" | grep -q '@sha256:'; then
                    echo "WARN: $f has dynamic unpinned base image: $line"
                    WARNINGS=$((WARNINGS + 1))
                fi
                continue
            fi

            if ! echo "$line" | grep -q '@sha256:'; then
                echo "ERROR: $f has unpinned base image: $line"
                ERRORS=$((ERRORS + 1))
            fi
        fi
    done < "$f"
done

if [ $WARNINGS -gt 0 ]; then
    echo "WARN: $WARNINGS dynamic base image(s) could not be verified (use per-variant pinning)"
fi

if [ $ERRORS -gt 0 ]; then
    echo "FAIL: $ERRORS unpinned base image(s) found"
    exit 1
fi

echo "OK: All static base images are digest-pinned"
