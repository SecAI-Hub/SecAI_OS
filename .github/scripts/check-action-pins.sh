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
            trimmed="${line#"${line%%[![:space:]]*}"}"
            echo "ERROR: $f has unpinned action: ${trimmed}"
            ERRORS=$((ERRORS + 1))
        fi
    done < "$f"
done
if [ $ERRORS -gt 0 ]; then
    echo "FAIL: $ERRORS unpinned action(s) found"
    exit 1
fi

# actions/checkout stores its token in the local Git configuration unless
# explicitly disabled. Read-only jobs do not need that credential after the
# checkout step, so enforce least privilege for every workflow.
python3 - <<'PY'
from pathlib import Path

errors = 0
for workflow in sorted(Path(".github/workflows").glob("*.y*ml")):
    lines = workflow.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if "uses: actions/checkout@" not in line:
            continue
        step_indent = len(line) - len(line.lstrip())
        block = []
        for candidate in lines[index + 1 :]:
            indent = len(candidate) - len(candidate.lstrip())
            if candidate.strip().startswith("- ") and indent <= step_indent:
                break
            block.append(candidate)
        if not any(
            candidate.strip() == "persist-credentials: false"
            for candidate in block
        ):
            print(
                f"ERROR: {workflow}:{index + 1}: checkout must set "
                "persist-credentials: false"
            )
            errors += 1

if errors:
    print(f"FAIL: {errors} checkout step(s) retain credentials")
    raise SystemExit(1)
PY

echo "OK: All actions are SHA-pinned and checkout credentials are not persisted"
