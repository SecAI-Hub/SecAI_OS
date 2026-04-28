#!/usr/bin/env bash
# Keep shell/config files portable across Linux, macOS, and Windows checkouts.
set -euo pipefail

errors=0

is_checked_file() {
    case "$1" in
        *.sh|*.py|*.service|*.timer|*.socket|*.target|*.path|*.mount|\
        *.yml|*.yaml|*.json|*.toml|*.md|*.lock|*.yar|\
        Containerfile|*/Containerfile|Containerfile.*|*/Containerfile.*|\
        Dockerfile|*/Dockerfile|Dockerfile.*|*/Dockerfile.*|\
        Makefile|*/Makefile|.gitattributes)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

while IFS= read -r -d '' file; do
    if ! is_checked_file "$file"; then
        continue
    fi
    if grep -Iq . "$file" && grep -q $'\r' "$file"; then
        echo "ERROR: CRLF detected in $file"
        errors=$((errors + 1))
    fi
done < <(git ls-files -z)

if [ "$errors" -gt 0 ]; then
    echo "FAIL: $errors text file(s) contain CRLF line endings"
    exit 1
fi

echo "OK: checked text files use LF line endings"
