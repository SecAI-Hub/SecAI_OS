#!/usr/bin/env bash
set -euo pipefail

repo_dir="/etc/yum.repos.d"
disabled_count=0

if [[ ! -d "$repo_dir" ]]; then
    echo "No yum repository directory present; skipping stale repo preflight."
    exit 0
fi

shopt -s nullglob
for repo_file in "$repo_dir"/*.repo; do
    if ! grep -Eiq '(^[[:space:]]*\[fedora-multimedia\]|negativo17\.org/.*/multimedia|fedora-multimedia)' "$repo_file"; then
        continue
    fi

    if grep -Eq '^[[:space:]]*enabled[[:space:]]*=' "$repo_file"; then
        sed -ri 's/^[[:space:]]*enabled[[:space:]]*=.*/enabled=0/' "$repo_file"
    else
        printf '\nenabled=0\n' >> "$repo_file"
    fi

    disabled_count=$((disabled_count + 1))
    echo "Disabled stale Fedora multimedia repository in ${repo_file}."
done

if [[ "$disabled_count" -eq 0 ]]; then
    echo "No stale Fedora multimedia repository found."
fi
