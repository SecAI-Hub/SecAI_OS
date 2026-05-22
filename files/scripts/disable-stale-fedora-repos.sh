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

    # rpm-ostree still refreshes repositories with enabled_metadata=1 even
    # when enabled=0, so disable both flags for this stale metadata source.
    if grep -Eq '^[[:space:]]*enabled[[:space:]]*=' "$repo_file"; then
        sed -ri 's/^[[:space:]]*enabled[[:space:]]*=.*/enabled=0/' "$repo_file"
    else
        printf '\nenabled=0\n' >> "$repo_file"
    fi

    if grep -Eq '^[[:space:]]*enabled_metadata[[:space:]]*=' "$repo_file"; then
        sed -ri 's/^[[:space:]]*enabled_metadata[[:space:]]*=.*/enabled_metadata=0/' "$repo_file"
    else
        printf 'enabled_metadata=0\n' >> "$repo_file"
    fi

    disabled_file="${repo_file}.disabled-by-secai"
    mv -f "$repo_file" "$disabled_file"

    disabled_count=$((disabled_count + 1))
    echo "Disabled stale Fedora multimedia repository by moving ${repo_file} to ${disabled_file}."
done

if [[ "$disabled_count" -eq 0 ]]; then
    echo "No stale Fedora multimedia repository found."
fi
