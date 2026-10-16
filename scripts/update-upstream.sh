#!/usr/bin/env bash
#
# Update a vendored upstream to a specific commit.
#
# Usage: scripts/update-upstream.sh <name> <commit-sha>
#
# This script:
#   1. Validates the upstream exists in .upstreams.lock.yaml
#   2. Fetches the archive at the given commit
#   3. Records the downloaded archive SHA256 (not independent authentication)
#   4. Performs a git subtree pull into upstreams/<name>/
#   5. Updates .upstreams.lock.yaml with the new commit, checksum, and date
#
# Requirements: git, curl, sha256sum, python3 with PyYAML, mktemp
#
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <name> <full-lowercase-commit-sha>" >&2
    exit 2
fi
NAME="$1"
COMMIT="$2"
if [[ ! "$NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]] ||
   [[ ! "$COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    echo "FATAL: expected a simple upstream name and full lowercase 40-digit commit SHA" >&2
    exit 2
fi

LOCK_FILE=".upstreams.lock.yaml"
LOCAL_PATH="upstreams/${NAME}"

if [ ! -f "$LOCK_FILE" ]; then
    echo "FATAL: ${LOCK_FILE} not found" >&2
    exit 1
fi

# Extract upstream URL from the lock manifest
UPSTREAM_URL=$(python3 - "$LOCK_FILE" "$NAME" <<'PY'
import sys
import yaml

with open(sys.argv[1], encoding='utf-8') as f:
    data = yaml.safe_load(f)
entry = data.get('upstreams', {}).get(sys.argv[2])
if not isinstance(entry, dict):
    print('NOT_FOUND', file=sys.stderr)
    sys.exit(1)
print(entry['upstream_url'])
PY
) || { echo "FATAL: '${NAME}' not found in ${LOCK_FILE}" >&2; exit 1; }

# The archive URL convention below is specific to GitHub HTTPS repositories.
if [[ ! "$UPSTREAM_URL" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    echo "FATAL: expected a GitHub HTTPS repository URL" >&2
    exit 1
fi

echo "=== Updating upstream: ${NAME} ==="
echo "  URL:    ${UPSTREAM_URL}"
echo "  Commit: ${COMMIT}"
echo "  Path:   ${LOCAL_PATH}"

# Fetch archive and compute SHA256
ARCHIVE_URL="${UPSTREAM_URL%.git}/archive/${COMMIT}.tar.gz"
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/secai-upstream.XXXXXXXXXX")
ARCHIVE_FILE="${WORK_DIR}/archive.tar.gz"
cleanup() {
    rm -f -- "$ARCHIVE_FILE"
    rmdir -- "$WORK_DIR"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

echo "Fetching archive: ${ARCHIVE_URL}"
curl --proto '=https' --proto-redir '=https' --connect-timeout 30 --max-time 600 \
    -fsSL -o "${ARCHIVE_FILE}" "${ARCHIVE_URL}"

ARCHIVE_SHA256=$(sha256sum "${ARCHIVE_FILE}" | awk '{print $1}')
echo "  SHA256: ${ARCHIVE_SHA256}"

# Perform subtree merge
if [ -d "${LOCAL_PATH}" ]; then
    echo "Updating existing subtree..."
    git subtree pull --prefix="${LOCAL_PATH}" "${UPSTREAM_URL}" "${COMMIT}" \
        --squash -m "chore: update upstream ${NAME} to ${COMMIT:0:12}"
else
    echo "Adding new subtree..."
    git subtree add --prefix="${LOCAL_PATH}" "${UPSTREAM_URL}" "${COMMIT}" \
        --squash -m "chore: add upstream ${NAME} at ${COMMIT:0:12}"
fi

# Update the lock manifest
SYNC_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
python3 - "$LOCK_FILE" "$NAME" "$COMMIT" "$ARCHIVE_SHA256" "$LOCAL_PATH" "$SYNC_DATE" "$UPSTREAM_URL" <<'PY'
import os
from pathlib import Path
import stat
import sys
import tempfile
import yaml

lock, name, commit, checksum, local_path, date, upstream_url = sys.argv[1:]
path = Path(lock)
original = path.read_text(encoding='utf-8')
data = yaml.safe_load(original)
entry = data['upstreams'][name]
if entry['upstream_url'] != upstream_url:
    raise SystemExit('FATAL: upstream URL changed during update; review subtree and lock')
entry.update(pinned_commit=commit, archive_sha256=checksum,
             local_path=local_path, sync_date=date)
header = []
for line in original.splitlines(keepends=True):
    if line.strip() and not line.startswith('#'):
        break
    header.append(line)
# Prepare the whole lock before replacing it; serialization/write failures leave
# the old lock intact. Git subtree may already have committed its source changes.
temporary = None
try:
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                     prefix='.upstreams-update-', delete=False) as f:
        temporary = f.name
        os.fchmod(f.fileno(), stat.S_IMODE(path.stat().st_mode))
        f.write(''.join(header))
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)
finally:
    if temporary is not None and os.path.exists(temporary):
        os.unlink(temporary)
PY

echo ""
echo "=== Updated ${NAME} ==="
echo "  Commit:  ${COMMIT}"
echo "  SHA256:  ${ARCHIVE_SHA256}"
echo "  Synced:  ${SYNC_DATE}"
echo ""
echo "Next steps:"
echo "  git subtree has committed its source change; review that commit as well."
echo "  The archive checksum records this HTTPS download; review the selected source independently."
echo "  1. Review the changes: git diff"
echo "  2. Run tests: make test"
echo "  3. Commit: git add ${LOCAL_PATH} ${LOCK_FILE} && git commit"
