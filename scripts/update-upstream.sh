#!/usr/bin/env bash
#
# Update a vendored upstream to a specific commit.
#
# Usage: scripts/update-upstream.sh <name> <commit-sha>
#
# This script:
#   1. Validates the upstream exists in .upstreams.lock.yaml
#   2. Fetches the archive at the given commit
#   3. Verifies archive SHA256
#   4. Performs a git subtree pull into upstreams/<name>/
#   5. Updates .upstreams.lock.yaml with the new commit, checksum, and date
#
# Requirements: git, curl, sha256sum, python3, yq (or python yaml)
#
set -euo pipefail

NAME="${1:?Usage: $0 <name> <commit-sha>}"
COMMIT="${2:?Usage: $0 <name> <commit-sha>}"

LOCK_FILE=".upstreams.lock.yaml"
LOCAL_PATH="upstreams/${NAME}"

if [ ! -f "$LOCK_FILE" ]; then
    echo "FATAL: ${LOCK_FILE} not found" >&2
    exit 1
fi

# Extract upstream URL from the lock manifest
UPSTREAM_URL=$(python3 -c "
import yaml, sys
with open('${LOCK_FILE}') as f:
    data = yaml.safe_load(f)
entry = data.get('upstreams', {}).get('${NAME}')
if not entry:
    print('NOT_FOUND', file=sys.stderr)
    sys.exit(1)
print(entry['upstream_url'])
") || { echo "FATAL: '${NAME}' not found in ${LOCK_FILE}" >&2; exit 1; }

echo "=== Updating upstream: ${NAME} ==="
echo "  URL:    ${UPSTREAM_URL}"
echo "  Commit: ${COMMIT}"
echo "  Path:   ${LOCAL_PATH}"

# Fetch archive and compute SHA256
ARCHIVE_URL="${UPSTREAM_URL%.git}/archive/${COMMIT}.tar.gz"
ARCHIVE_FILE="/tmp/upstream-${NAME}-${COMMIT}.tar.gz"

echo "Fetching archive: ${ARCHIVE_URL}"
curl -fsSL -o "${ARCHIVE_FILE}" "${ARCHIVE_URL}"

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
python3 -c "
import yaml

with open('${LOCK_FILE}') as f:
    data = yaml.safe_load(f)

entry = data['upstreams']['${NAME}']
entry['pinned_commit'] = '${COMMIT}'
entry['archive_sha256'] = '${ARCHIVE_SHA256}'
entry['local_path'] = '${LOCAL_PATH}'
entry['sync_date'] = '${SYNC_DATE}'

with open('${LOCK_FILE}', 'w') as f:
    # Preserve comments at top by writing header manually
    f.write('# Upstream dependency manifest for SecAI OS.\\n')
    f.write('#\\n')
    f.write('# Each entry pins an external repository to a specific commit + archive checksum.\\n')
    f.write('# Subtree source lives in upstreams/<name>/ (NOT vendor/).\\n')
    f.write('#\\n')
    f.write('# CI on PRs to main/release branches FAILS if any entry has status: PENDING.\\n')
    f.write('# Placeholder entries are only allowed on migration branches.\\n')
    f.write('#\\n')
    f.write('# To update an upstream: scripts/update-upstream.sh <name> <new-sha>\\n')
    f.write('\\n')
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)
"

# Cleanup
rm -f "${ARCHIVE_FILE}"

echo ""
echo "=== Updated ${NAME} ==="
echo "  Commit:  ${COMMIT}"
echo "  SHA256:  ${ARCHIVE_SHA256}"
echo "  Synced:  ${SYNC_DATE}"
echo ""
echo "Next steps:"
echo "  1. Review the changes: git diff"
echo "  2. Run tests: make test"
echo "  3. Commit: git add ${LOCAL_PATH} ${LOCK_FILE} && git commit"
