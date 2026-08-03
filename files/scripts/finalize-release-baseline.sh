#!/usr/bin/env bash
# Generate immutable measurements only after every recipe module that can
# change release-scoped files has completed. BlueBuild's automatic post-build
# cleanup touches /var, so all candidates must live under immutable /usr or
# policy-owned /etc paths.
set -euo pipefail
umask 022

readonly SOURCE_MANIFEST="/tmp/SOURCE_PREP_MANIFEST.json"
readonly GENERATOR="/tmp/files/scripts/generate-release-baseline.py"
readonly POLICY_JSON="/etc/containers/policy.json"
readonly REGISTRIES_CONFIG="/etc/containers/registries.d/secai-os.yaml"
readonly COSIGN_PUBLIC_KEY="/etc/pki/containers/secai-cosign.pub"
readonly RELEASE_BASELINE="/usr/share/secure-ai/integrity/release-baseline.json"
readonly IMAGE_REPOSITORY="ghcr.io/secai-hub/secai_os"

fail() {
    echo "FATAL: $1" >&2
    exit 1
}

for required_file in \
    "$SOURCE_MANIFEST" \
    "$GENERATOR" \
    "$POLICY_JSON" \
    "$REGISTRIES_CONFIG" \
    "$COSIGN_PUBLIC_KEY"; do
    if [ ! -f "$required_file" ] || [ -L "$required_file" ]; then
        fail "unsafe or missing finalization input: ${required_file}"
    fi
done

source_commit="$(
    python3 - "$SOURCE_MANIFEST" <<'PY'
import json
import re
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
source_commit = manifest.get("commit_sha")
if not isinstance(source_commit, str) or re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
    raise SystemExit("source-prep manifest has no immutable commit_sha")
print(source_commit)
PY
)" || fail "could not extract the verified source commit"

python3 - \
    "$POLICY_JSON" \
    "$REGISTRIES_CONFIG" \
    "$COSIGN_PUBLIC_KEY" \
    "$IMAGE_REPOSITORY" <<'PY'
import json
import sys
from pathlib import Path

import yaml

policy_path, registries_path, key_path = map(Path, sys.argv[1:4])
repository = sys.argv[4]

policy = json.loads(policy_path.read_text(encoding="utf-8"))
if policy.get("default") != [{"type": "reject"}]:
    raise SystemExit("container signing policy is not reject-by-default")

expected_rule = [
    {
        "type": "sigstoreSigned",
        "keyPath": str(key_path),
        "signedIdentity": {"type": "matchRepository"},
    }
]
actual_rule = policy.get("transports", {}).get("docker", {}).get(repository)
if actual_rule != expected_rule:
    raise SystemExit("container signing policy does not contain the approved SecAI rule")

registries = yaml.safe_load(registries_path.read_text(encoding="utf-8"))
if registries != {
    "docker": {repository: {"use-sigstore-attachments": True}}
}:
    raise SystemExit("registry attachment policy does not match the approved SecAI rule")
PY

python3 "$GENERATOR" --source-commit "$source_commit" || \
    fail "release integrity baseline generation failed"

if [ ! -f "$RELEASE_BASELINE" ] || [ -L "$RELEASE_BASELINE" ]; then
    fail "release integrity baseline was not written safely"
fi

echo "Final release baseline bound to source commit ${source_commit}"
