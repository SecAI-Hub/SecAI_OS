# Branch Protection Rules

Required branch protection settings for SecAI OS release infrastructure.
Configure these in GitHub Settings > Branches > Add branch protection rule,
or use the setup script below.

Last updated: 2026-07-27

The canonical repository ruleset is
[`rulesets/main-and-release.json`](rulesets/main-and-release.json). Applying the
file is an administrative action and must be reviewed before it replaces or
updates an active GitHub ruleset.

## `main`

`main` is protected by the canonical ruleset. Changes require a pull request,
one approval from a code owner, resolution of review threads, and a fresh
approval after the last push. Force pushes and deletion are denied. The CI
checks named in the ruleset are mandatory and branches must be up to date.

---

## `release/*` branches

| Setting | Value |
|---------|-------|
| Require pull request before merging | Yes |
| Required approvals | 1 |
| Dismiss stale reviews | Yes |
| Require status checks to pass | Yes |
| Required status checks | See list below |
| Require branches to be up to date | Yes |
| Require signed commits | Recommended |
| Allow force pushes | No |
| Allow deletions | No |

### Required status checks for `release/*`

All required checks in the canonical ruleset must pass before a PR can merge.
The release-only hardened gate is additionally required for `release/*` and
`stable`:

1. **Go Build & Test** (`go-build-and-test`)
2. **Python Test & Lint** (`python-test`)
3. **Shell Script Lint** (`shellcheck`)
4. **Hadolint & Semgrep** (`appsec-lint`)
5. **Validate YAML configs** (`policy-validate`)
6. **Image Reference Consistency** (`image-ref-consistency`)
7. **Verify action, container, and EOL pins** (`check-pins`)
8. **Supply Chain & SBOM Verification** (`supply-chain-verify`)
9. **Security Regression Tests** (`security-regression`)
10. **Test Count Drift Check** (`test-count-check`)
11. **Dependency Vulnerability Audit** (`dependency-audit`)
12. **Documentation Validation** (`docs-validation`)
13. **Release Branch Hardened Gate** (`release-gate`, release/stable only)

Do not configure only the aggregate release gate. Explicit required checks
prevent a workflow refactor from silently dropping a security job.

---

## `stable` branch

Same settings as `release/*`, plus:

| Setting | Value |
|---------|-------|
| Restrict who can push | Maintainers only |
| Require conversation resolution | Yes |

---

## `release` signing environment

Create a GitHub Environment named `release` and configure:

| Setting | Value |
|---------|-------|
| Required reviewers | At least 1 maintainer who cannot approve their own run |
| Prevent self-review | Enabled |
| Deployment branches/tags | `main`, `release/*`, `stable`, and protected `v*` tags only |
| Environment secret | `SIGNING_SECRET` |

Remove `SIGNING_SECRET` from repository-level and organization-level Actions
secrets after the environment secret is confirmed. The unprivileged pull
request BlueBuild job has only `contents: read`, sets `push: false`, and never
references this secret. Only the non-PR publish job enters the `release`
environment and receives package, OIDC, attestation, and signing authority.

---

## What the release-gate adds over dev CI

| Check | Dev CI (`main` / PRs) | Release branches |
|-------|----------------------|------------------|
| Bandit severity gate | HIGH severity + HIGH confidence | HIGH severity at **any** confidence |
| Go vuln waiver matching | Count-based subtraction | CVE-ID matching (per-vulnerability) |
| M5 acceptance suite | Runs in `python-test` | Re-runs in dedicated `release-gate` step |
| Container pin check | Checked (since M53) | Same |
| Docs consistency | Milestone counts + test refs (since M53) | Same |

---

## Setup Script

Run from a machine with the `gh` CLI authenticated as a repository admin.

**Note:** The GitHub API endpoint for branch protection rules with wildcard
patterns (`release/*`) requires using rulesets. The script below uses the
branch protection API for `stable` (exact name) and documents the UI steps
for wildcard patterns.

### For `stable` branch (exact match -- API supported)

```bash
#!/usr/bin/env bash
set -euo pipefail

OWNER="SecAI-Hub"
REPO="SecAI_OS"

gh api -X PUT "repos/${OWNER}/${REPO}/branches/stable/protection" \
  --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [],
    "checks": [
      {"context": "Go Build & Test"},
      {"context": "Python Test & Lint"},
      {"context": "Security Regression Tests"},
      {"context": "Hadolint & Semgrep"},
      {"context": "Dependency Vulnerability Audit"},
      {"context": "Test Count Drift Check"},
      {"context": "Documentation Validation"},
      {"context": "Release Branch Hardened Gate"}
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF
echo "OK: Branch protection set for stable"
```

### For `release/*` branches (wildcard -- use GitHub UI)

1. Go to **Settings > Branches > Add branch protection rule**
2. Branch name pattern: `release/*`
3. Enable all settings listed in the table above
4. Under "Require status checks to pass", add all 8 check names listed above
5. Save changes
