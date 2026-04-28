# Branch Protection Rules

Required branch protection settings for SecAI OS release infrastructure.
Configure these in GitHub Settings > Branches > Add branch protection rule,
or use the setup script below.

Last updated: 2026-04-28

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

All 8 of these must pass before a PR can merge into a release branch:

1. **Go Build & Test** (`go-build-and-test`) -- Builds and tests all 9 Go services with race detector
2. **Python Test & Lint** (`python-test`) -- Ruff, bandit, mypy, unit/integration tests, adversarial + M5 acceptance
3. **Security Regression Tests** (`security-regression`) -- Adversarial tests (Python + Go MCP/policy/incident-recorder)
4. **Hadolint & Semgrep** (`appsec-lint`) -- Container linting plus repo-owned application security rules
5. **Dependency Vulnerability Audit** (`dependency-audit`) -- govulncheck + pip-audit with waiver mechanism
6. **Test Count Drift Check** (`test-count-check`) -- Ensures test counts do not drop below documented floor
7. **Documentation Validation** (`docs-validation`) -- Broken links, required docs, milestone count consistency, test references
8. **Release Branch Hardened Gate** (`release-gate`) -- Zero-tolerance bandit, CVE-ID govulncheck waivers, M5 acceptance re-run

The `release-gate` job has `needs:` on all of the above, so configuring it as the sole required check is sufficient.
However, listing all 8 makes failure diagnosis easier in the GitHub UI.

---

## `stable` branch

Same settings as `release/*`, plus:

| Setting | Value |
|---------|-------|
| Restrict who can push | Maintainers only |
| Require conversation resolution | Yes |

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
