# Branch Protection Rules

Required branch protection settings for SecAI OS release infrastructure.
Configure these in GitHub Settings > Branches > Add branch protection rule,
or use the setup script below.

Last updated: 2026-08-02

The canonical repository rulesets are [`rulesets/main.json`](rulesets/main.json)
and [`rulesets/release.json`](rulesets/release.json). Applying either file is an
administrative action and must be reviewed before it replaces or updates an
active GitHub ruleset.

Hosted-state note (verified 2026-08-02): the active `basic` repository ruleset
currently prevents branch deletion and non-fast-forward updates, but the
canonical pull-request and required-check policy below is not yet active. Do
not describe the hosted repository as fully protected until the API/UI state
matches this file. Requiring an independent approval also requires an eligible
reviewer other than the change author; enabling it on a single-maintainer
repository can deadlock releases.

## `main`

When the canonical ruleset is applied, changes to `main` require a pull request,
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

1. **Secret Scan (Current Tree + Git History)** (`secret-scan`)
2. **Go Build & Test** (`go-build-and-test`)
3. **Python Test & Lint** (`python-test`)
4. **Windows Sandbox Security Qualification** (`windows-sandbox-security`)
5. **Shell Script Lint** (`shellcheck`)
6. **Release Helper Script Smoke** (`release-helper-smoke`)
7. **Hadolint & Semgrep** (`appsec-lint`)
8. **Validate YAML configs** (`policy-validate`)
9. **Image Reference Consistency** (`image-ref-consistency`)
10. **Verify action, container, and EOL pins** (`check-pins`)
11. **Supply Chain & SBOM Verification** (`supply-chain-verify`)
12. **Sandbox OpenVEX Smoke** (`sandbox-vex-smoke`)
13. **Security Regression Tests** (`security-regression`)
14. **Test Count Drift Check** (`test-count-check`)
15. **Dependency Vulnerability Audit** (`dependency-audit`)
16. **Documentation Validation** (`docs-validation`)
17. **Release Branch Hardened Gate** (`release-gate`, release/stable only)

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

## Applying the desired rulesets

Run from a machine where `gh` is authenticated as a repository administrator.
Before applying either file, confirm that an eligible independent reviewer is
available and that every named check has completed successfully on the current
default branch. Otherwise the no-bypass pull-request rule can intentionally
block all merges.

Inspect the live rulesets first:

```bash
gh api repos/SecAI-Hub/SecAI_OS/rulesets
```

After review, create the two desired rulesets:

```bash
gh api --method POST repos/SecAI-Hub/SecAI_OS/rulesets \
  --input .github/rulesets/main.json
gh api --method POST repos/SecAI-Hub/SecAI_OS/rulesets \
  --input .github/rulesets/release.json
```

Use `PUT repos/SecAI-Hub/SecAI_OS/rulesets/<id>` with the corresponding JSON
file when updating an existing canonical ruleset. Do not delete or disable the
active baseline deletion/non-fast-forward ruleset until the replacement is
confirmed `active` through a fresh API read.
