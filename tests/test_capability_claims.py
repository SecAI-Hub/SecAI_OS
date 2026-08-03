"""Regression tests for externally visible support and assurance claims.

Implementation milestones are not production certification.  These tests keep
the high-level documentation aligned with the release-evidence model so that a
future code change cannot silently reintroduce unsupported hardware or
assurance claims.
"""

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_current_fedora_release_is_consistent() -> None:
    checked_files = (
        "README.md",
        "recipes/recipe.yml",
        "docs/install/quickstart.md",
        "docs/install/bare-metal.md",
        "docs/install/vm.md",
        "docs/compatibility-matrix.md",
        "docs/support-lifecycle.md",
        "docs/security-status.md",
    )
    for relative in checked_files:
        content = _read(relative)
        assert "Fedora Silverblue 42" not in content, relative
        assert "Fedora 42 base" not in content, relative

    assert "Fedora Silverblue 44" in _read("docs/install/quickstart.md")
    assert "Fedora Silverblue 44" in _read("docs/compatibility-matrix.md")


def test_capability_matrix_defines_evidence_statuses() -> None:
    matrix = _read("docs/capability-matrix.md")
    for status in (
        "**Verified**",
        "**Implemented**",
        "**Experimental**",
        "**Hardware-dependent**",
        "**Sandbox-only**",
        "**Planned**",
    ):
        assert status in matrix

    assert "implementation milestone" in matrix.lower()
    assert "release-specific evidence" in matrix


def test_apple_and_hsm_claims_are_not_overstated() -> None:
    readme = _read("README.md")
    support = _read("docs/support-lifecycle.md")
    status = _read("docs/security-status.md")

    assert "Apple" in readme and "Sandbox/dev only" in readme
    assert "Apple" in support and "No native Fedora appliance" in support
    assert "PKCS#11 is a degraded/stub provider" in status
    assert "Full PKCS#11 HSM operations | Planned" in status


def test_release_checklist_is_evidence_not_a_badge() -> None:
    checklist = _read("docs/production-readiness-checklist.md")
    assert "template, not evidence" in checklist
    assert "immutable source commit and image digest" in checklist
    assert "All 10 core services" not in checklist
    assert "Reboot recreates/loads every per-service credential" in checklist


def test_security_enforcement_is_not_exposed_as_an_unused_toggle() -> None:
    """Configuration must not imply that non-consumed flags change enforcement."""
    appliance = _read("files/system/etc/secure-ai/config/appliance.yaml")
    schema = _read("schemas/appliance.schema.json")
    for obsolete_flag in (
        "auto_reseal_on_update",
        "seccomp_enabled",
        "landlock_enabled",
    ):
        assert obsolete_flag not in appliance
        assert obsolete_flag not in schema

    assert "SystemCallFilter=" in appliance
    assert "fail-closed" in appliance
    assert "IPAddressDeny=any" in appliance


def test_quarantine_policy_cannot_disable_mandatory_admission_gates() -> None:
    policy = _read("files/system/etc/secure-ai/policy/policy.yaml")
    schema = json.loads(_read("schemas/policy.schema.json"))
    documentation = _read("docs/policy-schema.md")

    for obsolete_flag in (
        "require_source_verification",
        "require_entropy_analysis",
    ):
        assert obsolete_flag not in policy
        assert obsolete_flag not in json.dumps(schema)
        assert obsolete_flag not in documentation
    assert "\n  stages:" not in policy
    assert "Pipeline Stages Cannot Be Disabled" in _read(
        "examples/promote-through-quarantine.md"
    )

    model_properties = schema["properties"]["models"]["properties"]
    for required_gate in (
        "require_scan",
        "require_yara",
        "require_modelaudit",
        "require_behavior_tests",
    ):
        assert model_properties[required_gate]["const"] is True
    assert (
        schema["properties"]["gguf_guard"]["properties"]["required"]["const"]
        is True
    )


def test_codeowners_references_existing_repository_owner() -> None:
    owners = _read(".github/CODEOWNERS")
    assert "@SecAI-Hub" in owners
    assert "@sec_ai" not in owners


def _required_ruleset_checks(path: str) -> set[str]:
    ruleset = json.loads(_read(path))
    assert ruleset["enforcement"] == "active"
    rules = {entry["type"]: entry for entry in ruleset["rules"]}
    assert {
        "deletion",
        "non_fast_forward",
        "pull_request",
        "required_status_checks",
    } <= set(rules)
    assert rules["pull_request"]["parameters"]["require_code_owner_review"] is True
    assert rules["pull_request"]["parameters"]["required_approving_review_count"] >= 1
    return {
        entry["context"]
        for entry in rules["required_status_checks"]["parameters"][
            "required_status_checks"
        ]
    }


def test_declared_rulesets_protect_main_and_release_with_every_ci_check() -> None:
    main = json.loads(_read(".github/rulesets/main.json"))
    release = json.loads(_read(".github/rulesets/release.json"))
    assert main["conditions"]["ref_name"]["include"] == ["~DEFAULT_BRANCH"]
    assert release["conditions"]["ref_name"]["include"] == [
        "refs/heads/stable",
        "refs/heads/release/*",
    ]

    main_checks = _required_ruleset_checks(".github/rulesets/main.json")
    release_checks = _required_ruleset_checks(".github/rulesets/release.json")
    workflow_names = set(
        re.findall(r"^\s{4}name:\s+(.+?)\s*$", _read(".github/workflows/ci.yml"), re.M)
    )
    release_gate = "Release Branch Hardened Gate"
    assert main_checks == workflow_names - {release_gate}
    assert release_checks == workflow_names

    workflow = _read(".github/workflows/ci.yml")
    assert "github.event_name == 'pull_request'" in workflow
    assert "startsWith(github.base_ref, 'release/')" in workflow
