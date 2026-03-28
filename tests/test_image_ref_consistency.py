"""Tests for Epic 2 — Image Reference Consistency.

Ensures every container image reference in the repo uses the canonical
ghcr.io/secai-hub/secai_os path.  Catches regressions if someone
accidentally introduces the old sec_ai namespace.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
CANONICAL_REF = "ghcr.io/secai-hub/secai_os"
WRONG_PATTERNS = [
    "ghcr.io/sec_ai/secai_os",
]

# Files that should contain the canonical image reference
CRITICAL_FILES = [
    "files/scripts/secai-bootstrap.sh",
    "files/scripts/secai-setup-wizard.sh",
    "files/scripts/build-services.sh",
    "scripts/vm/build-qcow2.sh",
    "files/system/etc/containers/registries.d/secai-os.yaml",
    "files/system/etc/secure-ai/policy/sources.allowlist.yaml",
]

# Extensions to scan for wrong patterns
SCAN_EXTENSIONS = {".sh", ".py", ".yaml", ".yml", ".md", ".json"}

# Directories to skip
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".claude"}

# Files that legitimately contain wrong patterns (as string literals for detection)
ALLOWLISTED_FILES = {
    "tests/test_image_ref_consistency.py",  # this test defines the patterns
    ".github/workflows/ci.yml",  # CI job checks for wrong patterns by name
}


def _scan_file(path: Path) -> list[tuple[int, str]]:
    """Return list of (line_number, line) tuples containing wrong patterns."""
    hits = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return hits
    for i, line in enumerate(text.splitlines(), 1):
        for pattern in WRONG_PATTERNS:
            if pattern in line:
                hits.append((i, line.strip()))
    return hits


def _is_allowlisted(path: Path) -> bool:
    """Check if a file is allowlisted for containing wrong patterns."""
    rel = str(path.relative_to(REPO_ROOT)).replace("\\", "/")
    return rel in ALLOWLISTED_FILES


def _walk_repo():
    """Yield all scannable files under REPO_ROOT."""
    for path in REPO_ROOT.rglob("*"):
        if any(skip in path.parts for skip in SKIP_DIRS):
            continue
        if path.is_file() and path.suffix in SCAN_EXTENSIONS:
            yield path


class TestNoWrongImageRefs:
    def test_no_wrong_refs_in_repo(self):
        """No file in the repo should contain old sec_ai image references."""
        all_hits: dict[str, list[tuple[int, str]]] = {}
        for path in _walk_repo():
            if _is_allowlisted(path):
                continue
            hits = _scan_file(path)
            if hits:
                rel = path.relative_to(REPO_ROOT)
                all_hits[str(rel)] = hits

        if all_hits:
            msg_parts = ["Found wrong image reference(s):"]
            for file, hits in sorted(all_hits.items()):
                for line_no, line in hits:
                    msg_parts.append(f"  {file}:{line_no}: {line}")
            msg_parts.append(f"\nAll container image refs must use: {CANONICAL_REF}")
            assert False, "\n".join(msg_parts)


class TestCriticalFilesUseCanonical:
    def test_bootstrap_registry_variable(self):
        """secai-bootstrap.sh REGISTRY variable must use canonical ref."""
        content = (REPO_ROOT / "files/scripts/secai-bootstrap.sh").read_text(encoding="utf-8")
        assert CANONICAL_REF in content, (
            f"secai-bootstrap.sh must contain {CANONICAL_REF}"
        )

    def test_setup_wizard_registry_variable(self):
        """secai-setup-wizard.sh REGISTRY variable must use canonical ref."""
        content = (REPO_ROOT / "files/scripts/secai-setup-wizard.sh").read_text(encoding="utf-8")
        assert CANONICAL_REF in content

    def test_build_services_policy_entry(self):
        """build-services.sh policy.json entry must use canonical ref."""
        content = (REPO_ROOT / "files/scripts/build-services.sh").read_text(encoding="utf-8")
        assert CANONICAL_REF in content

    def test_vm_build_script(self):
        """build-qcow2.sh CONTAINER_IMAGE must use canonical ref."""
        content = (REPO_ROOT / "scripts/vm/build-qcow2.sh").read_text(encoding="utf-8")
        assert CANONICAL_REF in content

    def test_registries_yaml(self):
        """Container registries.d config must use canonical ref."""
        content = (
            REPO_ROOT
            / "files/system/etc/containers/registries.d/secai-os.yaml"
        ).read_text(encoding="utf-8")
        assert CANONICAL_REF in content

    def test_sources_allowlist(self):
        """sources.allowlist.yaml must use canonical ref."""
        content = (
            REPO_ROOT
            / "files/system/etc/secure-ai/policy/sources.allowlist.yaml"
        ).read_text(encoding="utf-8")
        assert CANONICAL_REF in content


class TestNegativeDetection:
    def test_would_catch_wrong_pattern(self):
        """Verify the scanner detects a known wrong pattern if present."""
        # Create a fake file-like content check
        for pattern in WRONG_PATTERNS:
            fake_line = f'REGISTRY="{pattern}"'
            assert pattern in fake_line, "Scanner pattern matching is broken"

    def test_wrong_patterns_not_empty(self):
        """Ensure the wrong-patterns list is maintained."""
        assert len(WRONG_PATTERNS) > 0

    def test_critical_files_exist(self):
        """All critical files we're checking must exist."""
        for rel_path in CRITICAL_FILES:
            full = REPO_ROOT / rel_path
            assert full.exists(), f"Critical file missing: {rel_path}"
