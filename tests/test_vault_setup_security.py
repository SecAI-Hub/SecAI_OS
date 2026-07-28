"""Static security invariants for the destructive vault setup ceremony."""

from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SETUP = (
    REPO_ROOT
    / "files"
    / "system"
    / "usr"
    / "libexec"
    / "secure-ai"
    / "setup-vault.sh"
)


def test_setup_requires_root_and_exact_target_confirmation():
    content = SETUP.read_text()
    assert 'if [ "$(id -u)" -ne 0 ]' in content
    assert 'Type ERASE $PARTITION to continue' in content
    assert '"ERASE $PARTITION"' in content


def test_setup_restricts_and_revalidates_block_device():
    content = SETUP.read_text()
    assert 'DEVICE_TYPE=$(lsblk -dnro TYPE "$PARTITION")' in content
    assert '"part"' in content and '"lvm"' in content
    assert 'blockdev --getro "$PARTITION"' in content
    assert "active swap" in content
    assert "/holders" in content
    assert "MAJ:MIN" in content
    assert "Block device identity changed after confirmation" in content


def test_setup_uses_luks2_argon2id_and_no_discard():
    content = SETUP.read_text()
    assert "cryptsetup luksFormat --type luks2" in content
    assert "--pbkdf argon2id" in content
    assert "--batch-mode" in content
    assert "luks,discard" not in content


def test_setup_mount_and_persistent_options_are_restrictive():
    content = SETUP.read_text()
    assert "mount -o nodev,nosuid,noexec" in content
    assert "defaults,nodev,nosuid,noexec" in content
    assert "os.replace" in content
    assert "os.fsync" in content
    assert "refusing symlink configuration" in content


def test_setup_cleans_partial_mapper_and_enrolls_canary():
    content = SETUP.read_text()
    assert "trap cleanup EXIT INT TERM" in content
    assert 'cryptsetup close "$MAPPER_NAME"' in content
    assert "/usr/libexec/secure-ai/canary-place.sh" in content
    assert "Vault setup succeeded, but canary enrollment failed" in content


def test_setup_refuses_plaintext_under_unmounted_vault():
    content = SETUP.read_text()
    assert 'findmnt -rn --mountpoint "$MOUNT_POINT"' in content
    assert "contains data while the vault is unmounted" in content
    assert "known, empty compatibility directories" in content


def test_setup_creates_and_verifies_exact_vault_contract():
    content = SETUP.read_text()
    assert 'chmod 0711 "$MOUNT_POINT"' in content
    assert '"schema_version": 1' in content
    assert '"mapper": "secure-ai-vault"' in content
    assert "/usr/libexec/secure-ai/verify-vault-mount.py" in content
    assert "secure-ai-vault-mounted.service" in content


def test_setup_failure_closes_unverified_vault():
    content = SETUP.read_text()
    complete_assignment = content.index("COMPLETE=true")
    exact_verification = content.index(
        "/usr/libexec/secure-ai/verify-vault-mount.py"
    )
    assert complete_assignment > exact_verification
    assert "will be unmounted and closed" in content
