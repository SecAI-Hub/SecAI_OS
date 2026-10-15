"""The source handoff must reject substitution before any native build/install."""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("stage_tor_inputs", ROOT / "scripts/stage-tor-inputs.py")
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
verify = stage.verify


def sha(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def contract_fixture(tmp_path, monkeypatch):
    contract_root = tmp_path / "contract"
    contract_root.mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()
    lock = json.loads((ROOT / "build/tor/source.lock.json").read_text())
    # These are transport fixtures, not a signed Tor release. Crypto acceptance
    # is tested independently and the real retained release has an actual-GPG
    # staging smoke; this fixture isolates content/bundle substitution checks.
    for name, row in lock["remote_inputs"].items():
        data = ("approved cache " + name).encode()
        (cache / name).write_bytes(data)
        row.update(bytes=len(data), sha256=sha(data))
    for name, row in lock["local_inputs"].items():
        data = ("approved committed " + name).encode()
        path = contract_root / row["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        row.update(bytes=len(data), sha256=sha(data))
    (contract_root / "source.lock.json").write_text(json.dumps(lock) + "\n")
    calls = []
    monkeypatch.setattr(stage, "CONTRACT_ROOT", contract_root)
    monkeypatch.setattr(verify, "authenticate_upstream", lambda output, contract: calls.append(output))
    return contract_root, cache, calls


def test_offline_stage_binds_every_input_and_requires_authentication(contract_fixture, tmp_path):
    contract, cache, calls = contract_fixture
    output = tmp_path / "staged"
    manifest = stage.stage_inputs(output, cache)
    assert len(calls) == 1
    assert manifest["contract_sha256"] == sha((contract / "source.lock.json").read_bytes())
    assert set(manifest["inputs"]) == {p.name for p in output.iterdir()} - {"TOR_SOURCE_MANIFEST.json"}
    assert all(p.stat().st_mode & 0o222 == 0 for p in output.iterdir())
    outer = tmp_path / "global.json"
    outer.write_text(json.dumps({"tor_source_manifest_sha256": sha((output / "TOR_SOURCE_MANIFEST.json").read_bytes()), "tor_source_contract_sha256": manifest["contract_sha256"]}))
    verify.verify_stage(output, contract / "source.lock.json", outer)


@pytest.mark.parametrize("mutation", ["hash", "missing", "symlink", "extra", "manifest", "schema_bool", "global"])
def test_staged_substitution_never_reaches_authentication(contract_fixture, tmp_path, mutation):
    contract, cache, calls = contract_fixture
    output = tmp_path / "staged"
    stage.stage_inputs(output, cache)
    calls.clear()
    victim = output / "tor-source.rpm"
    global_manifest = None
    if mutation == "hash":
        victim.chmod(0o600)
        victim.write_bytes(b"substituted source package")
    elif mutation == "missing":
        victim.unlink()
    elif mutation == "symlink":
        victim.unlink()
        victim.symlink_to(cache / "tor-source.rpm")
    elif mutation == "extra":
        (output / "extra-key.gpg").write_bytes(b"unapproved key")
    elif mutation in {"manifest", "schema_bool"}:
        path = output / "TOR_SOURCE_MANIFEST.json"
        path.chmod(0o600)
        obj = json.loads(path.read_text())
        if mutation == "manifest":
            obj["inputs"]["tor-source.rpm"]["sha256"] = "0" * 64
        else:
            obj["schema_version"] = True
        path.write_text(json.dumps(obj))
    else:
        global_manifest = tmp_path / "global.json"
        global_manifest.write_text(json.dumps({"tor_source_manifest_sha256": "0" * 64, "tor_source_contract_sha256": "0" * 64}))
    with pytest.raises((ValueError, OSError)):
        verify.verify_stage(output, contract / "source.lock.json", global_manifest)
    assert calls == []


def test_offline_cache_has_no_network_fallback_or_partial_destination(contract_fixture, tmp_path, monkeypatch):
    _, cache, _ = contract_fixture
    (cache / "tor-source.rpm").unlink()
    monkeypatch.setattr(stage.urllib.request, "build_opener", lambda *_: pytest.fail("offline cache must not create a network downloader"))
    with pytest.raises(OSError):
        stage.stage_inputs(tmp_path / "staged", cache)
    assert not (tmp_path / "staged").exists()


def test_existing_destination_is_preserved(contract_fixture, tmp_path):
    _, cache, _ = contract_fixture
    output = tmp_path / "staged"
    output.mkdir()
    (output / "keep").write_bytes(b"existing evidence")
    with pytest.raises(ValueError):
        stage.stage_inputs(output, cache)
    assert (output / "keep").read_bytes() == b"existing evidence"


@pytest.mark.parametrize("status", ["expired_only", "wrong_signer", "wrong_primary", "revoked", "bad"])
def test_signature_status_requires_current_exact_signer_primary(status):
    identity = {"signer": "514102454D0A87DB0767A1EBBE6A0531C18A9179", "primary": "1C1BC007A9F607AA8152C040BEA7B180B1491921", "good_keyid": "BE6A0531C18A9179"}
    text = "[GNUPG:] GOODSIG BE6A0531C18A9179 trusted\n[GNUPG:] VALIDSIG " + identity["signer"] + " 2026-10-07 1791384685 0 4 0 22 10 00 " + identity["primary"] + "\n"
    if status == "expired_only":
        text = text.replace("GOODSIG", "EXPKEYSIG")
    elif status == "wrong_signer":
        text = text.replace(identity["signer"], "0" * 40)
    elif status == "wrong_primary":
        text = text.replace(identity["primary"], "0" * 40)
    elif status == "revoked":
        text += "[GNUPG:] REVKEYSIG invalid\n"
    else:
        text += "[GNUPG:] BADSIG invalid\n"
    with pytest.raises(ValueError):
        verify.accept_gpg_status(text, identity)


def test_plain_http_redirect_is_rejected():
    with pytest.raises(ValueError):
        stage.HTTPSRedirect().redirect_request(None, None, 302, "", {}, "http://dist.torproject.org/source")


def test_native_entry_contract_has_no_stock_tor_or_network_fallback():
    shell = (ROOT / "files/scripts/build-current-tor.sh").read_text()
    builder = (ROOT / "build/tor/build.py").read_text()
    lock = json.loads((ROOT / "build/tor/source.lock.json").read_text())
    assert lock["build"]["timeout_seconds"] == 3300
    assert "timeout --signal=TERM --kill-after=10s 3600s" in shell
    assert '"--disablerepo=*", "install", str(main)' in builder
    assert '["make", "-j2", "check"]' in builder
    assert '"--noclean"' in builder
    assert '"installed-rpm-header"' in builder
    assert 'receipt["packaged_tor_elf_sha256"]' in builder
    assert "authenticated_source_built_checked_and_installed" in builder
    assert "wget" not in builder and "curl" not in builder


@pytest.mark.parametrize("seconds", [True, 3300.0, 0, 1100, 3301, None])
def test_source_contract_rejects_unapproved_build_timeout(tmp_path, seconds):
    lock = json.loads((ROOT / "build/tor/source.lock.json").read_text())
    lock["build"]["timeout_seconds"] = seconds
    path = tmp_path / "source.lock.json"
    path.write_text(json.dumps(lock) + "\n")
    with pytest.raises(ValueError, match="unsupported bounded Tor build timeout"):
        verify.load_contract(path)


def test_compiler_and_package_transaction_have_separate_file_limits(monkeypatch):
    monkeypatch.setitem(sys.modules, 'verify', verify)
    spec = importlib.util.spec_from_file_location('tor_native_build', ROOT/'build/tor/build.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    recorded = []
    monkeypatch.setattr(builder.resource, 'setrlimit', lambda kind, bounds: recorded.append((kind, bounds)))
    builder.child_limits()
    assert (builder.resource.RLIMIT_FSIZE, (64 << 20, 64 << 20)) in recorded
    recorded.clear()
    builder.child_limits(128 << 20)
    assert (builder.resource.RLIMIT_FSIZE, (128 << 20, 128 << 20)) in recorded
    assert (builder.resource.RLIMIT_AS, (3 << 30, 3 << 30)) in recorded
    assert (builder.resource.RLIMIT_CORE, (0, 0)) in recorded
    lock = json.loads((ROOT/'build/tor/source.lock.json').read_text())
    assert lock['build']['file_limit_bytes'] == 64 << 20
    assert lock['build']['install_file_limit_bytes'] == 128 << 20
