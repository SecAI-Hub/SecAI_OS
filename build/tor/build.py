#!/usr/bin/env python3
"""Offline image-build compilation, full upstream checks and exact local install."""
from __future__ import annotations

import argparse
import json
import os
import re
import resource
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from verify import digest, stable_bytes, verify_stage


def allocated(root: Path) -> int:
    seen, total = set(), 0
    for directory, _, names in os.walk(root, followlinks=False):
        for name in names:
            try:
                info = (Path(directory) / name).lstat()
            except FileNotFoundError:
                continue
            identity = info.st_dev, info.st_ino
            if identity not in seen:
                seen.add(identity)
                total += info.st_blocks * 512
    return total


def child_limits(file_limit_bytes: int = 64 << 20) -> None:
    resource.setrlimit(resource.RLIMIT_AS, (3 << 30, 3 << 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit_bytes, file_limit_bytes))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def build(stage: Path, config: Path, contract: Path, global_manifest: Path | None) -> None:
    if os.geteuid() != 0:
        raise ValueError("Tor local installation is restricted to an owned image build as root")
    def owner_termination(signum, frame):
        raise TimeoutError("Tor build owner deadline terminated the build")
    signal.signal(signal.SIGTERM, owner_termination)
    signal.signal(signal.SIGINT, owner_termination)
    lock, manifest = verify_stage(stage, contract, global_manifest)
    if os.uname().machine != lock["architecture"]:
        raise ValueError("Tor source contract requires native x86_64")
    if not config.is_file() or config.is_symlink():
        raise ValueError("current appliance Tor configuration is required")
    # The existing OS RPM database exceeds the compiler's per-file cap. Keep
    # the coordinator bounded at the installation cap; compile/check children
    # receive the original smaller cap explicitly.
    install_file_limit = lock["build"]["install_file_limit_bytes"]
    if install_file_limit != 128 << 20:
        raise ValueError("unsupported bounded Tor installation file limit")
    child_limits(install_file_limit)
    keep = Path("/usr/share/secure-ai/integrity")
    keep.mkdir(parents=True, exist_ok=True)
    logs = keep / "tor-build-logs"
    if logs.exists() or logs.is_symlink():
        raise ValueError("Tor build log destination already exists; refusing stale receipt")
    logs.mkdir(mode=0o755)
    receipt = {"schema_version": 1, "version": lock["version"], "release": lock["release"], "source_contract_sha256": digest(stable_bytes(contract, 128 << 10)), "source_manifest_sha256": digest(stable_bytes(stage / "TOR_SOURCE_MANIFEST.json", 128 << 10)), "source_inputs": manifest["inputs"], "upstream_signature": lock["upstream_signature"], "qualification_limits": lock["qualification_limits"], "warnings_closed": False, "commands": [], "status": "building", "compiler_uid": os.geteuid(), "appliance_config_sha256": digest(stable_bytes(config, 128 << 10))}
    start, deadline = time.monotonic(), time.monotonic() + lock["build"]["timeout_seconds"]
    root = Path(tempfile.mkdtemp(prefix="secure-ai-tor-build-", dir="/tmp"))
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C", "HOME": str(root / "home"), "TMPDIR": str(root / "tmp")}
    for name in ("home", "tmp"):
        (root / name).mkdir(mode=0o700)

    def native(name: str, argv: list[str], cwd: Path | None = None, command_env: dict | None = None,
               file_limit_bytes: int = 64 << 20) -> str:
        receipt["commands"].append({"name": name, "argv": argv, "cwd": str(cwd) if cwd else None,
                                    "file_limit_bytes": file_limit_bytes})
        with (logs / (name + ".log")).open("xb") as output:
            process = subprocess.Popen(argv, cwd=cwd, env=command_env or env, stdout=output, stderr=subprocess.STDOUT,
                                       start_new_session=True, preexec_fn=lambda: child_limits(file_limit_bytes))
            try:
                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        raise ValueError("Tor compilation/check/install deadline exceeded")
                    if allocated(root) >= lock["build"]["tree_stop_bytes"]:
                        raise ValueError("private Tor build tree exceeds allocation stop")
                    if sum(p.stat().st_size for p in logs.glob("*.log")) > 16 << 20:
                        raise ValueError("Tor build logs exceed bounded retention")
                    time.sleep(0.25)
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                raise
            if process.returncode != 0:
                raise ValueError(name + " failed; retained log: " + str(logs / (name + ".log")))
        return (logs / (name + ".log")).read_text(errors="replace")

    try:
        versions = native("build-tool-versions", ["rpm", "-q", "rpm", "rpm-build", "redhat-rpm-config", "gcc", "glibc-devel", "openssl-devel", "libseccomp-devel"])
        receipt["native_build_packages"] = versions
        if native("fedora-target", ["rpm", "--eval", "%{?fedora}"]).strip() != "44":
            raise ValueError("reviewed Tor package contract targets Fedora44")
        verify_db = root / "verify-rpmdb"
        verify_db.mkdir()
        native("fedora-key-import", ["rpmkeys", "--dbpath", str(verify_db), "--import", str(stage / "fedora44-key.asc")])
        identities = native("fedora-key-identity", ["rpmkeys", "--dbpath", str(verify_db), "--list"])
        if len(identities.splitlines()) != 1 or identities.split()[0].upper() != lock["fedora_signature"]["fingerprint"]:
            raise ValueError("Fedora source key identity does not match contract")
        signature = native("fedora-source-signature", ["rpmkeys", "--dbpath", str(verify_db), "--checksig", str(stage / "tor-source.rpm")])
        if "digests signatures OK" not in signature:
            raise ValueError("Fedora packaging source lacks expected native signature receipt")
        top = root / "rpmbuild"
        top.mkdir()
        native("fedora-source-extract", ["rpm", "--define", "_topdir " + str(top), "-i", str(stage / "tor-source.rpm")])
        original_spec = stable_bytes(top / "SPECS/tor.spec", 128 << 10)
        if digest(original_spec) != lock["provenance"]["fedora_spec_sha256"]:
            raise ValueError("Fedora source package spec does not match approved baseline")
        # Every unchanged auxiliary is tied both to the committed hash and to
        # extraction from the independently signed Fedora SRPM.
        for name in lock["provenance"]["unchanged_fedora_auxiliaries"]:
            if stable_bytes(top / "SOURCES" / name, 128 << 10) != stable_bytes(stage / name, 128 << 10):
                raise ValueError("Fedora auxiliary differs from signed packaging baseline")
        sources = top / "SOURCES"
        for name in lock["remote_inputs"]:
            if name != "tor-source.rpm":
                shutil.copyfile(stage / name, sources / name)
        for name in lock["provenance"]["unchanged_fedora_auxiliaries"] + ["tor-sigblock-candidate.patch"]:
            shutil.copyfile(stage / name, sources / name)
        shutil.copyfile(stage / "tor-keyring.gpg", sources / "tor-keyring.pub")
        shutil.copyfile(stage / "tor.spec", top / "SPECS/tor.spec")
        definitions = ["--define", "source_date_epoch_from_changelog 1", "--define", "use_source_date_epoch_as_buildtime 1", "--define", "build_mtime_policy clamp_to_source_date_epoch", "--define", "_topdir " + str(top), "--define", "_smp_mflags -j2", "--define", "optflags " + lock["build"]["optflags"]]
        epoch = int(native("native-changelog-epoch", ["rpmspec", "-q", "--srpm", "--qf", "%{CHANGELOGTIME}\n", *definitions, str(top / "SPECS/tor.spec")]).strip())
        if epoch % 86400 == 43200:
            epoch -= 43200
        if epoch != lock["build"]["source_date_epoch"]:
            raise ValueError("native RPM source epoch differs from reviewed changelog")
        receipt["source_date_epoch"] = epoch
        native("rpmbuild", ["rpmbuild", "-ba", "--noclean", *definitions, str(top / "SPECS/tor.spec")])
        source = top / ("BUILD/tor-" + lock["version"] + "-build/tor-" + lock["version"])
        check_env = {**env, "SOURCE_DATE_EPOCH": str(epoch)}
        check = native("upstream-check", ["make", "-j2", "check"], source, check_env)
        counts = {key: int(value) for key, value in re.findall(r"^# (TOTAL|PASS|SKIP|XFAIL|FAIL|XPASS|ERROR):\s*(\d+)\s*$", check, re.MULTILINE)}
        skip_rows = re.findall(r"^SKIP: (.+)$", check, re.MULTILINE)
        if not counts or counts.get("PASS", 0) < 32 or any(counts.get(key, -1) != 0 for key in ("FAIL", "ERROR", "XPASS")) or any(name not in ("src/test/fuzz_static_testcases.sh", "src/test/test_switch_id.sh") for name in skip_rows):
            raise ValueError("full upstream Tor checks did not pass approved coverage")
        receipt["upstream_counts"], receipt["upstream_skips"] = counts, skip_rows
        main = top / ("RPMS/x86_64/tor-" + lock["version"] + "-" + lock["release"] + ".x86_64.rpm")
        header = native("main-rpm-header", ["rpm", "-qp", "--qf", "%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n", str(main)]).strip()
        expected_header = "\t".join(("tor", lock["version"], lock["release"], lock["architecture"]))
        if header != expected_header:
            raise ValueError("built Tor package identity differs from approved source")
        native("main-rpm-digests", ["rpmkeys", "--checksig", str(main)])
        runtime = root / "runtime"
        runtime.mkdir()
        # Positional argument avoids interpolating paths as shell code.
        native("extract-runtime", ["bash", "-o", "pipefail", "-c", 'rpm2cpio "$1" | cpio -idm --no-absolute-filenames', "extract", str(main)], runtime)
        binary = runtime / "usr/bin/tor"
        version = native("packaged-version", [str(binary), "--version"])
        if not version.startswith("Tor version " + lock["version"] + ".\n"):
            raise ValueError("packaged Tor ELF is not the approved version")
        header_elf = native("elf-header", ["readelf", "-h", str(binary)])
        dynamic = native("elf-dynamic", ["readelf", "-d", str(binary)])
        program = native("elf-program", ["readelf", "-lW", str(binary)])
        symbols = native("elf-symbols", ["readelf", "-Ws", str(binary)])
        stack = [line for line in program.splitlines() if "GNU_STACK" in line]
        if "DYN (Position-Independent Executable file)" not in header_elf or "BIND_NOW" not in dynamic or "GNU_RELRO" not in program or len(stack) != 1 or "RWE" in stack[0] or "__stack_chk_fail" not in symbols:
            raise ValueError("packaged Tor ELF lacks required native hardening")
        data = root / "config-data"
        data.mkdir(mode=0o700)
        native("appliance-config", [str(binary), "--verify-config", "-f", str(config), "--DataDirectory", str(data), "--Log", "notice stdout", "--SocksPort", "0", "--DisableNetwork", "1"])
        receipt["main_rpm_sha256"] = digest(stable_bytes(main, 64 << 20))
        receipt["packaged_tor_elf_sha256"] = digest(stable_bytes(binary, 64 << 20))
        receipt["native_runtime_version"] = version
        warning_lines = [line for line in (logs / "rpmbuild.log").read_text(errors="replace").splitlines() if "warning:" in line]
        receipt["compiler_warning_occurrences"] = len(warning_lines)
        receipt["compiler_warning_unique_lines"] = len(set(warning_lines))
        # Local transaction only. No repositories or fallback distribution Tor.
        native("install-local-tor", ["dnf5", "-y", "--disablerepo=*", "install", str(main)],
               file_limit_bytes=install_file_limit)
        installed = native("installed-rpm-header", ["rpm", "-q", "--qf", "%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n", "tor"]).strip()
        installed_version = native("installed-tor-version", ["/usr/bin/tor", "--version"])
        if installed != expected_header or not installed_version.startswith("Tor version " + lock["version"] + ".\n") or digest(stable_bytes(Path("/usr/bin/tor"), 64 << 20)) != receipt["packaged_tor_elf_sha256"]:
            raise ValueError("local transaction did not install exactly the built Tor ELF")
        receipt["status"] = "authenticated_source_built_checked_and_installed"
    except BaseException as error:
        receipt["status"], receipt["failure"] = "failed", str(error)
        raise
    finally:
        receipt["elapsed_seconds"] = time.monotonic() - start
        (keep / "tor-build.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        (keep / "tor-build.json").chmod(0o644)
        # Only the exact mkdtemp root is disposable. Source contract, native
        # command logs and receipt remain available to the image verifier.
        shutil.rmtree(root)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", type=Path)
    parser.add_argument("config", type=Path)
    parser.add_argument("--contract", type=Path, default=Path(__file__).with_name("source.lock.json"))
    parser.add_argument("--global-manifest", type=Path)
    args = parser.parse_args()
    build(args.stage, args.config, args.contract, args.global_manifest)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit("Required Tor source build failed: " + str(error))
