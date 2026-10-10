"""Exercise retained-artifact validation and all-output staging without downloads."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

GENERATOR = Path(__file__).resolve().parents[1] / "scripts/generate-diffusion-locks.sh"
BACKENDS = {"cpu": "cpu", "cuda": "cu129", "rocm": "rocm7.1"}
OLD_HASH, NEW_HASH, TORCH_HASH = "a" * 64, "b" * 64, "c" * 64


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hashed_lock(version, sources=""):
    return (sources + f"numpy=={version} \\\n    --hash=sha256:{OLD_HASH if version == '2.5.2' else NEW_HASH}\n"
            + f"torch==1.0 \\\n    --hash=sha256:{TORCH_HASH}\n")


@pytest.fixture
def checkout(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    script = scripts / GENERATOR.name
    script.write_bytes(GENERATOR.read_bytes())
    files = tmp_path / "files/scripts"
    files.mkdir(parents=True)
    work = tmp_path / "work"
    (work / "locks").mkdir(parents=True)
    (work / "pylocks").mkdir()
    manifest = {"schema_version": 5, "python_version": "3.12",
                "supported_architectures": ["x86_64"], "format_policy": "wheel_only", "backends": {}}
    for backend, index in BACKENDS.items():
        sources = "--index-url https://pypi.org/simple\n" + "".join(
            f"--find-links https://download.pytorch.org/whl/{index}/{name}/\n"
            for name in ["torch", "torchvision"] + {"cuda": ["triton"], "rocm": ["triton-rocm"]}.get(backend, []))
        for suffix in ("", "-py314"):
            lock = files / f"diffusion-{backend}{suffix}.lock"
            lock.write_text(hashed_lock("2.5.2", sources))
            staged = work / "locks" / lock.name
            staged.write_text(hashed_lock("2.5.3", sources))
            staged.with_suffix(".lock.seed").write_bytes(lock.read_bytes())
        inp = files / f"diffusion-{backend}.in"
        inp.write_text("numpy==2.5.3\ntorch==1.0\n")
        (work / (inp.name + ".seed")).write_bytes(inp.read_bytes())
        manifest["backends"][backend] = {
            "lockfile": f"diffusion-{backend}.lock", "lock_sha256": sha(files / f"diffusion-{backend}.lock"),
            "inputfile": inp.name, "input_sha256": "d" * 64, "estimated_size_mb": 2000,
            "torch_index": f"https://download.pytorch.org/whl/{index}",
            "wheels": [
                {"filename": "numpy-2.5.2-cp312-cp312-manylinux_2_28_x86_64.whl", "sha256": OLD_HASH,
                 "source": "https://files.pythonhosted.org/packages/*"},
                {"filename": "torch-1.0-cp312-cp312-manylinux_2_28_x86_64.whl", "sha256": TORCH_HASH,
                 "source": f"https://download.pytorch.org/whl/{index}/*"}],
        }
    (files / "diffusion-runtime-manifest.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False))
    (work / "manifest.seed").write_bytes((files / "diffusion-runtime-manifest.yaml").read_bytes())
    (work / "pylocks/pylock.target.toml").write_text(
        '[[packages]]\nname="numpy"\nversion="2.5.3"\n[[packages.wheels]]\n'
        'url="https://files.pythonhosted.org/packages/numpy-2.5.3-cp312-cp312-manylinux_2_28_x86_64.whl"\n'
        f'hashes={{sha256="{NEW_HASH}"}}\n')
    return tmp_path, files, work


def run_manifest(checkout):
    root, files, work = checkout
    code = GENERATOR.read_text().split("<<'PYMANIFEST'\n", 1)[1].split("\nPYMANIFEST", 1)[0]
    # Any accidental network fallback fails the control instead of downloading.
    code = ('import urllib.request\ndef no_network(*a, **kw):\n'
            '    raise AssertionError("network forbidden")\nurllib.request.urlopen = no_network\n') + code
    return subprocess.run([sys.executable, "-c", code, str(root), str(work),
                           str(files / "diffusion-runtime-manifest.yaml"), "numpy"], capture_output=True, text=True)


@pytest.mark.parametrize("case", ["valid", "missing-entry", "extra-entry", "duplicate-entry", "wrong-version",
                                  "wrong-hash", "wrong-source", "wrong-seed-digest", "changed-manifest",
                                  "changed-input", "incompatible-wheel", "ambiguous-wheel", "wrong-target-hash",
                                  "wrong-target-source", "changed-nontarget", "missing-target", "wrong-lock-source"])
def test_retained_manifest_binding(checkout, case):
    _, files, work = checkout
    template = files / "diffusion-runtime-manifest.yaml"
    old = yaml.safe_load(template.read_text())
    cfg = old["backends"]["rocm"]
    if case == "missing-entry":
        cfg["wheels"].pop()
    elif case in {"extra-entry", "duplicate-entry"}:
        entry = cfg["wheels"][-1].copy()
        if case == "extra-entry":
            entry["filename"] = "extra-1.0-py3-none-any.whl"
        cfg["wheels"].append(entry)
    elif case == "wrong-version":
        cfg["wheels"][-1]["filename"] = cfg["wheels"][-1]["filename"].replace("1.0-", "1.1-")
    elif case == "wrong-hash":
        cfg["wheels"][-1]["sha256"] = "e" * 64
    elif case == "wrong-source":
        cfg["wheels"][-1]["source"] = "https://download.pytorch.org/whl/cpu/*"
    elif case == "wrong-seed-digest":
        cfg["lock_sha256"] = "e" * 64
    template.write_text(yaml.safe_dump(old, sort_keys=False))
    if case != "changed-manifest":
        (work / "manifest.seed").write_bytes(template.read_bytes())
    else:
        template.write_text(template.read_text() + "# concurrently edited\n")
    if case == "changed-input":
        (files / "diffusion-rocm.in").write_text("numpy==2.5.4\n")
    pylock = work / "pylocks/pylock.target.toml"
    text = pylock.read_text()
    if case == "incompatible-wheel":
        text = text.replace("cp312-cp312", "cp314-cp314")
    elif case == "ambiguous-wheel":
        text += "[[packages.wheels]]\n" + text.split("[[packages.wheels]]\n")[1]
    elif case == "wrong-target-hash":
        text = text.replace(NEW_HASH, "e" * 64)
    elif case == "wrong-target-source":
        text = text.replace("files.pythonhosted.org", "example.invalid")
    pylock.write_text(text)
    staged = work / "locks/diffusion-rocm.lock"
    if case == "changed-nontarget":
        staged.write_text(staged.read_text().replace("torch==1.0", "torch==1.1"))
    elif case == "missing-target":
        staged.write_text(staged.read_text().replace(f"numpy==2.5.3 \\\n    --hash=sha256:{NEW_HASH}\n", ""))
    elif case == "wrong-lock-source":
        staged.write_text(staged.read_text().replace("whl/rocm7.1/", "whl/cpu/"))
    result = run_manifest(checkout)
    assert "network forbidden" not in result.stderr
    output = work / "diffusion-runtime-manifest.yaml"
    if case != "valid":
        assert result.returncode != 0
        assert not output.exists()
        return
    assert result.returncode == 0, result.stderr
    new = yaml.safe_load(output.read_text())
    for backend in BACKENDS:
        before, after = old["backends"][backend], new["backends"][backend]
        assert after["wheels"][1:] == before["wheels"][1:]
        assert after["wheels"][0]["sha256"] == NEW_HASH
        assert after["estimated_size_mb"] == before["estimated_size_mb"]
        assert after["lock_sha256"] == sha(work / f"locks/diffusion-{backend}.lock")
        assert after["input_sha256"] == sha(files / f"diffusion-{backend}.in")
    assert new["schema_version"] == old["schema_version"] + 1


@pytest.mark.parametrize("failure", ["", "last-graph", "manifest-wheel"])
def test_generator_stages_all_six_graphs_before_publication(checkout, failure):
    root, files, work = checkout
    bin_dir = root / "bin"
    bin_dir.mkdir()
    uv = bin_dir / "uv"
    uv.write_text(f'''#!{sys.executable}
import os, pathlib, sys
args=sys.argv[1:]
if args == ['--version']:
 print('uv 0.12.10'); sys.exit(0)
with open({str(root / 'calls')!r}, 'a') as log: log.write(repr(args)+'\\n')
output=pathlib.Path(args[args.index('--output-file')+1])
if '--format' in args:
 text=pathlib.Path({str(work / 'pylocks/pylock.target.toml')!r}).read_text()
 if {failure!r} == 'manifest-wheel': text=text.replace('cp312-cp312','cp314-cp314')
elif '--no-deps' in args:
 text='numpy==2.5.3 \\\\\\n    --hash=sha256:{NEW_HASH}\\n'
else:
 if {failure!r} == 'last-graph' and output.name == 'diffusion-rocm-py314.lock.resolved': sys.exit(19)
 seed=output.with_suffix('').with_suffix('.lock.seed')
 text=seed.read_text().replace('numpy==2.5.2','numpy==2.5.3')
output.write_text(text)
''')
    uv.chmod(0o755)
    originals = {path.name: path.read_bytes() for path in files.iterdir()}
    env = {**os.environ, "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"], "PYTHON_BIN": sys.executable}
    result = subprocess.run(["bash", str(root / "scripts" / GENERATOR.name), "--upgrade-package", "numpy"],
                            env=env, capture_output=True, text=True)
    if failure:
        assert result.returncode != 0
        assert {path.name: path.read_bytes() for path in files.iterdir()} == originals
    else:
        assert result.returncode == 0, result.stderr
        for path in files.glob("*.lock"):
            assert "numpy==2.5.3" in path.read_text()
        assert b"numpy-2.5.3" in (files / "diffusion-runtime-manifest.yaml").read_bytes()
        calls = (root / "calls").read_text().splitlines()
        assert len(calls) == 13  # six graph solves, six target hashes, one target pylock
        assert sum("'--format'" in call for call in calls) == 1
        assert all("target.in" in call for call in calls if "'--format'" in call)


@pytest.mark.parametrize("tags", ["cp312-cp312-linux_x86_64", "cp38-abi3-manylinux2014_x86_64", "py3-none-any"])
def test_retained_compatible_wheel_tags(checkout, tags):
    _, files, work = checkout
    template = files / "diffusion-runtime-manifest.yaml"
    old = yaml.safe_load(template.read_text())
    old["backends"]["rocm"]["wheels"][-1]["filename"] = f"torch-1.0-{tags}.whl"
    template.write_text(yaml.safe_dump(old, sort_keys=False))
    (work / "manifest.seed").write_bytes(template.read_bytes())
    result = run_manifest(checkout)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("recorded,matching", [(False, True), (False, False), (True, True), (True, False)])
def test_manifest_hash_always_binds_selected_wheel_to_lock(monkeypatch, recorded, matching):
    import importlib.util
    import io

    helper = GENERATOR.with_name("generate-diffusion-manifest.py")
    spec = importlib.util.spec_from_file_location("manifest_hash_binding", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    payload = b"synthetic selected wheel bytes"
    actual = hashlib.sha256(payload).hexdigest()
    trusted = {actual if matching else "d" * 64, "e" * 64}
    url = "https://files.pythonhosted.org/packages/example.whl"
    wheel = {"url": url, "hashes": {"sha256": actual} if recorded else {}}
    requested = []

    def download(request, **kwargs):
        assert not recorded, "recorded hash must not download an artifact"
        requested.append(request.full_url)
        response = io.BytesIO(payload)
        response.url = url
        return response

    monkeypatch.setattr(module.urllib.request, "urlopen", download)
    if matching:
        assert module.wheel_hash(wheel, trusted) == actual
    else:
        with pytest.raises(ValueError, match="absent from requirements lock"):
            module.wheel_hash(wheel, trusted)
    assert requested == ([] if recorded else [url])
