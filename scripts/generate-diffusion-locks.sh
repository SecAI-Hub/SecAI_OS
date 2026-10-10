#!/usr/bin/env bash
#
# Rebuild Linux/x86_64 diffusion locks for CPython 3.12.14/3.14.7 and
# the CPython 3.12 on-demand wheel manifest.
#
# The resolver is pinned because changes in resolver/index behavior can change
# both the selected graph and the set of artifact hashes. All outputs are
# staged first; checked-in files are replaced only after every backend succeeds.
#
# Usage:
#   scripts/generate-diffusion-locks.sh
#   scripts/generate-diffusion-locks.sh --locks-only
#   scripts/generate-diffusion-locks.sh --upgrade-package numpy
# Targeted mode solves the complete seeded graph, refreshes only the PyPI
# target hashes, and retains every other reviewed block and source unchanged.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPTS_DIR="${REPO_ROOT}/files/scripts"
MANIFEST="${SCRIPTS_DIR}/diffusion-runtime-manifest.yaml"
UV_VERSION="0.12.10"
PYTHON_BIN="${PYTHON_BIN:-python3}"
LOCKS_ONLY=false

UPGRADE_PACKAGE=""
COMPILE_COMMAND="scripts/generate-diffusion-locks.sh"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --locks-only)
            [ "$LOCKS_ONLY" = false ] || { echo "duplicate --locks-only" >&2; exit 64; }
            LOCKS_ONLY=true; COMPILE_COMMAND+=" --locks-only"; shift ;;
        --upgrade-package)
            if [ -n "$UPGRADE_PACKAGE" ] || [ "$#" -lt 2 ] ||
               [[ ! "$2" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]]; then
                echo "invalid --upgrade-package" >&2; exit 64
            fi
            UPGRADE_PACKAGE="$2"; COMPILE_COMMAND+=" --upgrade-package $2"; shift 2 ;;
        *) echo "usage: $0 [--locks-only] [--upgrade-package normalized-package-name]" >&2; exit 64 ;;
    esac
done

# Targeted updates use exact, hashed seeds and constrain every other version.
# Reject graph, source or hash drift before any staged output is published.
target_lock() {
    "$PYTHON_BIN" - "$1" "$2" "$3" "$UPGRADE_PACKAGE" <<'PYLOCK'
import pathlib, re, sys
mode, seed_name, output_name, target = sys.argv[1:]
seed, output = pathlib.Path(seed_name), pathlib.Path(output_name)
def parse(path, require_hashes=True):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"targeted update requires a regular existing lock: {path}")
    packages, sources, current = {}, [], None
    data = path.read_bytes()
    for line in data.decode("utf-8").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if text.startswith(("--index-url ", "--find-links ")):
            if not re.fullmatch(r"--(?:index-url https://pypi\.org/simple|find-links https://download\.pytorch\.org/whl/(?:cpu|cu129|rocm7\.1)/(?:torch|torchvision|triton|triton-rocm)/)", text):
                raise ValueError(f"unsupported seed source: {text}")
            sources.append(text)
            continue
        pin = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9.!+_-]*)\s*\\?", text)
        if pin:
            current = re.sub(r"[-_.]+", "-", pin[1]).lower()
            if current in packages:
                raise ValueError(f"duplicate seed package: {current}")
            packages[current] = (pin[2], set())
            continue
        digest = re.fullmatch(r"--hash=sha256:([0-9a-f]{64})\s*\\?", text)
        if digest and current:
            packages[current][1].add(digest[1])
            continue
        raise ValueError(f"unsupported targeted lock syntax: {text}")
    if not packages or (require_hashes and any(not hashes for _, hashes in packages.values())):
        raise ValueError(f"targeted update requires a nonempty fully hashed lock: {path}")
    return packages, sources, data
before, sources, seed_bytes = parse(seed)
if mode == "seed":
    output.write_bytes(seed_bytes)
    output.with_suffix(output.suffix + ".seed").write_bytes(seed_bytes)
    output.with_suffix(output.suffix + ".constraints").write_text(
        "".join(f"{name}=={value[0]}\n" for name, value in before.items() if name != target),
        encoding="utf-8",
    )
elif mode in {"request", "merge"}:
    if seed_bytes != output.with_suffix(output.suffix + ".seed").read_bytes():
        raise ValueError(f"seed changed during generation: {seed}")
    resolved, new_sources, resolved_bytes = parse(
        output.with_suffix(output.suffix + ".resolved"), require_hashes=False,
    )
    if target not in before or target not in resolved or sources != new_sources:
        raise ValueError("targeted metadata solve changed sources or lost the target")
    if {k:v[0] for k,v in before.items() if k != target} != {k:v[0] for k,v in resolved.items() if k != target}:
        raise ValueError("targeted metadata solve changed the non-target graph")
    if mode == "request":
        output.with_suffix(output.suffix + ".target.in").write_text(
            f"{target}=={resolved[target][0]}\n", encoding="utf-8",
        )
    else:
        updated, target_sources, target_bytes = parse(output.with_suffix(output.suffix + ".target"))
        if set(updated) != {target} or updated[target][0] != resolved[target][0] or target_sources:
            raise ValueError("target hash solve does not match the exact resolved target")
        pattern = r"(?m)(?=^[A-Za-z0-9][A-Za-z0-9_.-]*==)"
        old_blocks = re.split(pattern, seed_bytes.decode("utf-8"))
        target_blocks = re.split(pattern, target_bytes.decode("utf-8"))
        header = re.split(pattern, resolved_bytes.decode("utf-8"))[0]
        if len(target_blocks) != 2:
            raise ValueError("ambiguous generated target block")
        result = [header]
        for block in old_blocks[1:]:
            name = re.sub(r"[-_.]+", "-", block.split("==", 1)[0]).lower()
            result.append(target_blocks[1] if name == target else block)
        output.write_text("".join(result), encoding="utf-8")
elif mode == "check":
    if seed_bytes != output.with_suffix(output.suffix + ".seed").read_bytes():
        raise ValueError(f"seed changed during generation: {seed}")
    after, new_sources, _ = parse(output)
    if sources != new_sources or {k:v for k,v in before.items() if k != target} != {k:v for k,v in after.items() if k != target}:
        raise ValueError(f"targeted update changed non-target versions, hashes, packages or sources: {seed}")
else:
    raise ValueError("unknown targeted lock operation")
PYLOCK
}

if ! command -v uv >/dev/null 2>&1; then
    echo "ERROR: uv ${UV_VERSION} is required to regenerate diffusion locks" >&2
    exit 69
fi
if [ "$(uv --version | awk '{print $2}')" != "$UV_VERSION" ]; then
    echo "ERROR: expected uv ${UV_VERSION}, found: $(uv --version)" >&2
    exit 69
fi

# Stage beside the checked-in artifacts so each final rename is guaranteed to
# be atomic (not a cross-filesystem copy). Nothing is published until every
# requested lock and the manifest have passed generation.
WORK_DIR="$(mktemp -d "${SCRIPTS_DIR}/.diffusion-locks.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT
UV_CACHE_DIR="${UV_CACHE_DIR:-${WORK_DIR}/uv-cache}"
mkdir -p "${WORK_DIR}/locks" "${WORK_DIR}/pylocks" "$UV_CACHE_DIR"

backend_config() {
    case "$1" in
        cpu)
            index="https://download.pytorch.org/whl/cpu"
            uv_torch_backend="cpu"
            ;;
        cuda)
            index="https://download.pytorch.org/whl/cu129"
            uv_torch_backend="cu129"
            ;;
        rocm)
            index="https://download.pytorch.org/whl/rocm7.1"
            uv_torch_backend="rocm7.1"
            ;;
        *)
            echo "ERROR: unsupported diffusion backend: $1" >&2
            exit 64
            ;;
    esac
}

hash_options=(--generate-hashes)
upgrade=(--upgrade)
if [ -n "$UPGRADE_PACKAGE" ]; then
    hash_options=()
    upgrade=(--upgrade-package "$UPGRADE_PACKAGE")
    cp "$MANIFEST" "${WORK_DIR}/manifest.seed"
    for backend in cpu cuda rocm; do
        cp "${SCRIPTS_DIR}/diffusion-${backend}.in" "${WORK_DIR}/diffusion-${backend}.in.seed"
    done
    # Validate all six seeds before invoking the resolver.
    for suffix in "" "-py314"; do
        for backend in cpu cuda rocm; do
            target_lock seed "${SCRIPTS_DIR}/diffusion-${backend}${suffix}.lock" \
                "${WORK_DIR}/locks/diffusion-${backend}${suffix}.lock"
        done
    done
fi

echo "=== SecAI diffusion lock generator ==="
echo "  resolver: uv ${UV_VERSION}"
echo "  targets:  CPython 3.12.14 and 3.14.7, x86_64-manylinux_2_28"

for python_version in 3.12.14 3.14.7; do
    python_suffix=""
    if [ "$python_version" = "3.14.7" ]; then
        python_suffix="-py314"
    fi
    for backend in cpu cuda rocm; do
        input="${SCRIPTS_DIR}/diffusion-${backend}.in"
        output="${WORK_DIR}/locks/diffusion-${backend}${python_suffix}.lock"
        backend_config "$backend"
        seed_constraint=()
        if [ -n "$UPGRADE_PACKAGE" ]; then seed_constraint=(--constraint "$output.constraints"); fi
        # A full metadata solve proves compatibility without re-downloading
        # unchanged multi-GB accelerator wheels just to recalculate their hashes.
        resolved_output="$output"
        if [ -n "$UPGRADE_PACKAGE" ]; then resolved_output="$output.resolved"; fi
        echo "  resolving ${backend} for Python ${python_version}"
        uv pip compile "$input" \
            --python-version "$python_version" \
            --python-platform x86_64-manylinux_2_28 \
            --extra-index-url "$index" \
            --index-strategy unsafe-best-match \
            "${hash_options[@]}" \
            --only-binary=:all: \
            --emit-index-url \
            --cache-dir "$UV_CACHE_DIR" \
            "${upgrade[@]}" "${seed_constraint[@]}" \
            --output-file "$resolved_output" \
            --custom-compile-command "$COMPILE_COMMAND" \
            >/dev/null

        # pip does not provide per-package index selection. Leaving PyTorch as
        # an extra index allows mirrored packages such as MarkupSafe to win
        # over PyPI, which breaks reviewed hashes and creates dependency-
        # confusion risk. Restrict secondary locations to package listings.
        source_rewrite="${resolved_output}.sources"
        awk -v baseurl="$index" -v backend="$backend" '
            /^--extra-index-url / {
                print "--find-links " baseurl "/torch/"
                print "--find-links " baseurl "/torchvision/"
                if (backend == "cuda") {
                    print "--find-links " baseurl "/triton/"
                } else if (backend == "rocm") {
                    print "--find-links " baseurl "/triton-rocm/"
                }
                next
            }
            { print }
        ' "$resolved_output" > "$source_rewrite"
        mv "$source_rewrite" "$resolved_output"
        if [ -n "$UPGRADE_PACKAGE" ]; then
            target_lock request "${SCRIPTS_DIR}/diffusion-${backend}${python_suffix}.lock" "$output"
            # NumPy (or another reviewed PyPI target) gets fresh resolver hashes;
            # every non-target block remains byte-identical to its reviewed seed.
            env -u UV_INDEX -u UV_DEFAULT_INDEX -u UV_INDEX_URL -u UV_EXTRA_INDEX_URL -u UV_FIND_LINKS \
                uv pip compile "$output.target.in" \
                --python-version "$python_version" \
                --python-platform x86_64-manylinux_2_28 \
                --index-url https://pypi.org/simple \
                --no-config --no-sources --no-deps --generate-hashes \
                --only-binary=:all: --cache-dir "$UV_CACHE_DIR" \
                --upgrade-package "$UPGRADE_PACKAGE" \
                --output-file "$output.target" \
                --custom-compile-command "$COMPILE_COMMAND" >/dev/null
            sed -i "s#${output}.target.in#files/scripts/diffusion-${backend}.in#g" "$output.target"
            target_lock merge "${SCRIPTS_DIR}/diffusion-${backend}${python_suffix}.lock" "$output"
            target_lock check "${SCRIPTS_DIR}/diffusion-${backend}${python_suffix}.lock" "$output"
            sed -i "s#${output}.constraints#files/scripts/diffusion-${backend}${python_suffix}.lock#g" "$output"
        fi
    done
done

if [ "$LOCKS_ONLY" = false ]; then
    if ! "$PYTHON_BIN" -c 'import sys, tomllib, yaml; assert sys.version_info >= (3, 11)' >/dev/null 2>&1; then
        echo "ERROR: ${PYTHON_BIN} must be Python 3.11+ with PyYAML installed" >&2
        exit 69
    fi

    if [ -n "$UPGRADE_PACKAGE" ]; then
        # The complete six backend graphs were solved above. Only the target
        # needs new wheel selection; a full pylock may implicitly re-download
        # unchanged accelerator wheels to hash them, even without hash flags.
        env -u UV_INDEX -u UV_DEFAULT_INDEX -u UV_INDEX_URL -u UV_EXTRA_INDEX_URL -u UV_FIND_LINKS \
            uv pip compile "${WORK_DIR}/locks/diffusion-cpu.lock.target.in" \
            --python-version 3.12.14 \
            --python-platform x86_64-manylinux_2_28 \
            --index-url https://pypi.org/simple \
            --no-config --no-sources --no-deps --generate-hashes \
            --only-binary=:all: --cache-dir "$UV_CACHE_DIR" \
            --upgrade-package "$UPGRADE_PACKAGE" --format pylock.toml \
            --output-file "${WORK_DIR}/pylocks/pylock.target.toml" \
            --custom-compile-command "$COMPILE_COMMAND" >/dev/null

        "$PYTHON_BIN" - "$REPO_ROOT" "$WORK_DIR" "$MANIFEST" "$UPGRADE_PACKAGE" <<'PYMANIFEST'
import hashlib, pathlib, re, sys, tomllib, urllib.parse
import yaml
root, work, template = map(pathlib.Path, sys.argv[1:4])
target = sys.argv[4]
backends = {"cpu": "cpu", "cuda": "cu129", "rocm": "rocm7.1"}
pypi_source = "https://files.pythonhosted.org/packages/*"
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()
def lock(path):
    packages, sources, current = {}, [], None
    for line in path.read_text().splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if text.startswith(("--index-url ", "--find-links ")):
            sources.append(text)
            continue
        pin = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\s]+?)\s*\\?", text)
        if pin:
            current = canonical(pin[1])
            if current in packages:
                raise ValueError("duplicate lock package")
            packages[current] = (pin[2], set())
            continue
        value = re.fullmatch(r"--hash=sha256:([0-9a-f]{64})\s*\\?", text)
        if not value or current is None:
            raise ValueError("unsupported lock syntax")
        packages[current][1].add(value[1])
    if not packages or any(not item[1] for item in packages.values()):
        raise ValueError("incomplete lock hashes")
    return packages, sources
def wheel_identity(filename):
    if not isinstance(filename, str) or not re.fullmatch(r"[A-Za-z0-9_.+!-]+\.whl", filename):
        raise ValueError("invalid wheel filename")
    parts = filename[:-4].split("-")
    if len(parts) not in (5, 6) or (len(parts) == 6 and not re.fullmatch(r"[0-9][A-Za-z0-9_.]*", parts[2])):
        raise ValueError("ambiguous wheel filename")
    name, version = parts[:2]
    python_tags, abi_tags, platforms = (part.split(".") for part in parts[-3:])
    compatible = False
    for py in python_tags:
        for abi in abi_tags:
            for platform in platforms:
                linux = re.fullmatch(r"manylinux_2_([0-9]+)_x86_64", platform)
                linux = bool(linux and int(linux[1]) <= 28) or platform in {
                    "manylinux1_x86_64", "manylinux2010_x86_64", "manylinux2014_x86_64", "linux_x86_64",
                }
                stable = re.fullmatch(r"cp3([0-9]+)", py)
                interpreter = (py == "cp312" and abi in {"cp312", "abi3", "none"}) or (
                    bool(stable) and 2 <= int(stable[1]) <= 12 and abi == "abi3"
                ) or (py in {"py3", "py312"} and abi == "none")
                compatible |= interpreter and (linux or (platform == "any" and abi == "none"))
    if not compatible:
        raise ValueError("wheel is incompatible with CPython 3.12 Linux/x86_64")
    return canonical(name), version
seed_manifest = work / "manifest.seed"
if template.read_bytes() != seed_manifest.read_bytes():
    raise ValueError("manifest changed during generation")
manifest = yaml.safe_load(seed_manifest.read_text())
if (set(manifest["backends"]) != set(backends) or manifest.get("python_version") != "3.12"
        or manifest.get("supported_architectures") != ["x86_64"] or manifest.get("format_policy") != "wheel_only"):
    raise ValueError("unsupported seed manifest target")
packages = tomllib.loads((work / "pylocks/pylock.target.toml").read_text()).get("packages", [])
if len(packages) != 1 or canonical(packages[0]["name"]) != target:
    raise ValueError("target pylock must contain exactly the target")
package = packages[0]
wheels = package.get("wheels", [])
if len(wheels) != 1:
    raise ValueError("target pylock wheel selection is ambiguous")
wheel = wheels[0]
url = urllib.parse.urlsplit(wheel["url"])
if (url.scheme != "https" or url.netloc != "files.pythonhosted.org" or
        not url.path.startswith("/packages/") or url.query or url.fragment):
    raise ValueError("target wheel must come from PyPI")
filename = pathlib.PurePosixPath(urllib.parse.unquote(url.path)).name
if wheel_identity(filename) != (target, package["version"]):
    raise ValueError("target wheel identity differs from target pylock")
sha256 = wheel.get("hashes", {}).get("sha256", "")
if not re.fullmatch(r"[0-9a-f]{64}", sha256):
    raise ValueError("target pylock requires an exact wheel hash")
new_entry = {"filename": filename, "sha256": sha256, "source": pypi_source}
for backend, index in backends.items():
    staged = work / "locks" / f"diffusion-{backend}.lock"
    seed = staged.with_suffix(".lock.seed")
    before, sources = lock(seed)
    after, next_sources = lock(staged)
    cfg = manifest["backends"][backend]
    expected_sources = ["--index-url https://pypi.org/simple"] + [
        f"--find-links https://download.pytorch.org/whl/{index}/{name}/"
        for name in ["torch", "torchvision"] + ({"cuda": ["triton"], "rocm": ["triton-rocm"]}.get(backend, []))
    ]
    if sources != expected_sources or next_sources != sources:
        raise ValueError("seed or staged sources differ from reviewed backend")
    if cfg.get("lockfile") != staged.name or cfg.get("lock_sha256") != digest(seed):
        raise ValueError("old manifest is not bound to exact seed lock")
    if cfg.get("torch_index") != f"https://download.pytorch.org/whl/{index}":
        raise ValueError("old manifest index changed")
    if ({k:v for k,v in before.items() if k != target} != {k:v for k,v in after.items() if k != target}
            or target not in before or target not in after
            or after[target][0] != package["version"] or sha256 not in after[target][1]):
        raise ValueError("staged manifest graph/hash differs from resolved target and seed")
    seen, entries = set(), []
    for entry in cfg["wheels"]:
        if set(entry) != {"filename", "sha256", "source"}:
            raise ValueError("unexpected seed wheel fields")
        name, version = wheel_identity(entry["filename"])
        if name in seen or name not in before or version != before[name][0] or entry["sha256"] not in before[name][1]:
            raise ValueError("missing, extra, duplicate or mutated old manifest artifact")
        seen.add(name)
        source = f"https://download.pytorch.org/whl/{index}/*" if name in {
            "torch", "torchvision", "triton", "triton-rocm",
        } else pypi_source
        if entry["source"] != source or (name == target and source != pypi_source):
            raise ValueError("old manifest wheel source differs from reviewed seed")
        entries.append(new_entry.copy() if name == target else entry)
    if seen != set(before):
        raise ValueError("old manifest does not cover exact seed graph")
    input_path = template.parent / f"diffusion-{backend}.in"
    if cfg.get("inputfile") != input_path.name or input_path.read_bytes() != (work / (input_path.name + ".seed")).read_bytes():
        raise ValueError("input changed during generation")
    cfg["wheels"] = entries
    cfg["lock_sha256"] = digest(staged)
    cfg["input_sha256"] = digest(input_path)
# estimated_size_mb remains the existing coarse policy estimate. The prior
# manifest contains no exact URL/size provenance; retaining it does not rehash
# remote accelerator artifacts or establish new size measurements.
manifest["schema_version"] = max(int(manifest["schema_version"]) + 1, 2)
(work / "diffusion-runtime-manifest.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False, width=120))
PYMANIFEST
    else
    # PEP 751 output records the exact compatible Linux wheel URL. The
    # PyTorch backend option keeps non-PyTorch packages on PyPI instead of
    # selecting duplicate packages mirrored by the PyTorch index.
    for backend in cpu cuda rocm; do
        backend_config "$backend"
        # Bind manifest wheel selection to the complete resolved backend graph.
        uv pip compile "${SCRIPTS_DIR}/diffusion-${backend}.in" \
            --python-version 3.12.14 \
            --python-platform x86_64-manylinux_2_28 \
            --torch-backend "$uv_torch_backend" \
            "${hash_options[@]}" \
            --only-binary=:all: \
            --cache-dir "$UV_CACHE_DIR" \
            "${upgrade[@]}" \
            --format pylock.toml \
            --output-file "${WORK_DIR}/pylocks/pylock.${backend}.toml" \
            --custom-compile-command "$COMPILE_COMMAND" \
            >/dev/null
    done

    "$PYTHON_BIN" "${REPO_ROOT}/scripts/generate-diffusion-manifest.py" \
        --template "$MANIFEST" \
        --lock-dir "${WORK_DIR}/locks" \
        --pylock-dir "${WORK_DIR}/pylocks" \
        --output "${WORK_DIR}/diffusion-runtime-manifest.yaml"
    fi
fi

# Recheck every original seed immediately before publication, including cp314.
if [ -n "$UPGRADE_PACKAGE" ]; then
    for suffix in "" "-py314"; do
        for backend in cpu cuda rocm; do
            target_lock check "${SCRIPTS_DIR}/diffusion-${backend}${suffix}.lock" \
                "${WORK_DIR}/locks/diffusion-${backend}${suffix}.lock"
        done
    done
    cmp "$MANIFEST" "${WORK_DIR}/manifest.seed"
    for backend in cpu cuda rocm; do
        cmp "${SCRIPTS_DIR}/diffusion-${backend}.in" "${WORK_DIR}/diffusion-${backend}.in.seed"
    done
fi

# Publish only after all requested outputs have been generated and validated.
chmod 0644 "${WORK_DIR}/locks/"*.lock
if [ "$LOCKS_ONLY" = false ]; then
    chmod 0644 "${WORK_DIR}/diffusion-runtime-manifest.yaml"
fi
for python_suffix in "" "-py314"; do
    for backend in cpu cuda rocm; do
        mv "${WORK_DIR}/locks/diffusion-${backend}${python_suffix}.lock" \
           "${SCRIPTS_DIR}/diffusion-${backend}${python_suffix}.lock"
    done
done
if [ "$LOCKS_ONLY" = false ]; then
    mv "${WORK_DIR}/diffusion-runtime-manifest.yaml" "$MANIFEST"
fi

echo "=== Diffusion dependency artifacts regenerated successfully ==="
