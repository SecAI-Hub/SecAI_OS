#!/usr/bin/env bash
# Resolve one consistent runtime graph, then constrain every service to it.
# All hash-locked outputs are staged before any tracked lock is replaced.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
UV_VERSION="0.12.10"
PYTHON_BIN="${PYTHON_BIN:-python3}"
UPGRADE_PACKAGE=""
COMPILE_COMMAND="scripts/generate-application-locks.sh"
if [ "$#" -ne 0 ]; then
    if [ "$#" -ne 2 ] || [ "$1" != --upgrade-package ] ||
       [[ ! "$2" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]]; then
        echo "usage: $0 [--upgrade-package normalized-package-name]" >&2; exit 64
    fi
    UPGRADE_PACKAGE="$2"
    COMPILE_COMMAND+=" --upgrade-package $UPGRADE_PACKAGE"
fi

# Targeted updates use exact, hashed seeds and constrain every other version.
# Reject graph, source or hash drift before any staged output is published.
target_lock() {
    "$PYTHON_BIN" - "$1" "$2" "$3" "$UPGRADE_PACKAGE" <<'PYLOCK'
import pathlib, re, sys
mode, seed_name, output_name, target = sys.argv[1:]
seed, output = pathlib.Path(seed_name), pathlib.Path(output_name)
def parse(path):
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
    if not packages or any(not hashes for _, hashes in packages.values()):
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

[ "$(uv --version | awk '{print $2}')" = "$UV_VERSION" ] || {
    echo "uv ${UV_VERSION} is required" >&2; exit 69;
}
STAGING_DIR="$(mktemp -d .application-locks.XXXXXX)"
trap 'rm -rf -- "$STAGING_DIR"' EXIT
upgrade=(--upgrade)
if [ -n "$UPGRADE_PACKAGE" ]; then
    upgrade=(--upgrade-package "$UPGRADE_PACKAGE")
    # Validate every seed before invoking the resolver.
    target_lock seed vendor/application-requirements.lock "$STAGING_DIR/application.lock"
    target_lock seed requirements-ci.lock "$STAGING_DIR/ci.lock"
    for service in agent search-mediator ui quarantine; do
        target_lock seed "services/$service/requirements.lock" "$STAGING_DIR/$service.lock"
    done
fi
common=(--python-version 3.12.15 --generate-hashes "${upgrade[@]}"
        --custom-compile-command "$COMPILE_COMMAND")
seed_constraint=()
if [ -n "$UPGRADE_PACKAGE" ]; then
    seed_constraint=(--constraint "$STAGING_DIR/application.lock.constraints")
fi
uv pip compile vendor/application-requirements.in services/ui/pyproject.toml \
    services/quarantine/pyproject.toml "${common[@]}" "${seed_constraint[@]}" \
    --output-file "$STAGING_DIR/application.lock" >/dev/null
for service in agent search-mediator ui quarantine; do
    input="services/${service}/requirements.txt"
    extra=()
    if [ "$service" = ui ] || [ "$service" = quarantine ]; then
        input="services/${service}/pyproject.toml"
    fi
    if [ "$service" = quarantine ]; then extra=(--extra scan); fi
    seed_constraint=()
    if [ -n "$UPGRADE_PACKAGE" ]; then
        seed_constraint=(--constraint "$STAGING_DIR/$service.lock.constraints")
    fi
    uv pip compile "$input" "${extra[@]}" "${common[@]}" "${seed_constraint[@]}" \
        --constraint "$STAGING_DIR/application.lock" \
        --output-file "$STAGING_DIR/${service}.lock" >/dev/null
done
seed_constraint=()
if [ -n "$UPGRADE_PACKAGE" ]; then
    seed_constraint=(--constraint "$STAGING_DIR/ci.lock.constraints")
fi
uv pip compile requirements-ci.txt "${common[@]}" "${seed_constraint[@]}" \
    --output-file "$STAGING_DIR/ci.lock" >/dev/null
if [ -n "$UPGRADE_PACKAGE" ]; then
    target_lock check vendor/application-requirements.lock "$STAGING_DIR/application.lock"
    target_lock check requirements-ci.lock "$STAGING_DIR/ci.lock"
    for service in agent search-mediator ui quarantine; do
        target_lock check "services/$service/requirements.lock" "$STAGING_DIR/$service.lock"
        sed -i "s#${STAGING_DIR}/${service}.lock.constraints#services/${service}/requirements.lock#g" "$STAGING_DIR/$service.lock"
    done
    sed -i "s#${STAGING_DIR}/ci.lock.constraints#requirements-ci.lock#g" "$STAGING_DIR/ci.lock"
fi
# Canonicalize resolver comments so temporary staging names never enter locks.
for lock in "$STAGING_DIR/"*.lock; do
    sed -i -e "s#${STAGING_DIR}/application.lock.constraints#vendor/application-requirements.lock#g" -e "s#${STAGING_DIR}/application.lock#vendor/application-requirements.lock#g" "$lock"
done
for service in agent search-mediator ui quarantine; do
    mv "$STAGING_DIR/${service}.lock" "services/${service}/requirements.lock"
done
mv "$STAGING_DIR/application.lock" vendor/application-requirements.lock
mv "$STAGING_DIR/ci.lock" requirements-ci.lock
