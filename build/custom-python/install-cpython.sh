#!/bin/sh
set -eu

: "${PYTHON_VERSION:?PYTHON_VERSION is required}"
: "${PYTHON_TARBALL_SHA256:?PYTHON_TARBALL_SHA256 is required}"

PREFIX="${PREFIX:-/opt/python}"
PATCH_DIR="${PATCH_DIR:-/build/cpython-patches}"
PATCH_STATUS_FILE="${PATCH_STATUS_FILE:-/tmp/secai-cpython-patch-status.tsv}"
export PATCH_STATUS_FILE
PYTHON_TARBALL="Python-${PYTHON_VERSION}.tar.xz"
PYTHON_URL="https://www.python.org/ftp/python/${PYTHON_VERSION}/${PYTHON_TARBALL}"

apk add --no-cache \
    build-base \
    bzip2 \
    bzip2-dev \
    ca-certificates \
    expat \
    expat-dev \
    gdbm \
    gdbm-dev \
    libffi \
    libffi-dev \
    libgcc \
    libstdc++ \
    linux-headers \
    ncurses-libs \
    ncurses-dev \
    openssl \
    openssl-dev \
    patch \
    readline \
    readline-dev \
    sqlite-libs \
    sqlite-dev \
    tar \
    wget \
    xz \
    xz-dev \
    zlib \
    zlib-dev

mkdir -p /tmp/python-src
wget -O "/tmp/${PYTHON_TARBALL}" "${PYTHON_URL}"
echo "${PYTHON_TARBALL_SHA256}  /tmp/${PYTHON_TARBALL}" | sha256sum -c -
tar -xJf "/tmp/${PYTHON_TARBALL}" -C /tmp/python-src --strip-components=1

cd /tmp/python-src
record_patch_status() {
    patch_file="${1}"
    patch_status="${2}"
    patch_name="$(basename "${patch_file}")"
    patch_sha256="$(sha256sum "${patch_file}" | awk '{print $1}')"
    printf '%s\t%s\t%s\n' "${patch_name}" "${patch_sha256}" "${patch_status}" >> "${PATCH_STATUS_FILE}"
}

patch_fix_already_present() {
    patch_name="$(basename "${1}")"
    case "${patch_name}" in
        0001-cve-2026-4786-webbrowser-action-bypass.patch)
            grep -F 'self._check_url(url.replace("%action", action))' Lib/webbrowser.py >/dev/null 2>&1 &&
                grep -F 'arg.replace("%action", action).replace("%s", url)' Lib/webbrowser.py >/dev/null 2>&1
            ;;
        *)
            return 1
            ;;
    esac
}

if [ -d "${PATCH_DIR}" ]; then
    : > "${PATCH_STATUS_FILE}"
    for patch_file in "${PATCH_DIR}"/*.patch; do
        [ -f "${patch_file}" ] || continue
        if patch --forward --dry-run --batch --fuzz=0 -p1 < "${patch_file}" >/dev/null 2>&1; then
            patch --forward --batch --fuzz=0 -p1 < "${patch_file}"
            record_patch_status "${patch_file}" "applied"
            continue
        fi
        if patch --reverse --dry-run --batch --fuzz=0 -p1 < "${patch_file}" >/dev/null 2>&1; then
            echo "patch already present upstream: ${patch_file}"
            record_patch_status "${patch_file}" "upstream_present"
            continue
        fi
        if patch_fix_already_present "${patch_file}"; then
            echo "patch fix already present upstream: ${patch_file}"
            record_patch_status "${patch_file}" "upstream_present"
            continue
        fi
        echo "failed to apply patch: ${patch_file}" >&2
        exit 1
    done
fi

./configure \
    --prefix="${PREFIX}" \
    --enable-ipv6 \
    --with-ensurepip=install
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
make install

mkdir -p "${PREFIX}/share"
"${PREFIX}/bin/python3" - <<'PY'
import hashlib
import json
import os
from pathlib import Path

prefix = Path(os.environ["PREFIX"])
patch_dir = Path(os.environ["PATCH_DIR"])
patch_status_file = Path(os.environ["PATCH_STATUS_FILE"])
patch_statuses = {}
if patch_status_file.exists():
    for line in patch_status_file.read_text(encoding="utf-8").splitlines():
        name, sha256, status = line.split("\t", 2)
        patch_statuses[name] = {"sha256": sha256, "status": status}
manifest = {
    "upstream_version": os.environ["PYTHON_VERSION"],
    "source_tarball_sha256": os.environ["PYTHON_TARBALL_SHA256"],
    "patches": [],
}
for patch_path in sorted(patch_dir.glob("*.patch")):
    patch_status = patch_statuses.get(patch_path.name, {})
    manifest["patches"].append({
        "name": patch_path.name,
        "sha256": patch_status.get("sha256") or hashlib.sha256(patch_path.read_bytes()).hexdigest(),
        "status": patch_status.get("status", "unknown"),
    })
(prefix / "share" / "secai-cpython-build.json").write_text(
    json.dumps(manifest, indent=2),
    encoding="utf-8",
)
PY

rm -rf /tmp/python-src "/tmp/${PYTHON_TARBALL}"
