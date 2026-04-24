#!/bin/sh
set -eu

: "${PYTHON_VERSION:?PYTHON_VERSION is required}"
: "${PYTHON_TARBALL_SHA256:?PYTHON_TARBALL_SHA256 is required}"

PREFIX="${PREFIX:-/opt/python}"
PATCH_DIR="${PATCH_DIR:-/build/cpython-patches}"
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
if [ -d "${PATCH_DIR}" ]; then
    for patch_file in "${PATCH_DIR}"/*.patch; do
        [ -f "${patch_file}" ] || continue
        patch -p1 < "${patch_file}"
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
manifest = {
    "upstream_version": os.environ["PYTHON_VERSION"],
    "source_tarball_sha256": os.environ["PYTHON_TARBALL_SHA256"],
    "patches": [],
}
for patch_path in sorted(patch_dir.glob("*.patch")):
    manifest["patches"].append({
        "name": patch_path.name,
        "sha256": hashlib.sha256(patch_path.read_bytes()).hexdigest(),
    })
(prefix / "share" / "secai-cpython-build.json").write_text(
    json.dumps(manifest, indent=2),
    encoding="utf-8",
)
PY

rm -rf /tmp/python-src "/tmp/${PYTHON_TARBALL}"
