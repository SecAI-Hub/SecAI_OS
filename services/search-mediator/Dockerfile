FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40 AS build

# hadolint ignore=DL3002
USER root
ENV PYTHON_VERSION=3.14.5
ENV PYTHON_TARBALL_SHA256=7e32597b99e5d9a39abed35de4693fa169df3e5850d4c334337ffd6a19a36db6
ENV PREFIX=/opt/python
ENV PATCH_DIR=/build/cpython-patches
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="${VIRTUAL_ENV}/bin:${PREFIX}/bin:${PATH}"

WORKDIR /app
COPY build/custom-python/install-cpython.sh /build/install-cpython.sh
COPY build/cpython-patches/ /build/cpython-patches/
RUN chmod 0555 /build/install-cpython.sh && /build/install-cpython.sh
RUN python3 -m venv "${VIRTUAL_ENV}"

COPY services/search-mediator/requirements.lock /app/requirements.lock
COPY services/common/ /app/services/common/
COPY services/search-mediator/ /app/services/search-mediator/
COPY services/search-mediator/entrypoint.py /app/entrypoint.py

RUN pip install --no-cache-dir --require-hashes -r /app/requirements.lock && \
    BASE_SITE_PACKAGES="$("${PREFIX}/bin/python3" -c "import sysconfig; print(sysconfig.get_paths()['purelib'])")" && \
    VENV_SITE_PACKAGES="$("${VIRTUAL_ENV}/bin/python" -c "import sysconfig; print(sysconfig.get_paths()['purelib'])")" && \
    rm -rf \
        "${PREFIX}/bin/pip"* \
        "${PREFIX}/lib/python3.14/ensurepip" \
        "${BASE_SITE_PACKAGES}/pip" \
        "${BASE_SITE_PACKAGES}"/pip-*.dist-info \
        "${BASE_SITE_PACKAGES}/pkg_resources" \
        "${BASE_SITE_PACKAGES}/setuptools" \
        "${BASE_SITE_PACKAGES}"/setuptools-*.dist-info \
        "${BASE_SITE_PACKAGES}/wheel" \
        "${BASE_SITE_PACKAGES}"/wheel-*.dist-info \
        "${VIRTUAL_ENV}/bin/pip"* \
        "${VENV_SITE_PACKAGES}/pip" \
        "${VENV_SITE_PACKAGES}"/pip-*.dist-info \
        "${VENV_SITE_PACKAGES}/pkg_resources" \
        "${VENV_SITE_PACKAGES}/setuptools" \
        "${VENV_SITE_PACKAGES}"/setuptools-*.dist-info \
        "${VENV_SITE_PACKAGES}/wheel" \
        "${VENV_SITE_PACKAGES}"/wheel-*.dist-info && \
    chmod 0555 /app/entrypoint.py && \
    chown -R 65534:65534 /app "${VIRTUAL_ENV}" "${PREFIX}"

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40 AS runtime-base

RUN apk add --no-cache \
        bzip2 \
        ca-certificates \
        expat \
        gdbm \
        libffi \
        libgcc \
        libstdc++ \
        ncurses-libs \
        openssl \
        readline \
        sqlite-libs \
        xz \
        zlib

FROM scratch

ENV VIRTUAL_ENV=/opt/venv
ENV PATH="${VIRTUAL_ENV}/bin:/opt/python/bin:${PATH}"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/services

WORKDIR /app
COPY --from=runtime-base /etc/ssl /etc/ssl
COPY --from=runtime-base /lib/ld-musl-*.so.1 /lib/
COPY --from=runtime-base /lib/libc.musl-*.so.1 /lib/
COPY --from=build /usr/lib/libbz2.so* /usr/lib/
COPY --from=runtime-base /usr/lib/engines-3 /usr/lib/engines-3
COPY --from=runtime-base /usr/lib/ossl-modules /usr/lib/ossl-modules
COPY --from=runtime-base /usr/lib/libcrypto.so.3 /usr/lib/
COPY --from=runtime-base /usr/lib/libssl.so.3 /usr/lib/
COPY --from=runtime-base /usr/lib/libexpat.so.1* /usr/lib/
COPY --from=runtime-base /usr/lib/libffi.so.8* /usr/lib/
COPY --from=runtime-base /usr/lib/libformw.so.6* /usr/lib/
COPY --from=runtime-base /usr/lib/libgcc_s.so.1 /usr/lib/
COPY --from=runtime-base /usr/lib/libgdbm.so.6* /usr/lib/
COPY --from=runtime-base /usr/lib/libgdbm_compat.so.4* /usr/lib/
COPY --from=runtime-base /usr/lib/liblzma.so.5* /usr/lib/
COPY --from=runtime-base /usr/lib/libmenuw.so.6* /usr/lib/
COPY --from=runtime-base /usr/lib/libncursesw.so.6* /usr/lib/
COPY --from=runtime-base /usr/lib/libpanelw.so.6* /usr/lib/
COPY --from=runtime-base /usr/lib/libreadline.so.8* /usr/lib/
COPY --from=runtime-base /usr/lib/libsqlite3.so.0* /usr/lib/
COPY --from=runtime-base /usr/lib/libstdc++.so.6* /usr/lib/
COPY --from=runtime-base /usr/lib/libz.so.1* /usr/lib/
COPY --from=build /opt/python /opt/python
COPY --from=build /opt/venv /opt/venv
COPY --from=build /app /app

USER 65534:65534
EXPOSE 8485
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 CMD ["/opt/venv/bin/python", "-c", "from urllib.request import urlopen; import os, sys; port=os.getenv('BIND_ADDR','127.0.0.1:8485').rsplit(':',1)[-1]; sys.exit(0 if urlopen(f'http://127.0.0.1:{port}/live', timeout=3).status == 200 else 1)"]
ENTRYPOINT ["/opt/venv/bin/python", "/app/entrypoint.py"]
