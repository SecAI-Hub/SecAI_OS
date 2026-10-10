ARG ENABLE_GARAK_SCANNER=false

FROM ghcr.io/ggml-org/llama.cpp:server@sha256:fcca4dac388066ca93db561751e8caf5fc7d46d9df5f00a7422026db68468e31 AS llama_server

FROM cgr.dev/chainguard/wolfi-base:latest@sha256:96ff486b326d15db16aa1fbd41a17043a557bebf76d2c0ac932e717534025940 AS build

ARG ENABLE_GARAK_SCANNER

WORKDIR /app
COPY pyproject.toml .
COPY requirements.lock .
COPY quarantine/ quarantine/

RUN apk upgrade --no-cache && \
    apk add --no-cache \
    build-base \
    ca-certificates \
    libffi-dev \
    openssl-dev \
    py3.12-pip \
    python-3.12-dev \
    yara-dev

RUN python -m venv /opt/venv && \
    /opt/venv/bin/python -m pip install --no-cache-dir --require-hashes -r requirements.lock && \
    /opt/venv/bin/python -m pip install --no-cache-dir --no-deps .

RUN set -eu; \
    if [ "$ENABLE_GARAK_SCANNER" = "true" ]; then \
        echo "ERROR: garak is not present in the reviewed default scanner lock"; \
        exit 1; \
    fi; \
    /opt/venv/bin/python -m pip check; \
    for scanner in modelscan fickling modelaudit; do \
        test -x "/opt/venv/bin/$scanner"; \
    done

RUN rm -rf \
    /opt/venv/bin/pip* \
    /opt/venv/lib/python3.12/site-packages/pip \
    /opt/venv/lib/python3.12/site-packages/pip-*.dist-info \
    /opt/venv/lib/python3.12/site-packages/wheel \
    /opt/venv/lib/python3.12/site-packages/wheel-*.dist-info

FROM cgr.dev/chainguard/wolfi-base:latest@sha256:96ff486b326d15db16aa1fbd41a17043a557bebf76d2c0ac932e717534025940

WORKDIR /app

RUN apk upgrade --no-cache && \
    apk add --no-cache \
    ca-certificates \
    libffi \
    libgcc \
    libgomp \
    libstdc++ \
    openssl \
    python-3.12 \
    yara

COPY --from=llama_server /app/ /opt/llama-server/
COPY --from=build /opt/venv /opt/venv
RUN mkdir -p /usr/local/bin && \
    ln -sf /opt/venv/bin/modelscan /usr/local/bin/modelscan && \
    ln -sf /opt/venv/bin/fickling /usr/local/bin/fickling && \
    ln -sf /opt/venv/bin/modelaudit /usr/local/bin/modelaudit

ENV LLAMA_SERVER_BIN=/opt/llama-server/llama-server
ENV LD_LIBRARY_PATH=/opt/llama-server
ENV PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin
ENV HOME=/tmp/secure-ai-home
ENV XDG_CONFIG_HOME=/tmp/secure-ai-config
ENV XDG_DATA_HOME=/tmp/secure-ai-data
ENV XDG_CACHE_HOME=/tmp/secure-ai-cache
USER 65534:65534
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["python", "-c", "from pathlib import Path; import sys; sys.exit(0 if Path('/var/lib/secure-ai/quarantine').is_dir() and Path('/var/lib/secure-ai/registry').is_dir() else 1)"]
ENTRYPOINT ["/opt/venv/bin/secure-ai-quarantine"]
