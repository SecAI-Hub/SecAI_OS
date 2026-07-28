# Diffusion worker: image and video generation via diffusers library.
#
# Build from the repository root so the reviewed backend lockfiles are in the
# Docker context:
#   docker build -f services/diffusion-worker/Dockerfile \
#     --build-arg COMPUTE=cpu .
#
# COMPUTE selects cuda (CUDA 12.9), rocm (ROCm 7.1), or cpu.
ARG COMPUTE=cuda
ARG TARGETARCH

FROM docker.io/library/python:3.12-slim@sha256:401f6e1a67dad31a1bd78e9ad22d0ee0a3b52154e6bd30e90be696bb6a3d7461 AS base

ARG COMPUTE
ARG TARGETARCH

RUN test "$TARGETARCH" = "amd64" || \
    { echo "diffusion locks support only linux/amd64 (got: ${TARGETARCH:-unknown})" >&2; exit 64; }

COPY files/scripts/diffusion-cpu.lock \
     files/scripts/diffusion-cuda.lock \
     files/scripts/diffusion-rocm.lock \
     /tmp/diffusion-locks/

# The lock itself carries the backend-specific PyTorch index. Every artifact,
# including packaging tools used during the build, is exact-versioned and
# hash-verified. Unsupported COMPUTE values fail closed.
RUN case "$COMPUTE" in \
        cpu|cuda|rocm) lock="/tmp/diffusion-locks/diffusion-${COMPUTE}.lock" ;; \
        *) echo "unsupported COMPUTE backend: $COMPUTE" >&2; exit 64 ;; \
    esac && \
    python -m pip install --no-cache-dir --require-hashes -r "$lock" && \
    python -m pip uninstall --yes pip setuptools wheel && \
    rm -rf /tmp/diffusion-locks

COPY services/diffusion-worker/app.py /app/app.py
COPY services/diffusion-worker/entrypoint.sh /app/diffusion-entrypoint.sh

RUN chmod 0555 /app/diffusion-entrypoint.sh

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
USER 65534:65534
EXPOSE 8455
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=5 CMD python -c "from urllib.request import urlopen; import os, sys; port=os.getenv('BIND_ADDR','127.0.0.1:8455').rsplit(':',1)[-1]; sys.exit(0 if urlopen(f'http://127.0.0.1:{port}/health', timeout=5).status == 200 else 1)"
ENTRYPOINT ["/app/diffusion-entrypoint.sh"]
