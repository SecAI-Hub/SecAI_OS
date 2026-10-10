# Inference worker: wraps llama-server (llama.cpp) with optional accelerator images.
# Build from the repository root with -f services/inference-worker/Dockerfile.
# Every selectable upstream is pinned independently. Callers select one of the
# fixed final targets (for example, --target inference-cuda); no build argument
# is ever interpolated into a FROM instruction.
#
# Available final targets:
#   inference-cpu      - CPU only
#   inference-cuda     - NVIDIA GPUs (CUDA 12)
#   inference-cuda13   - NVIDIA GPUs (CUDA 13)
#   inference-rocm     - AMD GPUs
#   inference-vulkan   - Cross-vendor Vulkan compute
#   inference-intel    - Intel SYCL
#   inference-openvino - Intel OpenVINO
FROM ghcr.io/ggml-org/llama.cpp:server@sha256:fcca4dac388066ca93db561751e8caf5fc7d46d9df5f00a7422026db68468e31 AS server
FROM ghcr.io/ggml-org/llama.cpp:server-cuda@sha256:7f87a3bbe3143cdb857f5c84f82d2c15528be70ca0e7c5ade9a47d56b791f93f AS server-cuda
FROM ghcr.io/ggml-org/llama.cpp:server-cuda13@sha256:873a4e2f20385c10c6e5ea7476c07ff3885fa0f87939a4b8e13259f8c5ba3f08 AS server-cuda13
FROM ghcr.io/ggml-org/llama.cpp:server-rocm@sha256:c0bbf966565a5c55d06ae938d940a79fa8a60a2d06aed456e2905b0930051ca2 AS server-rocm
FROM ghcr.io/ggml-org/llama.cpp:server-vulkan@sha256:f862c901a0089bc3dc326bd24f208bfcd147839783328d252e911a004c94ff3c AS server-vulkan
FROM ghcr.io/ggml-org/llama.cpp:server-intel@sha256:9cc08fd43780a3ed5248feb9f89d20d4b2cf7653c883f0481ee7fe0bf3a67543 AS server-intel
FROM ghcr.io/ggml-org/llama.cpp:server-openvino@sha256:8371d87bebd1ae867e17b78d31a2dad39189e41e6a16761cb435eb329a12d5bd AS server-openvino

FROM cgr.dev/chainguard/wolfi-base:latest@sha256:96ff486b326d15db16aa1fbd41a17043a557bebf76d2c0ac932e717534025940 AS runtime-base

RUN apk upgrade --no-cache && \
    apk add --no-cache \
        ca-certificates \
        libgcc \
        libgomp \
        libstdc++ \
        openssl \
        zlib

# The entrypoint script reads appliance.yaml and starts llama-server
# with the correct model path and settings.
COPY services/inference-worker/entrypoint.sh /entrypoint.sh
COPY files/system/usr/libexec/secure-ai/prepare-inference-auth.sh /prepare-inference-auth.sh
RUN sed -i 's/\r$//' /entrypoint.sh \
    && sed -i 's/\r$//' /prepare-inference-auth.sh \
    && chmod +x /entrypoint.sh /prepare-inference-auth.sh

ENV LD_LIBRARY_PATH=/opt/llama-server
ENV LLAMA_SERVER_BIN=/opt/llama-server/llama-server

USER 65534:65534
EXPOSE 8465
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=5 CMD port_hex="$(printf '%04X' "${BIND_ADDR##*:}")"; grep -qi "00000000:${port_hex} .* 0A " /proc/net/tcp || grep -qi "0100007F:${port_hex} .* 0A " /proc/net/tcp || exit 1
ENTRYPOINT ["/entrypoint.sh"]

FROM runtime-base AS inference-cpu
COPY --from=server /app/ /opt/llama-server/

FROM runtime-base AS inference-cuda
COPY --from=server-cuda /app/ /opt/llama-server/

FROM runtime-base AS inference-cuda13
COPY --from=server-cuda13 /app/ /opt/llama-server/

FROM runtime-base AS inference-rocm
COPY --from=server-rocm /app/ /opt/llama-server/

FROM runtime-base AS inference-vulkan
COPY --from=server-vulkan /app/ /opt/llama-server/

FROM runtime-base AS inference-intel
COPY --from=server-intel /app/ /opt/llama-server/

FROM runtime-base AS inference-openvino
COPY --from=server-openvino /app/ /opt/llama-server/

# Keep the default build result CPU-only. Accelerator builds must explicitly
# select one of the fixed targets above.
FROM inference-cpu AS runtime
