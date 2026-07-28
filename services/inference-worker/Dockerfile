# Inference worker: wraps llama-server (llama.cpp) with optional accelerator images.
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
FROM ghcr.io/ggml-org/llama.cpp:server@sha256:a576442ad3649c0b5ea74e20ad29a17c121117f32607cfe59ff27cc38066f874 AS server
FROM ghcr.io/ggml-org/llama.cpp:server-cuda@sha256:fc26b60b30836e5a12fdb28823a3d4bda984c9386a4b04200c78e5a5150067fb AS server-cuda
FROM ghcr.io/ggml-org/llama.cpp:server-cuda13@sha256:88b644c232f36da21405f5d849e2d58d333210e79512e7b3efd8bde7345f64fd AS server-cuda13
FROM ghcr.io/ggml-org/llama.cpp:server-rocm@sha256:36bd528235ab24e0e9d88a11da55a6b142e2f13c1ede97d8f038dc46a5014765 AS server-rocm
FROM ghcr.io/ggml-org/llama.cpp:server-vulkan@sha256:eddb40b8a348a652c8829ef036df9bbbae537755ae7026bf6d4b403840cd468e AS server-vulkan
FROM ghcr.io/ggml-org/llama.cpp:server-intel@sha256:ded090960b3a0c4e2be2f47b092a7de276f7a534356675d16cc1280bf7b39c57 AS server-intel
FROM ghcr.io/ggml-org/llama.cpp:server-openvino@sha256:df1a75e34c7d40dc6d156624dc87258cb9a254cd4f6122461b0b2a6fa31b8ad1 AS server-openvino

FROM cgr.dev/chainguard/wolfi-base:latest@sha256:003627df3c1e1bba0c4116afcddb314aca9594ee2328c7e876a8081a6c988b2e AS runtime-base

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
COPY entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh \
    && chmod +x /entrypoint.sh

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
