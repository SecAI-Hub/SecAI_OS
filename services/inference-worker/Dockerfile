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
FROM ghcr.io/ggml-org/llama.cpp:server@sha256:51570a4f93c5ce81ac6f2b1ea16a58771cfded2adb34241df7e75329b24fe76e AS server
FROM ghcr.io/ggml-org/llama.cpp:server-cuda@sha256:4c0ece468721077a8bff8c114f8b0a92a8604ed310c91939fadfe37595a53b9e AS server-cuda
FROM ghcr.io/ggml-org/llama.cpp:server-cuda13@sha256:d43a80e7b7f5a32c2341d3c981cf8da16be6348a3baed65bf39296d519b3466b AS server-cuda13
FROM ghcr.io/ggml-org/llama.cpp:server-rocm@sha256:dca144cf7524616bc11a03732296924e652f727f321c4bc125d0b7671138da4b AS server-rocm
FROM ghcr.io/ggml-org/llama.cpp:server-vulkan@sha256:31bca24d4ecd1ee8decae5d626ae833bb5d34b94ba9d2f308e7cedcd6bb3e247 AS server-vulkan
FROM ghcr.io/ggml-org/llama.cpp:server-intel@sha256:3e76f50d7217e288b3ce760b0ef12ec9c7b1c7a7cc1dcaf3c4c1732404f33d48 AS server-intel
FROM ghcr.io/ggml-org/llama.cpp:server-openvino@sha256:0ed9be3e1b943632ebdd26cf6ce7a127b9adaa4cb9335fa654784b15cd33b2b0 AS server-openvino

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
