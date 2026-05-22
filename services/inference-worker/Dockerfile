# Inference worker: wraps llama-server (llama.cpp) with optional accelerator images.
# Build arg IMAGE_TAG selects the upstream image tag:
#   server         - CPU only
#   server-cuda    - NVIDIA GPUs (CUDA 12)
#   server-cuda13  - NVIDIA GPUs (CUDA 13)
#   server-rocm    - AMD GPUs
#   server-vulkan  - Cross-vendor Vulkan compute
#   server-intel   - Intel SYCL
#   server-openvino- Intel OpenVINO
ARG IMAGE_TAG=server

# SECURITY: Cannot digest-pin this image because the tag is dynamic.
# Pin each variant when building for production:
#   skopeo inspect docker://ghcr.io/ggml-org/llama.cpp:server-cuda   | jq -r '.Digest'
#   skopeo inspect docker://ghcr.io/ggml-org/llama.cpp:server-rocm   | jq -r '.Digest'
#   skopeo inspect docker://ghcr.io/ggml-org/llama.cpp:server        | jq -r '.Digest'
# TODO: pin digest per COMPUTE variant
#
# Upstream moved the published images from `ggerganov/llama.cpp` to
# `ggml-org/llama.cpp`; the old CPU tag no longer resolves.
FROM ghcr.io/ggml-org/llama.cpp:${IMAGE_TAG} AS llama_server

FROM cgr.dev/chainguard/wolfi-base:latest@sha256:0cff4df29a6597173dc8b813787318150141eb96ac783dc3ff4f5ff52c49a1e2 AS runtime

RUN apk upgrade --no-cache && \
    apk add --no-cache \
        ca-certificates \
        libgcc \
        libgomp \
        libstdc++ \
        openssl \
        zlib

COPY --from=llama_server /app/ /opt/llama-server/

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
