# Diffusion worker: image and video generation via diffusers library.
# Build arg COMPUTE selects the GPU backend:
#   cuda  - NVIDIA GPUs (CUDA 13.2)
#   rocm  - AMD GPUs (ROCm 6.4)
#   cpu   - CPU only (AVX2/AVX-512 optimized, works everywhere)
ARG COMPUTE=cuda
ARG TORCH_CUDA_VERSION=2.12.0+cu132
ARG TORCH_ROCM_VERSION=2.9.1+rocm6.4
ARG TORCH_CPU_VERSION=2.12.0+cpu
ARG TORCHVISION_CUDA_VERSION=0.27.0+cu132
ARG TORCHVISION_ROCM_VERSION=0.24.1+rocm6.4
ARG TORCHVISION_CPU_VERSION=0.27.0+cpu
ARG TORCH_CUDA_INDEX_URL=https://download.pytorch.org/whl/cu132
ARG TORCH_ROCM_INDEX_URL=https://download.pytorch.org/whl/rocm6.4
ARG TORCH_CPU_INDEX_URL=https://download.pytorch.org/whl/cpu
ARG IPEX_CPU_VERSION=2.6.0

FROM docker.io/library/python:3.14-slim@sha256:c845af9399020c7e562969a13689e929074a10fd057acd1b1fad06a2fb068e97 AS base

ARG COMPUTE
ARG TORCH_CUDA_VERSION
ARG TORCH_ROCM_VERSION
ARG TORCH_CPU_VERSION
ARG TORCHVISION_CUDA_VERSION
ARG TORCHVISION_ROCM_VERSION
ARG TORCHVISION_CPU_VERSION
ARG TORCH_CUDA_INDEX_URL
ARG TORCH_ROCM_INDEX_URL
ARG TORCH_CPU_INDEX_URL
ARG IPEX_CPU_VERSION

RUN python -m pip install --no-cache-dir --upgrade pip==26.1.1 setuptools==82.0.1

# Install PyTorch with the appropriate compute backend
RUN if [ "$COMPUTE" = "cuda" ]; then \
        pip install --no-cache-dir "torch==${TORCH_CUDA_VERSION}" "torchvision==${TORCHVISION_CUDA_VERSION}" --index-url "${TORCH_CUDA_INDEX_URL}"; \
    elif [ "$COMPUTE" = "rocm" ]; then \
        pip install --no-cache-dir "torch==${TORCH_ROCM_VERSION}" "torchvision==${TORCHVISION_ROCM_VERSION}" --index-url "${TORCH_ROCM_INDEX_URL}"; \
    else \
        pip install --no-cache-dir "torch==${TORCH_CPU_VERSION}" "torchvision==${TORCHVISION_CPU_VERSION}" --index-url "${TORCH_CPU_INDEX_URL}"; \
    fi

RUN pip install --no-cache-dir \
    "diffusers[torch]==0.38.0" \
    transformers==5.6.2 \
    accelerate==1.13.0 \
    safetensors==0.8.0rc0 \
    flask==3.1.3 \
    gunicorn==23.0.0 \
    imageio==2.37.3 \
    imageio-ffmpeg==0.6.0 \
    pyyaml==6.0.3 \
    Pillow==12.2.0 \
    urllib3==2.7.0

# Intel XPU support (install IPEX when building for CPU — it auto-detects Intel GPUs)
RUN if [ "$COMPUTE" = "cpu" ]; then \
        pip install --no-cache-dir "intel-extension-for-pytorch==${IPEX_CPU_VERSION}" 2>/dev/null || true; \
    fi

COPY app.py /app/app.py
COPY entrypoint.sh /app/diffusion-entrypoint.sh

RUN chmod 0555 /app/diffusion-entrypoint.sh

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
USER 65534:65534
EXPOSE 8455
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=5 CMD python -c "from urllib.request import urlopen; import os, sys; port=os.getenv('BIND_ADDR','127.0.0.1:8455').rsplit(':',1)[-1]; sys.exit(0 if urlopen(f'http://127.0.0.1:{port}/health', timeout=5).status == 200 else 1)"
ENTRYPOINT ["/app/diffusion-entrypoint.sh"]
