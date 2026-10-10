FROM docker.io/library/python:3.14.8-alpine3.24@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72

# Build from the repository root: docker build -f services/ui/Dockerfile .
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/services

WORKDIR /app
COPY services/ui/pyproject.toml .
COPY services/ui/requirements.lock .
COPY services/ui/ui/ ui/
COPY services/common/ services/common/

RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock && \
    python -m pip install --no-cache-dir --no-deps --no-build-isolation .

USER 65534:65534
EXPOSE 8480
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 CMD python -c "from urllib.request import urlopen; import os, sys; port=os.getenv('BIND_ADDR','127.0.0.1:8480').rsplit(':',1)[-1]; sys.exit(0 if urlopen(f'http://127.0.0.1:{port}/health', timeout=3).status == 200 else 1)"
ENTRYPOINT ["secure-ai-ui"]
