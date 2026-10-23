FROM docker.io/library/python:3.15.0-alpine3.24@sha256:2699b90f4d562a22e2dd076c82f964032f64814204bff36d271a54ba4cc2c7e2

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
