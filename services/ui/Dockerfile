FROM docker.io/library/python:3.14-alpine3.23@sha256:b165067c5afc37fa5608a3c05609cc3d51aafd808a30fbfd822ee594fef55ad4

WORKDIR /app
COPY pyproject.toml .
COPY requirements.lock .
COPY ui/ ui/

RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock && \
    python -m pip install --no-cache-dir --no-deps .

USER 65534:65534
EXPOSE 8480
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 CMD python -c "from urllib.request import urlopen; import os, sys; port=os.getenv('BIND_ADDR','127.0.0.1:8480').rsplit(':',1)[-1]; sys.exit(0 if urlopen(f'http://127.0.0.1:{port}/health', timeout=3).status == 200 else 1)"
ENTRYPOINT ["secure-ai-ui"]
