FROM docker.io/library/python:3.14-alpine3.23@sha256:5a824eb82cc75361f98611f3cfc5091ea33f10a6ccea4d4ebdabbc523b9a1614

WORKDIR /app
COPY requirements.txt .
COPY setup.py .
COPY agent/ agent/

RUN python -m pip install --no-cache-dir --upgrade pip==26.1.1 && \
    python -m pip install --no-cache-dir -r requirements.txt && \
    python -m pip install --no-cache-dir .

USER 65534:65534
EXPOSE 8476
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 CMD python -c "from urllib.request import urlopen; import os, sys; port=os.getenv('BIND_ADDR','127.0.0.1:8476').rsplit(':',1)[-1]; sys.exit(0 if urlopen(f'http://127.0.0.1:{port}/health', timeout=3).status == 200 else 1)"
ENTRYPOINT ["secai-agent"]
