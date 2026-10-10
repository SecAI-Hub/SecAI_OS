FROM docker.io/library/alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk add --no-cache tor

RUN mkdir -p /var/lib/tor && \
    chown -R tor:tor /var/lib/tor

USER tor
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=5 CMD nc -z 127.0.0.1 9050 || exit 1
ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
