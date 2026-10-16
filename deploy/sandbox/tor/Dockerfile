FROM docker.io/library/alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

RUN apk add --no-cache tor

RUN mkdir -p /var/lib/tor && \
    chown -R tor:tor /var/lib/tor

USER tor
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=5 CMD nc -z 127.0.0.1 9050 || exit 1
ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
