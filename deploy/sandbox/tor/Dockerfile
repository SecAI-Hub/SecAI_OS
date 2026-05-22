FROM docker.io/library/alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11

RUN apk add --no-cache tor

RUN mkdir -p /var/lib/tor && \
    chown -R tor:tor /var/lib/tor

USER tor
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=5 CMD nc -z 127.0.0.1 9050 || exit 1
ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
