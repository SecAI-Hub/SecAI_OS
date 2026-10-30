FROM docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

RUN apk add --no-cache tor

RUN mkdir -p /var/lib/tor && \
    chown -R tor:tor /var/lib/tor

USER tor
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=5 CMD nc -z 127.0.0.1 9050 || exit 1
ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
