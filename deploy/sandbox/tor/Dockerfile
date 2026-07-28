FROM docker.io/library/alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

RUN apk add --no-cache tor

RUN mkdir -p /var/lib/tor && \
    chown -R tor:tor /var/lib/tor

USER tor
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=5 CMD nc -z 127.0.0.1 9050 || exit 1
ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
