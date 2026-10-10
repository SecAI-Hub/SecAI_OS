FROM docker.io/library/golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mcp-firewall .

FROM docker.io/library/alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
LABEL org.opencontainers.image.source="https://github.com/SecAI-Hub/mcp-firewall" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN mkdir -p /etc/ssl/certs /etc/mcp-firewall /var/lib/secure-ai/mcp-firewall && \
    chown 65534:65534 /etc/mcp-firewall /var/lib/secure-ai/mcp-firewall && \
    chmod 0755 /etc/mcp-firewall && \
    chmod 0750 /var/lib/secure-ai/mcp-firewall
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --chown=65534:65534 policies/default-policy.yaml /etc/mcp-firewall/policy.yaml
COPY --from=build /out/mcp-firewall /usr/local/bin/mcp-firewall
ENV MCP_FIREWALL_POLICY=/etc/mcp-firewall/policy.yaml \
    BIND_ADDR=0.0.0.0:8510 \
    ALLOW_REMOTE_BIND=true
USER 65534:65534
EXPOSE 8510
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 \
  CMD wget -q -T 3 -O - http://127.0.0.1:8510/health >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/mcp-firewall"]
CMD ["serve"]
