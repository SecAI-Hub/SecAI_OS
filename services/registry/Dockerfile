FROM docker.io/library/golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 go build -o /registry . && \
    CGO_ENABLED=0 go build -o /secai-registryctl ./cmd/securectl/

FROM docker.io/library/alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
RUN apk add --no-cache ca-certificates
COPY --from=build /registry /usr/local/bin/registry
COPY --from=build /secai-registryctl /usr/local/bin/secai-registryctl
USER 65534:65534
EXPOSE 8470
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 CMD port="${BIND_ADDR##*:}"; port="${port:-8470}"; wget -q -T 3 -O - "http://127.0.0.1:${port}/health" >/dev/null || exit 1
ENTRYPOINT ["registry"]
