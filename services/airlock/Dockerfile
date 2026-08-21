FROM docker.io/library/golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 go build -o /airlock .

FROM docker.io/library/alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
RUN apk add --no-cache ca-certificates
COPY --from=build /airlock /usr/local/bin/airlock
USER 65534:65534
EXPOSE 8490
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 CMD port="${BIND_ADDR##*:}"; port="${port:-8490}"; wget -q -T 3 -O - "http://127.0.0.1:${port}/health" >/dev/null || exit 1
ENTRYPOINT ["airlock"]
