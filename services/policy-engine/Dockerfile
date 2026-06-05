FROM docker.io/library/golang:1.26.4-alpine@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 go build -o /policy-engine .

FROM docker.io/library/alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
RUN apk add --no-cache ca-certificates
COPY --from=build /policy-engine /usr/local/bin/policy-engine
USER 65534:65534
EXPOSE 8500
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 CMD port="${BIND_ADDR##*:}"; port="${port:-8500}"; wget -q -T 3 -O - "http://127.0.0.1:${port}/health" >/dev/null || exit 1
ENTRYPOINT ["policy-engine"]
