FROM docker.io/library/golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 go build -o /tool-firewall .

FROM docker.io/library/alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
RUN apk add --no-cache ca-certificates
COPY --from=build /tool-firewall /usr/local/bin/tool-firewall
USER 65534:65534
EXPOSE 8475
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 CMD port="${BIND_ADDR##*:}"; port="${port:-8475}"; wget -q -T 3 -O - "http://127.0.0.1:${port}/health" >/dev/null || exit 1
ENTRYPOINT ["tool-firewall"]
