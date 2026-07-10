FROM docker.io/library/golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /mcp-firewall .

FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
RUN apk add --no-cache ca-certificates
COPY --from=build /mcp-firewall /usr/local/bin/mcp-firewall
USER 65534:65534
EXPOSE 8510
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 CMD wget -q -T 3 -O - http://127.0.0.1:8510/health >/dev/null || exit 1
ENTRYPOINT ["mcp-firewall"]
