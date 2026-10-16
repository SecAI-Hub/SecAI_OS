FROM docker.io/library/golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 go build -o /policy-engine .

FROM docker.io/library/alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache ca-certificates
COPY --from=build /policy-engine /usr/local/bin/policy-engine
USER 65534:65534
EXPOSE 8500
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 CMD port="${BIND_ADDR##*:}"; port="${port:-8500}"; wget -q -T 3 -O - "http://127.0.0.1:${port}/health" >/dev/null || exit 1
ENTRYPOINT ["policy-engine"]
