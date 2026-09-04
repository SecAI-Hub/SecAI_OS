FROM docker.io/library/golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build

WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 go build \
    -buildvcs=false \
    -trimpath \
    -ldflags="-s -w -buildid=" \
    -o /ui-ingress .

FROM scratch

COPY --from=build --chown=65534:65534 /ui-ingress /ui-ingress
USER 65534:65534
EXPOSE 8480
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=5 CMD ["/ui-ingress", "healthcheck"]
ENTRYPOINT ["/ui-ingress"]
