FROM docker.io/library/golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build

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
