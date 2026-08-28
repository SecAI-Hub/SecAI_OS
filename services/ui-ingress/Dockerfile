FROM docker.io/library/golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build

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
