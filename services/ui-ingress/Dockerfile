FROM docker.io/library/golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build

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
