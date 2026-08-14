FROM docker.io/library/golang:1.27rc2-alpine@sha256:dcbb18cc5fa1082364dc6aa95224b6b55429d09cbb9631a053d8064c1c367300 AS build

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
