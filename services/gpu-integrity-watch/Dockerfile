FROM docker.io/library/golang:1.26-alpine@sha256:f85330846cde1e57ca9ec309382da3b8e6ae3ab943d2739500e08c86393a21b1 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /gpu-integrity-watch .

FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
RUN apk add --no-cache ca-certificates
COPY --from=build /gpu-integrity-watch /usr/local/bin/gpu-integrity-watch
USER 65534:65534
EXPOSE 8505
ENTRYPOINT ["gpu-integrity-watch"]
