FROM golang:1.23-alpine@sha256:ef18ee7117463ac1055f5a370ed18b8750f01589f13ea0b48a1c3c025e611b02 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /runtime-attestor .

FROM alpine:3.20@sha256:1e42bbe2508154c9126d48c2b8a75420c3544343bf86fd041fb7527e017a4b4a
RUN apk add --no-cache ca-certificates
COPY --from=build /runtime-attestor /usr/local/bin/runtime-attestor
USER 65534:65534
EXPOSE 8485
ENTRYPOINT ["runtime-attestor"]
