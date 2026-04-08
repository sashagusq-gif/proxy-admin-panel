FROM golang:1.26-alpine AS build

ENV CGO_ENABLED=0

RUN apk add --no-cache ca-certificates git

WORKDIR /src
RUN git clone --depth 1 https://github.com/dolonet/mtg-multi.git .
RUN mkdir -p /out
RUN version="$(git describe --exact-match HEAD 2>/dev/null || git describe --tags --always 2>/dev/null || echo dev)" && \
    go build -o /out/mtg -trimpath -mod=readonly -ldflags="-extldflags '-static' -s -w -X 'main.version=$version'" -a -tags netgo

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /out/mtg /usr/local/bin/mtg
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
