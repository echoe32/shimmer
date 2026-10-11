# syntax=docker/dockerfile:1

# The build is pure Go (modernc.org/sqlite needs no C compiler), so the binary
# is static and cross-compiles on the build host for any target platform.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY cmd ./cmd
COPY internal ./internal

# timetzdata embeds the zone database, so TZ works in the empty final image.
ARG TARGETOS TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -tags timetzdata -ldflags="-s -w" -o /out/shimmer ./cmd/shimmer \
 && mkdir /out/data

FROM scratch
# CA roots for the TLS checks (gstatic, ipify) and https:// lists.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/shimmer /shimmer
COPY --from=build --chown=65532:65532 /out/data /data

USER 65532:65532
# Relative paths in flags and the config file resolve from here; mount the
# directory holding lists, results and .mmdb files at /data.
WORKDIR /data
ENTRYPOINT ["/shimmer"]
CMD ["-h"]
