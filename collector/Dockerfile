# syntax=docker/dockerfile:1.28@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
# Build stage
FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder

# Install build dependencies including Vectorscan (Hyperscan fork)
RUN apk add --no-cache git build-base clang lld vectorscan-dev vectorscan-static pkgconf

# Install ocb (OpenTelemetry Collector Builder)
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go install go.opentelemetry.io/collector/cmd/builder@v0.163.0

WORKDIR /build

# Copy the entire repo for local module resolution
COPY . .

WORKDIR /build/collector

# Cache mounts let unchanged imports skip recompilation across releases even though
# the version sed in CI invalidates this layer's input on every release.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CC=clang CXX=clang++ \
    builder --ldflags="-s -w -linkmode external -extldflags '-static -fuse-ld=lld'" --config=manifest.yaml

# Export target used by the release workflow for architecture-specific binaries.
FROM scratch AS binary

COPY --from=builder /build/collector/_build/tero-collector /tero-collector

# Runtime stage
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

LABEL org.opencontainers.image.description="Tero OpenTelemetry Collector Distribution"
LABEL org.opencontainers.image.source="https://github.com/usetero/tero-collector-distro"
LABEL org.opencontainers.image.licenses="Apache-2.0"


RUN apk add --no-cache ca-certificates libstdc++ libgcc vectorscan

COPY --from=builder /build/collector/_build/tero-collector /usr/bin/tero-collector

# Default config and policies
COPY --from=builder /build/collector/config.yaml /etc/tero-collector/config.yaml
COPY --from=builder /build/collector/policies.json /etc/tero-collector/policies.json

EXPOSE 4317 4318 13133

ENTRYPOINT ["/usr/bin/tero-collector"]
CMD ["--config", "/etc/tero-collector/config.yaml"]
