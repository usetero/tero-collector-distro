# syntax=docker/dockerfile:1.27@sha256:bde3983e9c939224420ddaf6b784cc30e09b035a4dea01f581230c50809f372e
# Build stage
FROM golang:1.27-alpine@sha256:4cb7ac979db5fcc41cae44b2227ba5ab8a51e8807f40d9ba4dee20a0ad960b5b AS builder

# Install build dependencies including Vectorscan (Hyperscan fork)
RUN apk add --no-cache git build-base clang lld vectorscan-dev vectorscan-static pkgconf

# Install ocb (OpenTelemetry Collector Builder)
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go install go.opentelemetry.io/collector/cmd/builder@v0.161.0

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
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

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
