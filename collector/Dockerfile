# syntax=docker/dockerfile:1.23@sha256:2780b5c3bab67f1f76c781860de469442999ed1a0d7992a5efdf2cffc0e3d769
# Build stage
FROM golang:1.26-alpine@sha256:f85330846cde1e57ca9ec309382da3b8e6ae3ab943d2739500e08c86393a21b1 AS builder

# Install build dependencies including Vectorscan (Hyperscan fork)
RUN apk add --no-cache git build-base vectorscan-dev vectorscan-static pkgconf

# Install ocb (OpenTelemetry Collector Builder)
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go install go.opentelemetry.io/collector/cmd/builder@v0.148.0

WORKDIR /build

# Copy the entire repo for local module resolution
COPY . .

WORKDIR /build/collector

# Cache mounts let unchanged imports skip recompilation across releases even though
# the version sed in CI invalidates this layer's input on every release.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    builder --config=manifest.yaml

# Runtime stage
FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11

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
