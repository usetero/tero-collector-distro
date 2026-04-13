# Build stage
FROM golang:1.26-alpine@sha256:c2a1f7b2095d046ae14b286b18413a05bb82c9bca9b25fe7ff5efef0f0826166 AS builder

# Install build dependencies including Vectorscan (Hyperscan fork)
RUN apk add --no-cache git build-base vectorscan-dev vectorscan-static pkgconf

# Install ocb (OpenTelemetry Collector Builder)
RUN go install go.opentelemetry.io/collector/cmd/builder@v0.148.0

WORKDIR /build

# Copy the entire repo for local module resolution
COPY . .

WORKDIR /build/collector

# Generate collector source code (skip compilation to control CGO ourselves)
RUN builder --config=manifest.yaml

# Runtime stage
FROM alpine:3.23@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659

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
