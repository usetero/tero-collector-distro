# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies including Vectorscan (Hyperscan fork)
RUN apk add --no-cache git build-base vectorscan-dev vectorscan-static pkgconf

# Enable CGO for Vectorscan support
ENV CGO_ENABLED=1

# Install ocb (OpenTelemetry Collector Builder)
RUN go install go.opentelemetry.io/collector/cmd/builder@v0.144.0

WORKDIR /build

# Copy the entire repo for local module resolution
COPY . .

WORKDIR /build/collector

# Generate collector source code (skip compilation to control CGO ourselves)
RUN builder --config=manifest.yaml --skip-compilation

# Build the collector with CGO enabled for Vectorscan
WORKDIR /build/collector/_build
RUN go build -trimpath -o tero-collector -ldflags="-s -w" .

# Runtime stage
FROM alpine:3.21

LABEL org.opencontainers.image.description="Tero OpenTelemetry Collector Distribution"

RUN apk add --no-cache ca-certificates libstdc++ libgcc vectorscan

COPY --from=builder /build/collector/_build/tero-collector /usr/bin/tero-collector

# Default config location
COPY --from=builder /build/collector/config.yaml /etc/tero-collector/config.yaml

EXPOSE 4317 4318 13133

ENTRYPOINT ["/usr/bin/tero-collector"]
CMD ["--config", "/etc/tero-collector/config.yaml"]
