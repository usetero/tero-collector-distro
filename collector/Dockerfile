# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies including Hyperscan
RUN apk add --no-cache git build-base hyperscan-dev pkgconf

# Install ocb (OpenTelemetry Collector Builder)
RUN go install go.opentelemetry.io/collector/cmd/builder@v0.144.0

WORKDIR /build

# Copy the entire repo for local module resolution
COPY . .

WORKDIR /build/collector

# Generate collector source code from manifest
RUN builder --config=manifest.yaml

# Build the collector with CGO enabled for Hyperscan
WORKDIR /build/collector/_build
RUN CGO_ENABLED=1 go build -o tero-collector .

# Runtime stage
FROM alpine:3.21

LABEL org.opencontainers.image.description="Tero OpenTelemetry Collector Distribution"

RUN apk add --no-cache ca-certificates hyperscan

COPY --from=builder /build/collector/_build/tero-collector /usr/bin/tero-collector

# Default config location
COPY --from=builder /build/collector/config.yaml /etc/tero-collector/config.yaml

EXPOSE 4317 4318 13133

ENTRYPOINT ["/usr/bin/tero-collector"]
CMD ["--config", "/etc/tero-collector/config.yaml"]
