# Tero Collector

<p align="center">
  <a href="https://github.com/tero-platform/tero-collector-distro/actions/workflows/release.yaml">
    <img src="https://github.com/tero-platform/tero-collector-distro/actions/workflows/release.yaml/badge.svg" alt="Build Status">
  </a>
  <a href="https://opensource.org/licenses/Apache-2.0">
    <img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License">
  </a>
</p>

A custom OpenTelemetry Collector distribution with the Policy Processor for
filtering, sampling, and routing telemetry data based on configurable policies.

## Overview

Tero Collector is built on top of the
[OpenTelemetry Collector](https://opentelemetry.io/docs/collector/) and includes
the Policy Processor, which enables real-time filtering and sampling of logs,
metrics, and traces using the [policy-go](https://github.com/usetero/policy-go)
library.

## Policy Processor

The Policy Processor evaluates incoming telemetry against a set of policies and
applies actions such as:

- **Drop**: Remove telemetry that matches specified patterns
- **Keep**: Retain telemetry that matches specified patterns
- **Sample**: Probabilistically sample telemetry at a configurable rate

Policies are defined in JSON and can be loaded from local files or remote
sources. The processor supports hot-reloading, allowing policy updates without
restarting the collector.

### Configuration

```yaml
processors:
  policy:
    providers:
      - type: file
        id: local-policies
        path: /etc/tero-collector/policies.json
        poll_interval_secs: 30
```

### Example Policies

```json
{
  "policies": [
    {
      "id": "drop-debug-logs",
      "name": "Drop debug level logs",
      "log": {
        "match": [{ "log_field": "severity_text", "regex": "DEBUG" }],
        "keep": "none"
      }
    },
    {
      "id": "sample-high-volume-service",
      "name": "Sample logs from high-volume service at 10%",
      "log": {
        "match": [
          { "resource_attribute": "service.name", "regex": "^high-volume-.*$" }
        ],
        "keep": { "percentage": 10.0 }
      }
    }
  ]
}
```

## Building

### Prerequisites

- Go 1.24+
- Docker
- [Task](https://taskfile.dev/) (optional, for build automation)

### Build Commands

```bash
# Run tests
task test

# Build Docker image
task build:collector

# Lint code
task lint
```

### Docker Image

The collector is distributed as a multi-architecture Docker image supporting
`linux/amd64` and `linux/arm64`.

```bash
docker pull ghcr.io/usetero/tero-collector-distro:latest
```

## Running

### Docker

```bash
docker run --rm -p 4317:4317 -p 4318:4318 \
  -v /path/to/policies.json:/etc/tero-collector/policies.json:ro \
  -v /path/to/config.yaml:/etc/tero-collector/config.yaml:ro \
  ghcr.io/usetero/tero-collector-distro:latest
```

### Example Configuration

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  policy:
    providers:
      - type: file
        id: local
        path: /etc/tero-collector/policies.json

exporters:
  debug:
    verbosity: detailed

service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [policy]
      exporters: [debug]
```

## Components

This distribution includes the following components:

### Receivers

- OTLP (gRPC and HTTP)

### Processors

- Policy Processor (custom)
- Batch
- Memory Limiter
- Attributes
- Filter
- Resource

### Exporters

- Debug
- OTLP (gRPC)
- OTLP/HTTP

### Extensions

- Health Check v2
- zPages
- PProf
- Basic Auth
- Bearer Token Auth

## Project Structure

```
├── collector/
│   ├── manifest.yaml    # OCB manifest defining the distribution
│   ├── config.yaml      # Default collector configuration
│   └── Dockerfile       # Multi-stage build for the collector
├── processor/
│   └── policyprocessor/ # Policy processor implementation
├── examples/
│   ├── config.yaml      # Example collector configuration
│   └── policies.json    # Example policy definitions
└── Taskfile.yaml        # Build automation
```

## License

Apache License 2.0
