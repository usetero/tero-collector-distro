# Policy Processor

The Policy Processor filters, samples, and routes OpenTelemetry logs based on
configurable policies using the
[policy-go](https://github.com/usetero/policy-go) library.

## Installation

```bash
go get github.com/usetero/tero-collector-distro/processor/policyprocessor@latest
```

## Usage in a Custom Collector

### OCB Manifest

Add the processor to your OpenTelemetry Collector Builder manifest:

```yaml
dist:
  module: github.com/example/my-collector
  name: my-collector
  version: 1.0.0
  cgo_enabled: true # Required for Hyperscan/Vectorscan

processors:
  - gomod:
      github.com/usetero/tero-collector-distro/processor/policyprocessor v0.2.0

receivers:
  - gomod: go.opentelemetry.io/collector/receiver/otlpreceiver v0.144.0

exporters:
  - gomod: go.opentelemetry.io/collector/exporter/debugexporter v0.144.0
```

Build the collector:

```bash
builder --config=manifest.yaml
```

> **Note**: The policy processor requires CGO and the Hyperscan/Vectorscan
> library. Set `cgo_enabled: true` in the manifest and install the appropriate
> system packages:
>
> - **macOS**: `brew install vectorscan`
> - **Ubuntu/Debian**: `apt-get install libhyperscan-dev`
> - **Alpine**: `apk add vectorscan-dev`

### Collector Configuration

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

processors:
  policy:
    providers:
      - type: file
        id: local-policies
        path: /etc/collector/policies.json
        poll_interval_secs: 30

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

## Configuration

| Field       | Type               | Description              |
| ----------- | ------------------ | ------------------------ |
| `providers` | `[]ProviderConfig` | List of policy providers |

### Provider Configuration

| Field                | Type       | Description                               |
| -------------------- | ---------- | ----------------------------------------- |
| `type`               | `string`   | Provider type: `file`, `http`, or `grpc`  |
| `id`                 | `string`   | Unique identifier for this provider       |
| `path`               | `string`   | Path to policy file (file provider only)  |
| `poll_interval_secs` | `int`      | How often to check for updates (optional) |
| `url`                | `string`   | URL for remote provider (http/grpc only)  |
| `headers`            | `[]Header` | HTTP headers (http provider only)         |

## Policy Format

Policies are defined in JSON. See the
[policy-go documentation](https://github.com/usetero/policy-go) for the full
schema.

### Example

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
      "id": "sample-noisy-service",
      "name": "Sample noisy service at 10%",
      "log": {
        "match": [
          { "resource_attribute": "service.name", "regex": "^noisy-service$" }
        ],
        "keep": { "percentage": 10.0 }
      }
    }
  ]
}
```

## Supported Telemetry Types

| Type    | Status            |
| ------- | ----------------- |
| Logs    | Alpha             |
| Metrics | Not yet supported |
| Traces  | Not yet supported |

## Telemetry

The processor emits the following metrics:

| Metric                     | Type    | Description                                                                |
| -------------------------- | ------- | -------------------------------------------------------------------------- |
| `processor_policy_records` | Counter | Number of records processed, with attributes `telemetry_type` and `result` |

Result values: `dropped`, `kept`, `sampled`, `no_match`
