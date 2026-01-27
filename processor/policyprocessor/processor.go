package policyprocessor

import (
	"context"
	"sync/atomic"

	"github.com/usetero/policy-go"
	"github.com/usetero/tero-collector-distro/processor/policyprocessor/internal/metadata"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"
)

// Attribute keys for telemetry.
var (
	attrTelemetryType = attribute.Key("telemetry_type")
	attrResult        = attribute.Key("result")
)

type policyProcessor struct {
	logger    *zap.Logger
	config    *Config
	telemetry *metadata.TelemetryBuilder
	registry  *policy.PolicyRegistry
	engine    *policy.PolicyEngine
	providers []policy.LoadedProvider
	snapshot  atomic.Pointer[policy.PolicySnapshot]
}

func newPolicyProcessor(logger *zap.Logger, cfg *Config, telemetry *metadata.TelemetryBuilder) *policyProcessor {
	return &policyProcessor{
		logger:    logger,
		config:    cfg,
		telemetry: telemetry,
		engine:    policy.NewPolicyEngine(),
	}
}

func (p *policyProcessor) start(_ context.Context, _ component.Host) error {
	p.logger.Info("Policy processor starting",
		zap.Int("provider_count", len(p.config.Providers)),
	)

	// Create registry
	p.registry = policy.NewPolicyRegistry()

	// Set callback for when policies are recompiled
	// The callback receives the new snapshot directly, avoiding lock contention
	p.registry.SetOnRecompile(func(snapshot *policy.PolicySnapshot) {
		p.logger.Info("Policies recompiled")
		p.snapshot.Store(snapshot)
	})

	// Create config loader
	loader := policy.NewConfigLoader(p.registry).
		WithOnError(func(err error) {
			p.logger.Error("Policy provider error", zap.Error(err))
		})

	// Load providers from config
	cfg := &policy.Config{Providers: p.config.Providers}
	providers, err := loader.Load(cfg)
	if err != nil {
		return err
	}
	p.providers = providers

	// Get initial snapshot
	p.updateSnapshot()

	p.logger.Info("Policy processor started",
		zap.Int("providers_loaded", len(p.providers)),
	)
	return nil
}

func (p *policyProcessor) updateSnapshot() {
	snapshot := p.registry.Snapshot()
	p.snapshot.Store(snapshot)
}

func (p *policyProcessor) shutdown(_ context.Context) error {
	p.logger.Info("Policy processor shutting down")
	if len(p.providers) > 0 {
		policy.StopAll(p.providers)
		policy.UnregisterAll(p.providers)
	}
	if p.telemetry != nil {
		p.telemetry.Shutdown()
	}
	return nil
}

func (p *policyProcessor) processTraces(_ context.Context, td ptrace.Traces) (ptrace.Traces, error) {
	// Traces not yet supported - pass through
	return td, nil
}

func (p *policyProcessor) processMetrics(_ context.Context, md pmetric.Metrics) (pmetric.Metrics, error) {
	// Metrics not yet supported - pass through
	return md, nil
}

func (p *policyProcessor) processLogs(ctx context.Context, ld plog.Logs) (plog.Logs, error) {
	snapshot := p.snapshot.Load()
	if snapshot == nil {
		return ld, nil
	}

	resourceLogs := ld.ResourceLogs()
	for i := 0; i < resourceLogs.Len(); i++ {
		rl := resourceLogs.At(i)
		resource := rl.Resource()

		scopeLogs := rl.ScopeLogs()
		for j := 0; j < scopeLogs.Len(); j++ {
			sl := scopeLogs.At(j)
			scope := sl.Scope()

			logRecords := sl.LogRecords()
			for k := logRecords.Len() - 1; k >= 0; k-- {
				record := logRecords.At(k)

				wrapper := &LogRecordWrapper{
					Record:   record,
					Resource: resource,
					Scope:    scope,
				}

				result := p.engine.Evaluate(snapshot, wrapper)
				p.recordMetric(ctx, "logs", result)

				if result == policy.ResultDrop {
					logRecords.RemoveIf(func(lr plog.LogRecord) bool {
						return lr.ObservedTimestamp() == record.ObservedTimestamp() &&
							lr.Timestamp() == record.Timestamp()
					})
				}
			}
		}
	}

	return ld, nil
}

func (p *policyProcessor) recordMetric(ctx context.Context, telemetryType string, result policy.EvaluateResult) {
	var resultStr string
	switch result {
	case policy.ResultDrop:
		resultStr = "dropped"
	case policy.ResultKeep:
		resultStr = "kept"
	case policy.ResultSample:
		resultStr = "sampled"
	default:
		resultStr = "no_match"
	}

	p.telemetry.ProcessorPolicyRecords.Add(ctx, 1,
		metric.WithAttributes(
			attrTelemetryType.String(telemetryType),
			attrResult.String(resultStr),
		),
	)
}
