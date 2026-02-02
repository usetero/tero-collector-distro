package policyprocessor

import (
	"context"

	"github.com/usetero/policy-go"
	"github.com/usetero/tero-collector-distro/processor/policyprocessor/internal/metadata"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
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
}

func newPolicyProcessor(logger *zap.Logger, cfg *Config, telemetry *metadata.TelemetryBuilder) *policyProcessor {
	return &policyProcessor{
		logger:    logger,
		config:    cfg,
		telemetry: telemetry,
	}
}

func (p *policyProcessor) start(_ context.Context, _ component.Host) error {
	p.logger.Info("Policy processor starting",
		zap.Int("provider_count", len(p.config.Providers)),
	)

	// Create registry
	p.registry = policy.NewPolicyRegistry()

	// Create engine with the registry
	p.engine = policy.NewPolicyEngine(p.registry)

	// Set callback for when policies are recompiled
	p.registry.SetOnRecompile(func() {
		p.logger.Info("Policies recompiled")
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

	p.logger.Info("Policy processor started",
		zap.Int("providers_loaded", len(p.providers)),
	)
	return nil
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

func (p *policyProcessor) processMetrics(ctx context.Context, md pmetric.Metrics) (pmetric.Metrics, error) {
	md.ResourceMetrics().RemoveIf(func(rm pmetric.ResourceMetrics) bool {
		resource := rm.Resource()

		rm.ScopeMetrics().RemoveIf(func(sm pmetric.ScopeMetrics) bool {
			scope := sm.Scope()

			sm.Metrics().RemoveIf(func(m pmetric.Metric) bool {
				return p.processMetricDatapoints(ctx, m, resource, scope)
			})

			return sm.Metrics().Len() == 0
		})

		return rm.ScopeMetrics().Len() == 0
	})

	return md, nil
}

// processMetricDatapoints evaluates all datapoints in a metric and removes dropped ones.
// Returns true if the entire metric should be dropped (all datapoints were dropped).
func (p *policyProcessor) processMetricDatapoints(ctx context.Context, m pmetric.Metric, resource pcommon.Resource, scope pcommon.InstrumentationScope) bool {
	switch m.Type() {
	case pmetric.MetricTypeGauge:
		p.processNumberDataPoints(ctx, m, m.Gauge().DataPoints(), pmetric.AggregationTemporalityUnspecified, resource, scope)
		return m.Gauge().DataPoints().Len() == 0
	case pmetric.MetricTypeSum:
		sum := m.Sum()
		p.processNumberDataPoints(ctx, m, sum.DataPoints(), sum.AggregationTemporality(), resource, scope)
		return sum.DataPoints().Len() == 0
	case pmetric.MetricTypeHistogram:
		hist := m.Histogram()
		p.processHistogramDataPoints(ctx, m, hist.DataPoints(), hist.AggregationTemporality(), resource, scope)
		return hist.DataPoints().Len() == 0
	case pmetric.MetricTypeExponentialHistogram:
		expHist := m.ExponentialHistogram()
		p.processExponentialHistogramDataPoints(ctx, m, expHist.DataPoints(), expHist.AggregationTemporality(), resource, scope)
		return expHist.DataPoints().Len() == 0
	case pmetric.MetricTypeSummary:
		p.processSummaryDataPoints(ctx, m, m.Summary().DataPoints(), resource, scope)
		return m.Summary().DataPoints().Len() == 0
	default:
		return false
	}
}

func (p *policyProcessor) processNumberDataPoints(ctx context.Context, m pmetric.Metric, datapoints pmetric.NumberDataPointSlice, temporality pmetric.AggregationTemporality, resource pcommon.Resource, scope pcommon.InstrumentationScope) {
	datapoints.RemoveIf(func(dp pmetric.NumberDataPoint) bool {
		metricCtx := MetricContext{
			Metric:                 m,
			DatapointAttributes:    dp.Attributes(),
			AggregationTemporality: temporality,
			Resource:               resource,
			Scope:                  scope,
		}

		result := policy.EvaluateMetric(p.engine, metricCtx, MetricMatcher)
		p.recordMetric(ctx, "metrics", result)

		return result == policy.ResultDrop
	})
}

func (p *policyProcessor) processHistogramDataPoints(ctx context.Context, m pmetric.Metric, datapoints pmetric.HistogramDataPointSlice, temporality pmetric.AggregationTemporality, resource pcommon.Resource, scope pcommon.InstrumentationScope) {
	datapoints.RemoveIf(func(dp pmetric.HistogramDataPoint) bool {
		metricCtx := MetricContext{
			Metric:                 m,
			DatapointAttributes:    dp.Attributes(),
			AggregationTemporality: temporality,
			Resource:               resource,
			Scope:                  scope,
		}

		result := policy.EvaluateMetric(p.engine, metricCtx, MetricMatcher)
		p.recordMetric(ctx, "metrics", result)

		return result == policy.ResultDrop
	})
}

func (p *policyProcessor) processExponentialHistogramDataPoints(ctx context.Context, m pmetric.Metric, datapoints pmetric.ExponentialHistogramDataPointSlice, temporality pmetric.AggregationTemporality, resource pcommon.Resource, scope pcommon.InstrumentationScope) {
	datapoints.RemoveIf(func(dp pmetric.ExponentialHistogramDataPoint) bool {
		metricCtx := MetricContext{
			Metric:                 m,
			DatapointAttributes:    dp.Attributes(),
			AggregationTemporality: temporality,
			Resource:               resource,
			Scope:                  scope,
		}

		result := policy.EvaluateMetric(p.engine, metricCtx, MetricMatcher)
		p.recordMetric(ctx, "metrics", result)

		return result == policy.ResultDrop
	})
}

func (p *policyProcessor) processSummaryDataPoints(ctx context.Context, m pmetric.Metric, datapoints pmetric.SummaryDataPointSlice, resource pcommon.Resource, scope pcommon.InstrumentationScope) {
	datapoints.RemoveIf(func(dp pmetric.SummaryDataPoint) bool {
		metricCtx := MetricContext{
			Metric:                 m,
			DatapointAttributes:    dp.Attributes(),
			AggregationTemporality: pmetric.AggregationTemporalityUnspecified,
			Resource:               resource,
			Scope:                  scope,
		}

		result := policy.EvaluateMetric(p.engine, metricCtx, MetricMatcher)
		p.recordMetric(ctx, "metrics", result)

		return result == policy.ResultDrop
	})
}

func (p *policyProcessor) processLogs(ctx context.Context, ld plog.Logs) (plog.Logs, error) {
	ld.ResourceLogs().RemoveIf(func(rl plog.ResourceLogs) bool {
		resource := rl.Resource()

		rl.ScopeLogs().RemoveIf(func(sl plog.ScopeLogs) bool {
			scope := sl.Scope()

			sl.LogRecords().RemoveIf(func(lr plog.LogRecord) bool {
				logCtx := LogContext{
					Record:   lr,
					Resource: resource,
					Scope:    scope,
				}

				result := policy.EvaluateLog(p.engine, logCtx, LogMatcher)
				p.recordMetric(ctx, "logs", result)

				return result == policy.ResultDrop
			})

			return sl.LogRecords().Len() == 0
		})

		return rl.ScopeLogs().Len() == 0
	})

	return ld, nil
}

func (p *policyProcessor) recordMetric(ctx context.Context, telemetryType string, result policy.EvaluateResult) {
	if p.telemetry == nil {
		return
	}

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
