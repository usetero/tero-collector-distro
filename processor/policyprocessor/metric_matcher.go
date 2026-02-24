package policyprocessor

import (
	"github.com/usetero/policy-go"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// MetricContext holds the context needed to evaluate a metric datapoint against policies.
type MetricContext struct {
	Metric                 pmetric.Metric
	DatapointAttributes    pcommon.Map
	AggregationTemporality pmetric.AggregationTemporality
	Resource               pcommon.Resource
	Scope                  pcommon.InstrumentationScope
	ResourceSchemaURL      string
	ScopeSchemaURL         string
}

// MetricMatcher extracts field values from a MetricContext for policy evaluation.
// This implements policy.MetricMatchFunc[MetricContext].
func MetricMatcher(ctx MetricContext, ref policy.MetricFieldRef) []byte {
	if ref.IsField() {
		switch ref.Field {
		case policy.MetricFieldName:
			if name := ctx.Metric.Name(); name != "" {
				return []byte(name)
			}
			return nil
		case policy.MetricFieldDescription:
			if desc := ctx.Metric.Description(); desc != "" {
				return []byte(desc)
			}
			return nil
		case policy.MetricFieldUnit:
			if unit := ctx.Metric.Unit(); unit != "" {
				return []byte(unit)
			}
			return nil
		case policy.MetricFieldType:
			switch ctx.Metric.Type() {
			case pmetric.MetricTypeGauge:
				return []byte("gauge")
			case pmetric.MetricTypeSum:
				return []byte("sum")
			case pmetric.MetricTypeHistogram:
				return []byte("histogram")
			case pmetric.MetricTypeExponentialHistogram:
				return []byte("exponential_histogram")
			case pmetric.MetricTypeSummary:
				return []byte("summary")
			default:
				return nil
			}
		case policy.MetricFieldAggregationTemporality:
			switch ctx.AggregationTemporality {
			case pmetric.AggregationTemporalityDelta:
				return []byte("delta")
			case pmetric.AggregationTemporalityCumulative:
				return []byte("cumulative")
			default:
				return nil
			}
		case policy.MetricFieldScopeName:
			if name := ctx.Scope.Name(); name != "" {
				return []byte(name)
			}
			return nil
		case policy.MetricFieldScopeVersion:
			if version := ctx.Scope.Version(); version != "" {
				return []byte(version)
			}
			return nil
		case policy.MetricFieldResourceSchemaURL:
			if ctx.ResourceSchemaURL == "" {
				return nil
			}
			return []byte(ctx.ResourceSchemaURL)
		case policy.MetricFieldScopeSchemaURL:
			if ctx.ScopeSchemaURL == "" {
				return nil
			}
			return []byte(ctx.ScopeSchemaURL)
		default:
			return nil
		}
	}

	// Attribute lookup
	var attrs pcommon.Map
	switch {
	case ref.IsResourceAttr():
		attrs = ctx.Resource.Attributes()
	case ref.IsScopeAttr():
		attrs = ctx.Scope.Attributes()
	case ref.IsRecordAttr():
		attrs = ctx.DatapointAttributes
	default:
		return nil
	}

	return traversePath(attrs, ref.AttrPath)
}
