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

// MetricValue extracts string-typed field values as bytes for regex/substring/redact matching.
// Returns nil for absent fields and for non-textual types.
// Used as the WithMetricValue option for policy.EvaluateMetric.
func MetricValue(ctx MetricContext, ref policy.MetricFieldRef) []byte {
	if ref.IsField() {
		switch ref.Field {
		case policy.MetricFieldName:
			s := ctx.Metric.Name()
			if s == "" {
				return nil
			}
			return []byte(s)
		case policy.MetricFieldDescription:
			s := ctx.Metric.Description()
			if s == "" {
				return nil
			}
			return []byte(s)
		case policy.MetricFieldUnit:
			s := ctx.Metric.Unit()
			if s == "" {
				return nil
			}
			return []byte(s)
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
			s := ctx.Scope.Name()
			if s == "" {
				return nil
			}
			return []byte(s)
		case policy.MetricFieldScopeVersion:
			s := ctx.Scope.Version()
			if s == "" {
				return nil
			}
			return []byte(s)
		case policy.MetricFieldResourceSchemaURL:
			s := ctx.ResourceSchemaURL
			if s == "" {
				return nil
			}
			return []byte(s)
		case policy.MetricFieldScopeSchemaURL:
			s := ctx.ScopeSchemaURL
			if s == "" {
				return nil
			}
			return []byte(s)
		default:
			return nil
		}
	}

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

// MetricTypedMatcher extracts field values from a MetricContext for typed comparison (equals/gt/gte/lt/lte).
// Returns TypedValue{} (absent) for missing fields.
// Used as the WithMetricTypedValue option for policy.EvaluateMetric.
func MetricTypedMatcher(ctx MetricContext, ref policy.MetricFieldRef) policy.TypedValue {
	if ref.IsField() {
		switch ref.Field {
		case policy.MetricFieldName:
			s := ctx.Metric.Name()
			if s == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(s)
		case policy.MetricFieldDescription:
			s := ctx.Metric.Description()
			if s == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(s)
		case policy.MetricFieldUnit:
			s := ctx.Metric.Unit()
			if s == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(s)
		case policy.MetricFieldType:
			switch ctx.Metric.Type() {
			case pmetric.MetricTypeGauge:
				return policy.TypedValueOfString("gauge")
			case pmetric.MetricTypeSum:
				return policy.TypedValueOfString("sum")
			case pmetric.MetricTypeHistogram:
				return policy.TypedValueOfString("histogram")
			case pmetric.MetricTypeExponentialHistogram:
				return policy.TypedValueOfString("exponential_histogram")
			case pmetric.MetricTypeSummary:
				return policy.TypedValueOfString("summary")
			default:
				return policy.TypedValue{}
			}
		case policy.MetricFieldAggregationTemporality:
			switch ctx.AggregationTemporality {
			case pmetric.AggregationTemporalityDelta:
				return policy.TypedValueOfString("delta")
			case pmetric.AggregationTemporalityCumulative:
				return policy.TypedValueOfString("cumulative")
			default:
				return policy.TypedValue{}
			}
		case policy.MetricFieldScopeName:
			s := ctx.Scope.Name()
			if s == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(s)
		case policy.MetricFieldScopeVersion:
			s := ctx.Scope.Version()
			if s == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(s)
		case policy.MetricFieldResourceSchemaURL:
			s := ctx.ResourceSchemaURL
			if s == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(s)
		case policy.MetricFieldScopeSchemaURL:
			s := ctx.ScopeSchemaURL
			if s == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(s)
		default:
			return policy.TypedValue{}
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
		return policy.TypedValue{}
	}

	return traversePathTyped(attrs, ref.AttrPath)
}

// MetricExists reports whether the referenced field or attribute is set.
// Used as the WithMetricExists option for policy.EvaluateMetric.
func MetricExists(ctx MetricContext, ref policy.MetricFieldRef) bool {
	if ref.IsField() {
		switch ref.Field {
		case policy.MetricFieldName:
			return ctx.Metric.Name() != ""
		case policy.MetricFieldDescription:
			return ctx.Metric.Description() != ""
		case policy.MetricFieldUnit:
			return ctx.Metric.Unit() != ""
		case policy.MetricFieldType:
			return ctx.Metric.Type() != pmetric.MetricTypeEmpty
		case policy.MetricFieldAggregationTemporality:
			return ctx.AggregationTemporality != pmetric.AggregationTemporalityUnspecified
		case policy.MetricFieldScopeName:
			return ctx.Scope.Name() != ""
		case policy.MetricFieldScopeVersion:
			return ctx.Scope.Version() != ""
		case policy.MetricFieldResourceSchemaURL:
			return ctx.ResourceSchemaURL != ""
		case policy.MetricFieldScopeSchemaURL:
			return ctx.ScopeSchemaURL != ""
		default:
			return false
		}
	}

	var attrs pcommon.Map
	switch {
	case ref.IsResourceAttr():
		attrs = ctx.Resource.Attributes()
	case ref.IsScopeAttr():
		attrs = ctx.Scope.Attributes()
	case ref.IsRecordAttr():
		attrs = ctx.DatapointAttributes
	default:
		return false
	}

	return pathExists(attrs, ref.AttrPath)
}
