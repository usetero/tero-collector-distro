package policyprocessor

import (
	"reflect"
	"testing"

	"github.com/usetero/policy-go"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

func TestMetricMatcher_Fields(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() MetricContext
		ref      policy.MetricFieldRef
		expected policy.TypedValue
	}{
		{
			name: "metric name",
			setup: func() MetricContext {
				m := pmetric.NewMetric()
				m.SetName("http.server.duration")
				return MetricContext{Metric: m}
			},
			ref:      policy.MetricName(),
			expected: policy.TypedValueOfString("http.server.duration"),
		},
		{
			name: "metric name empty",
			setup: func() MetricContext {
				m := pmetric.NewMetric()
				return MetricContext{Metric: m}
			},
			ref:      policy.MetricName(),
			expected: policy.TypedValue{},
		},
		{
			name: "metric description",
			setup: func() MetricContext {
				m := pmetric.NewMetric()
				m.SetDescription("Duration of HTTP server requests")
				return MetricContext{Metric: m}
			},
			ref:      policy.MetricDescription(),
			expected: policy.TypedValueOfString("Duration of HTTP server requests"),
		},
		{
			name: "metric description empty",
			setup: func() MetricContext {
				m := pmetric.NewMetric()
				return MetricContext{Metric: m}
			},
			ref:      policy.MetricDescription(),
			expected: policy.TypedValue{},
		},
		{
			name: "metric unit",
			setup: func() MetricContext {
				m := pmetric.NewMetric()
				m.SetUnit("ms")
				return MetricContext{Metric: m}
			},
			ref:      policy.MetricUnit(),
			expected: policy.TypedValueOfString("ms"),
		},
		{
			name: "metric unit empty",
			setup: func() MetricContext {
				m := pmetric.NewMetric()
				return MetricContext{Metric: m}
			},
			ref:      policy.MetricUnit(),
			expected: policy.TypedValue{},
		},
		{
			name: "metric type gauge",
			setup: func() MetricContext {
				m := pmetric.NewMetric()
				m.SetEmptyGauge()
				return MetricContext{Metric: m}
			},
			ref:      policy.MetricType(),
			expected: policy.TypedValueOfString("gauge"),
		},
		{
			name: "metric type sum",
			setup: func() MetricContext {
				m := pmetric.NewMetric()
				m.SetEmptySum()
				return MetricContext{Metric: m}
			},
			ref:      policy.MetricType(),
			expected: policy.TypedValueOfString("sum"),
		},
		{
			name: "metric type histogram",
			setup: func() MetricContext {
				m := pmetric.NewMetric()
				m.SetEmptyHistogram()
				return MetricContext{Metric: m}
			},
			ref:      policy.MetricType(),
			expected: policy.TypedValueOfString("histogram"),
		},
		{
			name: "aggregation temporality cumulative",
			setup: func() MetricContext {
				return MetricContext{
					Metric:                 pmetric.NewMetric(),
					AggregationTemporality: pmetric.AggregationTemporalityCumulative,
				}
			},
			ref:      policy.MetricAggregationTemporality(),
			expected: policy.TypedValueOfString("cumulative"),
		},
		{
			name: "aggregation temporality delta",
			setup: func() MetricContext {
				return MetricContext{
					Metric:                 pmetric.NewMetric(),
					AggregationTemporality: pmetric.AggregationTemporalityDelta,
				}
			},
			ref:      policy.MetricAggregationTemporality(),
			expected: policy.TypedValueOfString("delta"),
		},
		{
			name: "scope name",
			setup: func() MetricContext {
				scope := pcommon.NewInstrumentationScope()
				scope.SetName("my.instrumentation.library")
				return MetricContext{
					Metric: pmetric.NewMetric(),
					Scope:  scope,
				}
			},
			ref:      policy.MetricFieldRef{Field: policy.MetricFieldScopeName},
			expected: policy.TypedValueOfString("my.instrumentation.library"),
		},
		{
			name: "scope name empty",
			setup: func() MetricContext {
				return MetricContext{
					Metric: pmetric.NewMetric(),
					Scope:  pcommon.NewInstrumentationScope(),
				}
			},
			ref:      policy.MetricFieldRef{Field: policy.MetricFieldScopeName},
			expected: policy.TypedValue{},
		},
		{
			name: "scope version",
			setup: func() MetricContext {
				scope := pcommon.NewInstrumentationScope()
				scope.SetVersion("1.2.3")
				return MetricContext{
					Metric: pmetric.NewMetric(),
					Scope:  scope,
				}
			},
			ref:      policy.MetricFieldRef{Field: policy.MetricFieldScopeVersion},
			expected: policy.TypedValueOfString("1.2.3"),
		},
		{
			name: "scope version empty",
			setup: func() MetricContext {
				return MetricContext{
					Metric: pmetric.NewMetric(),
					Scope:  pcommon.NewInstrumentationScope(),
				}
			},
			ref:      policy.MetricFieldRef{Field: policy.MetricFieldScopeVersion},
			expected: policy.TypedValue{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setup()
			result := MetricTypedMatcher(ctx, tt.ref)
			if !reflect.DeepEqual(tt.expected, result) {
				t.Errorf("expected %+v, got %+v", tt.expected, result)
			}
		})
	}
}

func TestMetricMatcher_Attributes(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() MetricContext
		ref      policy.MetricFieldRef
		expected policy.TypedValue
	}{
		{
			name: "resource attribute simple",
			setup: func() MetricContext {
				resource := pcommon.NewResource()
				resource.Attributes().PutStr("service.name", "my-service")
				return MetricContext{
					Metric:   pmetric.NewMetric(),
					Resource: resource,
				}
			},
			ref:      policy.MetricResourceAttr("service.name"),
			expected: policy.TypedValueOfString("my-service"),
		},
		{
			name: "scope attribute simple",
			setup: func() MetricContext {
				scope := pcommon.NewInstrumentationScope()
				scope.Attributes().PutStr("library.version", "1.0.0")
				return MetricContext{
					Metric: pmetric.NewMetric(),
					Scope:  scope,
				}
			},
			ref:      policy.MetricScopeAttr("library.version"),
			expected: policy.TypedValueOfString("1.0.0"),
		},
		{
			name: "datapoint attribute simple",
			setup: func() MetricContext {
				attrs := pcommon.NewMap()
				attrs.PutStr("http.method", "GET")
				return MetricContext{
					Metric:              pmetric.NewMetric(),
					DatapointAttributes: attrs,
				}
			},
			ref:      policy.DatapointAttr("http.method"),
			expected: policy.TypedValueOfString("GET"),
		},
		{
			name: "datapoint attribute nested",
			setup: func() MetricContext {
				attrs := pcommon.NewMap()
				nested := attrs.PutEmptyMap("http")
				nested.PutStr("method", "POST")
				return MetricContext{
					Metric:              pmetric.NewMetric(),
					DatapointAttributes: attrs,
				}
			},
			ref:      policy.DatapointAttr("http", "method"),
			expected: policy.TypedValueOfString("POST"),
		},
		{
			name: "attribute not found",
			setup: func() MetricContext {
				return MetricContext{
					Metric:              pmetric.NewMetric(),
					DatapointAttributes: pcommon.NewMap(),
				}
			},
			ref:      policy.DatapointAttr("nonexistent"),
			expected: policy.TypedValue{},
		},
		{
			name: "integer attribute returns typed int",
			setup: func() MetricContext {
				attrs := pcommon.NewMap()
				attrs.PutInt("http.status_code", 200)
				return MetricContext{
					Metric:              pmetric.NewMetric(),
					DatapointAttributes: attrs,
				}
			},
			ref:      policy.DatapointAttr("http.status_code"),
			expected: policy.TypedValueOfInt(200),
		},
		{
			name: "boolean attribute true",
			setup: func() MetricContext {
				attrs := pcommon.NewMap()
				attrs.PutBool("error", true)
				return MetricContext{
					Metric:              pmetric.NewMetric(),
					DatapointAttributes: attrs,
				}
			},
			ref:      policy.DatapointAttr("error"),
			expected: policy.TypedValueOfBool(true),
		},
		{
			name: "boolean attribute false",
			setup: func() MetricContext {
				attrs := pcommon.NewMap()
				attrs.PutBool("error", false)
				return MetricContext{
					Metric:              pmetric.NewMetric(),
					DatapointAttributes: attrs,
				}
			},
			ref:      policy.DatapointAttr("error"),
			expected: policy.TypedValueOfBool(false),
		},
		{
			name: "double attribute",
			setup: func() MetricContext {
				attrs := pcommon.NewMap()
				attrs.PutDouble("ratio", 0.95)
				return MetricContext{
					Metric:              pmetric.NewMetric(),
					DatapointAttributes: attrs,
				}
			},
			ref:      policy.DatapointAttr("ratio"),
			expected: policy.TypedValueOfDouble(0.95),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setup()
			result := MetricTypedMatcher(ctx, tt.ref)
			if !reflect.DeepEqual(tt.expected, result) {
				t.Errorf("expected %+v, got %+v", tt.expected, result)
			}
		})
	}
}
