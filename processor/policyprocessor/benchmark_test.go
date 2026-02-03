package policyprocessor

import (
	"context"
	"fmt"
	"testing"

	"github.com/usetero/policy-go"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

// Benchmark helper to create a processor with given policies.
func createBenchmarkProcessor(b *testing.B, policies []*policyv1.Policy) *policyProcessor {
	registry := policy.NewPolicyRegistry()
	engine := policy.NewPolicyEngine(registry)

	provider := &staticLogProvider{policies: policies}
	_, err := registry.Register(provider)
	if err != nil {
		b.Fatal(err)
	}

	return &policyProcessor{
		logger:   zap.NewNop(),
		registry: registry,
		engine:   engine,
	}
}

// =============================================================================
// LOGS BENCHMARKS
// =============================================================================

func generateLogs(numResources, numScopes, numRecords int) plog.Logs {
	logs := plog.NewLogs()
	for r := range numResources {
		rl := logs.ResourceLogs().AppendEmpty()
		rl.Resource().Attributes().PutStr("service.name", fmt.Sprintf("service-%d", r))
		rl.Resource().Attributes().PutStr("host.name", fmt.Sprintf("host-%d", r))

		for s := range numScopes {
			sl := rl.ScopeLogs().AppendEmpty()
			sl.Scope().SetName(fmt.Sprintf("scope-%d", s))

			for l := range numRecords {
				lr := sl.LogRecords().AppendEmpty()
				lr.Body().SetStr(fmt.Sprintf("Log message %d from resource %d scope %d", l, r, s))
				lr.SetSeverityText("INFO")
				lr.Attributes().PutStr("log.level", "info")
				lr.Attributes().PutInt("log.index", int64(l))
			}
		}
	}
	return logs
}

func logSlice(count int) []plog.Logs {
	out := make([]plog.Logs, count)
	for i := range count {
		out[i] = generateLogs(2, 2, 2)
	}
	return out
}

func benchmarkLogs(b *testing.B, policies []*policyv1.Policy) {
	p := createBenchmarkProcessor(b, policies)
	ctx := context.Background()
	logs := logSlice(128)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		for _, l := range logs {
			_, _ = p.processLogs(ctx, l)
		}
	}
}

func BenchmarkLogs_NoPolicy(b *testing.B) {
	benchmarkLogs(b, nil)
}

func BenchmarkLogs_ExactMatch(b *testing.B) {
	policies := []*policyv1.Policy{
		{
			Id:   "drop-debug",
			Name: "Drop Debug",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
							Match: &policyv1.LogMatcher_Exact{Exact: "DEBUG"},
						},
					},
					Keep: "none",
				},
			},
		},
	}
	benchmarkLogs(b, policies)
}

func BenchmarkLogs_RegexMatch(b *testing.B) {
	policies := []*policyv1.Policy{
		{
			Id:   "drop-pattern",
			Name: "Drop Pattern",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Regex{Regex: ".*resource 0.*"},
						},
					},
					Keep: "none",
				},
			},
		},
	}
	benchmarkLogs(b, policies)
}

func BenchmarkLogs_AttributeMatch(b *testing.B) {
	policies := []*policyv1.Policy{
		{
			Id:   "drop-by-attr",
			Name: "Drop By Attr",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{Path: []string{"service.name"}}},
							Match: &policyv1.LogMatcher_Exact{Exact: "service-0"},
						},
					},
					Keep: "none",
				},
			},
		},
	}
	benchmarkLogs(b, policies)
}

func BenchmarkLogs_MultiplePolicies(b *testing.B) {
	policies := []*policyv1.Policy{
		{
			Id:   "drop-debug",
			Name: "Drop Debug",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
							Match: &policyv1.LogMatcher_Exact{Exact: "DEBUG"},
						},
					},
					Keep: "none",
				},
			},
		},
		{
			Id:   "drop-trace",
			Name: "Drop Trace",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
							Match: &policyv1.LogMatcher_Exact{Exact: "TRACE"},
						},
					},
					Keep: "none",
				},
			},
		},
		{
			Id:   "drop-service-0",
			Name: "Drop Service 0",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{Path: []string{"service.name"}}},
							Match: &policyv1.LogMatcher_Exact{Exact: "service-0"},
						},
					},
					Keep: "none",
				},
			},
		},
	}
	benchmarkLogs(b, policies)
}

// =============================================================================
// METRICS BENCHMARKS
// =============================================================================

func generateMetrics(numResources, numScopes, numMetrics, numDatapoints int) pmetric.Metrics {
	metrics := pmetric.NewMetrics()
	for r := range numResources {
		rm := metrics.ResourceMetrics().AppendEmpty()
		rm.Resource().Attributes().PutStr("service.name", fmt.Sprintf("service-%d", r))
		rm.Resource().Attributes().PutStr("host.name", fmt.Sprintf("host-%d", r))

		for s := range numScopes {
			sm := rm.ScopeMetrics().AppendEmpty()
			sm.Scope().SetName(fmt.Sprintf("scope-%d", s))

			for m := range numMetrics {
				metric := sm.Metrics().AppendEmpty()
				metric.SetName(fmt.Sprintf("metric.%d.%d.%d", r, s, m))
				metric.SetDescription(fmt.Sprintf("Metric %d from resource %d scope %d", m, r, s))
				metric.SetUnit("1")

				gauge := metric.SetEmptyGauge()
				for d := range numDatapoints {
					dp := gauge.DataPoints().AppendEmpty()
					dp.SetIntValue(int64(d * 100))
					dp.Attributes().PutStr("method", fmt.Sprintf("method-%d", d%4))
					dp.Attributes().PutInt("status", int64(200+d%5))
				}
			}
		}
	}
	return metrics
}

func metricSlice(count int) []pmetric.Metrics {
	out := make([]pmetric.Metrics, count)
	for i := range count {
		out[i] = generateMetrics(2, 2, 2, 2)
	}
	return out
}

func benchmarkMetrics(b *testing.B, policies []*policyv1.Policy) {
	p := createBenchmarkProcessor(b, policies)
	ctx := context.Background()
	metrics := metricSlice(128)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		for _, m := range metrics {
			_, _ = p.processMetrics(ctx, m)
		}
	}
}

func BenchmarkMetrics_NoPolicy(b *testing.B) {
	benchmarkMetrics(b, nil)
}

func BenchmarkMetrics_ExactNameMatch(b *testing.B) {
	policies := []*policyv1.Policy{
		{
			Id:   "drop-metric",
			Name: "Drop Metric",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_Exact{Exact: "metric.0.0.0"},
						},
					},
					Keep: false,
				},
			},
		},
	}
	benchmarkMetrics(b, policies)
}

func BenchmarkMetrics_RegexMatch(b *testing.B) {
	policies := []*policyv1.Policy{
		{
			Id:   "drop-pattern",
			Name: "Drop Pattern",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_Regex{Regex: "metric\\.0\\..*"},
						},
					},
					Keep: false,
				},
			},
		},
	}
	benchmarkMetrics(b, policies)
}

func BenchmarkMetrics_TypeMatch(b *testing.B) {
	policies := []*policyv1.Policy{
		{
			Id:   "drop-gauge",
			Name: "Drop Gauge",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricType{MetricType: policyv1.MetricType_METRIC_TYPE_GAUGE},
						},
					},
					Keep: false,
				},
			},
		},
	}
	benchmarkMetrics(b, policies)
}

func BenchmarkMetrics_AttributeMatch(b *testing.B) {
	policies := []*policyv1.Policy{
		{
			Id:   "drop-by-attr",
			Name: "Drop By Attr",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: &policyv1.AttributePath{Path: []string{"method"}}},
							Match: &policyv1.MetricMatcher_Exact{Exact: "method-0"},
						},
					},
					Keep: false,
				},
			},
		},
	}
	benchmarkMetrics(b, policies)
}

func BenchmarkMetrics_MultiplePolicies(b *testing.B) {
	policies := []*policyv1.Policy{
		{
			Id:   "drop-metric-0",
			Name: "Drop Metric 0",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_Exact{Exact: "metric.0.0.0"},
						},
					},
					Keep: false,
				},
			},
		},
		{
			Id:   "drop-service-0",
			Name: "Drop Service 0",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{Path: []string{"service.name"}}},
							Match: &policyv1.MetricMatcher_Exact{Exact: "service-0"},
						},
					},
					Keep: false,
				},
			},
		},
		{
			Id:   "drop-method-1",
			Name: "Drop Method 1",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: &policyv1.AttributePath{Path: []string{"method"}}},
							Match: &policyv1.MetricMatcher_Exact{Exact: "method-1"},
						},
					},
					Keep: false,
				},
			},
		},
	}
	benchmarkMetrics(b, policies)
}

// =============================================================================
// TRACES BENCHMARKS
// =============================================================================

func generateTraces(numResources, numScopes, numSpans int) ptrace.Traces {
	traces := ptrace.NewTraces()
	for r := range numResources {
		rs := traces.ResourceSpans().AppendEmpty()
		rs.Resource().Attributes().PutStr("service.name", fmt.Sprintf("service-%d", r))
		rs.Resource().Attributes().PutStr("host.name", fmt.Sprintf("host-%d", r))

		for s := range numScopes {
			ss := rs.ScopeSpans().AppendEmpty()
			ss.Scope().SetName(fmt.Sprintf("scope-%d", s))

			for sp := range numSpans {
				span := ss.Spans().AppendEmpty()
				span.SetName(fmt.Sprintf("span-%d-%d-%d", r, s, sp))
				span.SetTraceID(pcommon.TraceID([16]byte{byte(r), byte(s), byte(sp), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}))
				span.SetSpanID(pcommon.SpanID([8]byte{byte(r), byte(s), byte(sp), 0, 0, 0, 0, 1}))

				kinds := []ptrace.SpanKind{ptrace.SpanKindInternal, ptrace.SpanKindServer, ptrace.SpanKindClient}
				span.SetKind(kinds[sp%len(kinds)])

				statuses := []ptrace.StatusCode{ptrace.StatusCodeOk, ptrace.StatusCodeError, ptrace.StatusCodeUnset}
				span.Status().SetCode(statuses[sp%len(statuses)])

				span.Attributes().PutStr("http.method", fmt.Sprintf("method-%d", sp%4))
				span.Attributes().PutInt("http.status_code", int64(200+sp%5))
			}
		}
	}
	return traces
}

func traceSlice(count int) []ptrace.Traces {
	out := make([]ptrace.Traces, count)
	for i := range count {
		out[i] = generateTraces(2, 2, 4)
	}
	return out
}

func benchmarkTraces(b *testing.B, policies []*policyv1.Policy) {
	p := createBenchmarkProcessor(b, policies)
	ctx := context.Background()
	traces := traceSlice(128)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		for _, t := range traces {
			_, _ = p.processTraces(ctx, t)
		}
	}
}

func BenchmarkTraces_NoPolicy(b *testing.B) {
	benchmarkTraces(b, nil)
}

func BenchmarkTraces_ExactNameMatch(b *testing.B) {
	policies := []*policyv1.Policy{
		{
			Id:   "drop-span",
			Name: "Drop Span",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_Exact{Exact: "span-0-0-0"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
	}
	benchmarkTraces(b, policies)
}

func BenchmarkTraces_RegexMatch(b *testing.B) {
	policies := []*policyv1.Policy{
		{
			Id:   "drop-pattern",
			Name: "Drop Pattern",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_Regex{Regex: "span-0-.*"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
	}
	benchmarkTraces(b, policies)
}

func BenchmarkTraces_SpanKindMatch(b *testing.B) {
	policies := []*policyv1.Policy{
		{
			Id:   "drop-internal",
			Name: "Drop Internal",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanKind{SpanKind: policyv1.SpanKind_SPAN_KIND_INTERNAL},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
	}
	benchmarkTraces(b, policies)
}

func BenchmarkTraces_StatusMatch(b *testing.B) {
	policies := []*policyv1.Policy{
		{
			Id:   "drop-errors",
			Name: "Drop Errors",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanStatus{SpanStatus: policyv1.SpanStatusCode_SPAN_STATUS_CODE_ERROR},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
	}
	benchmarkTraces(b, policies)
}

func BenchmarkTraces_AttributeMatch(b *testing.B) {
	policies := []*policyv1.Policy{
		{
			Id:   "drop-by-attr",
			Name: "Drop By Attr",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanAttribute{SpanAttribute: &policyv1.AttributePath{Path: []string{"http.method"}}},
							Match: &policyv1.TraceMatcher_Exact{Exact: "method-0"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
	}
	benchmarkTraces(b, policies)
}

func BenchmarkTraces_MultiplePolicies(b *testing.B) {
	policies := []*policyv1.Policy{
		{
			Id:   "drop-internal",
			Name: "Drop Internal",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanKind{SpanKind: policyv1.SpanKind_SPAN_KIND_INTERNAL},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
		{
			Id:   "drop-errors",
			Name: "Drop Errors",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanStatus{SpanStatus: policyv1.SpanStatusCode_SPAN_STATUS_CODE_ERROR},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
		{
			Id:   "drop-method-0",
			Name: "Drop Method 0",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanAttribute{SpanAttribute: &policyv1.AttributePath{Path: []string{"http.method"}}},
							Match: &policyv1.TraceMatcher_Exact{Exact: "method-0"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
	}
	benchmarkTraces(b, policies)
}
