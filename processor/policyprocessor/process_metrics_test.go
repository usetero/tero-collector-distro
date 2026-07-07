package policyprocessor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/usetero/policy-go/backend/hyperscan"
	"github.com/usetero/policy-go/policy"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"
)

// staticMetricProvider is a simple policy provider for testing.
type staticMetricProvider struct {
	policies []*policyv1.Policy
}

func (p *staticMetricProvider) Load() ([]*policyv1.Policy, error) {
	return p.policies, nil
}

func (p *staticMetricProvider) Subscribe(callback policy.PolicyCallback) error {
	callback(p.policies)
	return nil
}

func (p *staticMetricProvider) SetStatsCollector(collector policy.StatsCollector) {}

func createTestMetricProcessor(t *testing.T, policies []*policyv1.Policy) *policyProcessor {
	registry := policy.NewPolicyRegistry(policy.WithRegexBackend(hyperscan.New()))
	engine := policy.NewPolicyEngine(registry)

	provider := &staticMetricProvider{policies: policies}
	_, err := registry.Register(provider)
	require.NoError(t, err)

	return &policyProcessor{
		logger:   zap.NewNop(),
		registry: registry,
		engine:   engine,
	}
}

func TestProcessMetrics_NoPolicy(t *testing.T) {
	p := createTestMetricProcessor(t, nil)

	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	for _, name := range []string{"metric.a", "metric.b", "metric.c"} {
		m := sm.Metrics().AppendEmpty()
		m.SetName(name)
		m.SetEmptyGauge().DataPoints().AppendEmpty()
	}

	result, err := p.processMetrics(context.Background(), metrics)

	require.NoError(t, err)
	assert.Equal(t, 3, result.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().Len())
}

func TestProcessMetrics_DropByName(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-internal",
			Name:    "Drop Internal",
			Enabled: true,
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_StartsWith{StartsWith: "internal."},
						},
					},
					Keep: false,
				},
			},
		},
	}

	p := createTestMetricProcessor(t, policies)

	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	for _, name := range []string{"internal.requests", "http.requests", "internal.latency", "db.queries"} {
		m := sm.Metrics().AppendEmpty()
		m.SetName(name)
		m.SetEmptyGauge().DataPoints().AppendEmpty()
	}

	result, err := p.processMetrics(context.Background(), metrics)

	require.NoError(t, err)
	ms := result.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	assert.Equal(t, 2, ms.Len())

	names := []string{ms.At(0).Name(), ms.At(1).Name()}
	assert.Contains(t, names, "http.requests")
	assert.Contains(t, names, "db.queries")
}

func TestProcessMetrics_DropByDescription(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-deprecated",
			Name:    "Drop Deprecated",
			Enabled: true,
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_DESCRIPTION},
							Match: &policyv1.MetricMatcher_Contains{Contains: "DEPRECATED"},
						},
					},
					Keep: false,
				},
			},
		},
	}

	p := createTestMetricProcessor(t, policies)

	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()

	m1 := sm.Metrics().AppendEmpty()
	m1.SetName("old.metric")
	m1.SetDescription("DEPRECATED: use new.metric instead")
	m1.SetEmptyGauge().DataPoints().AppendEmpty()

	m2 := sm.Metrics().AppendEmpty()
	m2.SetName("new.metric")
	m2.SetDescription("The new metric to use")
	m2.SetEmptyGauge().DataPoints().AppendEmpty()

	result, err := p.processMetrics(context.Background(), metrics)

	require.NoError(t, err)
	ms := result.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	assert.Equal(t, 1, ms.Len())
	assert.Equal(t, "new.metric", ms.At(0).Name())
}

func TestProcessMetrics_DropByUnit(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-by-unit",
			Name:    "Drop By Unit",
			Enabled: true,
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_UNIT},
							Match: &policyv1.MetricMatcher_Exact{Exact: "By"},
						},
					},
					Keep: false,
				},
			},
		},
	}

	p := createTestMetricProcessor(t, policies)

	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()

	m1 := sm.Metrics().AppendEmpty()
	m1.SetName("memory.bytes")
	m1.SetUnit("By")
	m1.SetEmptyGauge().DataPoints().AppendEmpty()

	m2 := sm.Metrics().AppendEmpty()
	m2.SetName("request.duration")
	m2.SetUnit("ms")
	m2.SetEmptyGauge().DataPoints().AppendEmpty()

	result, err := p.processMetrics(context.Background(), metrics)

	require.NoError(t, err)
	ms := result.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	assert.Equal(t, 1, ms.Len())
	assert.Equal(t, "request.duration", ms.At(0).Name())
}

func TestProcessMetrics_DropByType(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-histograms",
			Name:    "Drop Histograms",
			Enabled: true,
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricType{MetricType: policyv1.MetricType_METRIC_TYPE_HISTOGRAM},
						},
					},
					Keep: false,
				},
			},
		},
	}

	p := createTestMetricProcessor(t, policies)

	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()

	m1 := sm.Metrics().AppendEmpty()
	m1.SetName("http.duration")
	m1.SetEmptyHistogram().DataPoints().AppendEmpty()

	m2 := sm.Metrics().AppendEmpty()
	m2.SetName("http.requests")
	m2.SetEmptySum().DataPoints().AppendEmpty()

	m3 := sm.Metrics().AppendEmpty()
	m3.SetName("active.connections")
	m3.SetEmptyGauge().DataPoints().AppendEmpty()

	result, err := p.processMetrics(context.Background(), metrics)

	require.NoError(t, err)
	ms := result.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	assert.Equal(t, 2, ms.Len())
}

func TestProcessMetrics_DropByDatapointAttribute(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-by-method",
			Name:    "Drop By Method",
			Enabled: true,
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: &policyv1.AttributePath{Path: []string{"http.method"}}},
							Match: &policyv1.MetricMatcher_Exact{Exact: "OPTIONS"},
						},
					},
					Keep: false,
				},
			},
		},
	}

	p := createTestMetricProcessor(t, policies)

	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()

	m := sm.Metrics().AppendEmpty()
	m.SetName("http.requests")
	gauge := m.SetEmptyGauge()

	dp1 := gauge.DataPoints().AppendEmpty()
	dp1.Attributes().PutStr("http.method", "GET")
	dp1.SetDoubleValue(100)

	dp2 := gauge.DataPoints().AppendEmpty()
	dp2.Attributes().PutStr("http.method", "OPTIONS")
	dp2.SetDoubleValue(50)

	dp3 := gauge.DataPoints().AppendEmpty()
	dp3.Attributes().PutStr("http.method", "POST")
	dp3.SetDoubleValue(75)

	result, err := p.processMetrics(context.Background(), metrics)

	require.NoError(t, err)
	ms := result.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	assert.Equal(t, 1, ms.Len())
	assert.Equal(t, 2, ms.At(0).Gauge().DataPoints().Len())
}

func TestProcessMetrics_DropByResourceAttribute(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-by-service",
			Name:    "Drop By Service",
			Enabled: true,
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{Path: []string{"service.name"}}},
							Match: &policyv1.MetricMatcher_Exact{Exact: "noisy-service"},
						},
					},
					Keep: false,
				},
			},
		},
	}

	p := createTestMetricProcessor(t, policies)

	metrics := pmetric.NewMetrics()

	rm1 := metrics.ResourceMetrics().AppendEmpty()
	rm1.Resource().Attributes().PutStr("service.name", "noisy-service")
	sm1 := rm1.ScopeMetrics().AppendEmpty()
	m1 := sm1.Metrics().AppendEmpty()
	m1.SetName("metric.from.noisy")
	m1.SetEmptyGauge().DataPoints().AppendEmpty()

	rm2 := metrics.ResourceMetrics().AppendEmpty()
	rm2.Resource().Attributes().PutStr("service.name", "important-service")
	sm2 := rm2.ScopeMetrics().AppendEmpty()
	m2 := sm2.Metrics().AppendEmpty()
	m2.SetName("metric.from.important")
	m2.SetEmptyGauge().DataPoints().AppendEmpty()

	result, err := p.processMetrics(context.Background(), metrics)

	require.NoError(t, err)
	// First resource should be removed entirely (all metrics dropped)
	// Only the important-service resource should remain
	assert.Equal(t, 1, result.ResourceMetrics().Len())
	serviceName, _ := result.ResourceMetrics().At(0).Resource().Attributes().Get("service.name")
	assert.Equal(t, "important-service", serviceName.Str())
	assert.Equal(t, 1, result.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().Len())
}

func TestProcessMetrics_MultipleMatchers(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-internal-histograms",
			Name:    "Drop Internal Histograms",
			Enabled: true,
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_StartsWith{StartsWith: "internal."},
						},
						{
							Field: &policyv1.MetricMatcher_MetricType{MetricType: policyv1.MetricType_METRIC_TYPE_HISTOGRAM},
						},
					},
					Keep: false,
				},
			},
		},
	}

	p := createTestMetricProcessor(t, policies)

	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()

	// internal histogram - should be dropped
	m1 := sm.Metrics().AppendEmpty()
	m1.SetName("internal.latency")
	m1.SetEmptyHistogram().DataPoints().AppendEmpty()

	// internal gauge - should be kept
	m2 := sm.Metrics().AppendEmpty()
	m2.SetName("internal.count")
	m2.SetEmptyGauge().DataPoints().AppendEmpty()

	// external histogram - should be kept
	m3 := sm.Metrics().AppendEmpty()
	m3.SetName("http.latency")
	m3.SetEmptyHistogram().DataPoints().AppendEmpty()

	result, err := p.processMetrics(context.Background(), metrics)

	require.NoError(t, err)
	ms := result.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	assert.Equal(t, 2, ms.Len())
}

func TestProcessMetrics_AllMetricTypes(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-test-metrics",
			Name:    "Drop Test Metrics",
			Enabled: true,
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_StartsWith{StartsWith: "test."},
						},
					},
					Keep: false,
				},
			},
		},
	}

	p := createTestMetricProcessor(t, policies)

	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()

	// Gauge
	m1 := sm.Metrics().AppendEmpty()
	m1.SetName("test.gauge")
	m1.SetEmptyGauge().DataPoints().AppendEmpty()

	// Sum
	m2 := sm.Metrics().AppendEmpty()
	m2.SetName("test.sum")
	m2.SetEmptySum().DataPoints().AppendEmpty()

	// Histogram
	m3 := sm.Metrics().AppendEmpty()
	m3.SetName("test.histogram")
	m3.SetEmptyHistogram().DataPoints().AppendEmpty()

	// Exponential Histogram
	m4 := sm.Metrics().AppendEmpty()
	m4.SetName("test.exp_histogram")
	m4.SetEmptyExponentialHistogram().DataPoints().AppendEmpty()

	// Summary
	m5 := sm.Metrics().AppendEmpty()
	m5.SetName("test.summary")
	m5.SetEmptySummary().DataPoints().AppendEmpty()

	// Keep one of each type
	m6 := sm.Metrics().AppendEmpty()
	m6.SetName("prod.gauge")
	m6.SetEmptyGauge().DataPoints().AppendEmpty()

	m7 := sm.Metrics().AppendEmpty()
	m7.SetName("prod.sum")
	m7.SetEmptySum().DataPoints().AppendEmpty()

	result, err := p.processMetrics(context.Background(), metrics)

	require.NoError(t, err)
	ms := result.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	assert.Equal(t, 2, ms.Len())
}

func TestProcessMetrics_MultipleDatapoints(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-errors",
			Name:    "Drop Errors",
			Enabled: true,
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: &policyv1.AttributePath{Path: []string{"status"}}},
							Match: &policyv1.MetricMatcher_Exact{Exact: "error"},
						},
					},
					Keep: false,
				},
			},
		},
	}

	p := createTestMetricProcessor(t, policies)

	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()

	m := sm.Metrics().AppendEmpty()
	m.SetName("http.requests")
	sum := m.SetEmptySum()

	// Multiple datapoints with different statuses
	dp1 := sum.DataPoints().AppendEmpty()
	dp1.Attributes().PutStr("status", "success")
	dp1.SetIntValue(100)

	dp2 := sum.DataPoints().AppendEmpty()
	dp2.Attributes().PutStr("status", "error")
	dp2.SetIntValue(10)

	dp3 := sum.DataPoints().AppendEmpty()
	dp3.Attributes().PutStr("status", "success")
	dp3.SetIntValue(200)

	dp4 := sum.DataPoints().AppendEmpty()
	dp4.Attributes().PutStr("status", "error")
	dp4.SetIntValue(5)

	result, err := p.processMetrics(context.Background(), metrics)

	require.NoError(t, err)
	ms := result.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	assert.Equal(t, 1, ms.Len())
	assert.Equal(t, 2, ms.At(0).Sum().DataPoints().Len())
}

func TestProcessMetrics_DropAllDatapoints(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-all-test",
			Name:    "Drop All Test",
			Enabled: true,
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_Exact{Exact: "test.metric"},
						},
					},
					Keep: false,
				},
			},
		},
	}

	p := createTestMetricProcessor(t, policies)

	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()

	m := sm.Metrics().AppendEmpty()
	m.SetName("test.metric")
	gauge := m.SetEmptyGauge()
	gauge.DataPoints().AppendEmpty()
	gauge.DataPoints().AppendEmpty()
	gauge.DataPoints().AppendEmpty()

	result, err := p.processMetrics(context.Background(), metrics)

	require.NoError(t, err)
	// When all metrics are dropped, empty resources are removed too
	assert.Equal(t, 0, result.ResourceMetrics().Len())
}

func TestProcessMetrics_EmptyMetrics(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-all",
			Name:    "Drop All",
			Enabled: true,
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_Regex{Regex: ".*"},
						},
					},
					Keep: false,
				},
			},
		},
	}

	p := createTestMetricProcessor(t, policies)
	metrics := pmetric.NewMetrics()

	result, err := p.processMetrics(context.Background(), metrics)

	require.NoError(t, err)
	assert.Equal(t, 0, result.ResourceMetrics().Len())
}

func TestProcessMetrics_MultiplePolicies(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-internal",
			Name:    "Drop Internal",
			Enabled: true,
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_StartsWith{StartsWith: "internal."},
						},
					},
					Keep: false,
				},
			},
		},
		{
			Id:      "drop-debug",
			Name:    "Drop Debug",
			Enabled: true,
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_StartsWith{StartsWith: "debug."},
						},
					},
					Keep: false,
				},
			},
		},
	}

	p := createTestMetricProcessor(t, policies)

	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	for _, name := range []string{"internal.metric", "debug.metric", "http.requests", "db.queries"} {
		m := sm.Metrics().AppendEmpty()
		m.SetName(name)
		m.SetEmptyGauge().DataPoints().AppendEmpty()
	}

	result, err := p.processMetrics(context.Background(), metrics)

	require.NoError(t, err)
	ms := result.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	assert.Equal(t, 2, ms.Len())
}

func TestProcessMetrics_KeepAll(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "keep-important",
			Name:    "Keep Important",
			Enabled: true,
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_StartsWith{StartsWith: "important."},
						},
					},
					Keep: true,
				},
			},
		},
	}

	p := createTestMetricProcessor(t, policies)

	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	for _, name := range []string{"important.metric", "other.metric"} {
		m := sm.Metrics().AppendEmpty()
		m.SetName(name)
		m.SetEmptyGauge().DataPoints().AppendEmpty()
	}

	result, err := p.processMetrics(context.Background(), metrics)

	require.NoError(t, err)
	// Both kept - important matches policy with keep=true, other has no match
	assert.Equal(t, 2, result.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().Len())
}

func TestProcessMetrics_MultipleResourcesAndScopes(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-internal",
			Name:    "Drop Internal",
			Enabled: true,
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_StartsWith{StartsWith: "internal."},
						},
					},
					Keep: false,
				},
			},
		},
	}

	p := createTestMetricProcessor(t, policies)

	metrics := pmetric.NewMetrics()

	// Resource 1, Scope 1
	rm1 := metrics.ResourceMetrics().AppendEmpty()
	rm1.Resource().Attributes().PutStr("service.name", "service-a")
	sm1a := rm1.ScopeMetrics().AppendEmpty()
	sm1a.Scope().SetName("scope-1")
	m1 := sm1a.Metrics().AppendEmpty()
	m1.SetName("internal.metric")
	m1.SetEmptyGauge().DataPoints().AppendEmpty()
	m2 := sm1a.Metrics().AppendEmpty()
	m2.SetName("http.requests")
	m2.SetEmptyGauge().DataPoints().AppendEmpty()

	// Resource 1, Scope 2
	sm1b := rm1.ScopeMetrics().AppendEmpty()
	sm1b.Scope().SetName("scope-2")
	m3 := sm1b.Metrics().AppendEmpty()
	m3.SetName("internal.other")
	m3.SetEmptyGauge().DataPoints().AppendEmpty()
	m4 := sm1b.Metrics().AppendEmpty()
	m4.SetName("db.queries")
	m4.SetEmptyGauge().DataPoints().AppendEmpty()

	// Resource 2
	rm2 := metrics.ResourceMetrics().AppendEmpty()
	rm2.Resource().Attributes().PutStr("service.name", "service-b")
	sm2 := rm2.ScopeMetrics().AppendEmpty()
	m5 := sm2.Metrics().AppendEmpty()
	m5.SetName("internal.metric")
	m5.SetEmptyGauge().DataPoints().AppendEmpty()
	m6 := sm2.Metrics().AppendEmpty()
	m6.SetName("cache.hits")
	m6.SetEmptyGauge().DataPoints().AppendEmpty()

	result, err := p.processMetrics(context.Background(), metrics)

	require.NoError(t, err)

	// Resource 1, Scope 1: 1 metric (http.requests)
	assert.Equal(t, 1, result.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().Len())
	// Resource 1, Scope 2: 1 metric (db.queries)
	assert.Equal(t, 1, result.ResourceMetrics().At(0).ScopeMetrics().At(1).Metrics().Len())
	// Resource 2: 1 metric (cache.hits)
	assert.Equal(t, 1, result.ResourceMetrics().At(1).ScopeMetrics().At(0).Metrics().Len())
}

func TestProcessMetrics_ScopeAttributes(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-by-scope",
			Name:    "Drop By Scope",
			Enabled: true,
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_ScopeAttribute{ScopeAttribute: &policyv1.AttributePath{Path: []string{"library.name"}}},
							Match: &policyv1.MetricMatcher_Exact{Exact: "noisy-lib"},
						},
					},
					Keep: false,
				},
			},
		},
	}

	p := createTestMetricProcessor(t, policies)

	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()

	sm1 := rm.ScopeMetrics().AppendEmpty()
	sm1.Scope().Attributes().PutStr("library.name", "noisy-lib")
	m1 := sm1.Metrics().AppendEmpty()
	m1.SetName("from.noisy")
	m1.SetEmptyGauge().DataPoints().AppendEmpty()

	sm2 := rm.ScopeMetrics().AppendEmpty()
	sm2.Scope().Attributes().PutStr("library.name", "good-lib")
	m2 := sm2.Metrics().AppendEmpty()
	m2.SetName("from.good")
	m2.SetEmptyGauge().DataPoints().AppendEmpty()

	result, err := p.processMetrics(context.Background(), metrics)

	require.NoError(t, err)
	// First scope (noisy-lib) should be removed entirely
	// Only good-lib scope should remain
	assert.Equal(t, 1, result.ResourceMetrics().At(0).ScopeMetrics().Len())
	libName, _ := result.ResourceMetrics().At(0).ScopeMetrics().At(0).Scope().Attributes().Get("library.name")
	assert.Equal(t, "good-lib", libName.Str())
	assert.Equal(t, 1, result.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().Len())
}

func TestProcessMetrics_RegexMatching(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-process-metrics",
			Name:    "Drop Process Metrics",
			Enabled: true,
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_Regex{Regex: "process\\.(cpu|memory).*"},
						},
					},
					Keep: false,
				},
			},
		},
	}

	p := createTestMetricProcessor(t, policies)

	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	for _, name := range []string{"process.cpu.usage", "process.memory.heap", "process.disk.io", "http.requests"} {
		m := sm.Metrics().AppendEmpty()
		m.SetName(name)
		m.SetEmptyGauge().DataPoints().AppendEmpty()
	}

	result, err := p.processMetrics(context.Background(), metrics)

	require.NoError(t, err)
	ms := result.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	assert.Equal(t, 2, ms.Len()) // process.disk.io and http.requests kept
}

// TestProcessMetrics_TypedMatchers exhaustively covers equals/gt/gte/lt/lte
// typed comparison matchers end-to-end: a drop-on-match policy is compiled
// and evaluated against a single gauge datapoint with the "value" attribute
// set per case (or left unset for the absent-field cases).
func TestProcessMetrics_TypedMatchers(t *testing.T) {
	attrPath := &policyv1.AttributePath{Path: []string{"value"}}

	tests := []struct {
		name     string
		setAttr  func(attrs pcommon.Map)
		matcher  *policyv1.MetricMatcher
		wantDrop bool
	}{
		{
			name:    "equals_bool_true_match",
			setAttr: func(a pcommon.Map) { a.PutBool("value", true) },
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_BoolValue{BoolValue: true}}},
			},
			wantDrop: true,
		},
		{
			name:    "equals_bool_false_nonmatch",
			setAttr: func(a pcommon.Map) { a.PutBool("value", true) },
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_BoolValue{BoolValue: false}}},
			},
			wantDrop: false,
		},
		{
			name:    "equals_int_match",
			setAttr: func(a pcommon.Map) { a.PutInt("value", 42) },
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_IntValue{IntValue: 42}}},
			},
			wantDrop: true,
		},
		{
			name:    "equals_int_nonmatch",
			setAttr: func(a pcommon.Map) { a.PutInt("value", 42) },
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_IntValue{IntValue: 43}}},
			},
			wantDrop: false,
		},
		{
			name:    "equals_double_match",
			setAttr: func(a pcommon.Map) { a.PutDouble("value", 3.14) },
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_DoubleValue{DoubleValue: 3.14}}},
			},
			wantDrop: true,
		},
		{
			name:    "equals_double_nonmatch",
			setAttr: func(a pcommon.Map) { a.PutDouble("value", 3.14) },
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_DoubleValue{DoubleValue: 2.71}}},
			},
			wantDrop: false,
		},
		{
			name:    "equals_int_field_double_target_cross_promotion_match",
			setAttr: func(a pcommon.Map) { a.PutInt("value", 5) },
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_DoubleValue{DoubleValue: 5.0}}},
			},
			wantDrop: true,
		},
		{
			name:    "equals_double_field_int_target_cross_promotion_match",
			setAttr: func(a pcommon.Map) { a.PutDouble("value", 5.0) },
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_IntValue{IntValue: 5}}},
			},
			wantDrop: true,
		},
		{
			name: "equals_bytes_match",
			setAttr: func(a pcommon.Map) {
				a.PutEmptyBytes("value").FromRaw([]byte{0xDE, 0xAD, 0xBE, 0xEF})
			},
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_HexValue{HexValue: "deadbeef"}}},
			},
			wantDrop: true,
		},
		{
			name: "equals_bytes_nonmatch",
			setAttr: func(a pcommon.Map) {
				a.PutEmptyBytes("value").FromRaw([]byte{0x00})
			},
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_HexValue{HexValue: "deadbeef"}}},
			},
			wantDrop: false,
		},
		{
			name:    "equals_type_mismatch_string_field_int_target_nonmatch",
			setAttr: func(a pcommon.Map) { a.PutStr("value", "hello") },
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_IntValue{IntValue: 5}}},
			},
			wantDrop: false,
		},
		{
			name:    "equals_absent_field_nonmatch",
			setAttr: nil,
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_IntValue{IntValue: 5}}},
			},
			wantDrop: false,
		},
		{
			name:    "gt_int_match",
			setAttr: func(a pcommon.Map) { a.PutInt("value", 100) },
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Gt{Gt: &policyv1.NumericValue{Value: &policyv1.NumericValue_IntValue{IntValue: 50}}},
			},
			wantDrop: true,
		},
		{
			name:    "gt_int_nonmatch_equal_boundary",
			setAttr: func(a pcommon.Map) { a.PutInt("value", 50) },
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Gt{Gt: &policyv1.NumericValue{Value: &policyv1.NumericValue_IntValue{IntValue: 50}}},
			},
			wantDrop: false,
		},
		{
			name:    "gt_int_nonmatch_less",
			setAttr: func(a pcommon.Map) { a.PutInt("value", 10) },
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Gt{Gt: &policyv1.NumericValue{Value: &policyv1.NumericValue_IntValue{IntValue: 50}}},
			},
			wantDrop: false,
		},
		{
			name:    "gte_int_match_equal_boundary",
			setAttr: func(a pcommon.Map) { a.PutInt("value", 50) },
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Gte{Gte: &policyv1.NumericValue{Value: &policyv1.NumericValue_IntValue{IntValue: 50}}},
			},
			wantDrop: true,
		},
		{
			name:    "gte_int_match_greater",
			setAttr: func(a pcommon.Map) { a.PutInt("value", 51) },
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Gte{Gte: &policyv1.NumericValue{Value: &policyv1.NumericValue_IntValue{IntValue: 50}}},
			},
			wantDrop: true,
		},
		{
			name:    "gte_int_nonmatch",
			setAttr: func(a pcommon.Map) { a.PutInt("value", 49) },
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Gte{Gte: &policyv1.NumericValue{Value: &policyv1.NumericValue_IntValue{IntValue: 50}}},
			},
			wantDrop: false,
		},
		{
			name:    "lt_double_match",
			setAttr: func(a pcommon.Map) { a.PutDouble("value", 1.5) },
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Lt{Lt: &policyv1.NumericValue{Value: &policyv1.NumericValue_DoubleValue{DoubleValue: 2.0}}},
			},
			wantDrop: true,
		},
		{
			name:    "lt_double_nonmatch_equal_boundary",
			setAttr: func(a pcommon.Map) { a.PutDouble("value", 2.0) },
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Lt{Lt: &policyv1.NumericValue{Value: &policyv1.NumericValue_DoubleValue{DoubleValue: 2.0}}},
			},
			wantDrop: false,
		},
		{
			name:    "lte_double_match_equal_boundary",
			setAttr: func(a pcommon.Map) { a.PutDouble("value", 2.0) },
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Lte{Lte: &policyv1.NumericValue{Value: &policyv1.NumericValue_DoubleValue{DoubleValue: 2.0}}},
			},
			wantDrop: true,
		},
		{
			name:    "lte_double_nonmatch",
			setAttr: func(a pcommon.Map) { a.PutDouble("value", 2.1) },
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Lte{Lte: &policyv1.NumericValue{Value: &policyv1.NumericValue_DoubleValue{DoubleValue: 2.0}}},
			},
			wantDrop: false,
		},
		{
			name:    "gt_nonnumeric_bool_field_nonmatch",
			setAttr: func(a pcommon.Map) { a.PutBool("value", true) },
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match: &policyv1.MetricMatcher_Gt{Gt: &policyv1.NumericValue{Value: &policyv1.NumericValue_IntValue{IntValue: 5}}},
			},
			wantDrop: false,
		},
		{
			name:    "negate_equals_match_becomes_nonmatch",
			setAttr: func(a pcommon.Map) { a.PutInt("value", 42) },
			matcher: &policyv1.MetricMatcher{
				Field:  &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match:  &policyv1.MetricMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_IntValue{IntValue: 42}}},
				Negate: true,
			},
			wantDrop: false,
		},
		{
			name:    "negate_equals_nonmatch_becomes_match",
			setAttr: func(a pcommon.Map) { a.PutInt("value", 42) },
			matcher: &policyv1.MetricMatcher{
				Field:  &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: attrPath},
				Match:  &policyv1.MetricMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_IntValue{IntValue: 43}}},
				Negate: true,
			},
			wantDrop: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policies := []*policyv1.Policy{
				{
					Id:      "typed-drop",
					Name:    "Typed Drop",
					Enabled: true,
					Target: &policyv1.Policy_Metric{
						Metric: &policyv1.MetricTarget{
							Match: []*policyv1.MetricMatcher{tc.matcher},
							Keep:  false,
						},
					},
				},
			}

			p := createTestMetricProcessor(t, policies)

			metrics := pmetric.NewMetrics()
			rm := metrics.ResourceMetrics().AppendEmpty()
			sm := rm.ScopeMetrics().AppendEmpty()
			m := sm.Metrics().AppendEmpty()
			m.SetName("test.metric")
			dp := m.SetEmptyGauge().DataPoints().AppendEmpty()
			dp.SetDoubleValue(1)
			if tc.setAttr != nil {
				tc.setAttr(dp.Attributes())
			}

			result, err := p.processMetrics(context.Background(), metrics)
			require.NoError(t, err)

			if tc.wantDrop {
				assert.Equal(t, 0, result.ResourceMetrics().Len(), "expected datapoint to be dropped")
			} else {
				require.Equal(t, 1, result.ResourceMetrics().Len(), "expected datapoint to be kept")
				ms := result.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
				require.Equal(t, 1, ms.Len())
				assert.Equal(t, 1, ms.At(0).Gauge().DataPoints().Len())
			}
		})
	}
}
