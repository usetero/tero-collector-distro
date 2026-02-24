package policyprocessor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/usetero/policy-go"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

// staticTraceProvider is a simple policy provider for testing.
type staticTraceProvider struct {
	policies []*policyv1.Policy
}

func (p *staticTraceProvider) Load() ([]*policyv1.Policy, error) {
	return p.policies, nil
}

func (p *staticTraceProvider) Subscribe(callback policy.PolicyCallback) error {
	callback(p.policies)
	return nil
}

func (p *staticTraceProvider) SetStatsCollector(collector policy.StatsCollector) {}

func createTestTraceProcessor(t *testing.T, policies []*policyv1.Policy) *policyProcessor {
	registry := policy.NewPolicyRegistry()
	engine := policy.NewPolicyEngine(registry)

	provider := &staticTraceProvider{policies: policies}
	_, err := registry.Register(provider)
	require.NoError(t, err)

	return &policyProcessor{
		logger:   zap.NewNop(),
		registry: registry,
		engine:   engine,
	}
}

// Helper to create a TraceSamplingConfig that drops (0% sampling)
func dropConfig() *policyv1.TraceSamplingConfig {
	return &policyv1.TraceSamplingConfig{
		Percentage: 0,
	}
}

// Helper to create a TraceSamplingConfig that keeps all (100% sampling)
func keepConfig() *policyv1.TraceSamplingConfig {
	return &policyv1.TraceSamplingConfig{
		Percentage: 100,
	}
}

func TestProcessTraces_NoPolicy(t *testing.T) {
	p := createTestTraceProcessor(t, nil)

	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	for _, name := range []string{"span.a", "span.b", "span.c"} {
		span := ss.Spans().AppendEmpty()
		span.SetName(name)
	}

	result, err := p.processTraces(context.Background(), traces)

	require.NoError(t, err)
	assert.Equal(t, 3, result.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
}

func TestProcessTraces_DropByName(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-internal",
			Name:    "Drop Internal",
			Enabled: true,
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_StartsWith{StartsWith: "internal/"},
						},
					},
					Keep: dropConfig(),
				},
			},
		},
	}

	p := createTestTraceProcessor(t, policies)

	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	for _, name := range []string{"internal/healthcheck", "GET /api/users", "internal/metrics", "POST /api/orders"} {
		span := ss.Spans().AppendEmpty()
		span.SetName(name)
	}

	result, err := p.processTraces(context.Background(), traces)

	require.NoError(t, err)
	spans := result.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
	assert.Equal(t, 2, spans.Len())

	names := []string{spans.At(0).Name(), spans.At(1).Name()}
	assert.Contains(t, names, "GET /api/users")
	assert.Contains(t, names, "POST /api/orders")
}

func TestProcessTraces_DropBySpanKind(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-internal-kind",
			Name:    "Drop Internal Kind",
			Enabled: true,
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanKind{SpanKind: policyv1.SpanKind_SPAN_KIND_INTERNAL},
						},
					},
					Keep: dropConfig(),
				},
			},
		},
	}

	p := createTestTraceProcessor(t, policies)

	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()

	span1 := ss.Spans().AppendEmpty()
	span1.SetName("internal-span")
	span1.SetKind(ptrace.SpanKindInternal)

	span2 := ss.Spans().AppendEmpty()
	span2.SetName("server-span")
	span2.SetKind(ptrace.SpanKindServer)

	span3 := ss.Spans().AppendEmpty()
	span3.SetName("client-span")
	span3.SetKind(ptrace.SpanKindClient)

	result, err := p.processTraces(context.Background(), traces)

	require.NoError(t, err)
	spans := result.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
	assert.Equal(t, 2, spans.Len())
}

func TestProcessTraces_DropByStatus(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-errors",
			Name:    "Drop Errors",
			Enabled: true,
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanStatus{SpanStatus: policyv1.SpanStatusCode_SPAN_STATUS_CODE_ERROR},
						},
					},
					Keep: dropConfig(),
				},
			},
		},
	}

	p := createTestTraceProcessor(t, policies)

	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()

	span1 := ss.Spans().AppendEmpty()
	span1.SetName("ok-span")
	span1.Status().SetCode(ptrace.StatusCodeOk)

	span2 := ss.Spans().AppendEmpty()
	span2.SetName("error-span")
	span2.Status().SetCode(ptrace.StatusCodeError)

	span3 := ss.Spans().AppendEmpty()
	span3.SetName("unset-span")
	span3.Status().SetCode(ptrace.StatusCodeUnset)

	result, err := p.processTraces(context.Background(), traces)

	require.NoError(t, err)
	spans := result.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
	assert.Equal(t, 2, spans.Len())
}

func TestProcessTraces_DropBySpanAttribute(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-by-method",
			Name:    "Drop By Method",
			Enabled: true,
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanAttribute{SpanAttribute: &policyv1.AttributePath{Path: []string{"http.method"}}},
							Match: &policyv1.TraceMatcher_Exact{Exact: "OPTIONS"},
						},
					},
					Keep: dropConfig(),
				},
			},
		},
	}

	p := createTestTraceProcessor(t, policies)

	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()

	span1 := ss.Spans().AppendEmpty()
	span1.SetName("GET request")
	span1.Attributes().PutStr("http.method", "GET")

	span2 := ss.Spans().AppendEmpty()
	span2.SetName("OPTIONS request")
	span2.Attributes().PutStr("http.method", "OPTIONS")

	span3 := ss.Spans().AppendEmpty()
	span3.SetName("POST request")
	span3.Attributes().PutStr("http.method", "POST")

	result, err := p.processTraces(context.Background(), traces)

	require.NoError(t, err)
	spans := result.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
	assert.Equal(t, 2, spans.Len())
}

func TestProcessTraces_DropByResourceAttribute(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-by-service",
			Name:    "Drop By Service",
			Enabled: true,
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{Path: []string{"service.name"}}},
							Match: &policyv1.TraceMatcher_Exact{Exact: "noisy-service"},
						},
					},
					Keep: dropConfig(),
				},
			},
		},
	}

	p := createTestTraceProcessor(t, policies)

	traces := ptrace.NewTraces()

	rs1 := traces.ResourceSpans().AppendEmpty()
	rs1.Resource().Attributes().PutStr("service.name", "noisy-service")
	ss1 := rs1.ScopeSpans().AppendEmpty()
	span1 := ss1.Spans().AppendEmpty()
	span1.SetName("span-from-noisy")

	rs2 := traces.ResourceSpans().AppendEmpty()
	rs2.Resource().Attributes().PutStr("service.name", "important-service")
	ss2 := rs2.ScopeSpans().AppendEmpty()
	span2 := ss2.Spans().AppendEmpty()
	span2.SetName("span-from-important")

	result, err := p.processTraces(context.Background(), traces)

	require.NoError(t, err)
	// First resource should be removed entirely (all spans dropped)
	assert.Equal(t, 1, result.ResourceSpans().Len())
	serviceName, _ := result.ResourceSpans().At(0).Resource().Attributes().Get("service.name")
	assert.Equal(t, "important-service", serviceName.Str())
}

func TestProcessTraces_MultipleMatchers(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-internal-errors",
			Name:    "Drop Internal Errors",
			Enabled: true,
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanKind{SpanKind: policyv1.SpanKind_SPAN_KIND_INTERNAL},
						},
						{
							Field: &policyv1.TraceMatcher_SpanStatus{SpanStatus: policyv1.SpanStatusCode_SPAN_STATUS_CODE_ERROR},
						},
					},
					Keep: dropConfig(),
				},
			},
		},
	}

	p := createTestTraceProcessor(t, policies)

	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()

	// internal + error - should be dropped
	span1 := ss.Spans().AppendEmpty()
	span1.SetName("internal-error")
	span1.SetKind(ptrace.SpanKindInternal)
	span1.Status().SetCode(ptrace.StatusCodeError)

	// internal + ok - should be kept
	span2 := ss.Spans().AppendEmpty()
	span2.SetName("internal-ok")
	span2.SetKind(ptrace.SpanKindInternal)
	span2.Status().SetCode(ptrace.StatusCodeOk)

	// server + error - should be kept
	span3 := ss.Spans().AppendEmpty()
	span3.SetName("server-error")
	span3.SetKind(ptrace.SpanKindServer)
	span3.Status().SetCode(ptrace.StatusCodeError)

	result, err := p.processTraces(context.Background(), traces)

	require.NoError(t, err)
	spans := result.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
	assert.Equal(t, 2, spans.Len())
}

func TestProcessTraces_MultiplePolicies(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-internal-kind",
			Name:    "Drop Internal Kind",
			Enabled: true,
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanKind{SpanKind: policyv1.SpanKind_SPAN_KIND_INTERNAL},
						},
					},
					Keep: dropConfig(),
				},
			},
		},
		{
			Id:      "drop-healthcheck",
			Name:    "Drop Healthcheck",
			Enabled: true,
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_Contains{Contains: "healthcheck"},
						},
					},
					Keep: dropConfig(),
				},
			},
		},
	}

	p := createTestTraceProcessor(t, policies)

	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()

	span1 := ss.Spans().AppendEmpty()
	span1.SetName("internal-span")
	span1.SetKind(ptrace.SpanKindInternal)

	span2 := ss.Spans().AppendEmpty()
	span2.SetName("GET /healthcheck")
	span2.SetKind(ptrace.SpanKindServer)

	span3 := ss.Spans().AppendEmpty()
	span3.SetName("GET /api/users")
	span3.SetKind(ptrace.SpanKindServer)

	span4 := ss.Spans().AppendEmpty()
	span4.SetName("POST /api/orders")
	span4.SetKind(ptrace.SpanKindServer)

	result, err := p.processTraces(context.Background(), traces)

	require.NoError(t, err)
	spans := result.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
	assert.Equal(t, 2, spans.Len())
}

func TestProcessTraces_KeepAll(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "keep-important",
			Name:    "Keep Important",
			Enabled: true,
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_StartsWith{StartsWith: "important/"},
						},
					},
					Keep: keepConfig(),
				},
			},
		},
	}

	p := createTestTraceProcessor(t, policies)

	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	for _, name := range []string{"important/span", "other/span"} {
		span := ss.Spans().AppendEmpty()
		span.SetName(name)
	}

	result, err := p.processTraces(context.Background(), traces)

	require.NoError(t, err)
	// Both kept - important matches policy with keep=100%, other has no match
	assert.Equal(t, 2, result.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
}

func TestProcessTraces_MultipleResourcesAndScopes(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-internal-kind",
			Name:    "Drop Internal Kind",
			Enabled: true,
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanKind{SpanKind: policyv1.SpanKind_SPAN_KIND_INTERNAL},
						},
					},
					Keep: dropConfig(),
				},
			},
		},
	}

	p := createTestTraceProcessor(t, policies)

	traces := ptrace.NewTraces()

	// Resource 1, Scope 1
	rs1 := traces.ResourceSpans().AppendEmpty()
	rs1.Resource().Attributes().PutStr("service.name", "service-a")
	ss1a := rs1.ScopeSpans().AppendEmpty()
	ss1a.Scope().SetName("scope-1")
	span1 := ss1a.Spans().AppendEmpty()
	span1.SetName("internal-span")
	span1.SetKind(ptrace.SpanKindInternal)
	span2 := ss1a.Spans().AppendEmpty()
	span2.SetName("server-span")
	span2.SetKind(ptrace.SpanKindServer)

	// Resource 1, Scope 2
	ss1b := rs1.ScopeSpans().AppendEmpty()
	ss1b.Scope().SetName("scope-2")
	span3 := ss1b.Spans().AppendEmpty()
	span3.SetName("internal-span-2")
	span3.SetKind(ptrace.SpanKindInternal)
	span4 := ss1b.Spans().AppendEmpty()
	span4.SetName("client-span")
	span4.SetKind(ptrace.SpanKindClient)

	// Resource 2
	rs2 := traces.ResourceSpans().AppendEmpty()
	rs2.Resource().Attributes().PutStr("service.name", "service-b")
	ss2 := rs2.ScopeSpans().AppendEmpty()
	span5 := ss2.Spans().AppendEmpty()
	span5.SetName("internal-span-3")
	span5.SetKind(ptrace.SpanKindInternal)
	span6 := ss2.Spans().AppendEmpty()
	span6.SetName("producer-span")
	span6.SetKind(ptrace.SpanKindProducer)

	result, err := p.processTraces(context.Background(), traces)

	require.NoError(t, err)

	// Resource 1, Scope 1: 1 span (server-span)
	assert.Equal(t, 1, result.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
	// Resource 1, Scope 2: 1 span (client-span)
	assert.Equal(t, 1, result.ResourceSpans().At(0).ScopeSpans().At(1).Spans().Len())
	// Resource 2: 1 span (producer-span)
	assert.Equal(t, 1, result.ResourceSpans().At(1).ScopeSpans().At(0).Spans().Len())
}

func TestProcessTraces_ScopeAttributes(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-by-scope",
			Name:    "Drop By Scope",
			Enabled: true,
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_ScopeAttribute{ScopeAttribute: &policyv1.AttributePath{Path: []string{"library.name"}}},
							Match: &policyv1.TraceMatcher_Exact{Exact: "noisy-lib"},
						},
					},
					Keep: dropConfig(),
				},
			},
		},
	}

	p := createTestTraceProcessor(t, policies)

	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()

	ss1 := rs.ScopeSpans().AppendEmpty()
	ss1.Scope().Attributes().PutStr("library.name", "noisy-lib")
	span1 := ss1.Spans().AppendEmpty()
	span1.SetName("span-from-noisy")

	ss2 := rs.ScopeSpans().AppendEmpty()
	ss2.Scope().Attributes().PutStr("library.name", "good-lib")
	span2 := ss2.Spans().AppendEmpty()
	span2.SetName("span-from-good")

	result, err := p.processTraces(context.Background(), traces)

	require.NoError(t, err)
	// First scope (noisy-lib) should be removed entirely
	assert.Equal(t, 1, result.ResourceSpans().At(0).ScopeSpans().Len())
	libName, _ := result.ResourceSpans().At(0).ScopeSpans().At(0).Scope().Attributes().Get("library.name")
	assert.Equal(t, "good-lib", libName.Str())
}

func TestProcessTraces_RegexMatching(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-api-v1",
			Name:    "Drop API v1",
			Enabled: true,
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_Regex{Regex: ".*\\/api\\/v1\\/.*"},
						},
					},
					Keep: dropConfig(),
				},
			},
		},
	}

	p := createTestTraceProcessor(t, policies)

	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	for _, name := range []string{"GET /api/v1/users", "POST /api/v2/orders", "GET /api/v1/products", "DELETE /api/v3/items"} {
		span := ss.Spans().AppendEmpty()
		span.SetName(name)
	}

	result, err := p.processTraces(context.Background(), traces)

	require.NoError(t, err)
	spans := result.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
	assert.Equal(t, 2, spans.Len()) // v2 and v3 kept
}

func TestProcessTraces_EmptyTraces(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-all",
			Name:    "Drop All",
			Enabled: true,
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_Regex{Regex: ".*"},
						},
					},
					Keep: dropConfig(),
				},
			},
		},
	}

	p := createTestTraceProcessor(t, policies)
	traces := ptrace.NewTraces()

	result, err := p.processTraces(context.Background(), traces)

	require.NoError(t, err)
	assert.Equal(t, 0, result.ResourceSpans().Len())
}

func TestProcessTraces_DropAllSpans(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-all-test",
			Name:    "Drop All Test",
			Enabled: true,
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_Exact{Exact: "test.span"},
						},
					},
					Keep: dropConfig(),
				},
			},
		},
	}

	p := createTestTraceProcessor(t, policies)

	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()

	for i := 0; i < 3; i++ {
		span := ss.Spans().AppendEmpty()
		span.SetName("test.span")
	}

	result, err := p.processTraces(context.Background(), traces)

	require.NoError(t, err)
	// When all spans are dropped, empty resources are removed too
	assert.Equal(t, 0, result.ResourceSpans().Len())
}

func TestProcessTraces_TraceID(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-specific-trace",
			Name:    "Drop Specific Trace",
			Enabled: true,
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_TRACE_ID},
							Match: &policyv1.TraceMatcher_Exact{Exact: "trace-id-abc1234"},
						},
					},
					Keep: dropConfig(),
				},
			},
		},
	}

	p := createTestTraceProcessor(t, policies)

	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()

	span1 := ss.Spans().AppendEmpty()
	span1.SetName("span-1")
	var traceID1 pcommon.TraceID
	copy(traceID1[:], "trace-id-abc1234")
	span1.SetTraceID(traceID1)

	span2 := ss.Spans().AppendEmpty()
	span2.SetName("span-2")
	var traceID2 pcommon.TraceID
	copy(traceID2[:], "trace-id-def5678")
	span2.SetTraceID(traceID2)

	result, err := p.processTraces(context.Background(), traces)

	require.NoError(t, err)
	spans := result.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
	assert.Equal(t, 1, spans.Len())
	assert.Equal(t, "span-2", spans.At(0).Name())
}

func TestProcessTraces_AllSpanKinds(t *testing.T) {
	// Test that all span kinds can be matched
	kinds := []struct {
		policyKind policyv1.SpanKind
		pdataKind  ptrace.SpanKind
		name       string
	}{
		{policyv1.SpanKind_SPAN_KIND_INTERNAL, ptrace.SpanKindInternal, "internal"},
		{policyv1.SpanKind_SPAN_KIND_SERVER, ptrace.SpanKindServer, "server"},
		{policyv1.SpanKind_SPAN_KIND_CLIENT, ptrace.SpanKindClient, "client"},
		{policyv1.SpanKind_SPAN_KIND_PRODUCER, ptrace.SpanKindProducer, "producer"},
		{policyv1.SpanKind_SPAN_KIND_CONSUMER, ptrace.SpanKindConsumer, "consumer"},
	}

	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			policies := []*policyv1.Policy{
				{
					Id:      "drop-" + k.name,
					Name:    "Drop " + k.name,
					Enabled: true,
					Target: &policyv1.Policy_Trace{
						Trace: &policyv1.TraceTarget{
							Match: []*policyv1.TraceMatcher{
								{
									Field: &policyv1.TraceMatcher_SpanKind{SpanKind: k.policyKind},
								},
							},
							Keep: dropConfig(),
						},
					},
				},
			}

			p := createTestTraceProcessor(t, policies)

			traces := ptrace.NewTraces()
			rs := traces.ResourceSpans().AppendEmpty()
			ss := rs.ScopeSpans().AppendEmpty()

			// Add target span (should be dropped)
			span1 := ss.Spans().AppendEmpty()
			span1.SetName("target")
			span1.SetKind(k.pdataKind)

			// Add a different kind span (should be kept)
			span2 := ss.Spans().AppendEmpty()
			span2.SetName("other")
			if k.pdataKind == ptrace.SpanKindServer {
				span2.SetKind(ptrace.SpanKindClient)
			} else {
				span2.SetKind(ptrace.SpanKindServer)
			}

			result, err := p.processTraces(context.Background(), traces)

			require.NoError(t, err)
			spans := result.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
			assert.Equal(t, 1, spans.Len())
			assert.Equal(t, "other", spans.At(0).Name())
		})
	}
}
