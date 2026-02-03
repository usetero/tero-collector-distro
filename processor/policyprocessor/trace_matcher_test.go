package policyprocessor

import (
	"testing"

	"github.com/usetero/policy-go"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

func TestTraceMatcher_Fields(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() TraceContext
		ref      policy.TraceFieldRef
		expected []byte
	}{
		{
			name: "span name",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.SetName("GET /api/users")
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldName},
			expected: []byte("GET /api/users"),
		},
		{
			name: "span name empty",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldName},
			expected: nil,
		},
		{
			name: "trace id",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				traceID := pcommon.TraceID([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
				span.SetTraceID(traceID)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldTraceID},
			expected: []byte("0102030405060708090a0b0c0d0e0f10"),
		},
		{
			name: "trace id empty",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldTraceID},
			expected: nil,
		},
		{
			name: "span id",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				spanID := pcommon.SpanID([8]byte{1, 2, 3, 4, 5, 6, 7, 8})
				span.SetSpanID(spanID)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldSpanID},
			expected: []byte("0102030405060708"),
		},
		{
			name: "span id empty",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldSpanID},
			expected: nil,
		},
		{
			name: "parent span id",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				parentSpanID := pcommon.SpanID([8]byte{8, 7, 6, 5, 4, 3, 2, 1})
				span.SetParentSpanID(parentSpanID)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldParentSpanID},
			expected: []byte("0807060504030201"),
		},
		{
			name: "parent span id empty",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldParentSpanID},
			expected: nil,
		},
		{
			name: "trace state",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.TraceState().FromRaw("vendor1=value1,vendor2=value2")
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldTraceState},
			expected: []byte("vendor1=value1,vendor2=value2"),
		},
		{
			name: "trace state empty",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldTraceState},
			expected: nil,
		},
		{
			name: "span kind internal",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.SetKind(ptrace.SpanKindInternal)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldKind},
			expected: []byte("internal"),
		},
		{
			name: "span kind server",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.SetKind(ptrace.SpanKindServer)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldKind},
			expected: []byte("server"),
		},
		{
			name: "span kind client",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.SetKind(ptrace.SpanKindClient)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldKind},
			expected: []byte("client"),
		},
		{
			name: "span kind producer",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.SetKind(ptrace.SpanKindProducer)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldKind},
			expected: []byte("producer"),
		},
		{
			name: "span kind consumer",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.SetKind(ptrace.SpanKindConsumer)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldKind},
			expected: []byte("consumer"),
		},
		{
			name: "span kind unspecified",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.SetKind(ptrace.SpanKindUnspecified)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldKind},
			expected: nil,
		},
		{
			name: "status ok",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.Status().SetCode(ptrace.StatusCodeOk)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldStatus},
			expected: []byte("ok"),
		},
		{
			name: "status error",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.Status().SetCode(ptrace.StatusCodeError)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldStatus},
			expected: []byte("error"),
		},
		{
			name: "status unset",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.Status().SetCode(ptrace.StatusCodeUnset)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldStatus},
			expected: nil,
		},
		{
			name: "scope name",
			setup: func() TraceContext {
				scope := pcommon.NewInstrumentationScope()
				scope.SetName("my.instrumentation.library")
				return TraceContext{
					Span:  ptrace.NewSpan(),
					Scope: scope,
				}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldScopeName},
			expected: []byte("my.instrumentation.library"),
		},
		{
			name: "scope name empty",
			setup: func() TraceContext {
				return TraceContext{
					Span:  ptrace.NewSpan(),
					Scope: pcommon.NewInstrumentationScope(),
				}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldScopeName},
			expected: nil,
		},
		{
			name: "scope version",
			setup: func() TraceContext {
				scope := pcommon.NewInstrumentationScope()
				scope.SetVersion("1.2.3")
				return TraceContext{
					Span:  ptrace.NewSpan(),
					Scope: scope,
				}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldScopeVersion},
			expected: []byte("1.2.3"),
		},
		{
			name: "scope version empty",
			setup: func() TraceContext {
				return TraceContext{
					Span:  ptrace.NewSpan(),
					Scope: pcommon.NewInstrumentationScope(),
				}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldScopeVersion},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setup()
			result := TraceMatcher(ctx, tt.ref)

			if tt.expected == nil && result != nil {
				t.Errorf("expected nil, got %q", result)
			} else if tt.expected != nil && result == nil {
				t.Errorf("expected %q, got nil", tt.expected)
			} else if string(result) != string(tt.expected) {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestTraceMatcher_Attributes(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() TraceContext
		ref      policy.TraceFieldRef
		expected []byte
	}{
		{
			name: "resource attribute simple",
			setup: func() TraceContext {
				resource := pcommon.NewResource()
				resource.Attributes().PutStr("service.name", "my-service")
				return TraceContext{
					Span:     ptrace.NewSpan(),
					Resource: resource,
				}
			},
			ref:      policy.TraceResourceAttr("service.name"),
			expected: []byte("my-service"),
		},
		{
			name: "scope attribute simple",
			setup: func() TraceContext {
				scope := pcommon.NewInstrumentationScope()
				scope.Attributes().PutStr("library.version", "1.0.0")
				return TraceContext{
					Span:  ptrace.NewSpan(),
					Scope: scope,
				}
			},
			ref:      policy.TraceScopeAttr("library.version"),
			expected: []byte("1.0.0"),
		},
		{
			name: "span attribute simple",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.Attributes().PutStr("http.method", "GET")
				return TraceContext{Span: span}
			},
			ref:      policy.SpanAttr("http.method"),
			expected: []byte("GET"),
		},
		{
			name: "span attribute nested",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				nested := span.Attributes().PutEmptyMap("http")
				nested.PutStr("method", "POST")
				return TraceContext{Span: span}
			},
			ref:      policy.SpanAttr("http", "method"),
			expected: []byte("POST"),
		},
		{
			name: "attribute not found",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				return TraceContext{Span: span}
			},
			ref:      policy.SpanAttr("nonexistent"),
			expected: nil,
		},
		{
			name: "integer attribute",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.Attributes().PutInt("http.status_code", 200)
				return TraceContext{Span: span}
			},
			ref:      policy.SpanAttr("http.status_code"),
			expected: []byte("200"),
		},
		{
			name: "boolean attribute true",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.Attributes().PutBool("error", true)
				return TraceContext{Span: span}
			},
			ref:      policy.SpanAttr("error"),
			expected: []byte("true"),
		},
		{
			name: "boolean attribute false",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.Attributes().PutBool("error", false)
				return TraceContext{Span: span}
			},
			ref:      policy.SpanAttr("error"),
			expected: []byte("false"),
		},
		{
			name: "double attribute",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.Attributes().PutDouble("duration", 1.5)
				return TraceContext{Span: span}
			},
			ref:      policy.SpanAttr("duration"),
			expected: []byte("1.5"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setup()
			result := TraceMatcher(ctx, tt.ref)

			if tt.expected == nil && result != nil {
				t.Errorf("expected nil, got %q", result)
			} else if tt.expected != nil && result == nil {
				t.Errorf("expected %q, got nil", tt.expected)
			} else if string(result) != string(tt.expected) {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}
