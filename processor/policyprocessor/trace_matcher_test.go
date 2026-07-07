package policyprocessor

import (
	"reflect"
	"testing"

	"github.com/usetero/policy-go/policy"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

func TestTraceMatcher_Fields(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() TraceContext
		ref      policy.TraceFieldRef
		expected policy.TypedValue
	}{
		{
			name: "span name",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.SetName("GET /api/users")
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldName},
			expected: policy.TypedValueOfString("GET /api/users"),
		},
		{
			name: "span name empty",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldName},
			expected: policy.TypedValue{},
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
			expected: policy.TypedValueOfBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}),
		},
		{
			name: "trace id empty",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldTraceID},
			expected: policy.TypedValue{},
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
			expected: policy.TypedValueOfBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		},
		{
			name: "span id empty",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldSpanID},
			expected: policy.TypedValue{},
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
			expected: policy.TypedValueOfBytes([]byte{8, 7, 6, 5, 4, 3, 2, 1}),
		},
		{
			name: "parent span id empty",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldParentSpanID},
			expected: policy.TypedValue{},
		},
		{
			name: "trace state",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.TraceState().FromRaw("vendor1=value1,vendor2=value2")
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldTraceState},
			expected: policy.TypedValueOfString("vendor1=value1,vendor2=value2"),
		},
		{
			name: "trace state empty",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldTraceState},
			expected: policy.TypedValue{},
		},
		{
			name: "span kind internal",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.SetKind(ptrace.SpanKindInternal)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldKind},
			expected: policy.TypedValueOfString("internal"),
		},
		{
			name: "span kind server",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.SetKind(ptrace.SpanKindServer)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldKind},
			expected: policy.TypedValueOfString("server"),
		},
		{
			name: "span kind client",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.SetKind(ptrace.SpanKindClient)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldKind},
			expected: policy.TypedValueOfString("client"),
		},
		{
			name: "span kind producer",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.SetKind(ptrace.SpanKindProducer)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldKind},
			expected: policy.TypedValueOfString("producer"),
		},
		{
			name: "span kind consumer",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.SetKind(ptrace.SpanKindConsumer)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldKind},
			expected: policy.TypedValueOfString("consumer"),
		},
		{
			name: "span kind unspecified",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.SetKind(ptrace.SpanKindUnspecified)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldKind},
			expected: policy.TypedValue{},
		},
		{
			name: "status ok",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.Status().SetCode(ptrace.StatusCodeOk)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldStatus},
			expected: policy.TypedValueOfString("ok"),
		},
		{
			name: "status error",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.Status().SetCode(ptrace.StatusCodeError)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldStatus},
			expected: policy.TypedValueOfString("error"),
		},
		{
			name: "status unset",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.Status().SetCode(ptrace.StatusCodeUnset)
				return TraceContext{Span: span}
			},
			ref:      policy.TraceFieldRef{Field: policy.TraceFieldStatus},
			expected: policy.TypedValueOfString("unset"),
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
			expected: policy.TypedValueOfString("my.instrumentation.library"),
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
			expected: policy.TypedValue{},
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
			expected: policy.TypedValueOfString("1.2.3"),
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
			expected: policy.TypedValue{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setup()
			result := TraceTypedMatcher(ctx, tt.ref)
			if !reflect.DeepEqual(tt.expected, result) {
				t.Errorf("expected %+v, got %+v", tt.expected, result)
			}
		})
	}
}

func TestTraceMatcher_Attributes(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() TraceContext
		ref      policy.TraceFieldRef
		expected policy.TypedValue
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
			expected: policy.TypedValueOfString("my-service"),
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
			expected: policy.TypedValueOfString("1.0.0"),
		},
		{
			name: "span attribute simple",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.Attributes().PutStr("http.method", "GET")
				return TraceContext{Span: span}
			},
			ref:      policy.SpanAttr("http.method"),
			expected: policy.TypedValueOfString("GET"),
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
			expected: policy.TypedValueOfString("POST"),
		},
		{
			name: "attribute not found",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				return TraceContext{Span: span}
			},
			ref:      policy.SpanAttr("nonexistent"),
			expected: policy.TypedValue{},
		},
		{
			name: "integer attribute returns typed int",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.Attributes().PutInt("http.status_code", 200)
				return TraceContext{Span: span}
			},
			ref:      policy.SpanAttr("http.status_code"),
			expected: policy.TypedValueOfInt(200),
		},
		{
			name: "boolean attribute true",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.Attributes().PutBool("error", true)
				return TraceContext{Span: span}
			},
			ref:      policy.SpanAttr("error"),
			expected: policy.TypedValueOfBool(true),
		},
		{
			name: "boolean attribute false",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.Attributes().PutBool("error", false)
				return TraceContext{Span: span}
			},
			ref:      policy.SpanAttr("error"),
			expected: policy.TypedValueOfBool(false),
		},
		{
			name: "double attribute",
			setup: func() TraceContext {
				span := ptrace.NewSpan()
				span.Attributes().PutDouble("duration", 1.5)
				return TraceContext{Span: span}
			},
			ref:      policy.SpanAttr("duration"),
			expected: policy.TypedValueOfDouble(1.5),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setup()
			result := TraceTypedMatcher(ctx, tt.ref)
			if !reflect.DeepEqual(tt.expected, result) {
				t.Errorf("expected %+v, got %+v", tt.expected, result)
			}
		})
	}
}
