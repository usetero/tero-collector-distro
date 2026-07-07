package policyprocessor

import (
	"reflect"
	"testing"

	"github.com/usetero/policy-go/policy"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestLogMatcher_Fields(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() LogContext
		ref      policy.LogFieldRef
		expected policy.TypedValue
	}{
		{
			name: "body string",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.Body().SetStr("hello world")
				return LogContext{Record: lr}
			},
			ref:      policy.LogBody(),
			expected: policy.TypedValueOfString("hello world"),
		},
		{
			name: "body empty",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				return LogContext{Record: lr}
			},
			ref:      policy.LogBody(),
			expected: policy.TypedValue{},
		},
		{
			name: "severity text",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.SetSeverityText("ERROR")
				return LogContext{Record: lr}
			},
			ref:      policy.LogSeverityText(),
			expected: policy.TypedValueOfString("ERROR"),
		},
		{
			name: "severity text empty",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				return LogContext{Record: lr}
			},
			ref:      policy.LogSeverityText(),
			expected: policy.TypedValue{},
		},
		{
			name: "trace id",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				var traceID pcommon.TraceID
				copy(traceID[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10})
				lr.SetTraceID(traceID)
				return LogContext{Record: lr}
			},
			ref:      policy.LogTraceID(),
			expected: policy.TypedValueOfBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}),
		},
		{
			name: "trace id empty",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				return LogContext{Record: lr}
			},
			ref:      policy.LogTraceID(),
			expected: policy.TypedValue{},
		},
		{
			name: "span id",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				var spanID pcommon.SpanID
				copy(spanID[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
				lr.SetSpanID(spanID)
				return LogContext{Record: lr}
			},
			ref:      policy.LogSpanID(),
			expected: policy.TypedValueOfBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}),
		},
		{
			name: "span id empty",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				return LogContext{Record: lr}
			},
			ref:      policy.LogSpanID(),
			expected: policy.TypedValue{},
		},
		{
			name: "event name",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.SetEventName("user.login")
				return LogContext{Record: lr}
			},
			ref:      policy.LogFieldRef{Field: policy.LogFieldEventName},
			expected: policy.TypedValueOfString("user.login"),
		},
		{
			name: "event name missing",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				return LogContext{Record: lr}
			},
			ref:      policy.LogFieldRef{Field: policy.LogFieldEventName},
			expected: policy.TypedValue{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setup()
			result := LogTypedMatcher(ctx, tt.ref)
			if !reflect.DeepEqual(tt.expected, result) {
				t.Errorf("expected %+v, got %+v", tt.expected, result)
			}
		})
	}
}

// TestLogExists_Body pins the spec rule: an empty-string body is missing,
// but a non-string body value (int, bool, map, …) is still present so that
// must-exist matchers continue to fire.
func TestLogExists_Body(t *testing.T) {
	tests := []struct {
		name   string
		setup  func() LogContext
		exists bool
	}{
		{
			name:   "body unset",
			setup:  func() LogContext { return LogContext{Record: plog.NewLogRecord()} },
			exists: false,
		},
		{
			name: "body empty string",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.Body().SetStr("")
				return LogContext{Record: lr}
			},
			exists: false,
		},
		{
			name: "body non-empty string",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.Body().SetStr("hello")
				return LogContext{Record: lr}
			},
			exists: true,
		},
		{
			name: "body int value still exists",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.Body().SetInt(42)
				return LogContext{Record: lr}
			},
			exists: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setup()
			got := LogExists(ctx, policy.LogBody())
			if got != tt.exists {
				t.Errorf("expected %v, got %v", tt.exists, got)
			}
		})
	}
}

// TestLogTypedMatcher_NonStringAttribute verifies that LogTypedMatcher returns
// typed values for non-string attributes (int, bool, double), while LogExists
// also reports them as present.
func TestLogTypedMatcher_NonStringAttribute(t *testing.T) {
	lr := plog.NewLogRecord()
	lr.Attributes().PutInt("count", 42)
	ctx := LogContext{Record: lr}

	if !LogExists(ctx, policy.LogAttr("count")) {
		t.Errorf("LogExists should be true for an int attribute")
	}
	v := LogTypedMatcher(ctx, policy.LogAttr("count"))
	if !reflect.DeepEqual(v, policy.TypedValueOfInt(42)) {
		t.Errorf("LogTypedMatcher should return TypedValueOfInt(42) for an int attribute, got %+v", v)
	}
}

func TestLogMatcher_Attributes(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() LogContext
		ref      policy.LogFieldRef
		expected policy.TypedValue
	}{
		{
			name: "resource attribute simple",
			setup: func() LogContext {
				resource := pcommon.NewResource()
				resource.Attributes().PutStr("service.name", "my-service")
				return LogContext{Resource: resource}
			},
			ref:      policy.LogResourceAttr("service.name"),
			expected: policy.TypedValueOfString("my-service"),
		},
		{
			name: "scope attribute simple",
			setup: func() LogContext {
				scope := pcommon.NewInstrumentationScope()
				scope.Attributes().PutStr("library.version", "1.0.0")
				return LogContext{Scope: scope}
			},
			ref:      policy.LogScopeAttr("library.version"),
			expected: policy.TypedValueOfString("1.0.0"),
		},
		{
			name: "record attribute simple",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.Attributes().PutStr("user.id", "12345")
				return LogContext{Record: lr}
			},
			ref:      policy.LogAttr("user.id"),
			expected: policy.TypedValueOfString("12345"),
		},
		{
			name: "nested attribute two levels",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				nested := lr.Attributes().PutEmptyMap("http")
				nested.PutStr("method", "GET")
				return LogContext{Record: lr}
			},
			ref:      policy.LogAttr("http", "method"),
			expected: policy.TypedValueOfString("GET"),
		},
		{
			name: "nested attribute three levels",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				http := lr.Attributes().PutEmptyMap("http")
				request := http.PutEmptyMap("request")
				request.PutStr("path", "/api/users")
				return LogContext{Record: lr}
			},
			ref:      policy.LogAttr("http", "request", "path"),
			expected: policy.TypedValueOfString("/api/users"),
		},
		{
			name: "attribute not found",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				return LogContext{Record: lr}
			},
			ref:      policy.LogAttr("nonexistent"),
			expected: policy.TypedValue{},
		},
		{
			name: "nested attribute partial path not found",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.Attributes().PutEmptyMap("http")
				return LogContext{Record: lr}
			},
			ref:      policy.LogAttr("http", "nonexistent"),
			expected: policy.TypedValue{},
		},
		{
			name: "nested path on non-map value",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.Attributes().PutStr("http", "not-a-map")
				return LogContext{Record: lr}
			},
			ref:      policy.LogAttr("http", "method"),
			expected: policy.TypedValue{},
		},
		{
			name: "integer attribute returns typed int",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.Attributes().PutInt("count", 42)
				return LogContext{Record: lr}
			},
			ref:      policy.LogAttr("count"),
			expected: policy.TypedValueOfInt(42),
		},
		{
			name: "boolean attribute true",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.Attributes().PutBool("enabled", true)
				return LogContext{Record: lr}
			},
			ref:      policy.LogAttr("enabled"),
			expected: policy.TypedValueOfBool(true),
		},
		{
			name: "boolean attribute false",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.Attributes().PutBool("enabled", false)
				return LogContext{Record: lr}
			},
			ref:      policy.LogAttr("enabled"),
			expected: policy.TypedValueOfBool(false),
		},
		{
			name: "double attribute",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.Attributes().PutDouble("rate", 3.14)
				return LogContext{Record: lr}
			},
			ref:      policy.LogAttr("rate"),
			expected: policy.TypedValueOfDouble(3.14),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setup()
			result := LogTypedMatcher(ctx, tt.ref)
			if !reflect.DeepEqual(tt.expected, result) {
				t.Errorf("expected %+v, got %+v", tt.expected, result)
			}
		})
	}
}
