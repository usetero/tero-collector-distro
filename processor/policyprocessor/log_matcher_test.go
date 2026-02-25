package policyprocessor

import (
	"testing"

	"github.com/usetero/policy-go"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestLogMatcher_Fields(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() LogContext
		ref      policy.LogFieldRef
		expected []byte
	}{
		{
			name: "body string",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.Body().SetStr("hello world")
				return LogContext{Record: lr}
			},
			ref:      policy.LogBody(),
			expected: []byte("hello world"),
		},
		{
			name: "body empty",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				return LogContext{Record: lr}
			},
			ref:      policy.LogBody(),
			expected: nil,
		},
		{
			name: "severity text",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.SetSeverityText("ERROR")
				return LogContext{Record: lr}
			},
			ref:      policy.LogSeverityText(),
			expected: []byte("ERROR"),
		},
		{
			name: "severity text empty",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				return LogContext{Record: lr}
			},
			ref:      policy.LogSeverityText(),
			expected: nil,
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
			expected: []byte("0102030405060708090a0b0c0d0e0f10"),
		},
		{
			name: "trace id empty",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				return LogContext{Record: lr}
			},
			ref:      policy.LogTraceID(),
			expected: nil,
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
			expected: []byte("0102030405060708"),
		},
		{
			name: "span id empty",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				return LogContext{Record: lr}
			},
			ref:      policy.LogSpanID(),
			expected: nil,
		},
		{
			name: "event name",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.SetEventName("user.login")
				return LogContext{Record: lr}
			},
			ref:      policy.LogFieldRef{Field: policy.LogFieldEventName},
			expected: []byte("user.login"),
		},
		{
			name: "event name missing",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				return LogContext{Record: lr}
			},
			ref:      policy.LogFieldRef{Field: policy.LogFieldEventName},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setup()
			result := LogMatcher(ctx, tt.ref)

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

func TestLogMatcher_Attributes(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() LogContext
		ref      policy.LogFieldRef
		expected []byte
	}{
		{
			name: "resource attribute simple",
			setup: func() LogContext {
				resource := pcommon.NewResource()
				resource.Attributes().PutStr("service.name", "my-service")
				return LogContext{Resource: resource}
			},
			ref:      policy.LogResourceAttr("service.name"),
			expected: []byte("my-service"),
		},
		{
			name: "scope attribute simple",
			setup: func() LogContext {
				scope := pcommon.NewInstrumentationScope()
				scope.Attributes().PutStr("library.version", "1.0.0")
				return LogContext{Scope: scope}
			},
			ref:      policy.LogScopeAttr("library.version"),
			expected: []byte("1.0.0"),
		},
		{
			name: "record attribute simple",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.Attributes().PutStr("user.id", "12345")
				return LogContext{Record: lr}
			},
			ref:      policy.LogAttr("user.id"),
			expected: []byte("12345"),
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
			expected: []byte("GET"),
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
			expected: []byte("/api/users"),
		},
		{
			name: "attribute not found",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				return LogContext{Record: lr}
			},
			ref:      policy.LogAttr("nonexistent"),
			expected: nil,
		},
		{
			name: "nested attribute partial path not found",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.Attributes().PutEmptyMap("http")
				return LogContext{Record: lr}
			},
			ref:      policy.LogAttr("http", "nonexistent"),
			expected: nil,
		},
		{
			name: "nested path on non-map value",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.Attributes().PutStr("http", "not-a-map")
				return LogContext{Record: lr}
			},
			ref:      policy.LogAttr("http", "method"),
			expected: nil,
		},
		{
			name: "integer attribute",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.Attributes().PutInt("count", 42)
				return LogContext{Record: lr}
			},
			ref:      policy.LogAttr("count"),
			expected: []byte("42"),
		},
		{
			name: "boolean attribute true",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.Attributes().PutBool("enabled", true)
				return LogContext{Record: lr}
			},
			ref:      policy.LogAttr("enabled"),
			expected: []byte("true"),
		},
		{
			name: "boolean attribute false",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.Attributes().PutBool("enabled", false)
				return LogContext{Record: lr}
			},
			ref:      policy.LogAttr("enabled"),
			expected: []byte("false"),
		},
		{
			name: "double attribute",
			setup: func() LogContext {
				lr := plog.NewLogRecord()
				lr.Attributes().PutDouble("rate", 3.14)
				return LogContext{Record: lr}
			},
			ref:      policy.LogAttr("rate"),
			expected: []byte("3.14"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setup()
			result := LogMatcher(ctx, tt.ref)

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
