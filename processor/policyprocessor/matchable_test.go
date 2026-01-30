package policyprocessor

import (
	"testing"

	"github.com/usetero/policy-go"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestLogRecordWrapper_GetField(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() *LogRecordWrapper
		field    policy.LogField
		expected []byte
	}{
		{
			name: "body string",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				lr.Body().SetStr("hello world")
				return &LogRecordWrapper{Record: lr}
			},
			field:    policy.LogFieldBody,
			expected: []byte("hello world"),
		},
		{
			name: "body empty",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				return &LogRecordWrapper{Record: lr}
			},
			field:    policy.LogFieldBody,
			expected: nil,
		},
		{
			name: "severity text",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				lr.SetSeverityText("ERROR")
				return &LogRecordWrapper{Record: lr}
			},
			field:    policy.LogFieldSeverityText,
			expected: []byte("ERROR"),
		},
		{
			name: "severity text empty",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				return &LogRecordWrapper{Record: lr}
			},
			field:    policy.LogFieldSeverityText,
			expected: nil,
		},
		{
			name: "trace id",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				var traceID pcommon.TraceID
				copy(traceID[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10})
				lr.SetTraceID(traceID)
				return &LogRecordWrapper{Record: lr}
			},
			field:    policy.LogFieldTraceID,
			expected: []byte("0102030405060708090a0b0c0d0e0f10"),
		},
		{
			name: "trace id empty",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				return &LogRecordWrapper{Record: lr}
			},
			field:    policy.LogFieldTraceID,
			expected: nil,
		},
		{
			name: "span id",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				var spanID pcommon.SpanID
				copy(spanID[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
				lr.SetSpanID(spanID)
				return &LogRecordWrapper{Record: lr}
			},
			field:    policy.LogFieldSpanID,
			expected: []byte("0102030405060708"),
		},
		{
			name: "span id empty",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				return &LogRecordWrapper{Record: lr}
			},
			field:    policy.LogFieldSpanID,
			expected: nil,
		},
		{
			name: "event name from attributes",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				lr.Attributes().PutStr("event.name", "user.login")
				return &LogRecordWrapper{Record: lr}
			},
			field:    policy.LogFieldEventName,
			expected: []byte("user.login"),
		},
		{
			name: "event name missing",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				return &LogRecordWrapper{Record: lr}
			},
			field:    policy.LogFieldEventName,
			expected: nil,
		},
		{
			name: "unknown field",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				lr.Body().SetStr("test")
				return &LogRecordWrapper{Record: lr}
			},
			field:    policy.LogField(999),
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper := tt.setup()
			result := wrapper.GetField(tt.field)

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

func TestLogRecordWrapper_GetAttribute(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() *LogRecordWrapper
		scope    policy.AttrScope
		path     []string
		expected []byte
	}{
		{
			name: "resource attribute simple",
			setup: func() *LogRecordWrapper {
				resource := pcommon.NewResource()
				resource.Attributes().PutStr("service.name", "my-service")
				return &LogRecordWrapper{Resource: resource}
			},
			scope:    policy.AttrScopeResource,
			path:     []string{"service.name"},
			expected: []byte("my-service"),
		},
		{
			name: "scope attribute simple",
			setup: func() *LogRecordWrapper {
				scope := pcommon.NewInstrumentationScope()
				scope.Attributes().PutStr("library.version", "1.0.0")
				return &LogRecordWrapper{Scope: scope}
			},
			scope:    policy.AttrScopeScope,
			path:     []string{"library.version"},
			expected: []byte("1.0.0"),
		},
		{
			name: "record attribute simple",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				lr.Attributes().PutStr("user.id", "12345")
				return &LogRecordWrapper{Record: lr}
			},
			scope:    policy.AttrScopeRecord,
			path:     []string{"user.id"},
			expected: []byte("12345"),
		},
		{
			name: "nested attribute two levels",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				nested := lr.Attributes().PutEmptyMap("http")
				nested.PutStr("method", "GET")
				return &LogRecordWrapper{Record: lr}
			},
			scope:    policy.AttrScopeRecord,
			path:     []string{"http", "method"},
			expected: []byte("GET"),
		},
		{
			name: "nested attribute three levels",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				http := lr.Attributes().PutEmptyMap("http")
				request := http.PutEmptyMap("request")
				request.PutStr("path", "/api/users")
				return &LogRecordWrapper{Record: lr}
			},
			scope:    policy.AttrScopeRecord,
			path:     []string{"http", "request", "path"},
			expected: []byte("/api/users"),
		},
		{
			name: "attribute not found",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				return &LogRecordWrapper{Record: lr}
			},
			scope:    policy.AttrScopeRecord,
			path:     []string{"nonexistent"},
			expected: nil,
		},
		{
			name: "nested attribute partial path not found",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				lr.Attributes().PutEmptyMap("http")
				return &LogRecordWrapper{Record: lr}
			},
			scope:    policy.AttrScopeRecord,
			path:     []string{"http", "nonexistent"},
			expected: nil,
		},
		{
			name: "nested path on non-map value",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				lr.Attributes().PutStr("http", "not-a-map")
				return &LogRecordWrapper{Record: lr}
			},
			scope:    policy.AttrScopeRecord,
			path:     []string{"http", "method"},
			expected: nil,
		},
		{
			name: "empty path",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				lr.Attributes().PutStr("key", "value")
				return &LogRecordWrapper{Record: lr}
			},
			scope:    policy.AttrScopeRecord,
			path:     []string{},
			expected: nil,
		},
		{
			name: "nil path",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				lr.Attributes().PutStr("key", "value")
				return &LogRecordWrapper{Record: lr}
			},
			scope:    policy.AttrScopeRecord,
			path:     nil,
			expected: nil,
		},
		{
			name: "unknown scope",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				lr.Attributes().PutStr("key", "value")
				return &LogRecordWrapper{Record: lr}
			},
			scope:    policy.AttrScope(999),
			path:     []string{"key"},
			expected: nil,
		},
		{
			name: "integer attribute",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				lr.Attributes().PutInt("count", 42)
				return &LogRecordWrapper{Record: lr}
			},
			scope:    policy.AttrScopeRecord,
			path:     []string{"count"},
			expected: []byte("42"),
		},
		{
			name: "boolean attribute true",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				lr.Attributes().PutBool("enabled", true)
				return &LogRecordWrapper{Record: lr}
			},
			scope:    policy.AttrScopeRecord,
			path:     []string{"enabled"},
			expected: []byte("true"),
		},
		{
			name: "boolean attribute false",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				lr.Attributes().PutBool("enabled", false)
				return &LogRecordWrapper{Record: lr}
			},
			scope:    policy.AttrScopeRecord,
			path:     []string{"enabled"},
			expected: []byte("false"),
		},
		{
			name: "double attribute",
			setup: func() *LogRecordWrapper {
				lr := plog.NewLogRecord()
				lr.Attributes().PutDouble("rate", 3.14)
				return &LogRecordWrapper{Record: lr}
			},
			scope:    policy.AttrScopeRecord,
			path:     []string{"rate"},
			expected: []byte("3.14"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper := tt.setup()
			result := wrapper.GetAttribute(tt.scope, tt.path)

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
