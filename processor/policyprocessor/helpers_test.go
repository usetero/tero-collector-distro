package policyprocessor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

func TestTraversePath(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(pcommon.Map)
		path     []string
		expected []byte
	}{
		{
			name:     "empty path returns nil",
			setup:    func(_ pcommon.Map) {},
			path:     []string{},
			expected: nil,
		},
		{
			name:     "nil path returns nil",
			setup:    func(_ pcommon.Map) {},
			path:     nil,
			expected: nil,
		},
		{
			name: "single key string match at top level",
			setup: func(m pcommon.Map) {
				m.PutStr("foo", "bar")
			},
			path:     []string{"foo"},
			expected: []byte("bar"),
		},
		{
			name: "single key not found returns nil",
			setup: func(m pcommon.Map) {
				m.PutStr("other", "value")
			},
			path:     []string{"missing"},
			expected: nil,
		},
		{
			name: "single key with dot in name found directly",
			setup: func(m pcommon.Map) {
				m.PutStr("k8s.pod.name", "my-pod")
			},
			path:     []string{"k8s.pod.name"},
			expected: []byte("my-pod"),
		},
		{
			name: "two level nested map found",
			setup: func(m pcommon.Map) {
				inner := m.PutEmptyMap("a")
				inner.PutStr("b", "nested-value")
			},
			path:     []string{"a", "b"},
			expected: []byte("nested-value"),
		},
		{
			name: "three level nested map found",
			setup: func(m pcommon.Map) {
				lvl1 := m.PutEmptyMap("a")
				lvl2 := lvl1.PutEmptyMap("b")
				lvl2.PutStr("c", "deep-value")
			},
			path:     []string{"a", "b", "c"},
			expected: []byte("deep-value"),
		},
		{
			name: "fallback to joined dotted key when nested path does not exist",
			setup: func(m pcommon.Map) {
				m.PutStr("k8s.pod.name", "my-pod")
			},
			path:     []string{"k8s", "pod", "name"},
			expected: []byte("my-pod"),
		},
		{
			name: "fallback when first segment does not exist as key",
			setup: func(m pcommon.Map) {
				m.PutStr("service.name", "auth-service")
			},
			path:     []string{"service", "name"},
			expected: []byte("auth-service"),
		},
		{
			name: "nested traversal takes precedence over dotted key fallback",
			setup: func(m pcommon.Map) {
				inner := m.PutEmptyMap("a")
				inner.PutStr("b", "from-nested")
				m.PutStr("a.b", "from-dotted")
			},
			path:     []string{"a", "b"},
			expected: []byte("from-nested"),
		},
		{
			name: "first key exists but is not a map, falls back to dotted key",
			setup: func(m pcommon.Map) {
				m.PutStr("a", "scalar")
				m.PutStr("a.b", "from-dotted")
			},
			path:     []string{"a", "b"},
			expected: []byte("from-dotted"),
		},
		{
			name: "first key exists but is not a map and no dotted fallback returns nil",
			setup: func(m pcommon.Map) {
				m.PutStr("a", "scalar")
			},
			path:     []string{"a", "b"},
			expected: nil,
		},
		{
			name: "intermediate key exists as map but inner key missing returns nil",
			setup: func(m pcommon.Map) {
				inner := m.PutEmptyMap("a")
				inner.PutStr("other", "value")
			},
			path:     []string{"a", "b"},
			expected: nil,
		},
		{
			name: "intermediate key exists as map, inner key missing, dotted fallback wins",
			setup: func(m pcommon.Map) {
				inner := m.PutEmptyMap("a")
				inner.PutStr("other", "value")
				m.PutStr("a.b", "fallback-value")
			},
			path:     []string{"a", "b"},
			expected: []byte("fallback-value"),
		},
		{
			name: "intermediate non-map at depth 2 with dotted fallback",
			setup: func(m pcommon.Map) {
				inner := m.PutEmptyMap("a")
				inner.PutStr("b", "scalar-not-map")
				m.PutStr("a.b.c", "fallback-value")
			},
			path:     []string{"a", "b", "c"},
			expected: []byte("fallback-value"),
		},
		{
			name: "intermediate non-map at depth 2 without fallback returns nil",
			setup: func(m pcommon.Map) {
				inner := m.PutEmptyMap("a")
				inner.PutStr("b", "scalar-not-map")
			},
			path:     []string{"a", "b", "c"},
			expected: nil,
		},
		{
			name:     "completely empty attributes returns nil",
			setup:    func(_ pcommon.Map) {},
			path:     []string{"any", "path"},
			expected: nil,
		},
		{
			name: "int value at leaf",
			setup: func(m pcommon.Map) {
				m.PutInt("count", 42)
			},
			path:     []string{"count"},
			expected: []byte("42"),
		},
		{
			name: "int value via fallback",
			setup: func(m pcommon.Map) {
				m.PutInt("a.b", 100)
			},
			path:     []string{"a", "b"},
			expected: []byte("100"),
		},
		{
			name: "double value at leaf",
			setup: func(m pcommon.Map) {
				m.PutDouble("ratio", 3.14)
			},
			path:     []string{"ratio"},
			expected: []byte("3.14"),
		},
		{
			name: "bool true value",
			setup: func(m pcommon.Map) {
				m.PutBool("enabled", true)
			},
			path:     []string{"enabled"},
			expected: []byte("true"),
		},
		{
			name: "bool false value",
			setup: func(m pcommon.Map) {
				m.PutBool("enabled", false)
			},
			path:     []string{"enabled"},
			expected: []byte("false"),
		},
		{
			name: "bytes value",
			setup: func(m pcommon.Map) {
				b := m.PutEmptyBytes("payload")
				b.FromRaw([]byte{0x01, 0x02, 0x03})
			},
			path:     []string{"payload"},
			expected: []byte{0x01, 0x02, 0x03},
		},
		{
			name: "empty string value returns nil",
			setup: func(m pcommon.Map) {
				m.PutStr("foo", "")
			},
			path:     []string{"foo"},
			expected: nil,
		},
		{
			name: "empty string value via fallback also returns nil",
			setup: func(m pcommon.Map) {
				m.PutStr("a.b", "")
			},
			path:     []string{"a", "b"},
			expected: nil,
		},
		{
			name: "nested empty string at leaf returns nil",
			setup: func(m pcommon.Map) {
				inner := m.PutEmptyMap("a")
				inner.PutStr("b", "")
			},
			path:     []string{"a", "b"},
			expected: nil,
		},
		{
			name: "nested empty string at leaf falls back to dotted key",
			setup: func(m pcommon.Map) {
				inner := m.PutEmptyMap("a")
				inner.PutStr("b", "")
				m.PutStr("a.b", "fallback")
			},
			path:     []string{"a", "b"},
			expected: []byte("fallback"),
		},
		{
			name: "map value at leaf returns its string serialization",
			setup: func(m pcommon.Map) {
				inner := m.PutEmptyMap("obj")
				inner.PutStr("k", "v")
			},
			path:     []string{"obj"},
			expected: []byte(`{"k":"v"}`),
		},
		{
			name: "slice value at leaf returns its string serialization",
			setup: func(m pcommon.Map) {
				s := m.PutEmptySlice("list")
				s.AppendEmpty().SetStr("a")
				s.AppendEmpty().SetStr("b")
			},
			path:     []string{"list"},
			expected: []byte(`["a","b"]`),
		},
		{
			name: "single segment path matching a key with multiple dots",
			setup: func(m pcommon.Map) {
				m.PutStr("a.b.c.d", "deep-flat")
			},
			path:     []string{"a.b.c.d"},
			expected: []byte("deep-flat"),
		},
		{
			name: "fallback with four-segment path joined",
			setup: func(m pcommon.Map) {
				m.PutStr("a.b.c.d", "deep-flat")
			},
			path:     []string{"a", "b", "c", "d"},
			expected: []byte("deep-flat"),
		},
		{
			name: "partial nesting plus dotted suffix is not supported and returns nil",
			setup: func(m pcommon.Map) {
				inner := m.PutEmptyMap("a")
				inner.PutStr("b.c", "partial")
			},
			path:     []string{"a", "b", "c"},
			expected: nil,
		},
		{
			name: "dotted key with empty intermediate map present, fallback wins",
			setup: func(m pcommon.Map) {
				m.PutEmptyMap("a")
				m.PutStr("a.b", "fallback")
			},
			path:     []string{"a", "b"},
			expected: []byte("fallback"),
		},
		{
			name: "single segment matches integer attribute via fallback when path has one element",
			setup: func(m pcommon.Map) {
				m.PutInt("answer", 42)
			},
			path:     []string{"answer"},
			expected: []byte("42"),
		},
		{
			name: "deeply nested mixed types: int at leaf via nested traversal",
			setup: func(m pcommon.Map) {
				lvl1 := m.PutEmptyMap("metrics")
				lvl2 := lvl1.PutEmptyMap("counters")
				lvl2.PutInt("requests", 1234)
			},
			path:     []string{"metrics", "counters", "requests"},
			expected: []byte("1234"),
		},
		{
			name: "deeply nested mixed types: bool at leaf via nested traversal",
			setup: func(m pcommon.Map) {
				lvl1 := m.PutEmptyMap("flags")
				lvl1.PutBool("on", true)
			},
			path:     []string{"flags", "on"},
			expected: []byte("true"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := pcommon.NewMap()
			tt.setup(attrs)
			got := traversePath(attrs, tt.path)
			assert.Equal(t, tt.expected, got)
		})
	}
}
