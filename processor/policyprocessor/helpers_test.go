package policyprocessor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/usetero/policy-go/policy"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

// TestTraversePathTyped covers attribute lookup: nested-map traversal, the
// flattened dotted-key fallback, precedence between the two, and the typed
// value produced at the leaf. Since policy-go v1.11.0 the TypedValue accessor
// is the single field-read primitive, so non-string leaves resolve to their
// native typed value rather than being invisible.
func TestTraversePathTyped(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(pcommon.Map)
		path     []string
		expected policy.TypedValue
	}{
		{
			name:     "empty path is absent",
			setup:    func(_ pcommon.Map) {},
			path:     []string{},
			expected: policy.TypedValue{},
		},
		{
			name:     "nil path is absent",
			setup:    func(_ pcommon.Map) {},
			path:     nil,
			expected: policy.TypedValue{},
		},
		{
			name: "single key string match at top level",
			setup: func(m pcommon.Map) {
				m.PutStr("foo", "bar")
			},
			path:     []string{"foo"},
			expected: policy.TypedValueOfString("bar"),
		},
		{
			name: "single key not found is absent",
			setup: func(m pcommon.Map) {
				m.PutStr("other", "value")
			},
			path:     []string{"missing"},
			expected: policy.TypedValue{},
		},
		{
			name: "single key with dot in name found directly",
			setup: func(m pcommon.Map) {
				m.PutStr("k8s.pod.name", "my-pod")
			},
			path:     []string{"k8s.pod.name"},
			expected: policy.TypedValueOfString("my-pod"),
		},
		{
			name: "two level nested map found",
			setup: func(m pcommon.Map) {
				inner := m.PutEmptyMap("a")
				inner.PutStr("b", "nested-value")
			},
			path:     []string{"a", "b"},
			expected: policy.TypedValueOfString("nested-value"),
		},
		{
			name: "three level nested map found",
			setup: func(m pcommon.Map) {
				lvl1 := m.PutEmptyMap("a")
				lvl2 := lvl1.PutEmptyMap("b")
				lvl2.PutStr("c", "deep-value")
			},
			path:     []string{"a", "b", "c"},
			expected: policy.TypedValueOfString("deep-value"),
		},
		{
			name: "fallback to joined dotted key when nested path does not exist",
			setup: func(m pcommon.Map) {
				m.PutStr("k8s.pod.name", "my-pod")
			},
			path:     []string{"k8s", "pod", "name"},
			expected: policy.TypedValueOfString("my-pod"),
		},
		{
			name: "fallback when first segment does not exist as key",
			setup: func(m pcommon.Map) {
				m.PutStr("service.name", "auth-service")
			},
			path:     []string{"service", "name"},
			expected: policy.TypedValueOfString("auth-service"),
		},
		{
			name: "nested traversal takes precedence over dotted key fallback",
			setup: func(m pcommon.Map) {
				inner := m.PutEmptyMap("a")
				inner.PutStr("b", "from-nested")
				m.PutStr("a.b", "from-dotted")
			},
			path:     []string{"a", "b"},
			expected: policy.TypedValueOfString("from-nested"),
		},
		{
			name: "first key exists but is not a map, falls back to dotted key",
			setup: func(m pcommon.Map) {
				m.PutStr("a", "scalar")
				m.PutStr("a.b", "from-dotted")
			},
			path:     []string{"a", "b"},
			expected: policy.TypedValueOfString("from-dotted"),
		},
		{
			name: "first key exists but is not a map and no dotted fallback is absent",
			setup: func(m pcommon.Map) {
				m.PutStr("a", "scalar")
			},
			path:     []string{"a", "b"},
			expected: policy.TypedValue{},
		},
		{
			name: "intermediate key exists as map but inner key missing is absent",
			setup: func(m pcommon.Map) {
				inner := m.PutEmptyMap("a")
				inner.PutStr("other", "value")
			},
			path:     []string{"a", "b"},
			expected: policy.TypedValue{},
		},
		{
			name: "intermediate key exists as map, inner key missing, dotted fallback wins",
			setup: func(m pcommon.Map) {
				inner := m.PutEmptyMap("a")
				inner.PutStr("other", "value")
				m.PutStr("a.b", "fallback-value")
			},
			path:     []string{"a", "b"},
			expected: policy.TypedValueOfString("fallback-value"),
		},
		{
			name: "intermediate non-map at depth 2 with dotted fallback",
			setup: func(m pcommon.Map) {
				inner := m.PutEmptyMap("a")
				inner.PutStr("b", "scalar-not-map")
				m.PutStr("a.b.c", "fallback-value")
			},
			path:     []string{"a", "b", "c"},
			expected: policy.TypedValueOfString("fallback-value"),
		},
		{
			name: "intermediate non-map at depth 2 without fallback is absent",
			setup: func(m pcommon.Map) {
				inner := m.PutEmptyMap("a")
				inner.PutStr("b", "scalar-not-map")
			},
			path:     []string{"a", "b", "c"},
			expected: policy.TypedValue{},
		},
		{
			name:     "completely empty attributes is absent",
			setup:    func(_ pcommon.Map) {},
			path:     []string{"any", "path"},
			expected: policy.TypedValue{},
		},
		{
			name: "int value at leaf resolves as typed int",
			setup: func(m pcommon.Map) {
				m.PutInt("count", 42)
			},
			path:     []string{"count"},
			expected: policy.TypedValueOfInt(42),
		},
		{
			name: "int value via dotted fallback resolves as typed int",
			setup: func(m pcommon.Map) {
				m.PutInt("a.b", 100)
			},
			path:     []string{"a", "b"},
			expected: policy.TypedValueOfInt(100),
		},
		{
			name: "double value at leaf resolves as typed double",
			setup: func(m pcommon.Map) {
				m.PutDouble("ratio", 3.14)
			},
			path:     []string{"ratio"},
			expected: policy.TypedValueOfDouble(3.14),
		},
		{
			name: "bool true value resolves as typed bool",
			setup: func(m pcommon.Map) {
				m.PutBool("enabled", true)
			},
			path:     []string{"enabled"},
			expected: policy.TypedValueOfBool(true),
		},
		{
			name: "bool false value resolves as typed bool",
			setup: func(m pcommon.Map) {
				m.PutBool("enabled", false)
			},
			path:     []string{"enabled"},
			expected: policy.TypedValueOfBool(false),
		},
		{
			name: "bytes value resolves as typed bytes",
			setup: func(m pcommon.Map) {
				m.PutEmptyBytes("payload").FromRaw([]byte{0x01, 0x02, 0x03})
			},
			path:     []string{"payload"},
			expected: policy.TypedValueOfBytes([]byte{0x01, 0x02, 0x03}),
		},
		{
			// An attribute holding the empty string is present with an empty
			// value — unlike log_field accessors, where empty means absent.
			name: "empty string value is a present empty string",
			setup: func(m pcommon.Map) {
				m.PutStr("foo", "")
			},
			path:     []string{"foo"},
			expected: policy.TypedValueOfString(""),
		},
		{
			name: "empty string via dotted fallback is a present empty string",
			setup: func(m pcommon.Map) {
				m.PutStr("a.b", "")
			},
			path:     []string{"a", "b"},
			expected: policy.TypedValueOfString(""),
		},
		{
			// The nested hit wins even though it is empty; the dotted key is
			// only consulted when the nested path resolves to nothing at all.
			name: "nested empty string at leaf wins over dotted fallback",
			setup: func(m pcommon.Map) {
				inner := m.PutEmptyMap("a")
				inner.PutStr("b", "")
				m.PutStr("a.b", "fallback")
			},
			path:     []string{"a", "b"},
			expected: policy.TypedValueOfString(""),
		},
		{
			name: "map value at leaf is absent",
			setup: func(m pcommon.Map) {
				inner := m.PutEmptyMap("obj")
				inner.PutStr("k", "v")
			},
			path:     []string{"obj"},
			expected: policy.TypedValue{},
		},
		{
			name: "slice value at leaf is absent",
			setup: func(m pcommon.Map) {
				s := m.PutEmptySlice("list")
				s.AppendEmpty().SetStr("a")
				s.AppendEmpty().SetStr("b")
			},
			path:     []string{"list"},
			expected: policy.TypedValue{},
		},
		{
			name: "single segment path matching a key with multiple dots",
			setup: func(m pcommon.Map) {
				m.PutStr("a.b.c.d", "deep-flat")
			},
			path:     []string{"a.b.c.d"},
			expected: policy.TypedValueOfString("deep-flat"),
		},
		{
			name: "fallback with four-segment path joined",
			setup: func(m pcommon.Map) {
				m.PutStr("a.b.c.d", "deep-flat")
			},
			path:     []string{"a", "b", "c", "d"},
			expected: policy.TypedValueOfString("deep-flat"),
		},
		{
			name: "partial nesting plus dotted suffix is not supported and is absent",
			setup: func(m pcommon.Map) {
				inner := m.PutEmptyMap("a")
				inner.PutStr("b.c", "partial")
			},
			path:     []string{"a", "b", "c"},
			expected: policy.TypedValue{},
		},
		{
			name: "dotted key with empty intermediate map present, fallback wins",
			setup: func(m pcommon.Map) {
				m.PutEmptyMap("a")
				m.PutStr("a.b", "fallback")
			},
			path:     []string{"a", "b"},
			expected: policy.TypedValueOfString("fallback"),
		},
		{
			name: "deeply nested int at leaf resolves as typed int",
			setup: func(m pcommon.Map) {
				lvl1 := m.PutEmptyMap("metrics")
				lvl2 := lvl1.PutEmptyMap("counters")
				lvl2.PutInt("requests", 1234)
			},
			path:     []string{"metrics", "counters", "requests"},
			expected: policy.TypedValueOfInt(1234),
		},
		{
			name: "deeply nested bool at leaf resolves as typed bool",
			setup: func(m pcommon.Map) {
				lvl1 := m.PutEmptyMap("flags")
				lvl1.PutBool("on", true)
			},
			path:     []string{"flags", "on"},
			expected: policy.TypedValueOfBool(true),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := pcommon.NewMap()
			tt.setup(attrs)
			got := traversePathTyped(attrs, tt.path)
			assert.Equal(t, tt.expected, got)
		})
	}
}
