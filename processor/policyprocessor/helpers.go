package policyprocessor

import (
	"strings"

	"github.com/usetero/policy-go/policy"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

func traversePath(attrs pcommon.Map, path []string) []byte {
	if result := traversePathRec(attrs, path); result != nil {
		return result
	}
	if result, ok := attrs.Get(strings.Join(path, ".")); ok {
		return valueToBytes(result)
	}
	return nil
}

// pathExists reports whether the attribute path is present in attrs.
// Matches the lookup behavior of traversePath: tries the nested path first,
// then the flattened dotted key.
func pathExists(attrs pcommon.Map, path []string) bool {
	if pathExistsRec(attrs, path) {
		return true
	}
	_, ok := attrs.Get(strings.Join(path, "."))
	return ok
}

func pathExistsRec(attrs pcommon.Map, path []string) bool {
	if len(path) == 0 {
		return false
	}
	val, ok := attrs.Get(path[0])
	if !ok {
		return false
	}
	if len(path) == 1 {
		return true
	}
	if val.Type() != pcommon.ValueTypeMap {
		return false
	}
	return pathExistsRec(val.Map(), path[1:])
}

func traversePathRec(attrs pcommon.Map, path []string) []byte {
	if len(path) == 0 {
		return nil
	}

	val, ok := attrs.Get(path[0])
	if !ok {
		return nil
	}

	if len(path) == 1 {
		return valueToBytes(val)
	}

	if val.Type() != pcommon.ValueTypeMap {
		return nil
	}

	return traversePathRec(val.Map(), path[1:])
}

// getNestedAttr retrieves a string value at a nested attribute path.
func getNestedAttr(attrs pcommon.Map, path []string) (string, bool) {
	if len(path) == 0 {
		return "", false
	}

	val, ok := attrs.Get(path[0])
	if !ok {
		return "", false
	}

	if len(path) == 1 {
		return val.AsString(), true
	}

	if val.Type() != pcommon.ValueTypeMap {
		return "", false
	}
	return getNestedAttr(val.Map(), path[1:])
}

// removeNestedAttr removes an attribute at a nested path. Returns true if it existed.
func removeNestedAttr(attrs pcommon.Map, path []string) bool {
	if len(path) == 0 {
		return false
	}

	if len(path) == 1 {
		var exists bool
		attrs.RemoveIf(func(key string, _ pcommon.Value) bool {
			if key == path[0] {
				exists = true
				return true
			}
			return false
		})
		return exists
	}

	val, ok := attrs.Get(path[0])
	if !ok || val.Type() != pcommon.ValueTypeMap {
		return false
	}
	return removeNestedAttr(val.Map(), path[1:])
}

// setNestedAttr sets a string value at a nested path. Returns true if the path existed before.
func setNestedAttr(attrs pcommon.Map, path []string, value string) bool {
	if len(path) == 0 {
		return false
	}

	if len(path) == 1 {
		_, exists := attrs.Get(path[0])
		attrs.PutStr(path[0], value)
		return exists
	}

	val, ok := attrs.Get(path[0])
	if !ok || val.Type() != pcommon.ValueTypeMap {
		return false
	}
	return setNestedAttr(val.Map(), path[1:], value)
}

// putNestedAttr sets a string value at a nested path, creating intermediate maps if needed.
func putNestedAttr(attrs pcommon.Map, path []string, value string) {
	if len(path) == 0 {
		return
	}

	if len(path) == 1 {
		attrs.PutStr(path[0], value)
		return
	}

	val, ok := attrs.Get(path[0])
	if !ok || val.Type() != pcommon.ValueTypeMap {
		putNestedAttr(attrs.PutEmptyMap(path[0]), path[1:], value)
		return
	}
	putNestedAttr(val.Map(), path[1:], value)
}

func valueToBytes(val pcommon.Value) []byte {
	if val.Type() != pcommon.ValueTypeStr {
		return nil
	}
	s := val.Str()
	if s == "" {
		return nil
	}
	return []byte(s)
}

func traversePathTyped(attrs pcommon.Map, path []string) policy.TypedValue {
	if result := traversePathRecTyped(attrs, path); result.Kind != policy.TypedValueAbsent {
		return result
	}
	if result, ok := attrs.Get(strings.Join(path, ".")); ok {
		return valueToTypedValue(result)
	}
	return policy.TypedValue{}
}

func traversePathRecTyped(attrs pcommon.Map, path []string) policy.TypedValue {
	if len(path) == 0 {
		return policy.TypedValue{}
	}

	val, ok := attrs.Get(path[0])
	if !ok {
		return policy.TypedValue{}
	}

	if len(path) == 1 {
		return valueToTypedValue(val)
	}

	if val.Type() != pcommon.ValueTypeMap {
		return policy.TypedValue{}
	}

	return traversePathRecTyped(val.Map(), path[1:])
}

func valueToTypedValue(val pcommon.Value) policy.TypedValue {
	switch val.Type() {
	case pcommon.ValueTypeStr:
		return policy.TypedValueOfString(val.Str())
	case pcommon.ValueTypeInt:
		return policy.TypedValueOfInt(val.Int())
	case pcommon.ValueTypeDouble:
		return policy.TypedValueOfDouble(val.Double())
	case pcommon.ValueTypeBool:
		return policy.TypedValueOfBool(val.Bool())
	case pcommon.ValueTypeBytes:
		return policy.TypedValueOfBytes(val.Bytes().AsRaw())
	default:
		return policy.TypedValue{}
	}
}
