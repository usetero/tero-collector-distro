package policyprocessor

import "go.opentelemetry.io/collector/pdata/pcommon"

func traversePath(attrs pcommon.Map, path []string) []byte {
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

	return traversePath(val.Map(), path[1:])
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
		_, exists := attrs.Get(path[0])
		if exists {
			attrs.Remove(path[0])
		}
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
	switch val.Type() {
	case pcommon.ValueTypeStr:
		if s := val.Str(); s != "" {
			return []byte(s)
		}
		return nil
	case pcommon.ValueTypeInt, pcommon.ValueTypeDouble:
		return []byte(val.AsString())
	case pcommon.ValueTypeBool:
		if val.Bool() {
			return []byte("true")
		}
		return []byte("false")
	case pcommon.ValueTypeBytes:
		return val.Bytes().AsRaw()
	case pcommon.ValueTypeMap, pcommon.ValueTypeSlice:
		return []byte(val.AsString())
	default:
		return nil
	}
}
