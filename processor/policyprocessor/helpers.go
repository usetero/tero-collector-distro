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
