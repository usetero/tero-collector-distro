package policyprocessor

import (
	"encoding/hex"

	"github.com/usetero/policy-go"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

// Verify interface compliance at compile time.
var _ policy.LogMatchable = (*LogRecordWrapper)(nil)

// LogRecordWrapper wraps plog types to implement policy.LogMatchable.
type LogRecordWrapper struct {
	Record   plog.LogRecord
	Resource pcommon.Resource
	Scope    pcommon.InstrumentationScope
}

// GetField implements policy.LogMatchable.
func (w *LogRecordWrapper) GetField(field policy.LogField) []byte {
	switch field {
	case policy.LogFieldBody:
		return valueToBytes(w.Record.Body())
	case policy.LogFieldSeverityText:
		if text := w.Record.SeverityText(); text != "" {
			return []byte(text)
		}
		return nil
	case policy.LogFieldTraceID:
		traceID := w.Record.TraceID()
		if traceID.IsEmpty() {
			return nil
		}
		buf := make([]byte, 32)
		hex.Encode(buf, traceID[:])
		return buf
	case policy.LogFieldSpanID:
		spanID := w.Record.SpanID()
		if spanID.IsEmpty() {
			return nil
		}
		buf := make([]byte, 16)
		hex.Encode(buf, spanID[:])
		return buf
	case policy.LogFieldEventName:
		if val, ok := w.Record.Attributes().Get("event.name"); ok {
			return valueToBytes(val)
		}
		return nil
	default:
		return nil
	}
}

// GetAttribute implements policy.LogMatchable.
func (w *LogRecordWrapper) GetAttribute(scope policy.AttrScope, path []string) []byte {
	if len(path) == 0 {
		return nil
	}

	var attrs pcommon.Map
	switch scope {
	case policy.AttrScopeResource:
		attrs = w.Resource.Attributes()
	case policy.AttrScopeScope:
		attrs = w.Scope.Attributes()
	case policy.AttrScopeRecord:
		attrs = w.Record.Attributes()
	default:
		return nil
	}

	return traversePath(attrs, path)
}

func traversePath(attrs pcommon.Map, path []string) []byte {
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
