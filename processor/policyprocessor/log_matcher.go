package policyprocessor

import (
	"encoding/hex"

	"github.com/usetero/policy-go"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

// LogContext holds the context needed to evaluate a log record against policies.
type LogContext struct {
	Record   plog.LogRecord
	Resource pcommon.Resource
	Scope    pcommon.InstrumentationScope
}

// LogMatcher extracts field values from a LogContext for policy evaluation.
// This implements policy.LogMatchFunc[LogContext].
func LogMatcher(ctx LogContext, ref policy.LogFieldRef) []byte {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			return valueToBytes(ctx.Record.Body())
		case policy.LogFieldSeverityText:
			if text := ctx.Record.SeverityText(); text != "" {
				return []byte(text)
			}
			return nil
		case policy.LogFieldTraceID:
			traceID := ctx.Record.TraceID()
			if traceID.IsEmpty() {
				return nil
			}
			buf := make([]byte, 32)
			hex.Encode(buf, traceID[:])
			return buf
		case policy.LogFieldSpanID:
			spanID := ctx.Record.SpanID()
			if spanID.IsEmpty() {
				return nil
			}
			buf := make([]byte, 16)
			hex.Encode(buf, spanID[:])
			return buf
		case policy.LogFieldEventName:
			if name := ctx.Record.EventName(); name != "" {
				return []byte(name)
			}
			return nil
		default:
			return nil
		}
	}

	// Attribute lookup
	var attrs pcommon.Map
	switch {
	case ref.IsResourceAttr():
		attrs = ctx.Resource.Attributes()
	case ref.IsScopeAttr():
		attrs = ctx.Scope.Attributes()
	case ref.IsRecordAttr():
		attrs = ctx.Record.Attributes()
	default:
		return nil
	}

	return traversePath(attrs, ref.AttrPath)
}
