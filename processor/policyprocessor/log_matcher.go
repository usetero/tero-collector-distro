package policyprocessor

import (
	"github.com/usetero/policy-go"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

// LogContext holds the context needed to evaluate a log record against policies.
type LogContext struct {
	Record            plog.LogRecord
	Resource          pcommon.Resource
	Scope             pcommon.InstrumentationScope
	ResourceSchemaURL string
	ScopeSchemaURL    string
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
			return traceID[:]
		case policy.LogFieldSpanID:
			spanID := ctx.Record.SpanID()
			if spanID.IsEmpty() {
				return nil
			}
			return spanID[:]
		case policy.LogFieldEventName:
			if name := ctx.Record.EventName(); name != "" {
				return []byte(name)
			}
			return nil
		case policy.LogFieldResourceSchemaURL:
			if ctx.ResourceSchemaURL == "" {
				return nil
			}
			return []byte(ctx.ResourceSchemaURL)
		case policy.LogFieldScopeSchemaURL:
			if ctx.ScopeSchemaURL == "" {
				return nil
			}
			return []byte(ctx.ScopeSchemaURL)
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
