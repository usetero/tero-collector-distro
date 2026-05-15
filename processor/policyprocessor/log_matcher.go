package policyprocessor

import (
	"encoding/hex"

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
// Used as the WithLogValue option for policy.EvaluateLog.
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
			return []byte(hex.EncodeToString(traceID[:]))
		case policy.LogFieldSpanID:
			spanID := ctx.Record.SpanID()
			if spanID.IsEmpty() {
				return nil
			}
			return []byte(hex.EncodeToString(spanID[:]))
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

// LogExists reports whether the referenced field or attribute is set on the
// log record. Used as the WithLogExists option for policy.EvaluateLog.
func LogExists(ctx LogContext, ref policy.LogFieldRef) bool {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			// An empty-string body is treated as missing, matching the spec rule
			// for log_field accessors: body_exists ⇔ body is set AND not the
			// empty string. Non-string body values (int, bool, map, ...) are
			// still "present" — only their textual value is invisible to matchers.
			body := ctx.Record.Body()
			if body.Type() == pcommon.ValueTypeEmpty {
				return false
			}
			if body.Type() == pcommon.ValueTypeStr && body.Str() == "" {
				return false
			}
			return true
		case policy.LogFieldSeverityText:
			return ctx.Record.SeverityText() != ""
		case policy.LogFieldTraceID:
			return !ctx.Record.TraceID().IsEmpty()
		case policy.LogFieldSpanID:
			return !ctx.Record.SpanID().IsEmpty()
		case policy.LogFieldEventName:
			return ctx.Record.EventName() != ""
		case policy.LogFieldResourceSchemaURL:
			return ctx.ResourceSchemaURL != ""
		case policy.LogFieldScopeSchemaURL:
			return ctx.ScopeSchemaURL != ""
		default:
			return false
		}
	}

	attrs, ok := logAttrs(ctx, ref)
	if !ok {
		return false
	}
	return pathExists(attrs, ref.AttrPath)
}
