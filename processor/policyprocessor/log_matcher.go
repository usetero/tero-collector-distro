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

// LogValue extracts string-typed field values as bytes for regex/substring/redact matching.
// Returns nil for absent fields and for non-textual types (int, bool, map, etc.).
// Used as the WithLogValue option for policy.EvaluateLog.
func LogValue(ctx LogContext, ref policy.LogFieldRef) []byte {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			body := ctx.Record.Body()
			if body.Type() != pcommon.ValueTypeStr {
				return nil
			}
			s := body.Str()
			if s == "" {
				return nil
			}
			return []byte(s)
		case policy.LogFieldSeverityText:
			s := ctx.Record.SeverityText()
			if s == "" {
				return nil
			}
			return []byte(s)
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
			s := ctx.Record.EventName()
			if s == "" {
				return nil
			}
			return []byte(s)
		case policy.LogFieldResourceSchemaURL:
			s := ctx.ResourceSchemaURL
			if s == "" {
				return nil
			}
			return []byte(s)
		case policy.LogFieldScopeSchemaURL:
			s := ctx.ScopeSchemaURL
			if s == "" {
				return nil
			}
			return []byte(s)
		default:
			return nil
		}
	}

	attrs, ok := logAttrs(ctx, ref)
	if !ok {
		return nil
	}
	return traversePath(attrs, ref.AttrPath)
}

// LogTypedMatcher extracts field values from a LogContext for typed comparison (equals/gt/gte/lt/lte).
// Returns TypedValue{} (absent) for missing fields or non-textual body types.
// Used as the WithLogTypedValue option for policy.EvaluateLog.
func LogTypedMatcher(ctx LogContext, ref policy.LogFieldRef) policy.TypedValue {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			body := ctx.Record.Body()
			if body.Type() != pcommon.ValueTypeStr || body.Str() == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(body.Str())
		case policy.LogFieldSeverityText:
			s := ctx.Record.SeverityText()
			if s == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(s)
		case policy.LogFieldTraceID:
			traceID := ctx.Record.TraceID()
			if traceID.IsEmpty() {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfBytes(traceID[:])
		case policy.LogFieldSpanID:
			spanID := ctx.Record.SpanID()
			if spanID.IsEmpty() {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfBytes(spanID[:])
		case policy.LogFieldEventName:
			s := ctx.Record.EventName()
			if s == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(s)
		case policy.LogFieldResourceSchemaURL:
			s := ctx.ResourceSchemaURL
			if s == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(s)
		case policy.LogFieldScopeSchemaURL:
			s := ctx.ScopeSchemaURL
			if s == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(s)
		default:
			return policy.TypedValue{}
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
		return policy.TypedValue{}
	}

	return traversePathTyped(attrs, ref.AttrPath)
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
