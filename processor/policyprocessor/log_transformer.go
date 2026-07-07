package policyprocessor

import (
	"github.com/usetero/policy-go/policy"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

// LogOptions returns the full set of options needed for policy.EvaluateLog
// to drive both matching and transforms on a LogContext.
func LogOptions() []policy.LogOption[LogContext] {
	return []policy.LogOption[LogContext]{
		policy.WithLogValue(LogValue),
		policy.WithLogTypedValue(LogTypedMatcher),
		policy.WithLogExists(LogExists),
		policy.WithLogSet(LogSet),
		policy.WithLogDelete(LogDelete),
		policy.WithLogMove(LogMove),
	}
}

// LogSet writes a string value at ref, creating the field if necessary.
// Used as the WithLogSet option.
func LogSet(ctx LogContext, ref policy.LogFieldRef, value string) {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			ctx.Record.Body().SetStr(value)
		case policy.LogFieldSeverityText:
			ctx.Record.SetSeverityText(value)
		case policy.LogFieldTraceID:
			var tid pcommon.TraceID
			copy(tid[:], value)
			ctx.Record.SetTraceID(tid)
		case policy.LogFieldSpanID:
			var sid pcommon.SpanID
			copy(sid[:], value)
			ctx.Record.SetSpanID(sid)
		case policy.LogFieldEventName:
			ctx.Record.SetEventName(value)
		}
		return
	}

	attrs, ok := logAttrs(ctx, ref)
	if !ok {
		return
	}
	putNestedAttr(attrs, ref.AttrPath, value)
}

// LogDelete removes the field at ref. Returns true if it existed.
// Used as the WithLogDelete option.
func LogDelete(ctx LogContext, ref policy.LogFieldRef) bool {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			hit := ctx.Record.Body().Type() != pcommon.ValueTypeEmpty
			ctx.Record.Body().SetStr("")
			return hit
		case policy.LogFieldSeverityText:
			hit := ctx.Record.SeverityText() != ""
			ctx.Record.SetSeverityText("")
			return hit
		case policy.LogFieldTraceID:
			hit := !ctx.Record.TraceID().IsEmpty()
			ctx.Record.SetTraceID(pcommon.TraceID{})
			return hit
		case policy.LogFieldSpanID:
			hit := !ctx.Record.SpanID().IsEmpty()
			ctx.Record.SetSpanID(pcommon.SpanID{})
			return hit
		case policy.LogFieldEventName:
			hit := ctx.Record.EventName() != ""
			ctx.Record.SetEventName("")
			return hit
		}
		return false
	}

	attrs, ok := logAttrs(ctx, ref)
	if !ok {
		return false
	}
	return removeNestedAttr(attrs, ref.AttrPath)
}

// LogMove transfers the value at from to to, deleting from.
// Used as the WithLogMove option.
func LogMove(ctx LogContext, from, to policy.LogFieldRef) {
	if from.IsField() {
		return
	}
	attrs, ok := logAttrs(ctx, from)
	if !ok {
		return
	}
	val, exists := getNestedAttr(attrs, from.AttrPath)
	if !exists {
		return
	}
	removeNestedAttr(attrs, from.AttrPath)

	toAttrs, ok := logAttrs(ctx, to)
	if !ok {
		return
	}
	putNestedAttr(toAttrs, to.AttrPath, val)
}

// logAttrs returns the attribute map for the given field ref scope.
// Returns the map by value (pcommon.Map is a lightweight handle) to avoid heap allocation.
func logAttrs(ctx LogContext, ref policy.LogFieldRef) (pcommon.Map, bool) {
	switch {
	case ref.IsRecordAttr():
		return ctx.Record.Attributes(), true
	case ref.IsResourceAttr():
		return ctx.Resource.Attributes(), true
	case ref.IsScopeAttr():
		return ctx.Scope.Attributes(), true
	default:
		return pcommon.Map{}, false
	}
}
