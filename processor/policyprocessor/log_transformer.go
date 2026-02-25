package policyprocessor

import (
	"github.com/usetero/policy-go"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

// LogTransformer applies a single transform operation to a log record.
// It implements policy.LogTransformFunc[LogContext].
// Returns true if the targeted field was present (hit), false if absent (miss).
func LogTransformer(ctx LogContext, op policy.TransformOp) bool {
	switch op.Kind {
	case policy.TransformRemove:
		return logRemove(ctx, op.Ref)
	case policy.TransformRedact:
		return logRedact(ctx, op.Ref, op.Value)
	case policy.TransformRename:
		return logRename(ctx, op.Ref, op.To, op.Upsert)
	case policy.TransformAdd:
		return logAdd(ctx, op.Ref, op.Value, op.Upsert)
	}
	return false
}

func logRemove(ctx LogContext, ref policy.LogFieldRef) bool {
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
	_, exists := attrs.Get(ref.AttrPath[0])
	if !exists {
		return false
	}
	if len(ref.AttrPath) == 1 {
		attrs.Remove(ref.AttrPath[0])
		return true
	}
	return removeNestedAttr(attrs, ref.AttrPath)
}

func logRedact(ctx LogContext, ref policy.LogFieldRef, replacement string) bool {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			hit := ctx.Record.Body().Type() != pcommon.ValueTypeEmpty
			ctx.Record.Body().SetStr(replacement)
			return hit
		case policy.LogFieldSeverityText:
			hit := ctx.Record.SeverityText() != ""
			ctx.Record.SetSeverityText(replacement)
			return hit
		case policy.LogFieldTraceID:
			hit := !ctx.Record.TraceID().IsEmpty()
			var tid pcommon.TraceID
			copy(tid[:], replacement)
			ctx.Record.SetTraceID(tid)
			return hit
		case policy.LogFieldSpanID:
			hit := !ctx.Record.SpanID().IsEmpty()
			var sid pcommon.SpanID
			copy(sid[:], replacement)
			ctx.Record.SetSpanID(sid)
			return hit
		case policy.LogFieldEventName:
			hit := ctx.Record.EventName() != ""
			ctx.Record.SetEventName(replacement)
			return hit
		}
		return false
	}

	attrs, ok := logAttrs(ctx, ref)
	if !ok {
		return false
	}
	// Only redact if the attribute exists; redacting a non-existent attribute is a no-op.
	if _, exists := getNestedAttr(attrs, ref.AttrPath); !exists {
		return false
	}
	return setNestedAttr(attrs, ref.AttrPath, replacement)
}

func logRename(ctx LogContext, ref policy.LogFieldRef, to string, upsert bool) bool {
	if ref.IsField() {
		return false
	}

	attrs, ok := logAttrs(ctx, ref)
	if !ok {
		return false
	}

	val, exists := getNestedAttr(attrs, ref.AttrPath)
	if !exists {
		return false
	}

	if !upsert {
		if _, found := attrs.Get(to); found {
			return true
		}
	}

	removeNestedAttr(attrs, ref.AttrPath)
	attrs.PutStr(to, val)
	return true
}

func logAdd(ctx LogContext, ref policy.LogFieldRef, value string, upsert bool) bool {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			if !upsert && ctx.Record.Body().Type() != pcommon.ValueTypeEmpty {
				return true
			}
			ctx.Record.Body().SetStr(value)
			return true
		case policy.LogFieldSeverityText:
			if !upsert && ctx.Record.SeverityText() != "" {
				return true
			}
			ctx.Record.SetSeverityText(value)
			return true
		case policy.LogFieldTraceID:
			if !upsert && !ctx.Record.TraceID().IsEmpty() {
				return true
			}
			var tid pcommon.TraceID
			copy(tid[:], value)
			ctx.Record.SetTraceID(tid)
			return true
		case policy.LogFieldSpanID:
			if !upsert && !ctx.Record.SpanID().IsEmpty() {
				return true
			}
			var sid pcommon.SpanID
			copy(sid[:], value)
			ctx.Record.SetSpanID(sid)
			return true
		case policy.LogFieldEventName:
			if !upsert && ctx.Record.EventName() != "" {
				return true
			}
			ctx.Record.SetEventName(value)
			return true
		}
		return false
	}

	attrs, ok := logAttrs(ctx, ref)
	if !ok {
		return false
	}

	if !upsert {
		if _, exists := getNestedAttr(attrs, ref.AttrPath); exists {
			return true
		}
	}

	putNestedAttr(attrs, ref.AttrPath, value)
	return true
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
