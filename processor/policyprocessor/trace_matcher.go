package policyprocessor

import (
	"github.com/usetero/policy-go"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// TraceContext holds the context needed to evaluate a span against policies.
type TraceContext struct {
	Span              ptrace.Span
	Resource          pcommon.Resource
	Scope             pcommon.InstrumentationScope
	ResourceSchemaURL string
	ScopeSchemaURL    string
}

// TraceValue extracts string-typed field values as bytes for regex/substring/redact matching.
// Returns nil for absent fields and for non-textual types.
// Used as the WithTraceValue option for policy.EvaluateTrace.
func TraceValue(ctx TraceContext, ref policy.TraceFieldRef) []byte {
	if ref.IsField() {
		switch ref.Field {
		case policy.TraceFieldName:
			s := ctx.Span.Name()
			if s == "" {
				return nil
			}
			return []byte(s)
		case policy.TraceFieldTraceID:
			traceID := ctx.Span.TraceID()
			if traceID.IsEmpty() {
				return nil
			}
			return traceID[:]
		case policy.TraceFieldSpanID:
			spanID := ctx.Span.SpanID()
			if spanID.IsEmpty() {
				return nil
			}
			return spanID[:]
		case policy.TraceFieldParentSpanID:
			parentSpanID := ctx.Span.ParentSpanID()
			if parentSpanID.IsEmpty() {
				return nil
			}
			return parentSpanID[:]
		case policy.TraceFieldTraceState:
			s := ctx.Span.TraceState().AsRaw()
			if s == "" {
				return nil
			}
			return []byte(s)
		case policy.TraceFieldKind:
			switch ctx.Span.Kind() {
			case ptrace.SpanKindInternal:
				return []byte("internal")
			case ptrace.SpanKindServer:
				return []byte("server")
			case ptrace.SpanKindClient:
				return []byte("client")
			case ptrace.SpanKindProducer:
				return []byte("producer")
			case ptrace.SpanKindConsumer:
				return []byte("consumer")
			default:
				return nil
			}
		case policy.TraceFieldStatus:
			switch ctx.Span.Status().Code() {
			case ptrace.StatusCodeOk:
				return []byte("ok")
			case ptrace.StatusCodeError:
				return []byte("error")
			case ptrace.StatusCodeUnset:
				return []byte("unset")
			default:
				return nil
			}
		case policy.TraceFieldEventName:
			events := ctx.Span.Events()
			for i := 0; i < events.Len(); i++ {
				if name := events.At(i).Name(); name != "" {
					return []byte(name)
				}
			}
			return nil
		case policy.TraceFieldScopeName:
			s := ctx.Scope.Name()
			if s == "" {
				return nil
			}
			return []byte(s)
		case policy.TraceFieldScopeVersion:
			s := ctx.Scope.Version()
			if s == "" {
				return nil
			}
			return []byte(s)
		case policy.TraceFieldResourceSchemaURL:
			s := ctx.ResourceSchemaURL
			if s == "" {
				return nil
			}
			return []byte(s)
		case policy.TraceFieldScopeSchemaURL:
			s := ctx.ScopeSchemaURL
			if s == "" {
				return nil
			}
			return []byte(s)
		default:
			return nil
		}
	}

	var attrs pcommon.Map
	switch {
	case ref.IsResourceAttr():
		attrs = ctx.Resource.Attributes()
	case ref.IsScopeAttr():
		attrs = ctx.Scope.Attributes()
	case ref.IsRecordAttr():
		attrs = ctx.Span.Attributes()
	default:
		return nil
	}

	return traversePath(attrs, ref.AttrPath)
}

// TraceTypedMatcher extracts field values from a TraceContext for typed comparison (equals/gt/gte/lt/lte).
// Returns TypedValue{} (absent) for missing fields.
// Used as the WithTraceTypedValue option for policy.EvaluateTrace.
func TraceTypedMatcher(ctx TraceContext, ref policy.TraceFieldRef) policy.TypedValue {
	if ref.IsField() {
		switch ref.Field {
		case policy.TraceFieldName:
			s := ctx.Span.Name()
			if s == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(s)
		case policy.TraceFieldTraceID:
			traceID := ctx.Span.TraceID()
			if traceID.IsEmpty() {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfBytes(traceID[:])
		case policy.TraceFieldSpanID:
			spanID := ctx.Span.SpanID()
			if spanID.IsEmpty() {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfBytes(spanID[:])
		case policy.TraceFieldParentSpanID:
			parentSpanID := ctx.Span.ParentSpanID()
			if parentSpanID.IsEmpty() {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfBytes(parentSpanID[:])
		case policy.TraceFieldTraceState:
			s := ctx.Span.TraceState().AsRaw()
			if s == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(s)
		case policy.TraceFieldKind:
			switch ctx.Span.Kind() {
			case ptrace.SpanKindInternal:
				return policy.TypedValueOfString("internal")
			case ptrace.SpanKindServer:
				return policy.TypedValueOfString("server")
			case ptrace.SpanKindClient:
				return policy.TypedValueOfString("client")
			case ptrace.SpanKindProducer:
				return policy.TypedValueOfString("producer")
			case ptrace.SpanKindConsumer:
				return policy.TypedValueOfString("consumer")
			default:
				return policy.TypedValue{}
			}
		case policy.TraceFieldStatus:
			switch ctx.Span.Status().Code() {
			case ptrace.StatusCodeOk:
				return policy.TypedValueOfString("ok")
			case ptrace.StatusCodeError:
				return policy.TypedValueOfString("error")
			case ptrace.StatusCodeUnset:
				return policy.TypedValueOfString("unset")
			default:
				return policy.TypedValue{}
			}
		case policy.TraceFieldEventName:
			events := ctx.Span.Events()
			for i := 0; i < events.Len(); i++ {
				if name := events.At(i).Name(); name != "" {
					return policy.TypedValueOfString(name)
				}
			}
			return policy.TypedValue{}
		case policy.TraceFieldScopeName:
			s := ctx.Scope.Name()
			if s == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(s)
		case policy.TraceFieldScopeVersion:
			s := ctx.Scope.Version()
			if s == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(s)
		case policy.TraceFieldResourceSchemaURL:
			s := ctx.ResourceSchemaURL
			if s == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(s)
		case policy.TraceFieldScopeSchemaURL:
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
		attrs = ctx.Span.Attributes()
	default:
		return policy.TypedValue{}
	}

	return traversePathTyped(attrs, ref.AttrPath)
}

// TraceExists reports whether the referenced field or attribute is set.
// Used as the WithTraceExists option for policy.EvaluateTrace.
func TraceExists(ctx TraceContext, ref policy.TraceFieldRef) bool {
	if ref.IsField() {
		switch ref.Field {
		case policy.TraceFieldName:
			return ctx.Span.Name() != ""
		case policy.TraceFieldTraceID:
			return !ctx.Span.TraceID().IsEmpty()
		case policy.TraceFieldSpanID:
			return !ctx.Span.SpanID().IsEmpty()
		case policy.TraceFieldParentSpanID:
			return !ctx.Span.ParentSpanID().IsEmpty()
		case policy.TraceFieldTraceState:
			return ctx.Span.TraceState().AsRaw() != ""
		case policy.TraceFieldKind:
			return ctx.Span.Kind() != ptrace.SpanKindUnspecified
		case policy.TraceFieldStatus:
			return true
		case policy.TraceFieldEventName:
			events := ctx.Span.Events()
			for i := 0; i < events.Len(); i++ {
				if events.At(i).Name() != "" {
					return true
				}
			}
			return false
		case policy.TraceFieldScopeName:
			return ctx.Scope.Name() != ""
		case policy.TraceFieldScopeVersion:
			return ctx.Scope.Version() != ""
		case policy.TraceFieldResourceSchemaURL:
			return ctx.ResourceSchemaURL != ""
		case policy.TraceFieldScopeSchemaURL:
			return ctx.ScopeSchemaURL != ""
		default:
			return false
		}
	}

	var attrs pcommon.Map
	switch {
	case ref.IsResourceAttr():
		attrs = ctx.Resource.Attributes()
	case ref.IsScopeAttr():
		attrs = ctx.Scope.Attributes()
	case ref.IsRecordAttr():
		attrs = ctx.Span.Attributes()
	default:
		return false
	}

	return pathExists(attrs, ref.AttrPath)
}
