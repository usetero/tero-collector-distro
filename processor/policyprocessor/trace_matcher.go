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

// TraceMatcher extracts field values from a TraceContext for policy evaluation.
// Used as the WithTraceValue option for policy.EvaluateTrace.
func TraceMatcher(ctx TraceContext, ref policy.TraceFieldRef) []byte {
	if ref.IsField() {
		switch ref.Field {
		case policy.TraceFieldName:
			if name := ctx.Span.Name(); name != "" {
				return []byte(name)
			}
			return nil
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
			if traceState := ctx.Span.TraceState().AsRaw(); traceState != "" {
				return []byte(traceState)
			}
			return nil
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
			if name := ctx.Scope.Name(); name != "" {
				return []byte(name)
			}
			return nil
		case policy.TraceFieldScopeVersion:
			if version := ctx.Scope.Version(); version != "" {
				return []byte(version)
			}
			return nil
		case policy.TraceFieldResourceSchemaURL:
			if ctx.ResourceSchemaURL == "" {
				return nil
			}
			return []byte(ctx.ResourceSchemaURL)
		case policy.TraceFieldScopeSchemaURL:
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
		attrs = ctx.Span.Attributes()
	default:
		return nil
	}

	return traversePath(attrs, ref.AttrPath)
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
