package policyprocessor

import (
	"github.com/usetero/policy-go"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// TraceContext holds the context needed to evaluate a span against policies.
type TraceContext struct {
	Span     ptrace.Span
	Resource pcommon.Resource
	Scope    pcommon.InstrumentationScope
}

// TraceMatcher extracts field values from a TraceContext for policy evaluation.
// This implements policy.TraceMatchFunc[TraceContext].
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
			if !traceID.IsEmpty() {
				return []byte(traceID.String())
			}
			return nil
		case policy.TraceFieldSpanID:
			spanID := ctx.Span.SpanID()
			if !spanID.IsEmpty() {
				return []byte(spanID.String())
			}
			return nil
		case policy.TraceFieldParentSpanID:
			parentSpanID := ctx.Span.ParentSpanID()
			if !parentSpanID.IsEmpty() {
				return []byte(parentSpanID.String())
			}
			return nil
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
			default:
				return nil
			}
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
