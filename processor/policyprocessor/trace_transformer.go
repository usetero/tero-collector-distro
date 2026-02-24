package policyprocessor

import (
	"strings"

	"github.com/usetero/policy-go"
)

// TraceTransformer writes a sampling threshold value back to a span's tracestate.
// It implements policy.TraceTransformFunc[TraceContext].
func TraceTransformer(ctx TraceContext, ref policy.TraceFieldRef, value string) {
	if ref.Field == policy.SpanSamplingThreshold().Field {
		ctx.Span.TraceState().FromRaw(mergeOTTracestate(ctx.Span.TraceState().AsRaw(), "th:"+value))
	}
}

// mergeOTTracestate merges an OpenTelemetry sub-key (e.g. "th:8000") into a
// W3C tracestate string under the "ot" vendor key.
func mergeOTTracestate(tracestate, subkv string) string {
	subKey := subkv
	if idx := strings.Index(subkv, ":"); idx >= 0 {
		subKey = subkv[:idx]
	}

	var otParts []string
	var otherVendors []string

	if tracestate != "" {
		for _, vendor := range strings.Split(tracestate, ",") {
			vendor = strings.TrimSpace(vendor)
			if vendor == "" {
				continue
			}
			if strings.HasPrefix(vendor, "ot=") {
				otValue := vendor[3:]
				for _, part := range strings.Split(otValue, ";") {
					part = strings.TrimSpace(part)
					if part == "" {
						continue
					}
					partKey := part
					if idx := strings.Index(part, ":"); idx >= 0 {
						partKey = part[:idx]
					}
					if partKey != subKey {
						otParts = append(otParts, part)
					}
				}
			} else {
				otherVendors = append(otherVendors, vendor)
			}
		}
	}

	otParts = append(otParts, subkv)
	result := "ot=" + strings.Join(otParts, ";")
	if len(otherVendors) > 0 {
		result += "," + strings.Join(otherVendors, ",")
	}
	return result
}
