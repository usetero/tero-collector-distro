package policyprocessor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/usetero/policy-go"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

func newLogContext() LogContext {
	lr := plog.NewLogRecord()
	resource := pcommon.NewResource()
	scope := pcommon.NewInstrumentationScope()
	return LogContext{
		Record:   lr,
		Resource: resource,
		Scope:    scope,
	}
}

func TestLogTransformer_RemoveRecordAttribute(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutStr("secret", "value")
	ctx.Record.Attributes().PutStr("keep", "ok")

	op := policy.TransformOp{
		Kind: policy.TransformRemove,
		Ref:  policy.LogAttr("secret"),
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	_, exists := ctx.Record.Attributes().Get("secret")
	assert.False(t, exists)
	val, exists := ctx.Record.Attributes().Get("keep")
	assert.True(t, exists)
	assert.Equal(t, "ok", val.Str())
}

func TestLogTransformer_RemoveRecordAttribute_Miss(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutStr("keep", "ok")

	op := policy.TransformOp{
		Kind: policy.TransformRemove,
		Ref:  policy.LogAttr("nonexistent"),
	}

	hit := LogTransformer(ctx, op)
	assert.False(t, hit)
}

func TestLogTransformer_RemoveBody(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Body().SetStr("hello world")

	op := policy.TransformOp{
		Kind: policy.TransformRemove,
		Ref: policy.LogFieldRef{
			Field: policy.LogFieldBody,
		},
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)
	assert.Equal(t, "", ctx.Record.Body().Str())
}

func TestLogTransformer_RemoveSeverityText(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.SetSeverityText("ERROR")

	op := policy.TransformOp{
		Kind: policy.TransformRemove,
		Ref: policy.LogFieldRef{
			Field: policy.LogFieldSeverityText,
		},
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)
	assert.Equal(t, "", ctx.Record.SeverityText())
}

func TestLogTransformer_RemoveResourceAttribute(t *testing.T) {
	ctx := newLogContext()
	ctx.Resource.Attributes().PutStr("service.name", "my-svc")

	op := policy.TransformOp{
		Kind: policy.TransformRemove,
		Ref:  policy.LogResourceAttr("service.name"),
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	_, exists := ctx.Resource.Attributes().Get("service.name")
	assert.False(t, exists)
}

func TestLogTransformer_RedactRecordAttribute(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutStr("api_key", "secret-123")

	op := policy.TransformOp{
		Kind:  policy.TransformRedact,
		Ref:   policy.LogAttr("api_key"),
		Value: "[REDACTED]",
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	val, exists := ctx.Record.Attributes().Get("api_key")
	assert.True(t, exists)
	assert.Equal(t, "[REDACTED]", val.Str())
}

func TestLogTransformer_RedactBody(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Body().SetStr("sensitive data")

	op := policy.TransformOp{
		Kind:  policy.TransformRedact,
		Ref:   policy.LogFieldRef{Field: policy.LogFieldBody},
		Value: "***",
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)
	assert.Equal(t, "***", ctx.Record.Body().Str())
}

func TestLogTransformer_RedactAttribute_Miss(t *testing.T) {
	ctx := newLogContext()

	op := policy.TransformOp{
		Kind:  policy.TransformRedact,
		Ref:   policy.LogAttr("nonexistent"),
		Value: "[REDACTED]",
	}

	hit := LogTransformer(ctx, op)
	assert.False(t, hit)
}

func TestLogTransformer_RenameRecordAttribute(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutStr("old_key", "the-value")

	op := policy.TransformOp{
		Kind:   policy.TransformRename,
		Ref:    policy.LogAttr("old_key"),
		To:     "new_key",
		Upsert: true,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	_, exists := ctx.Record.Attributes().Get("old_key")
	assert.False(t, exists)
	val, exists := ctx.Record.Attributes().Get("new_key")
	assert.True(t, exists)
	assert.Equal(t, "the-value", val.Str())
}

func TestLogTransformer_RenameRecordAttribute_NoUpsert(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutStr("old_key", "the-value")
	ctx.Record.Attributes().PutStr("new_key", "existing")

	op := policy.TransformOp{
		Kind:   policy.TransformRename,
		Ref:    policy.LogAttr("old_key"),
		To:     "new_key",
		Upsert: false,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)
	// Target exists and upsert=false, so new_key should keep its original value
	val, _ := ctx.Record.Attributes().Get("new_key")
	assert.Equal(t, "existing", val.Str())
}

func TestLogTransformer_RenameField_NotSupported(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Body().SetStr("hello")

	op := policy.TransformOp{
		Kind:   policy.TransformRename,
		Ref:    policy.LogFieldRef{Field: policy.LogFieldBody},
		To:     "new_body",
		Upsert: true,
	}

	hit := LogTransformer(ctx, op)
	assert.False(t, hit)
}

func TestLogTransformer_AddRecordAttribute(t *testing.T) {
	ctx := newLogContext()

	op := policy.TransformOp{
		Kind:   policy.TransformAdd,
		Ref:    policy.LogAttr("processed"),
		Value:  "true",
		Upsert: true,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	val, exists := ctx.Record.Attributes().Get("processed")
	assert.True(t, exists)
	assert.Equal(t, "true", val.Str())
}

func TestLogTransformer_AddRecordAttribute_NoUpsert(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutStr("processed", "original")

	op := policy.TransformOp{
		Kind:   policy.TransformAdd,
		Ref:    policy.LogAttr("processed"),
		Value:  "overwritten",
		Upsert: false,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)
	// Existing value should be preserved when upsert=false
	val, _ := ctx.Record.Attributes().Get("processed")
	assert.Equal(t, "original", val.Str())
}

func TestLogTransformer_AddRecordAttribute_Upsert(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutStr("processed", "original")

	op := policy.TransformOp{
		Kind:   policy.TransformAdd,
		Ref:    policy.LogAttr("processed"),
		Value:  "overwritten",
		Upsert: true,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)
	val, _ := ctx.Record.Attributes().Get("processed")
	assert.Equal(t, "overwritten", val.Str())
}

func TestLogTransformer_AddResourceAttribute(t *testing.T) {
	ctx := newLogContext()

	op := policy.TransformOp{
		Kind:   policy.TransformAdd,
		Ref:    policy.LogResourceAttr("env"),
		Value:  "production",
		Upsert: false,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	val, exists := ctx.Resource.Attributes().Get("env")
	assert.True(t, exists)
	assert.Equal(t, "production", val.Str())
}

func TestLogTransformer_AddScopeAttribute(t *testing.T) {
	ctx := newLogContext()

	op := policy.TransformOp{
		Kind:   policy.TransformAdd,
		Ref:    policy.LogScopeAttr("version"),
		Value:  "1.0",
		Upsert: true,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	val, exists := ctx.Scope.Attributes().Get("version")
	assert.True(t, exists)
	assert.Equal(t, "1.0", val.Str())
}

func TestLogTransformer_AddBody(t *testing.T) {
	ctx := newLogContext()

	op := policy.TransformOp{
		Kind:   policy.TransformAdd,
		Ref:    policy.LogFieldRef{Field: policy.LogFieldBody},
		Value:  "new body",
		Upsert: true,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)
	assert.Equal(t, "new body", ctx.Record.Body().Str())
}

func TestLogTransformer_AddSeverityText(t *testing.T) {
	ctx := newLogContext()

	op := policy.TransformOp{
		Kind:   policy.TransformAdd,
		Ref:    policy.LogFieldRef{Field: policy.LogFieldSeverityText},
		Value:  "WARN",
		Upsert: true,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)
	assert.Equal(t, "WARN", ctx.Record.SeverityText())
}

func TestLogTransformer_AddEventName(t *testing.T) {
	ctx := newLogContext()

	op := policy.TransformOp{
		Kind:   policy.TransformAdd,
		Ref:    policy.LogFieldRef{Field: policy.LogFieldEventName},
		Value:  "my.event",
		Upsert: true,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)
	assert.Equal(t, "my.event", ctx.Record.EventName())
}

func TestLogTransformer_RedactEventName(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.SetEventName("sensitive.event")

	op := policy.TransformOp{
		Kind:  policy.TransformRedact,
		Ref:   policy.LogFieldRef{Field: policy.LogFieldEventName},
		Value: "[REDACTED]",
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)
	assert.Equal(t, "[REDACTED]", ctx.Record.EventName())
}

func TestLogTransformer_RemoveTraceID(t *testing.T) {
	ctx := newLogContext()
	var traceID pcommon.TraceID
	copy(traceID[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10})
	ctx.Record.SetTraceID(traceID)

	op := policy.TransformOp{
		Kind: policy.TransformRemove,
		Ref:  policy.LogFieldRef{Field: policy.LogFieldTraceID},
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)
	assert.True(t, ctx.Record.TraceID().IsEmpty())
}

func TestLogTransformer_RemoveSpanID(t *testing.T) {
	ctx := newLogContext()
	var spanID pcommon.SpanID
	copy(spanID[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	ctx.Record.SetSpanID(spanID)

	op := policy.TransformOp{
		Kind: policy.TransformRemove,
		Ref:  policy.LogFieldRef{Field: policy.LogFieldSpanID},
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)
	assert.True(t, ctx.Record.SpanID().IsEmpty())
}

// ============================================================================
// Nested attribute tests — exhaustive coverage of two- and three-level paths,
// all four transform kinds, all three attribute scopes, and edge cases
// (missing intermediates, non-map intermediates, sibling preservation).
// ============================================================================

func TestLogTransformer_RemoveNestedRecordAttribute_TwoLevels(t *testing.T) {
	ctx := newLogContext()
	nested := ctx.Record.Attributes().PutEmptyMap("http")
	nested.PutStr("method", "GET")
	nested.PutStr("path", "/api")

	op := policy.TransformOp{
		Kind: policy.TransformRemove,
		Ref:  policy.LogAttr("http", "method"),
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	// "method" removed, "path" still exists
	httpVal, exists := ctx.Record.Attributes().Get("http")
	assert.True(t, exists)
	_, exists = httpVal.Map().Get("method")
	assert.False(t, exists)
	pathVal, exists := httpVal.Map().Get("path")
	assert.True(t, exists)
	assert.Equal(t, "/api", pathVal.Str())
}

func TestLogTransformer_RemoveNestedAttribute_ThreeLevels(t *testing.T) {
	ctx := newLogContext()
	l1 := ctx.Record.Attributes().PutEmptyMap("a")
	l2 := l1.PutEmptyMap("b")
	l2.PutStr("c", "deep-value")
	l2.PutStr("d", "sibling")

	op := policy.TransformOp{
		Kind: policy.TransformRemove,
		Ref:  policy.LogAttr("a", "b", "c"),
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	// "c" gone, "d" preserved
	aVal, _ := ctx.Record.Attributes().Get("a")
	bVal, _ := aVal.Map().Get("b")
	_, exists := bVal.Map().Get("c")
	assert.False(t, exists)
	dVal, exists := bVal.Map().Get("d")
	assert.True(t, exists)
	assert.Equal(t, "sibling", dVal.Str())
}

func TestLogTransformer_RemoveNestedAttribute_MissingIntermediate(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutStr("flat", "value")

	op := policy.TransformOp{
		Kind: policy.TransformRemove,
		Ref:  policy.LogAttr("nonexistent", "child"),
	}

	hit := LogTransformer(ctx, op)
	assert.False(t, hit)

	// Original attributes untouched
	val, exists := ctx.Record.Attributes().Get("flat")
	assert.True(t, exists)
	assert.Equal(t, "value", val.Str())
}

func TestLogTransformer_RemoveNestedAttribute_NonMapIntermediate(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutStr("http", "not-a-map")

	op := policy.TransformOp{
		Kind: policy.TransformRemove,
		Ref:  policy.LogAttr("http", "method"),
	}

	hit := LogTransformer(ctx, op)
	assert.False(t, hit)

	// Original string value untouched
	val, _ := ctx.Record.Attributes().Get("http")
	assert.Equal(t, "not-a-map", val.Str())
}

func TestLogTransformer_RedactNestedRecordAttribute_TwoLevels(t *testing.T) {
	ctx := newLogContext()
	nested := ctx.Record.Attributes().PutEmptyMap("user")
	nested.PutStr("email", "alice@example.com")
	nested.PutStr("name", "Alice")

	op := policy.TransformOp{
		Kind:  policy.TransformRedact,
		Ref:   policy.LogAttr("user", "email"),
		Value: "[REDACTED]",
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	userVal, _ := ctx.Record.Attributes().Get("user")
	emailVal, _ := userVal.Map().Get("email")
	assert.Equal(t, "[REDACTED]", emailVal.Str())
	// Sibling preserved
	nameVal, _ := userVal.Map().Get("name")
	assert.Equal(t, "Alice", nameVal.Str())
}

func TestLogTransformer_RedactNestedAttribute_ThreeLevels(t *testing.T) {
	ctx := newLogContext()
	l1 := ctx.Record.Attributes().PutEmptyMap("a")
	l2 := l1.PutEmptyMap("b")
	l2.PutStr("secret", "password123")

	op := policy.TransformOp{
		Kind:  policy.TransformRedact,
		Ref:   policy.LogAttr("a", "b", "secret"),
		Value: "***",
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	aVal, _ := ctx.Record.Attributes().Get("a")
	bVal, _ := aVal.Map().Get("b")
	secretVal, _ := bVal.Map().Get("secret")
	assert.Equal(t, "***", secretVal.Str())
}

func TestLogTransformer_RedactNestedAttribute_MissingIntermediate(t *testing.T) {
	ctx := newLogContext()

	op := policy.TransformOp{
		Kind:  policy.TransformRedact,
		Ref:   policy.LogAttr("missing", "child"),
		Value: "[REDACTED]",
	}

	hit := LogTransformer(ctx, op)
	assert.False(t, hit)
}

func TestLogTransformer_RedactNestedAttribute_NonMapIntermediate(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutInt("count", 42)

	op := policy.TransformOp{
		Kind:  policy.TransformRedact,
		Ref:   policy.LogAttr("count", "child"),
		Value: "[REDACTED]",
	}

	hit := LogTransformer(ctx, op)
	assert.False(t, hit)

	// Original int value untouched
	val, _ := ctx.Record.Attributes().Get("count")
	assert.Equal(t, int64(42), val.Int())
}

func TestLogTransformer_RedactNestedAttribute_MissingLeaf(t *testing.T) {
	ctx := newLogContext()
	nested := ctx.Record.Attributes().PutEmptyMap("http")
	nested.PutStr("method", "GET")

	op := policy.TransformOp{
		Kind:  policy.TransformRedact,
		Ref:   policy.LogAttr("http", "nonexistent"),
		Value: "[REDACTED]",
	}

	// setNestedAttr creates the leaf — it returns false because the key didn't exist before
	hit := LogTransformer(ctx, op)
	assert.False(t, hit)
}

func TestLogTransformer_RenameNestedRecordAttribute_TwoLevels(t *testing.T) {
	ctx := newLogContext()
	nested := ctx.Record.Attributes().PutEmptyMap("http")
	nested.PutStr("old_header", "val")

	op := policy.TransformOp{
		Kind:   policy.TransformRename,
		Ref:    policy.LogAttr("http", "old_header"),
		To:     "new_header",
		Upsert: true,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	// Nested "old_header" removed
	httpVal, _ := ctx.Record.Attributes().Get("http")
	_, exists := httpVal.Map().Get("old_header")
	assert.False(t, exists)
	// Renamed to top-level "new_header"
	newVal, exists := ctx.Record.Attributes().Get("new_header")
	assert.True(t, exists)
	assert.Equal(t, "val", newVal.Str())
}

func TestLogTransformer_RenameNestedAttribute_Miss(t *testing.T) {
	ctx := newLogContext()
	nested := ctx.Record.Attributes().PutEmptyMap("http")
	nested.PutStr("method", "GET")

	op := policy.TransformOp{
		Kind:   policy.TransformRename,
		Ref:    policy.LogAttr("http", "nonexistent"),
		To:     "target",
		Upsert: true,
	}

	hit := LogTransformer(ctx, op)
	assert.False(t, hit)
}

func TestLogTransformer_RenameNestedAttribute_NonMapIntermediate(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutStr("flat", "value")

	op := policy.TransformOp{
		Kind:   policy.TransformRename,
		Ref:    policy.LogAttr("flat", "child"),
		To:     "target",
		Upsert: true,
	}

	hit := LogTransformer(ctx, op)
	assert.False(t, hit)
}

func TestLogTransformer_AddNestedRecordAttribute_TwoLevels(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutEmptyMap("http")

	op := policy.TransformOp{
		Kind:   policy.TransformAdd,
		Ref:    policy.LogAttr("http", "status"),
		Value:  "200",
		Upsert: true,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	httpVal, _ := ctx.Record.Attributes().Get("http")
	statusVal, exists := httpVal.Map().Get("status")
	assert.True(t, exists)
	assert.Equal(t, "200", statusVal.Str())
}

func TestLogTransformer_AddNestedAttribute_ThreeLevels(t *testing.T) {
	ctx := newLogContext()
	l1 := ctx.Record.Attributes().PutEmptyMap("a")
	l1.PutEmptyMap("b")

	op := policy.TransformOp{
		Kind:   policy.TransformAdd,
		Ref:    policy.LogAttr("a", "b", "c"),
		Value:  "deep",
		Upsert: true,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	aVal, _ := ctx.Record.Attributes().Get("a")
	bVal, _ := aVal.Map().Get("b")
	cVal, exists := bVal.Map().Get("c")
	assert.True(t, exists)
	assert.Equal(t, "deep", cVal.Str())
}

func TestLogTransformer_AddNestedAttribute_CreatesIntermediateMaps(t *testing.T) {
	ctx := newLogContext()
	// No pre-existing "http" map — putNestedAttr should create it

	op := policy.TransformOp{
		Kind:   policy.TransformAdd,
		Ref:    policy.LogAttr("http", "status"),
		Value:  "200",
		Upsert: true,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	httpVal, exists := ctx.Record.Attributes().Get("http")
	assert.True(t, exists)
	assert.Equal(t, pcommon.ValueTypeMap, httpVal.Type())
	statusVal, exists := httpVal.Map().Get("status")
	assert.True(t, exists)
	assert.Equal(t, "200", statusVal.Str())
}

func TestLogTransformer_AddNestedAttribute_CreatesMultipleIntermediateMaps(t *testing.T) {
	ctx := newLogContext()
	// Nothing exists — should create a.b.c

	op := policy.TransformOp{
		Kind:   policy.TransformAdd,
		Ref:    policy.LogAttr("a", "b", "c"),
		Value:  "deep",
		Upsert: true,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	aVal, exists := ctx.Record.Attributes().Get("a")
	assert.True(t, exists)
	assert.Equal(t, pcommon.ValueTypeMap, aVal.Type())
	bVal, exists := aVal.Map().Get("b")
	assert.True(t, exists)
	assert.Equal(t, pcommon.ValueTypeMap, bVal.Type())
	cVal, exists := bVal.Map().Get("c")
	assert.True(t, exists)
	assert.Equal(t, "deep", cVal.Str())
}

func TestLogTransformer_AddNestedAttribute_OverwritesNonMapIntermediate(t *testing.T) {
	ctx := newLogContext()
	// "http" is a string — putNestedAttr should replace it with a map
	ctx.Record.Attributes().PutStr("http", "was-a-string")

	op := policy.TransformOp{
		Kind:   policy.TransformAdd,
		Ref:    policy.LogAttr("http", "status"),
		Value:  "200",
		Upsert: true,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	httpVal, _ := ctx.Record.Attributes().Get("http")
	assert.Equal(t, pcommon.ValueTypeMap, httpVal.Type())
	statusVal, exists := httpVal.Map().Get("status")
	assert.True(t, exists)
	assert.Equal(t, "200", statusVal.Str())
}

func TestLogTransformer_AddNestedAttribute_NoUpsertExisting(t *testing.T) {
	ctx := newLogContext()
	nested := ctx.Record.Attributes().PutEmptyMap("http")
	nested.PutStr("status", "original")

	op := policy.TransformOp{
		Kind:   policy.TransformAdd,
		Ref:    policy.LogAttr("http", "status"),
		Value:  "overwritten",
		Upsert: false,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)
	// Should NOT overwrite
	httpVal, _ := ctx.Record.Attributes().Get("http")
	statusVal, _ := httpVal.Map().Get("status")
	assert.Equal(t, "original", statusVal.Str())
}

func TestLogTransformer_AddNestedAttribute_NoUpsertMissing(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutEmptyMap("http")

	op := policy.TransformOp{
		Kind:   policy.TransformAdd,
		Ref:    policy.LogAttr("http", "status"),
		Value:  "200",
		Upsert: false,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)
	// Should add because it didn't exist
	httpVal, _ := ctx.Record.Attributes().Get("http")
	statusVal, exists := httpVal.Map().Get("status")
	assert.True(t, exists)
	assert.Equal(t, "200", statusVal.Str())
}

// ============================================================================
// Nested attribute tests across resource and scope scopes
// ============================================================================

func TestLogTransformer_RemoveNestedResourceAttribute(t *testing.T) {
	ctx := newLogContext()
	nested := ctx.Resource.Attributes().PutEmptyMap("cloud")
	nested.PutStr("provider", "aws")
	nested.PutStr("region", "us-east-1")

	op := policy.TransformOp{
		Kind: policy.TransformRemove,
		Ref:  policy.LogResourceAttr("cloud", "provider"),
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	cloudVal, _ := ctx.Resource.Attributes().Get("cloud")
	_, exists := cloudVal.Map().Get("provider")
	assert.False(t, exists)
	regionVal, exists := cloudVal.Map().Get("region")
	assert.True(t, exists)
	assert.Equal(t, "us-east-1", regionVal.Str())
}

func TestLogTransformer_RedactNestedScopeAttribute(t *testing.T) {
	ctx := newLogContext()
	nested := ctx.Scope.Attributes().PutEmptyMap("config")
	nested.PutStr("token", "secret-token")

	op := policy.TransformOp{
		Kind:  policy.TransformRedact,
		Ref:   policy.LogScopeAttr("config", "token"),
		Value: "***",
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	configVal, _ := ctx.Scope.Attributes().Get("config")
	tokenVal, _ := configVal.Map().Get("token")
	assert.Equal(t, "***", tokenVal.Str())
}

func TestLogTransformer_AddNestedResourceAttribute(t *testing.T) {
	ctx := newLogContext()

	op := policy.TransformOp{
		Kind:   policy.TransformAdd,
		Ref:    policy.LogResourceAttr("cloud", "region"),
		Value:  "eu-west-1",
		Upsert: true,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	cloudVal, exists := ctx.Resource.Attributes().Get("cloud")
	assert.True(t, exists)
	assert.Equal(t, pcommon.ValueTypeMap, cloudVal.Type())
	regionVal, exists := cloudVal.Map().Get("region")
	assert.True(t, exists)
	assert.Equal(t, "eu-west-1", regionVal.Str())
}

func TestLogTransformer_AddNestedScopeAttribute(t *testing.T) {
	ctx := newLogContext()

	op := policy.TransformOp{
		Kind:   policy.TransformAdd,
		Ref:    policy.LogScopeAttr("meta", "version"),
		Value:  "2.0",
		Upsert: true,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	metaVal, exists := ctx.Scope.Attributes().Get("meta")
	assert.True(t, exists)
	versionVal, exists := metaVal.Map().Get("version")
	assert.True(t, exists)
	assert.Equal(t, "2.0", versionVal.Str())
}

func TestLogTransformer_RenameNestedResourceAttribute(t *testing.T) {
	ctx := newLogContext()
	nested := ctx.Resource.Attributes().PutEmptyMap("service")
	nested.PutStr("old_name", "my-svc")

	op := policy.TransformOp{
		Kind:   policy.TransformRename,
		Ref:    policy.LogResourceAttr("service", "old_name"),
		To:     "new_name",
		Upsert: true,
	}

	hit := LogTransformer(ctx, op)
	assert.True(t, hit)

	serviceVal, _ := ctx.Resource.Attributes().Get("service")
	_, exists := serviceVal.Map().Get("old_name")
	assert.False(t, exists)
	newVal, exists := ctx.Resource.Attributes().Get("new_name")
	assert.True(t, exists)
	assert.Equal(t, "my-svc", newVal.Str())
}
