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

// ============================================================================
// LogDelete
// ============================================================================

func TestLogDelete_RecordAttribute(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutStr("secret", "value")
	ctx.Record.Attributes().PutStr("keep", "ok")

	hit := LogDelete(ctx, policy.LogAttr("secret"))
	assert.True(t, hit)

	_, exists := ctx.Record.Attributes().Get("secret")
	assert.False(t, exists)
	val, exists := ctx.Record.Attributes().Get("keep")
	assert.True(t, exists)
	assert.Equal(t, "ok", val.Str())
}

func TestLogDelete_RecordAttribute_Miss(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutStr("keep", "ok")

	hit := LogDelete(ctx, policy.LogAttr("nonexistent"))
	assert.False(t, hit)
}

func TestLogDelete_Body(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Body().SetStr("hello world")

	hit := LogDelete(ctx, policy.LogFieldRef{Field: policy.LogFieldBody})
	assert.True(t, hit)
	assert.Equal(t, "", ctx.Record.Body().Str())
}

func TestLogDelete_SeverityText(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.SetSeverityText("ERROR")

	hit := LogDelete(ctx, policy.LogFieldRef{Field: policy.LogFieldSeverityText})
	assert.True(t, hit)
	assert.Equal(t, "", ctx.Record.SeverityText())
}

func TestLogDelete_ResourceAttribute(t *testing.T) {
	ctx := newLogContext()
	ctx.Resource.Attributes().PutStr("service.name", "my-svc")

	hit := LogDelete(ctx, policy.LogResourceAttr("service.name"))
	assert.True(t, hit)

	_, exists := ctx.Resource.Attributes().Get("service.name")
	assert.False(t, exists)
}

func TestLogDelete_TraceID(t *testing.T) {
	ctx := newLogContext()
	var traceID pcommon.TraceID
	copy(traceID[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10})
	ctx.Record.SetTraceID(traceID)

	hit := LogDelete(ctx, policy.LogFieldRef{Field: policy.LogFieldTraceID})
	assert.True(t, hit)
	assert.True(t, ctx.Record.TraceID().IsEmpty())
}

func TestLogDelete_SpanID(t *testing.T) {
	ctx := newLogContext()
	var spanID pcommon.SpanID
	copy(spanID[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	ctx.Record.SetSpanID(spanID)

	hit := LogDelete(ctx, policy.LogFieldRef{Field: policy.LogFieldSpanID})
	assert.True(t, hit)
	assert.True(t, ctx.Record.SpanID().IsEmpty())
}

func TestLogDelete_NestedRecordAttribute_TwoLevels(t *testing.T) {
	ctx := newLogContext()
	nested := ctx.Record.Attributes().PutEmptyMap("http")
	nested.PutStr("method", "GET")
	nested.PutStr("path", "/api")

	hit := LogDelete(ctx, policy.LogAttr("http", "method"))
	assert.True(t, hit)

	httpVal, exists := ctx.Record.Attributes().Get("http")
	assert.True(t, exists)
	_, exists = httpVal.Map().Get("method")
	assert.False(t, exists)
	pathVal, exists := httpVal.Map().Get("path")
	assert.True(t, exists)
	assert.Equal(t, "/api", pathVal.Str())
}

func TestLogDelete_NestedAttribute_ThreeLevels(t *testing.T) {
	ctx := newLogContext()
	l1 := ctx.Record.Attributes().PutEmptyMap("a")
	l2 := l1.PutEmptyMap("b")
	l2.PutStr("c", "deep-value")
	l2.PutStr("d", "sibling")

	hit := LogDelete(ctx, policy.LogAttr("a", "b", "c"))
	assert.True(t, hit)

	aVal, _ := ctx.Record.Attributes().Get("a")
	bVal, _ := aVal.Map().Get("b")
	_, exists := bVal.Map().Get("c")
	assert.False(t, exists)
	dVal, exists := bVal.Map().Get("d")
	assert.True(t, exists)
	assert.Equal(t, "sibling", dVal.Str())
}

func TestLogDelete_NestedAttribute_MissingIntermediate(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutStr("flat", "value")

	hit := LogDelete(ctx, policy.LogAttr("nonexistent", "child"))
	assert.False(t, hit)

	val, exists := ctx.Record.Attributes().Get("flat")
	assert.True(t, exists)
	assert.Equal(t, "value", val.Str())
}

func TestLogDelete_NestedAttribute_NonMapIntermediate(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutStr("http", "not-a-map")

	hit := LogDelete(ctx, policy.LogAttr("http", "method"))
	assert.False(t, hit)

	val, _ := ctx.Record.Attributes().Get("http")
	assert.Equal(t, "not-a-map", val.Str())
}

func TestLogDelete_NestedResourceAttribute(t *testing.T) {
	ctx := newLogContext()
	nested := ctx.Resource.Attributes().PutEmptyMap("cloud")
	nested.PutStr("provider", "aws")
	nested.PutStr("region", "us-east-1")

	hit := LogDelete(ctx, policy.LogResourceAttr("cloud", "provider"))
	assert.True(t, hit)

	cloudVal, _ := ctx.Resource.Attributes().Get("cloud")
	_, exists := cloudVal.Map().Get("provider")
	assert.False(t, exists)
	regionVal, exists := cloudVal.Map().Get("region")
	assert.True(t, exists)
	assert.Equal(t, "us-east-1", regionVal.Str())
}

// ============================================================================
// LogSet
// ============================================================================

func TestLogSet_RecordAttribute_Overwrites(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutStr("api_key", "secret-123")

	LogSet(ctx, policy.LogAttr("api_key"), "[REDACTED]")

	val, exists := ctx.Record.Attributes().Get("api_key")
	assert.True(t, exists)
	assert.Equal(t, "[REDACTED]", val.Str())
}

func TestLogSet_RecordAttribute_Creates(t *testing.T) {
	ctx := newLogContext()

	LogSet(ctx, policy.LogAttr("processed"), "true")

	val, exists := ctx.Record.Attributes().Get("processed")
	assert.True(t, exists)
	assert.Equal(t, "true", val.Str())
}

func TestLogSet_ResourceAttribute(t *testing.T) {
	ctx := newLogContext()

	LogSet(ctx, policy.LogResourceAttr("env"), "production")

	val, exists := ctx.Resource.Attributes().Get("env")
	assert.True(t, exists)
	assert.Equal(t, "production", val.Str())
}

func TestLogSet_ScopeAttribute(t *testing.T) {
	ctx := newLogContext()

	LogSet(ctx, policy.LogScopeAttr("version"), "1.0")

	val, exists := ctx.Scope.Attributes().Get("version")
	assert.True(t, exists)
	assert.Equal(t, "1.0", val.Str())
}

func TestLogSet_Body(t *testing.T) {
	ctx := newLogContext()

	LogSet(ctx, policy.LogFieldRef{Field: policy.LogFieldBody}, "new body")
	assert.Equal(t, "new body", ctx.Record.Body().Str())
}

func TestLogSet_SeverityText(t *testing.T) {
	ctx := newLogContext()

	LogSet(ctx, policy.LogFieldRef{Field: policy.LogFieldSeverityText}, "WARN")
	assert.Equal(t, "WARN", ctx.Record.SeverityText())
}

func TestLogSet_EventName(t *testing.T) {
	ctx := newLogContext()

	LogSet(ctx, policy.LogFieldRef{Field: policy.LogFieldEventName}, "my.event")
	assert.Equal(t, "my.event", ctx.Record.EventName())
}

func TestLogSet_NestedRecordAttribute_TwoLevels(t *testing.T) {
	ctx := newLogContext()
	nested := ctx.Record.Attributes().PutEmptyMap("user")
	nested.PutStr("email", "alice@example.com")
	nested.PutStr("name", "Alice")

	LogSet(ctx, policy.LogAttr("user", "email"), "[REDACTED]")

	userVal, _ := ctx.Record.Attributes().Get("user")
	emailVal, _ := userVal.Map().Get("email")
	assert.Equal(t, "[REDACTED]", emailVal.Str())
	nameVal, _ := userVal.Map().Get("name")
	assert.Equal(t, "Alice", nameVal.Str())
}

func TestLogSet_NestedAttribute_ThreeLevels(t *testing.T) {
	ctx := newLogContext()
	l1 := ctx.Record.Attributes().PutEmptyMap("a")
	l1.PutEmptyMap("b")

	LogSet(ctx, policy.LogAttr("a", "b", "c"), "deep")

	aVal, _ := ctx.Record.Attributes().Get("a")
	bVal, _ := aVal.Map().Get("b")
	cVal, exists := bVal.Map().Get("c")
	assert.True(t, exists)
	assert.Equal(t, "deep", cVal.Str())
}

func TestLogSet_CreatesIntermediateMaps(t *testing.T) {
	ctx := newLogContext()

	LogSet(ctx, policy.LogAttr("http", "status"), "200")

	httpVal, exists := ctx.Record.Attributes().Get("http")
	assert.True(t, exists)
	assert.Equal(t, pcommon.ValueTypeMap, httpVal.Type())
	statusVal, exists := httpVal.Map().Get("status")
	assert.True(t, exists)
	assert.Equal(t, "200", statusVal.Str())
}

func TestLogSet_CreatesMultipleIntermediateMaps(t *testing.T) {
	ctx := newLogContext()

	LogSet(ctx, policy.LogAttr("a", "b", "c"), "deep")

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

func TestLogSet_OverwritesNonMapIntermediate(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutStr("http", "was-a-string")

	LogSet(ctx, policy.LogAttr("http", "status"), "200")

	httpVal, _ := ctx.Record.Attributes().Get("http")
	assert.Equal(t, pcommon.ValueTypeMap, httpVal.Type())
	statusVal, exists := httpVal.Map().Get("status")
	assert.True(t, exists)
	assert.Equal(t, "200", statusVal.Str())
}

func TestLogSet_NestedScopeAttribute(t *testing.T) {
	ctx := newLogContext()
	nested := ctx.Scope.Attributes().PutEmptyMap("config")
	nested.PutStr("token", "secret-token")

	LogSet(ctx, policy.LogScopeAttr("config", "token"), "***")

	configVal, _ := ctx.Scope.Attributes().Get("config")
	tokenVal, _ := configVal.Map().Get("token")
	assert.Equal(t, "***", tokenVal.Str())
}

// ============================================================================
// LogMove
// ============================================================================

func TestLogMove_RecordAttribute(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutStr("old_key", "the-value")

	LogMove(ctx, policy.LogAttr("old_key"), policy.LogAttr("new_key"))

	_, exists := ctx.Record.Attributes().Get("old_key")
	assert.False(t, exists)
	val, exists := ctx.Record.Attributes().Get("new_key")
	assert.True(t, exists)
	assert.Equal(t, "the-value", val.Str())
}

func TestLogMove_FieldRef_NoOp(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Body().SetStr("hello")

	LogMove(ctx,
		policy.LogFieldRef{Field: policy.LogFieldBody},
		policy.LogAttr("new_body"),
	)

	// Body untouched; no new attribute created.
	assert.Equal(t, "hello", ctx.Record.Body().Str())
	_, exists := ctx.Record.Attributes().Get("new_body")
	assert.False(t, exists)
}

func TestLogMove_MissingSource_NoOp(t *testing.T) {
	ctx := newLogContext()
	nested := ctx.Record.Attributes().PutEmptyMap("http")
	nested.PutStr("method", "GET")

	LogMove(ctx, policy.LogAttr("http", "nonexistent"), policy.LogAttr("target"))

	_, exists := ctx.Record.Attributes().Get("target")
	assert.False(t, exists)
}

func TestLogMove_NonMapIntermediate_NoOp(t *testing.T) {
	ctx := newLogContext()
	ctx.Record.Attributes().PutStr("flat", "value")

	LogMove(ctx, policy.LogAttr("flat", "child"), policy.LogAttr("target"))

	val, _ := ctx.Record.Attributes().Get("flat")
	assert.Equal(t, "value", val.Str())
	_, exists := ctx.Record.Attributes().Get("target")
	assert.False(t, exists)
}

func TestLogMove_NestedRecordAttribute_TwoLevels(t *testing.T) {
	ctx := newLogContext()
	nested := ctx.Record.Attributes().PutEmptyMap("http")
	nested.PutStr("old_header", "val")

	LogMove(ctx, policy.LogAttr("http", "old_header"), policy.LogAttr("new_header"))

	httpVal, _ := ctx.Record.Attributes().Get("http")
	_, exists := httpVal.Map().Get("old_header")
	assert.False(t, exists)
	newVal, exists := ctx.Record.Attributes().Get("new_header")
	assert.True(t, exists)
	assert.Equal(t, "val", newVal.Str())
}

func TestLogMove_NestedResourceAttribute(t *testing.T) {
	ctx := newLogContext()
	nested := ctx.Resource.Attributes().PutEmptyMap("service")
	nested.PutStr("old_name", "my-svc")

	LogMove(ctx,
		policy.LogResourceAttr("service", "old_name"),
		policy.LogResourceAttr("new_name"),
	)

	serviceVal, _ := ctx.Resource.Attributes().Get("service")
	_, exists := serviceVal.Map().Get("old_name")
	assert.False(t, exists)
	newVal, exists := ctx.Resource.Attributes().Get("new_name")
	assert.True(t, exists)
	assert.Equal(t, "my-svc", newVal.Str())
}
