package policyprocessor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/usetero/policy-go"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

// staticLogProvider is a simple policy provider for testing.
type staticLogProvider struct {
	policies []*policyv1.Policy
}

func (p *staticLogProvider) Load() ([]*policyv1.Policy, error) {
	return p.policies, nil
}

func (p *staticLogProvider) Subscribe(callback policy.PolicyCallback) error {
	callback(p.policies)
	return nil
}

func (p *staticLogProvider) SetStatsCollector(collector policy.StatsCollector) {}

func createTestLogProcessor(t *testing.T, policies []*policyv1.Policy) *policyProcessor {
	registry := policy.NewPolicyRegistry()
	engine := policy.NewPolicyEngine(registry)

	provider := &staticLogProvider{policies: policies}
	_, err := registry.Register(provider)
	require.NoError(t, err)

	return &policyProcessor{
		logger:   zap.NewNop(),
		registry: registry,
		engine:   engine,
	}
}

func TestProcessLogs_NoPolicy(t *testing.T) {
	p := createTestLogProcessor(t, nil)

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	sl.LogRecords().AppendEmpty().Body().SetStr("message0")
	sl.LogRecords().AppendEmpty().Body().SetStr("message1")
	sl.LogRecords().AppendEmpty().Body().SetStr("message2")

	result, err := p.processLogs(context.Background(), logs)

	require.NoError(t, err)
	assert.Equal(t, 3, result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().Len())
}

func TestProcessLogs_DropByBody(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-debug",
			Name:    "Drop Debug",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "debug"},
						},
					},
					Keep: "none",
				},
			},
		},
	}

	p := createTestLogProcessor(t, policies)

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	sl.LogRecords().AppendEmpty().Body().SetStr("debug message")
	sl.LogRecords().AppendEmpty().Body().SetStr("info message")
	sl.LogRecords().AppendEmpty().Body().SetStr("debug another")

	result, err := p.processLogs(context.Background(), logs)

	require.NoError(t, err)
	records := result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	assert.Equal(t, 1, records.Len())
	assert.Equal(t, "info message", records.At(0).Body().Str())
}

func TestProcessLogs_DropBySeverity(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-debug-severity",
			Name:    "Drop Debug Severity",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
							Match: &policyv1.LogMatcher_Exact{Exact: "DEBUG"},
						},
					},
					Keep: "none",
				},
			},
		},
	}

	p := createTestLogProcessor(t, policies)

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	lr1 := sl.LogRecords().AppendEmpty()
	lr1.SetSeverityText("DEBUG")
	lr1.Body().SetStr("debug log")

	lr2 := sl.LogRecords().AppendEmpty()
	lr2.SetSeverityText("INFO")
	lr2.Body().SetStr("info log")

	lr3 := sl.LogRecords().AppendEmpty()
	lr3.SetSeverityText("ERROR")
	lr3.Body().SetStr("error log")

	result, err := p.processLogs(context.Background(), logs)

	require.NoError(t, err)
	records := result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	assert.Equal(t, 2, records.Len())
}

func TestProcessLogs_DropByAttribute(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-by-env",
			Name:    "Drop By Env",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"environment"}}},
							Match: &policyv1.LogMatcher_Exact{Exact: "test"},
						},
					},
					Keep: "none",
				},
			},
		},
	}

	p := createTestLogProcessor(t, policies)

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	lr1 := sl.LogRecords().AppendEmpty()
	lr1.Attributes().PutStr("environment", "test")

	lr2 := sl.LogRecords().AppendEmpty()
	lr2.Attributes().PutStr("environment", "production")

	lr3 := sl.LogRecords().AppendEmpty()
	lr3.Attributes().PutStr("environment", "test")

	result, err := p.processLogs(context.Background(), logs)

	require.NoError(t, err)
	records := result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	assert.Equal(t, 1, records.Len())
	val, _ := records.At(0).Attributes().Get("environment")
	assert.Equal(t, "production", val.Str())
}

func TestProcessLogs_DropByResourceAttribute(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-by-service",
			Name:    "Drop By Service",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{Path: []string{"service.name"}}},
							Match: &policyv1.LogMatcher_Exact{Exact: "noisy-service"},
						},
					},
					Keep: "none",
				},
			},
		},
	}

	p := createTestLogProcessor(t, policies)

	logs := plog.NewLogs()

	// First resource - noisy service (should be dropped)
	rl1 := logs.ResourceLogs().AppendEmpty()
	rl1.Resource().Attributes().PutStr("service.name", "noisy-service")
	sl1 := rl1.ScopeLogs().AppendEmpty()
	sl1.LogRecords().AppendEmpty().Body().SetStr("log from noisy service")

	// Second resource - important service (should be kept)
	rl2 := logs.ResourceLogs().AppendEmpty()
	rl2.Resource().Attributes().PutStr("service.name", "important-service")
	sl2 := rl2.ScopeLogs().AppendEmpty()
	sl2.LogRecords().AppendEmpty().Body().SetStr("log from important service")

	result, err := p.processLogs(context.Background(), logs)

	require.NoError(t, err)
	// First resource should be removed entirely (all logs dropped)
	// Only the important-service resource should remain
	assert.Equal(t, 1, result.ResourceLogs().Len())
	serviceName, _ := result.ResourceLogs().At(0).Resource().Attributes().Get("service.name")
	assert.Equal(t, "important-service", serviceName.Str())
	assert.Equal(t, 1, result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().Len())
}

func TestProcessLogs_TransformRedactAttribute(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "redact-api-key",
			Name:    "Redact API Key",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogAttribute{
								LogAttribute: &policyv1.AttributePath{Path: []string{"api_key"}},
							},
							Match: &policyv1.LogMatcher_Exists{Exists: true},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Redact: []*policyv1.LogRedact{
							{
								Field: &policyv1.LogRedact_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"api_key"}},
								},
								Replacement: "[REDACTED]",
							},
						},
					},
				},
			},
		},
	}

	p := createTestLogProcessor(t, policies)

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	lr1 := sl.LogRecords().AppendEmpty()
	lr1.Body().SetStr("request with key")
	lr1.Attributes().PutStr("api_key", "secret-123")

	lr2 := sl.LogRecords().AppendEmpty()
	lr2.Body().SetStr("request without key")

	result, err := p.processLogs(context.Background(), logs)

	require.NoError(t, err)
	records := result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	assert.Equal(t, 2, records.Len())

	// First record should have redacted api_key
	val, exists := records.At(0).Attributes().Get("api_key")
	assert.True(t, exists)
	assert.Equal(t, "[REDACTED]", val.Str())

	// Second record should be untouched (no api_key to match)
	_, exists = records.At(1).Attributes().Get("api_key")
	assert.False(t, exists)
}

func TestProcessLogs_TransformRemoveAttribute(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "remove-secret",
			Name:    "Remove Secret",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogAttribute{
								LogAttribute: &policyv1.AttributePath{Path: []string{"secret"}},
							},
							Match: &policyv1.LogMatcher_Exists{Exists: true},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Remove: []*policyv1.LogRemove{
							{
								Field: &policyv1.LogRemove_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"secret"}},
								},
							},
						},
					},
				},
			},
		},
	}

	p := createTestLogProcessor(t, policies)

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	lr := sl.LogRecords().AppendEmpty()
	lr.Body().SetStr("message")
	lr.Attributes().PutStr("secret", "super-secret")
	lr.Attributes().PutStr("keep_me", "ok")

	result, err := p.processLogs(context.Background(), logs)

	require.NoError(t, err)
	records := result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	assert.Equal(t, 1, records.Len())

	_, exists := records.At(0).Attributes().Get("secret")
	assert.False(t, exists)
	val, exists := records.At(0).Attributes().Get("keep_me")
	assert.True(t, exists)
	assert.Equal(t, "ok", val.Str())
}

func TestProcessLogs_TransformAddAttribute(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "add-processed",
			Name:    "Add Processed Flag",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "important"},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Add: []*policyv1.LogAdd{
							{
								Field: &policyv1.LogAdd_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"processed"}},
								},
								Value:  "true",
								Upsert: true,
							},
						},
					},
				},
			},
		},
	}

	p := createTestLogProcessor(t, policies)

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	lr1 := sl.LogRecords().AppendEmpty()
	lr1.Body().SetStr("important message")

	lr2 := sl.LogRecords().AppendEmpty()
	lr2.Body().SetStr("boring message")

	result, err := p.processLogs(context.Background(), logs)

	require.NoError(t, err)
	records := result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	assert.Equal(t, 2, records.Len())

	// First record should have "processed" attribute added
	val, exists := records.At(0).Attributes().Get("processed")
	assert.True(t, exists)
	assert.Equal(t, "true", val.Str())

	// Second record should not have "processed" (no match)
	_, exists = records.At(1).Attributes().Get("processed")
	assert.False(t, exists)
}

func TestProcessLogs_TransformAllOps(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "all-transforms",
			Name:    "All Transform Types",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "test"},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Remove: []*policyv1.LogRemove{
							{
								Field: &policyv1.LogRemove_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"secret"}},
								},
							},
						},
						Redact: []*policyv1.LogRedact{
							{
								Field: &policyv1.LogRedact_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"api_key"}},
								},
								Replacement: "***",
							},
						},
						Rename: []*policyv1.LogRename{
							{
								From: &policyv1.LogRename_FromLogAttribute{
									FromLogAttribute: &policyv1.AttributePath{Path: []string{"old_key"}},
								},
								To:     "new_key",
								Upsert: true,
							},
						},
						Add: []*policyv1.LogAdd{
							{
								Field: &policyv1.LogAdd_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"env"}},
								},
								Value:  "production",
								Upsert: false,
							},
						},
					},
				},
			},
		},
	}

	p := createTestLogProcessor(t, policies)

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	lr := sl.LogRecords().AppendEmpty()
	lr.Body().SetStr("test message")
	lr.Attributes().PutStr("secret", "super-secret-value")
	lr.Attributes().PutStr("api_key", "key-123")
	lr.Attributes().PutStr("old_key", "some-value")
	lr.Attributes().PutStr("keep_me", "untouched")

	result, err := p.processLogs(context.Background(), logs)

	require.NoError(t, err)
	records := result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	assert.Equal(t, 1, records.Len())

	rec := records.At(0)

	// Remove: "secret" should be gone
	_, exists := rec.Attributes().Get("secret")
	assert.False(t, exists)

	// Redact: "api_key" should be replaced
	val, exists := rec.Attributes().Get("api_key")
	assert.True(t, exists)
	assert.Equal(t, "***", val.Str())

	// Rename: "old_key" gone, "new_key" has its value
	_, exists = rec.Attributes().Get("old_key")
	assert.False(t, exists)
	val, exists = rec.Attributes().Get("new_key")
	assert.True(t, exists)
	assert.Equal(t, "some-value", val.Str())

	// Add: "env" should be added
	val, exists = rec.Attributes().Get("env")
	assert.True(t, exists)
	assert.Equal(t, "production", val.Str())

	// Untouched attributes remain
	val, exists = rec.Attributes().Get("keep_me")
	assert.True(t, exists)
	assert.Equal(t, "untouched", val.Str())
}

func TestProcessLogs_TransformNotAppliedOnDrop(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-with-transform",
			Name:    "Drop With Transform",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "debug"},
						},
					},
					Keep: "none",
					Transform: &policyv1.LogTransform{
						Add: []*policyv1.LogAdd{
							{
								Field: &policyv1.LogAdd_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"should_not_exist"}},
								},
								Value:  "true",
								Upsert: true,
							},
						},
					},
				},
			},
		},
	}

	p := createTestLogProcessor(t, policies)

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	sl.LogRecords().AppendEmpty().Body().SetStr("debug message")
	sl.LogRecords().AppendEmpty().Body().SetStr("info message")

	result, err := p.processLogs(context.Background(), logs)

	require.NoError(t, err)
	records := result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	// debug message should be dropped
	assert.Equal(t, 1, records.Len())
	assert.Equal(t, "info message", records.At(0).Body().Str())
}

func TestProcessLogs_TransformRedactBody(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "redact-body",
			Name:    "Redact Body",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
							Match: &policyv1.LogMatcher_Exact{Exact: "DEBUG"},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Redact: []*policyv1.LogRedact{
							{
								Field: &policyv1.LogRedact_LogField{
									LogField: policyv1.LogField_LOG_FIELD_BODY,
								},
								Replacement: "[DEBUG LOG REDACTED]",
							},
						},
					},
				},
			},
		},
	}

	p := createTestLogProcessor(t, policies)

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	lr1 := sl.LogRecords().AppendEmpty()
	lr1.SetSeverityText("DEBUG")
	lr1.Body().SetStr("sensitive debug info")

	lr2 := sl.LogRecords().AppendEmpty()
	lr2.SetSeverityText("INFO")
	lr2.Body().SetStr("normal info message")

	result, err := p.processLogs(context.Background(), logs)

	require.NoError(t, err)
	records := result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	assert.Equal(t, 2, records.Len())

	// DEBUG log should have redacted body
	assert.Equal(t, "[DEBUG LOG REDACTED]", records.At(0).Body().Str())
	// INFO log should be untouched
	assert.Equal(t, "normal info message", records.At(1).Body().Str())
}

func TestProcessLogs_KeepAll(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "keep-errors",
			Name:    "Keep Errors",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
							Match: &policyv1.LogMatcher_Exact{Exact: "ERROR"},
						},
					},
					Keep: "all",
				},
			},
		},
	}

	p := createTestLogProcessor(t, policies)

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	lr1 := sl.LogRecords().AppendEmpty()
	lr1.SetSeverityText("ERROR")

	lr2 := sl.LogRecords().AppendEmpty()
	lr2.SetSeverityText("INFO")

	result, err := p.processLogs(context.Background(), logs)

	require.NoError(t, err)
	// Both kept - ERROR matches policy with keep=all, INFO has no match
	assert.Equal(t, 2, result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().Len())
}

func TestProcessLogs_MultiplePolicies(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-debug",
			Name:    "Drop Debug",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
							Match: &policyv1.LogMatcher_Exact{Exact: "DEBUG"},
						},
					},
					Keep: "none",
				},
			},
		},
		{
			Id:      "drop-trace",
			Name:    "Drop Trace",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
							Match: &policyv1.LogMatcher_Exact{Exact: "TRACE"},
						},
					},
					Keep: "none",
				},
			},
		},
	}

	p := createTestLogProcessor(t, policies)

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	severities := []string{"DEBUG", "TRACE", "INFO", "WARN", "ERROR"}
	for _, sev := range severities {
		lr := sl.LogRecords().AppendEmpty()
		lr.SetSeverityText(sev)
	}

	result, err := p.processLogs(context.Background(), logs)

	require.NoError(t, err)
	records := result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	assert.Equal(t, 3, records.Len()) // INFO, WARN, ERROR kept
}

func TestProcessLogs_MultipleMatchers(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-debug-from-noisy",
			Name:    "Drop Debug From Noisy",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
							Match: &policyv1.LogMatcher_Exact{Exact: "DEBUG"},
						},
						{
							Field: &policyv1.LogMatcher_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{Path: []string{"service.name"}}},
							Match: &policyv1.LogMatcher_Exact{Exact: "noisy-service"},
						},
					},
					Keep: "none",
				},
			},
		},
	}

	p := createTestLogProcessor(t, policies)

	logs := plog.NewLogs()

	// Noisy service with DEBUG - should be dropped
	rl1 := logs.ResourceLogs().AppendEmpty()
	rl1.Resource().Attributes().PutStr("service.name", "noisy-service")
	sl1 := rl1.ScopeLogs().AppendEmpty()
	lr1 := sl1.LogRecords().AppendEmpty()
	lr1.SetSeverityText("DEBUG")

	// Noisy service with INFO - should be kept (doesn't match both matchers)
	lr2 := sl1.LogRecords().AppendEmpty()
	lr2.SetSeverityText("INFO")

	// Other service with DEBUG - should be kept (doesn't match resource attribute)
	rl2 := logs.ResourceLogs().AppendEmpty()
	rl2.Resource().Attributes().PutStr("service.name", "other-service")
	sl2 := rl2.ScopeLogs().AppendEmpty()
	lr3 := sl2.LogRecords().AppendEmpty()
	lr3.SetSeverityText("DEBUG")

	result, err := p.processLogs(context.Background(), logs)

	require.NoError(t, err)
	// Noisy service should have 1 log (INFO)
	assert.Equal(t, 1, result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().Len())
	// Other service should have 1 log (DEBUG)
	assert.Equal(t, 1, result.ResourceLogs().At(1).ScopeLogs().At(0).LogRecords().Len())
}

func TestProcessLogs_RegexMatching(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-health-checks",
			Name:    "Drop Health Checks",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Regex{Regex: "GET /health.*"},
						},
					},
					Keep: "none",
				},
			},
		},
	}

	p := createTestLogProcessor(t, policies)

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	bodies := []string{
		"GET /health",
		"GET /healthz",
		"GET /health/ready",
		"GET /api/users",
		"POST /health",
	}
	for _, body := range bodies {
		lr := sl.LogRecords().AppendEmpty()
		lr.Body().SetStr(body)
	}

	result, err := p.processLogs(context.Background(), logs)

	require.NoError(t, err)
	records := result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	assert.Equal(t, 2, records.Len()) // GET /api/users and POST /health
}

func TestProcessLogs_MultipleResourcesAndScopes(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-debug",
			Name:    "Drop Debug",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
							Match: &policyv1.LogMatcher_Exact{Exact: "DEBUG"},
						},
					},
					Keep: "none",
				},
			},
		},
	}

	p := createTestLogProcessor(t, policies)

	logs := plog.NewLogs()

	// Resource 1, Scope 1
	rl1 := logs.ResourceLogs().AppendEmpty()
	rl1.Resource().Attributes().PutStr("service.name", "service-a")
	sl1a := rl1.ScopeLogs().AppendEmpty()
	sl1a.Scope().SetName("scope-1")
	sl1a.LogRecords().AppendEmpty().SetSeverityText("DEBUG")
	sl1a.LogRecords().AppendEmpty().SetSeverityText("INFO")

	// Resource 1, Scope 2
	sl1b := rl1.ScopeLogs().AppendEmpty()
	sl1b.Scope().SetName("scope-2")
	sl1b.LogRecords().AppendEmpty().SetSeverityText("DEBUG")
	sl1b.LogRecords().AppendEmpty().SetSeverityText("ERROR")

	// Resource 2, Scope 1
	rl2 := logs.ResourceLogs().AppendEmpty()
	rl2.Resource().Attributes().PutStr("service.name", "service-b")
	sl2 := rl2.ScopeLogs().AppendEmpty()
	sl2.Scope().SetName("scope-1")
	sl2.LogRecords().AppendEmpty().SetSeverityText("DEBUG")
	sl2.LogRecords().AppendEmpty().SetSeverityText("WARN")

	result, err := p.processLogs(context.Background(), logs)

	require.NoError(t, err)

	// Resource 1, Scope 1: 1 log (INFO)
	assert.Equal(t, 1, result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().Len())
	// Resource 1, Scope 2: 1 log (ERROR)
	assert.Equal(t, 1, result.ResourceLogs().At(0).ScopeLogs().At(1).LogRecords().Len())
	// Resource 2, Scope 1: 1 log (WARN)
	assert.Equal(t, 1, result.ResourceLogs().At(1).ScopeLogs().At(0).LogRecords().Len())
}

func TestProcessLogs_EmptyLogs(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-all",
			Name:    "Drop All",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Regex{Regex: ".*"},
						},
					},
					Keep: "none",
				},
			},
		},
	}

	p := createTestLogProcessor(t, policies)
	logs := plog.NewLogs()

	result, err := p.processLogs(context.Background(), logs)

	require.NoError(t, err)
	assert.Equal(t, 0, result.ResourceLogs().Len())
}

func TestProcessLogs_TraceContext(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-by-trace",
			Name:    "Drop By Trace",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_TRACE_ID},
							Match: &policyv1.LogMatcher_Exact{Exact: "trace-id-abc1234"},
						},
					},
					Keep: "none",
				},
			},
		},
	}

	p := createTestLogProcessor(t, policies)

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	// Log with matching trace ID (raw bytes of "trace-id-abc1234")
	lr1 := sl.LogRecords().AppendEmpty()
	var traceID1 pcommon.TraceID
	copy(traceID1[:], "trace-id-abc1234")
	lr1.SetTraceID(traceID1)

	// Log with different trace ID
	lr2 := sl.LogRecords().AppendEmpty()
	var traceID2 pcommon.TraceID
	copy(traceID2[:], "trace-id-def5678")
	lr2.SetTraceID(traceID2)

	// Log without trace ID
	sl.LogRecords().AppendEmpty()

	result, err := p.processLogs(context.Background(), logs)

	require.NoError(t, err)
	assert.Equal(t, 2, result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().Len())
}

// TestProcessLogs_CompoundTransformsAcrossPolicies verifies that transforms from
// multiple matching policies are applied in alphanumeric order by policy ID.
// This mirrors the conformance test "compound_transforms_across_policies".
func TestProcessLogs_CompoundTransformsAcrossPolicies(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "add-env-tag",
			Name:    "Add environment tag",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Regex{Regex: "^.*$"},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Add: []*policyv1.LogAdd{
							{
								Field: &policyv1.LogAdd_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"env"}},
								},
								Value:  "production",
								Upsert: true,
							},
						},
					},
				},
			},
		},
		{
			Id:      "add-region-tag",
			Name:    "Add region tag",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Regex{Regex: "^.*$"},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Add: []*policyv1.LogAdd{
							{
								Field: &policyv1.LogAdd_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"region"}},
								},
								Value:  "us-east-1",
								Upsert: true,
							},
						},
					},
				},
			},
		},
		{
			Id:      "add-team-tag",
			Name:    "Add team tag",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_ResourceAttribute{
								ResourceAttribute: &policyv1.AttributePath{Path: []string{"service.name"}},
							},
							Match: &policyv1.LogMatcher_Exact{Exact: "api-server"},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Add: []*policyv1.LogAdd{
							{
								Field: &policyv1.LogAdd_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"team"}},
								},
								Value:  "platform",
								Upsert: true,
							},
						},
					},
				},
			},
		},
		{
			Id:      "redact-secrets",
			Name:    "Redact secret attribute",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogAttribute{
								LogAttribute: &policyv1.AttributePath{Path: []string{"secret"}},
							},
							Match: &policyv1.LogMatcher_Exists{Exists: true},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Redact: []*policyv1.LogRedact{
							{
								Field: &policyv1.LogRedact_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"secret"}},
								},
								Replacement: "[REDACTED]",
							},
						},
					},
				},
			},
		},
		{
			Id:      "rename-legacy-attr",
			Name:    "Rename legacy attribute",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogAttribute{
								LogAttribute: &policyv1.AttributePath{Path: []string{"old_name"}},
							},
							Match: &policyv1.LogMatcher_Exists{Exists: true},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Rename: []*policyv1.LogRename{
							{
								From: &policyv1.LogRename_FromLogAttribute{
									FromLogAttribute: &policyv1.AttributePath{Path: []string{"old_name"}},
								},
								To:     "new_name",
								Upsert: true,
							},
						},
					},
				},
			},
		},
	}

	p := createTestLogProcessor(t, policies)

	// Helper to collect attribute keys in order from a log record.
	attrKeys := func(lr plog.LogRecord) []string {
		var keys []string
		lr.Attributes().Range(func(k string, _ pcommon.Value) bool {
			keys = append(keys, k)
			return true
		})
		return keys
	}

	// Batch 1: resource "api-server" with 3 log records.
	t.Run("batch1_api_server", func(t *testing.T) {
		logs := plog.NewLogs()
		rl := logs.ResourceLogs().AppendEmpty()
		rl.Resource().Attributes().PutStr("service.name", "api-server")
		sl := rl.ScopeLogs().AppendEmpty()

		// Log 1: normal log (no attributes) — matches add-env, add-region, add-team
		lr1 := sl.LogRecords().AppendEmpty()
		lr1.SetSeverityText("INFO")
		lr1.Body().SetStr("normal log")

		// Log 2: log with secret — matches add-env, add-region, add-team, redact-secrets
		lr2 := sl.LogRecords().AppendEmpty()
		lr2.SetSeverityText("INFO")
		lr2.Body().SetStr("log with secret")
		lr2.Attributes().PutStr("secret", "my-api-key-12345")

		// Log 3: log with legacy attr — matches add-env, add-region, add-team, rename-legacy-attr
		lr3 := sl.LogRecords().AppendEmpty()
		lr3.SetSeverityText("INFO")
		lr3.Body().SetStr("log with legacy attr")
		lr3.Attributes().PutStr("old_name", "important-value")

		result, err := p.processLogs(context.Background(), logs)
		require.NoError(t, err)

		records := result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
		require.Equal(t, 3, records.Len())

		// Record 1: "normal log" — transforms applied in alphanumeric policy ID order:
		// add-env-tag → add-region-tag → add-team-tag
		// Expected attribute order: env, region, team
		rec1 := records.At(0)
		assert.Equal(t, []string{"env", "region", "team"}, attrKeys(rec1))
		val, _ := rec1.Attributes().Get("env")
		assert.Equal(t, "production", val.Str())
		val, _ = rec1.Attributes().Get("region")
		assert.Equal(t, "us-east-1", val.Str())
		val, _ = rec1.Attributes().Get("team")
		assert.Equal(t, "platform", val.Str())

		// Record 2: "log with secret" — transforms applied in order:
		// add-env-tag → add-region-tag → add-team-tag → redact-secrets
		// Expected attribute order: secret, env, region, team
		// (secret was already present and gets redacted in-place)
		rec2 := records.At(1)
		assert.Equal(t, []string{"secret", "env", "region", "team"}, attrKeys(rec2))
		val, _ = rec2.Attributes().Get("secret")
		assert.Equal(t, "[REDACTED]", val.Str())

		// Record 3: "log with legacy attr" — transforms applied in order:
		// add-env-tag → add-region-tag → add-team-tag → rename-legacy-attr
		// Expected attribute order: env, region, team, new_name
		// (old_name is removed and new_name is added at the end)
		rec3 := records.At(2)
		assert.Equal(t, []string{"env", "region", "team", "new_name"}, attrKeys(rec3))
		val, _ = rec3.Attributes().Get("new_name")
		assert.Equal(t, "important-value", val.Str())
	})

	// Batch 2: resource "worker-service" with 1 log record.
	t.Run("batch2_worker_service", func(t *testing.T) {
		logs := plog.NewLogs()
		rl := logs.ResourceLogs().AppendEmpty()
		rl.Resource().Attributes().PutStr("service.name", "worker-service")
		sl := rl.ScopeLogs().AppendEmpty()

		// Log with both secret and old_name — matches add-env, add-region, redact-secrets, rename-legacy-attr
		// (NOT add-team-tag, since resource is worker-service, not api-server)
		lr := sl.LogRecords().AppendEmpty()
		lr.SetSeverityText("INFO")
		lr.Body().SetStr("worker processing")
		lr.Attributes().PutStr("secret", "another-secret")
		lr.Attributes().PutStr("old_name", "legacy-data")

		result, err := p.processLogs(context.Background(), logs)
		require.NoError(t, err)

		records := result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
		require.Equal(t, 1, records.Len())

		// Transforms applied in alphanumeric policy ID order:
		// add-env-tag → add-region-tag → redact-secrets → rename-legacy-attr
		// Expected attribute order: secret, env, region, new_name
		rec := records.At(0)
		assert.Equal(t, []string{"secret", "env", "region", "new_name"}, attrKeys(rec))
		val, _ := rec.Attributes().Get("secret")
		assert.Equal(t, "[REDACTED]", val.Str())
		val, _ = rec.Attributes().Get("env")
		assert.Equal(t, "production", val.Str())
		val, _ = rec.Attributes().Get("region")
		assert.Equal(t, "us-east-1", val.Str())
		val, _ = rec.Attributes().Get("new_name")
		assert.Equal(t, "legacy-data", val.Str())
	})
}

func TestProcessLogs_ScopeAttributes(t *testing.T) {
	policies := []*policyv1.Policy{
		{
			Id:      "drop-by-scope",
			Name:    "Drop By Scope",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_ScopeAttribute{ScopeAttribute: &policyv1.AttributePath{Path: []string{"library.name"}}},
							Match: &policyv1.LogMatcher_Exact{Exact: "noisy-lib"},
						},
					},
					Keep: "none",
				},
			},
		},
	}

	p := createTestLogProcessor(t, policies)

	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()

	// Scope with noisy lib
	sl1 := rl.ScopeLogs().AppendEmpty()
	sl1.Scope().Attributes().PutStr("library.name", "noisy-lib")
	sl1.LogRecords().AppendEmpty().Body().SetStr("from noisy lib")

	// Scope with other lib
	sl2 := rl.ScopeLogs().AppendEmpty()
	sl2.Scope().Attributes().PutStr("library.name", "good-lib")
	sl2.LogRecords().AppendEmpty().Body().SetStr("from good lib")

	result, err := p.processLogs(context.Background(), logs)

	require.NoError(t, err)
	// First scope (noisy-lib) should be removed entirely
	// Only good-lib scope should remain
	assert.Equal(t, 1, result.ResourceLogs().At(0).ScopeLogs().Len())
	libName, _ := result.ResourceLogs().At(0).ScopeLogs().At(0).Scope().Attributes().Get("library.name")
	assert.Equal(t, "good-lib", libName.Str())
	assert.Equal(t, 1, result.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().Len())
}
