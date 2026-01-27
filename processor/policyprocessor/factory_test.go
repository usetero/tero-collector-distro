package policyprocessor

import (
	"context"
	"path/filepath"
	"testing"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor/processortest"
)

var testType = component.MustNewType("policy")

func testPolicyFile() string {
	return filepath.Join("testdata", "policies.json")
}

func TestNewFactory(t *testing.T) {
	factory := NewFactory()
	if factory == nil {
		t.Fatal("NewFactory() returned nil")
	}
	if factory.Type().String() != "policy" {
		t.Errorf("expected type 'policy', got '%s'", factory.Type().String())
	}
}

func TestCreateDefaultConfig(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
	if cfg == nil {
		t.Fatal("CreateDefaultConfig() returned nil")
	}

	_, ok := cfg.(*Config)
	if !ok {
		t.Fatal("config is not of type *Config")
	}
}

func TestCreateTracesProcessor(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.PolicyFile = testPolicyFile()

	ctx := context.Background()
	set := processortest.NewNopSettings(testType)
	next := consumertest.NewNop()

	proc, err := factory.CreateTraces(ctx, set, cfg, next)
	if err != nil {
		t.Fatalf("CreateTraces() error: %v", err)
	}
	if proc == nil {
		t.Fatal("CreateTraces() returned nil processor")
	}

	err = proc.Start(ctx, componenttest.NewNopHost())
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	err = proc.Shutdown(ctx)
	if err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}
}

func TestCreateMetricsProcessor(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.PolicyFile = testPolicyFile()

	ctx := context.Background()
	set := processortest.NewNopSettings(testType)
	next := consumertest.NewNop()

	proc, err := factory.CreateMetrics(ctx, set, cfg, next)
	if err != nil {
		t.Fatalf("CreateMetrics() error: %v", err)
	}
	if proc == nil {
		t.Fatal("CreateMetrics() returned nil processor")
	}

	err = proc.Start(ctx, componenttest.NewNopHost())
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	err = proc.Shutdown(ctx)
	if err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}
}

func TestCreateLogsProcessor(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.PolicyFile = testPolicyFile()

	ctx := context.Background()
	set := processortest.NewNopSettings(testType)
	next := consumertest.NewNop()

	proc, err := factory.CreateLogs(ctx, set, cfg, next)
	if err != nil {
		t.Fatalf("CreateLogs() error: %v", err)
	}
	if proc == nil {
		t.Fatal("CreateLogs() returned nil processor")
	}

	err = proc.Start(ctx, componenttest.NewNopHost())
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	err = proc.Shutdown(ctx)
	if err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}
}

func TestProcessTraces(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.PolicyFile = testPolicyFile()

	ctx := context.Background()
	set := processortest.NewNopSettings(testType)
	sink := new(consumertest.TracesSink)

	proc, err := factory.CreateTraces(ctx, set, cfg, sink)
	if err != nil {
		t.Fatalf("CreateTraces() error: %v", err)
	}

	err = proc.Start(ctx, componenttest.NewNopHost())
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer proc.Shutdown(ctx)

	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", "test-service")
	ss := rs.ScopeSpans().AppendEmpty()
	span := ss.Spans().AppendEmpty()
	span.SetName("test-span")

	err = proc.ConsumeTraces(ctx, td)
	if err != nil {
		t.Fatalf("ConsumeTraces() error: %v", err)
	}

	if len(sink.AllTraces()) != 1 {
		t.Errorf("expected 1 trace, got %d", len(sink.AllTraces()))
	}
}

func TestProcessMetrics(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.PolicyFile = testPolicyFile()

	ctx := context.Background()
	set := processortest.NewNopSettings(testType)
	sink := new(consumertest.MetricsSink)

	proc, err := factory.CreateMetrics(ctx, set, cfg, sink)
	if err != nil {
		t.Fatalf("CreateMetrics() error: %v", err)
	}

	err = proc.Start(ctx, componenttest.NewNopHost())
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer proc.Shutdown(ctx)

	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("service.name", "test-service")
	sm := rm.ScopeMetrics().AppendEmpty()
	m := sm.Metrics().AppendEmpty()
	m.SetName("test-metric")

	err = proc.ConsumeMetrics(ctx, md)
	if err != nil {
		t.Fatalf("ConsumeMetrics() error: %v", err)
	}

	if len(sink.AllMetrics()) != 1 {
		t.Errorf("expected 1 metrics, got %d", len(sink.AllMetrics()))
	}
}

func TestProcessLogs_PassThrough(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.PolicyFile = testPolicyFile()

	ctx := context.Background()
	set := processortest.NewNopSettings(testType)
	sink := new(consumertest.LogsSink)

	proc, err := factory.CreateLogs(ctx, set, cfg, sink)
	if err != nil {
		t.Fatalf("CreateLogs() error: %v", err)
	}

	err = proc.Start(ctx, componenttest.NewNopHost())
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer proc.Shutdown(ctx)

	// INFO log should pass through (not matched by drop-debug policy)
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", "test-service")
	sl := rl.ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()
	lr.Body().SetStr("info log message")
	lr.SetSeverityText("INFO")

	err = proc.ConsumeLogs(ctx, ld)
	if err != nil {
		t.Fatalf("ConsumeLogs() error: %v", err)
	}

	if len(sink.AllLogs()) != 1 {
		t.Errorf("expected 1 log batch, got %d", len(sink.AllLogs()))
	}
}

func TestProcessLogs_Drop(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.PolicyFile = testPolicyFile()

	ctx := context.Background()
	set := processortest.NewNopSettings(testType)
	sink := new(consumertest.LogsSink)

	proc, err := factory.CreateLogs(ctx, set, cfg, sink)
	if err != nil {
		t.Fatalf("CreateLogs() error: %v", err)
	}

	err = proc.Start(ctx, componenttest.NewNopHost())
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer proc.Shutdown(ctx)

	// DEBUG log should be dropped by the policy
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", "test-service")
	sl := rl.ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()
	lr.Body().SetStr("debug log message")
	lr.SetSeverityText("DEBUG")

	err = proc.ConsumeLogs(ctx, ld)
	if err != nil {
		t.Fatalf("ConsumeLogs() error: %v", err)
	}

	// Log batch is sent but should have 0 records
	if len(sink.AllLogs()) != 1 {
		t.Fatalf("expected 1 log batch, got %d", len(sink.AllLogs()))
	}

	logs := sink.AllLogs()[0]
	recordCount := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().Len()
	if recordCount != 0 {
		t.Errorf("expected 0 log records (dropped), got %d", recordCount)
	}
}
