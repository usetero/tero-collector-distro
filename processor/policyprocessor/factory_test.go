package policyprocessor

import (
	"context"
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

	pcfg, ok := cfg.(*Config)
	if !ok {
		t.Fatal("config is not of type *Config")
	}
	if !pcfg.Enabled {
		t.Error("expected Enabled to be true by default")
	}
}

func TestCreateTracesProcessor(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
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

	// Test lifecycle
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
	cfg := factory.CreateDefaultConfig()
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

	// Test lifecycle
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
	cfg := factory.CreateDefaultConfig()
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

	// Test lifecycle
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
	cfg := factory.CreateDefaultConfig()
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

	// Create test traces
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

	// Verify traces were passed through
	if len(sink.AllTraces()) != 1 {
		t.Errorf("expected 1 trace, got %d", len(sink.AllTraces()))
	}
}

func TestProcessMetrics(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
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

	// Create test metrics
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

	// Verify metrics were passed through
	if len(sink.AllMetrics()) != 1 {
		t.Errorf("expected 1 metrics, got %d", len(sink.AllMetrics()))
	}
}

func TestProcessLogs(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
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

	// Create test logs
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", "test-service")
	sl := rl.ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()
	lr.Body().SetStr("test log message")

	err = proc.ConsumeLogs(ctx, ld)
	if err != nil {
		t.Fatalf("ConsumeLogs() error: %v", err)
	}

	// Verify logs were passed through
	if len(sink.AllLogs()) != 1 {
		t.Errorf("expected 1 logs, got %d", len(sink.AllLogs()))
	}
}
