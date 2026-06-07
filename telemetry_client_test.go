package main

import (
	"bufio"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestTelemetryEventRedaction is the privacy guard: the JSON we ship must
// contain ONLY metadata fields. If anyone adds a query/sql/body/params field
// to TelemetryEvent, this test fails — keeping query content off our servers.
func TestTelemetryEventRedaction(t *testing.T) {
	ev := TelemetryEvent{
		EventType:      "blocked",
		Decision:       "block",
		TableName:      "users",
		OpType:         "DELETE",
		LatencyMs:      0.42,
		CostFlag:       true,
		RiskScore:      0.91,
		P99BreachProb:  0.5,
		QWMThresholdMs: 500,
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	allowed := map[string]bool{
		"event_type": true, "decision": true, "table_name": true,
		"op_type": true, "latency_ms": true, "cost_flag": true,
		"risk_score": true, "p99_breach_prob": true, "qwm_threshold_ms": true,
	}
	for k := range m {
		if !allowed[k] {
			t.Errorf("UNEXPECTED telemetry field %q — telemetry must be metadata-only", k)
		}
	}

	// Explicit forbidden-field assertions (defense in depth).
	for _, forbidden := range []string{"query", "sql", "body", "params", "rows", "row_data", "text", "policy"} {
		if _, ok := m[forbidden]; ok {
			t.Errorf("forbidden field %q present in telemetry payload", forbidden)
		}
	}

	// And the raw JSON must not contain a literal query string anywhere.
	if strings.Contains(string(b), "SELECT") || strings.Contains(string(b), "FROM") {
		t.Errorf("telemetry JSON appears to contain query text: %s", b)
	}
}

// TestTelemetryPayloadShape verifies the batch envelope matches what the
// control plane's POST /v1/telemetry handler expects.
func TestTelemetryPayloadShape(t *testing.T) {
	p := telemetryPayload{
		InstallationID: "inst-123",
		Events: []TelemetryEvent{
			{EventType: "allowed", Decision: "allow", TableName: "orders", OpType: "SELECT", LatencyMs: 0.1},
		},
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["installation_id"]; !ok {
		t.Error("missing installation_id")
	}
	evs, ok := m["events"].([]any)
	if !ok || len(evs) != 1 {
		t.Fatalf("expected 1 event, got %v", m["events"])
	}
}

// TestTelemetryClientNonBlocking verifies Emit never blocks, even when the
// buffer overflows — the sub-3ms hot-path promise. We install a flushFn that
// blocks, fill far past the buffer, and assert Emit returns quickly.
func TestTelemetryClientNonBlocking(t *testing.T) {
	var mu sync.Mutex
	var flushed int

	tc := &TelemetryClient{
		cfg:  ControlPlaneConfig{URL: "http://example.invalid", Token: "x"},
		ch:   make(chan TelemetryEvent, 8),
		stop: make(chan struct{}),
	}
	tc.flushFn = func(events []TelemetryEvent) {
		mu.Lock()
		flushed += len(events)
		mu.Unlock()
		time.Sleep(20 * time.Millisecond) // simulate slow network
	}
	tc.wg.Add(1)
	go tc.run()
	defer tc.Close()

	start := time.Now()
	for i := 0; i < 10000; i++ {
		tc.Emit(TelemetryEvent{EventType: "allowed", Decision: "allow"})
	}
	elapsed := time.Since(start)

	// 10k non-blocking sends should be effectively instant (well under the
	// time a single blocking network flush would take).
	if elapsed > 200*time.Millisecond {
		t.Errorf("Emit blocked: 10k sends took %v (expected non-blocking)", elapsed)
	}

	// Some events must have been dropped (buffer is tiny) — proving drop-on-full.
	tc.mu.Lock()
	dropped := tc.dropped
	tc.mu.Unlock()
	if dropped == 0 {
		t.Error("expected some dropped events with a tiny buffer + slow flush")
	}
}

// TestEmitNilClientSafe ensures the hot-path helper is a safe no-op when no
// control plane is configured.
func TestEmitNilClientSafe(t *testing.T) {
	telemetryClient = nil
	// Must not panic.
	emitTelemetry("allowed", "allow", "t", "SELECT", 0.1, false)
	emitTelemetryFor("allowed", "allow", nil, nil, 0.1)
}

// TestParseControlPlaneTOML checks the minimal TOML parser reads the file
// install.sh writes.
func TestParseControlPlaneTOML(t *testing.T) {
	in := `# header comment
[control_plane]
url = "https://api.faultwall.com"
token = "TFW_secret"
mode = "monitor"
installation_id = "inst-9"
telemetry_enabled = true
`
	var cfg ControlPlaneConfig
	parseControlPlaneTOML(bufio.NewScanner(strings.NewReader(in)), &cfg)
	if cfg.URL != "https://api.faultwall.com" {
		t.Errorf("url = %q", cfg.URL)
	}
	if cfg.Token != "TFW_secret" {
		t.Errorf("token = %q", cfg.Token)
	}
	if cfg.InstallationID != "inst-9" {
		t.Errorf("installation_id = %q", cfg.InstallationID)
	}
	if !cfg.TelemetryEnabled {
		t.Error("telemetry_enabled should be true")
	}
}
