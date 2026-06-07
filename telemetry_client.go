package main

// Control-plane telemetry client.
//
// PRIVACY CONTRACT (non-negotiable): this client sends METADATA ONLY to the
// control plane — event_type, decision, table_name, op_type, latency_ms,
// cost_flag, and QWM risk scores (risk_score, p99_breach_prob,
// qwm_threshold_ms). It NEVER sends query text, bound parameter values, row
// data, or policy bodies. The TelemetryEvent struct deliberately has no
// query/sql/body field; telemetry_client_test.go asserts this via JSON
// marshaling.
//
// PERFORMANCE CONTRACT: emitting telemetry must NOT add latency to the query
// hot path (the sub-3ms promise). Emit() is a non-blocking send onto a buffered
// channel; if the buffer is full, the event is dropped. A background goroutine
// batches and flushes over HTTP. Network I/O never happens on the caller's
// goroutine.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// qwmTelemetrySLOMs is the p99 SLO threshold (ms) reported alongside the
// lightweight QWM risk score on telemetry events. This is an OSS-side default
// for the open-core proxy; the trained cost-prediction model and its calibrated
// SLO decisioning live in the closed faultwall-ebpf repo, not here.
const qwmTelemetrySLOMs = 500

// TelemetryEvent is the metadata-only shape pushed to the control plane.
// NOTE: there is intentionally NO field carrying query text or row data.
type TelemetryEvent struct {
	EventType string  `json:"event_type"` // allowed | blocked | monitored
	Decision  string  `json:"decision"`   // allow | block | flag
	TableName string  `json:"table_name"`
	OpType    string  `json:"op_type"` // SELECT | INSERT | UPDATE | DELETE | ...
	LatencyMs float64 `json:"latency_ms"`
	CostFlag  bool    `json:"cost_flag"`
	// QWM risk signals — METADATA ONLY (scores derived from the Query Workload
	// Model, never the query text itself). Zero values mean "not scored".
	RiskScore      float64 `json:"risk_score"`       // P(bad) for this query, 0..1
	P99BreachProb  float64 `json:"p99_breach_prob"`  // P(p99 latency breach), 0..1
	QWMThresholdMs int     `json:"qwm_threshold_ms"` // configured QWM p99 threshold (ms)
}

// ControlPlaneConfig is parsed from ~/.faultwall/config.toml ([control_plane]).
type ControlPlaneConfig struct {
	URL              string
	Token            string
	Mode             string
	InstallationID   string
	TelemetryEnabled bool
}

// TelemetryClient buffers events and flushes them to the control plane.
type TelemetryClient struct {
	cfg      ControlPlaneConfig
	ch       chan TelemetryEvent
	http     *http.Client
	wg       sync.WaitGroup
	stop     chan struct{}
	stopOnce sync.Once

	// flushFn is the transport used to ship a batch. Overridable in tests so
	// no real network is required. Defaults to postBatch.
	flushFn func(events []TelemetryEvent)

	dropped uint64
	mu      sync.Mutex
}

// telemetryClient is the process-global client (nil when control plane is not
// configured — Emit becomes a no-op).
var telemetryClient *TelemetryClient

const (
	telemetryBufSize    = 1024
	telemetryBatchSize  = 50
	telemetryFlushEvery = 5 * time.Second
)

// loadControlPlaneConfig reads ~/.faultwall/config.toml. Returns ok=false when
// the file is absent or telemetry is disabled. This is a tiny purpose-built
// parser for the [control_plane] table written by install.sh (no TOML dep).
func loadControlPlaneConfig() (ControlPlaneConfig, bool) {
	var cfg ControlPlaneConfig

	// Env overrides win (useful for containers/tests).
	if v := os.Getenv("FAULTWALL_CONTROL_PLANE_URL"); v != "" {
		cfg.URL = v
	}
	if v := os.Getenv("FAULTWALL_CONTROL_PLANE_TOKEN"); v != "" {
		cfg.Token = v
	}

	path := os.Getenv("FAULTWALL_CONFIG_FILE")
	if path == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, ".faultwall", "config.toml")
		}
	}
	if path != "" {
		if f, err := os.Open(path); err == nil {
			parseControlPlaneTOML(bufio.NewScanner(f), &cfg)
			f.Close()
		}
	}

	if cfg.URL == "" || cfg.Token == "" {
		return cfg, false
	}
	// Telemetry on by default once configured, unless explicitly disabled.
	if os.Getenv("FAULTWALL_TELEMETRY") == "false" {
		cfg.TelemetryEnabled = false
	}
	return cfg, cfg.TelemetryEnabled
}

// parseControlPlaneTOML extracts [control_plane] keys from a scanner. Minimal
// by design: handles `key = "value"` and `key = true/false`.
func parseControlPlaneTOML(sc *bufio.Scanner, cfg *ControlPlaneConfig) {
	inSection := false
	cfg.TelemetryEnabled = true // default true if section present without the key
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inSection = line == "[control_plane]"
			continue
		}
		if !inSection {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"`)
		switch key {
		case "url":
			if cfg.URL == "" {
				cfg.URL = val
			}
		case "token":
			if cfg.Token == "" {
				cfg.Token = val
			}
		case "mode":
			cfg.Mode = val
		case "installation_id":
			cfg.InstallationID = val
		case "telemetry_enabled":
			cfg.TelemetryEnabled = val == "true"
		}
	}
}

// NewTelemetryClient builds a client and starts its background flusher.
func NewTelemetryClient(cfg ControlPlaneConfig) *TelemetryClient {
	tc := &TelemetryClient{
		cfg:  cfg,
		ch:   make(chan TelemetryEvent, telemetryBufSize),
		http: &http.Client{Timeout: 5 * time.Second},
		stop: make(chan struct{}),
	}
	tc.flushFn = tc.postBatch
	tc.wg.Add(1)
	go tc.run()
	return tc
}

// Emit queues an event. NON-BLOCKING: if the buffer is full the event is
// dropped so the query path is never stalled. Safe to call with a nil client.
func (tc *TelemetryClient) Emit(ev TelemetryEvent) {
	if tc == nil {
		return
	}
	select {
	case tc.ch <- ev:
	default:
		tc.mu.Lock()
		tc.dropped++
		tc.mu.Unlock()
	}
}

// run batches events and flushes on size or interval.
func (tc *TelemetryClient) run() {
	defer tc.wg.Done()
	ticker := time.NewTicker(telemetryFlushEvery)
	defer ticker.Stop()
	batch := make([]TelemetryEvent, 0, telemetryBatchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		out := make([]TelemetryEvent, len(batch))
		copy(out, batch)
		batch = batch[:0]
		tc.flushFn(out)
	}

	for {
		select {
		case ev := <-tc.ch:
			batch = append(batch, ev)
			if len(batch) >= telemetryBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-tc.stop:
			// Drain whatever is buffered, then final flush.
			for {
				select {
				case ev := <-tc.ch:
					batch = append(batch, ev)
				default:
					flush()
					return
				}
			}
		}
	}
}

// Close stops the flusher and waits for a final drain.
func (tc *TelemetryClient) Close() {
	if tc == nil {
		return
	}
	tc.stopOnce.Do(func() { close(tc.stop) })
	tc.wg.Wait()
}

// telemetryPayload is the request body for POST /v1/telemetry.
type telemetryPayload struct {
	InstallationID string           `json:"installation_id"`
	Events         []TelemetryEvent `json:"events"`
}

// postBatch ships a batch to the control plane. Errors are logged and swallowed
// (fire-and-forget) — telemetry must never break the proxy.
func (tc *TelemetryClient) postBatch(events []TelemetryEvent) {
	if len(events) == 0 {
		return
	}
	body, err := json.Marshal(telemetryPayload{
		InstallationID: tc.cfg.InstallationID,
		Events:         events,
	})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(tc.cfg.URL, "/")+"/v1/telemetry", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+tc.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := tc.http.Do(req)
	if err != nil {
		log.Printf("telemetry flush failed (dropped %d events this batch): %v", len(events), err)
		return
	}
	resp.Body.Close()
}

// sendHeartbeat posts a single heartbeat (called periodically by a goroutine).
func (tc *TelemetryClient) sendHeartbeat() {
	if tc == nil {
		return
	}
	body, _ := json.Marshal(map[string]string{"installation_id": tc.cfg.InstallationID})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(tc.cfg.URL, "/")+"/v1/heartbeat", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+tc.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := tc.http.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// StartHeartbeat launches a periodic heartbeat goroutine.
func (tc *TelemetryClient) StartHeartbeat(every time.Duration) {
	if tc == nil {
		return
	}
	go func() {
		tc.sendHeartbeat() // immediate first beat
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				tc.sendHeartbeat()
			case <-tc.stop:
				return
			}
		}
	}()
}

// emitTelemetryFor adapts the proxy's decision artifacts (violation + parsed
// query) into a metadata-only telemetry event and fires it. table/op are
// derived from the parsed query / violation only — never the raw SQL text.
// This is the single call site used by the proxy hot path.
//
// When the QWM security scorer is loaded, we attach its harm probability
// (risk_score) — a model OUTPUT (a float in [0,1]), never the query content.
// The configured SLO threshold (qwm_threshold_ms) travels too so the dashboard
// can contextualise the score. p99_breach_prob is left 0 here: the cost
// scorer's featurize path is heavier and gated, so we don't run it on the hot
// path purely for telemetry.
func emitTelemetryFor(eventType, decision string, v *PolicyViolation, pq *ParsedQuery, latencyMs float64) {
	if telemetryClient == nil {
		return
	}
	var table, op string
	if v != nil {
		table = v.Table
		op = v.Operation
	}
	if pq != nil {
		if op == "" {
			op = pq.Operation
		}
		if table == "" && len(pq.Tables) > 0 {
			table = pq.Tables[0]
		}
	}
	costFlag := decision == "flag"

	var riskScore float64
	qwmThresholdMs := qwmTelemetrySLOMs
	if qwmScorer != nil && pq != nil {
		// Cheap logistic-regression scorer (no CGO / featurize). Output only.
		riskScore = qwmScorer.Score(pq, QWMInfraState{})
	}

	emitTelemetryEvent(TelemetryEvent{
		EventType:      eventType,
		Decision:       decision,
		TableName:      table,
		OpType:         op,
		LatencyMs:      latencyMs,
		CostFlag:       costFlag,
		RiskScore:      riskScore,
		P99BreachProb:  0,
		QWMThresholdMs: qwmThresholdMs,
	})
}

// emitTelemetry is the package-level helper called from the proxy hot path.
// It maps the proxy's decision vocabulary to the control-plane schema and
// fires-and-forgets. Designed to be a cheap no-op when telemetry is off.
// (No QWM risk attached — callers with a parsed query should prefer
// emitTelemetryFor, which scores risk.)
func emitTelemetry(eventType, decision, table, op string, latencyMs float64, costFlag bool) {
	emitTelemetryEvent(TelemetryEvent{
		EventType: eventType,
		Decision:  decision,
		TableName: table,
		OpType:    op,
		LatencyMs: latencyMs,
		CostFlag:  costFlag,
	})
}

// emitTelemetryEvent is the single funnel onto the buffered client. No-op when
// telemetry is not configured.
func emitTelemetryEvent(ev TelemetryEvent) {
	if telemetryClient == nil {
		return
	}
	telemetryClient.Emit(ev)
}
