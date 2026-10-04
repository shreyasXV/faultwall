package main

// Control-plane telemetry client.
//
// PRIVACY CONTRACT: this client sends METADATA to the control plane. It
// NEVER sends raw query text, bound parameter values, row data, or policy
// bodies. Per event it sends:
//
//   - decision metadata: event_type, decision, op_type, table_name, tables,
//     latency_ms, cost_flag, QWM scores (risk_score, p99_breach_prob,
//     qwm_threshold_ms), rows_affected (from the CommandComplete tag), and
//     the flag codes / reasons from the zero-config rules (try_activity.go).
//   - identity metadata: agent_id and mission from application_name
//     (agent:<id>:mission:<mission>; the :token: part is never sent).
//   - fingerprint: pg_query's structural hash (hex). Literals do not affect it.
//   - query_shape (GATED, see telemetryQueryShapeDefault): the statement with
//     EVERY literal replaced by ? and comments removed, built from the
//     pg_query token stream (telemetry_shape.go). "UPDATE orders SET status
//     = ? WHERE id = ?". Off with FW_TELEMETRY_QUERY_SHAPE=off.
//
// The TelemetryEvent struct deliberately has no query/sql/params field;
// telemetry_client_test.go asserts this via JSON marshaling and checks that a
// planted literal never survives into query_shape.
//
// PERFORMANCE CONTRACT: emitting telemetry must NOT add latency to the query
// hot path (the sub-3ms promise). Emit() is a non-blocking send onto a buffered
// channel; if the buffer is full, the event is dropped. A background goroutine
// batches and flushes over HTTP, retrying failed batches with exponential
// backoff from a bounded buffer. Network I/O never happens on the caller's
// goroutine.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// telemetryQueryShapeDefault decides whether literal-free query shapes are
// sent to the control plane when FW_TELEMETRY_QUERY_SHAPE is not set.
// FOUNDER DECISION PENDING: this is the single line to flip. true = shapes on
// by default once enrolled (the hosted feed shows "UPDATE orders SET status =
// ? WHERE id = ?"); false = opt-in, the feed shows op + table + rows only.
const telemetryQueryShapeDefault = true

// telemetryQueryShapeEnabled resolves FW_TELEMETRY_QUERY_SHAPE (env) >
// query_shape in [control_plane] (config.toml) > telemetryQueryShapeDefault.
func telemetryQueryShapeEnabled(env string, cfgVal *bool) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "1", "true", "on", "yes":
		return true
	case "0", "false", "off", "no":
		return false
	}
	if cfgVal != nil {
		return *cfgVal
	}
	return telemetryQueryShapeDefault
}

// qwmTelemetrySLOMs is the p99 SLO threshold (ms) reported alongside the
// lightweight QWM risk score on telemetry events. This is an OSS-side default
// for the open-core proxy; the trained cost-prediction model and its calibrated
// SLO decisioning live in the closed faultwall-ebpf repo, not here.
const qwmTelemetrySLOMs = 500

// TelemetryEvent is the metadata shape pushed to the control plane.
// NOTE: there is intentionally NO field carrying raw query text, parameter
// values or row data. QueryShape is literal-free and gated (see above).
type TelemetryEvent struct {
	TS        string  `json:"ts,omitempty"` // RFC3339Nano, when the statement ran
	EventType string  `json:"event_type"`   // allowed | blocked | monitored
	Decision  string  `json:"decision"`     // allow | block | flag
	TableName string  `json:"table_name"`
	OpType    string  `json:"op_type"` // SELECT | INSERT | UPDATE | DELETE | ...
	LatencyMs float64 `json:"latency_ms"`
	CostFlag  bool    `json:"cost_flag"`
	// QWM risk signals — METADATA ONLY (scores derived from the Query Workload
	// Model, never the query text itself). Zero values mean "not scored".
	RiskScore      float64 `json:"risk_score"`       // P(bad) for this query, 0..1
	P99BreachProb  float64 `json:"p99_breach_prob"`  // P(p99 latency breach), 0..1
	QWMThresholdMs int     `json:"qwm_threshold_ms"` // configured QWM p99 threshold (ms)

	// Activity feed metadata (hosted See screen).
	AgentID      string   `json:"agent_id,omitempty"`      // from application_name; "unknown" if none
	AgentUnnamed bool     `json:"agent_unnamed,omitempty"` // connected without agent:<name>:…
	Mission      string   `json:"mission,omitempty"`
	Tables       []string `json:"tables,omitempty"`
	RowsAffected int64    `json:"rows_affected"`         // from CommandComplete ("UPDATE 12" -> 12)
	RowsKnown    bool     `json:"rows_known,omitempty"`  // false: statement errored / never completed
	Failed       bool     `json:"failed,omitempty"`      // upstream returned an error
	Flags        []string `json:"flags,omitempty"`       // ddl | no_where | secret_read | mass_write | server_func | policy
	Reasons      []string `json:"reasons,omitempty"`     // human text for each flag (no literals)
	Fingerprint  string   `json:"fingerprint,omitempty"` // pg_query structural hash (hex)
	QueryShape   string   `json:"query_shape,omitempty"` // literals stripped; gated by FW_TELEMETRY_QUERY_SHAPE
}

// ControlPlaneConfig is parsed from ~/.faultwall/config.toml ([control_plane]).
type ControlPlaneConfig struct {
	URL              string
	Token            string
	Mode             string
	InstallationID   string
	TelemetryEnabled bool
	// Rev C3 local trust anchor, written by install.sh. Env vars
	// (FW_TENANT_ID, FW_DATABASE_ID, FW_ENVIRONMENT, FW_POLICY_PUBKEY) win.
	TenantID     string
	DatabaseID   string
	Environment  string
	PolicyPubKey string
	// QueryShape: send literal-free query shapes (resolved at load time).
	QueryShape    bool
	queryShapeCfg *bool
}

// TelemetryClient buffers events and flushes them to the control plane.
type TelemetryClient struct {
	cfg      ControlPlaneConfig
	ch       chan telemetryItem
	http     *http.Client
	wg       sync.WaitGroup
	stop     chan struct{}
	stopOnce sync.Once

	// flushFn is the transport used to ship a batch. Overridable in tests so
	// no real network is required. Defaults to postBatch. A non-nil error
	// marked retryable (see errTelemetryRetry) keeps the batch for retry.
	flushFn func(events []TelemetryEvent) error

	dropped uint64
	sent    uint64
	mu      sync.Mutex

	// Backoff state (only touched by run()).
	backoffBase time.Duration
	backoffMax  time.Duration
}

// errTelemetryRetry wraps transport errors worth retrying (network, 5xx, 429).
type errTelemetryRetry struct{ err error }

func (e errTelemetryRetry) Error() string { return e.err.Error() }

// telemetryClient is the process-global client (nil when control plane is not
// configured — Emit becomes a no-op).
var telemetryClient *TelemetryClient

const (
	telemetryBufSize    = 4096
	telemetryBatchSize  = 200
	telemetryFlushEvery = 2 * time.Second
	// telemetryRetryMax bounds events held for retry while the control plane
	// is unreachable; oldest are dropped first.
	telemetryRetryMax = 10000
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
	if v := os.Getenv("FAULTWALL_INSTALLATION_ID"); v != "" {
		cfg.InstallationID = v
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

	cfg.QueryShape = telemetryQueryShapeEnabled(os.Getenv("FW_TELEMETRY_QUERY_SHAPE"), cfg.queryShapeCfg)
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
			if cfg.InstallationID == "" {
				cfg.InstallationID = val
			}
		case "tenant_id":
			cfg.TenantID = val
		case "database_id":
			cfg.DatabaseID = val
		case "environment":
			cfg.Environment = val
		case "policy_pubkey":
			cfg.PolicyPubKey = val
		case "query_shape":
			b := val == "true"
			cfg.queryShapeCfg = &b
		case "telemetry_enabled":
			cfg.TelemetryEnabled = val == "true"
		}
	}
}

// NewTelemetryClient builds a client and starts its background flusher.
func NewTelemetryClient(cfg ControlPlaneConfig) *TelemetryClient {
	tc := &TelemetryClient{
		cfg:  cfg,
		ch:   make(chan telemetryItem, telemetryBufSize),
		http: &http.Client{Timeout: 5 * time.Second},
		stop: make(chan struct{}),

		backoffBase: time.Second,
		backoffMax:  60 * time.Second,
	}
	tc.flushFn = tc.postBatch
	tc.wg.Add(1)
	go tc.run()
	return tc
}

// Emit queues an event. NON-BLOCKING: if the buffer is full the event is
// dropped so the query path is never stalled. Safe to call with a nil client.
func (tc *TelemetryClient) Emit(ev TelemetryEvent) {
	tc.emitItem(telemetryItem{ev: ev})
}

// emitItem is Emit for events that still need finalizing (flags, shape) on
// the background goroutine. NON-BLOCKING.
func (tc *TelemetryClient) emitItem(it telemetryItem) {
	if tc == nil {
		return
	}
	select {
	case tc.ch <- it:
	default:
		tc.mu.Lock()
		tc.dropped++
		tc.mu.Unlock()
	}
}

// run batches events and flushes on size or interval. Failed batches are
// kept (bounded by telemetryRetryMax) and retried with exponential backoff +
// jitter; new events keep being accepted meanwhile.
func (tc *TelemetryClient) run() {
	defer tc.wg.Done()
	ticker := time.NewTicker(telemetryFlushEvery)
	defer ticker.Stop()
	batch := make([]TelemetryEvent, 0, telemetryBatchSize)
	var retry []TelemetryEvent
	var nextTry time.Time
	failures := 0
	base, max := tc.backoffBase, tc.backoffMax
	if base <= 0 {
		base = time.Second
	}
	if max <= 0 {
		max = 60 * time.Second
	}

	send := func(evs []TelemetryEvent) bool {
		err := tc.flushFn(evs)
		if err == nil {
			tc.mu.Lock()
			tc.sent += uint64(len(evs))
			tc.mu.Unlock()
			return true
		}
		if _, ok := err.(errTelemetryRetry); !ok {
			// Non-retryable (4xx, marshal): drop, don't hammer.
			tc.mu.Lock()
			tc.dropped += uint64(len(evs))
			tc.mu.Unlock()
			return true
		}
		return false
	}

	flush := func(final bool) {
		if len(batch) > 0 {
			retry = append(retry, batch...)
			batch = batch[:0]
		}
		if over := len(retry) - telemetryRetryMax; over > 0 {
			retry = retry[over:]
			tc.mu.Lock()
			tc.dropped += uint64(over)
			tc.mu.Unlock()
		}
		if len(retry) == 0 || (!final && time.Now().Before(nextTry)) {
			return
		}
		for len(retry) > 0 {
			n := len(retry)
			if n > telemetryBatchSize {
				n = telemetryBatchSize
			}
			out := make([]TelemetryEvent, n)
			copy(out, retry[:n])
			if !send(out) {
				failures++
				d := base << uint(minInt(failures-1, 16))
				if d > max || d <= 0 {
					d = max
				}
				d = d/2 + time.Duration(rand.Int63n(int64(d/2)+1))
				nextTry = time.Now().Add(d)
				if failures == 1 || failures%10 == 0 {
					log.Printf("telemetry: control plane unreachable, %d events queued, retry in %s", len(retry), d.Round(time.Millisecond))
				}
				return
			}
			failures = 0
			retry = retry[n:]
		}
		retry = nil
	}

	for {
		select {
		case it := <-tc.ch:
			batch = append(batch, finalizeTelemetryItem(it, tc.cfg.QueryShape))
			if len(batch) >= telemetryBatchSize {
				flush(false)
			}
		case <-ticker.C:
			flush(false)
		case <-tc.stop:
			// Drain whatever is buffered, then one final attempt.
			for {
				select {
				case it := <-tc.ch:
					batch = append(batch, finalizeTelemetryItem(it, tc.cfg.QueryShape))
				default:
					flush(true)
					return
				}
			}
		}
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Stats returns (sent, dropped) counters.
func (tc *TelemetryClient) Stats() (sent, dropped uint64) {
	if tc == nil {
		return 0, 0
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.sent, tc.dropped
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

// postBatch ships a batch to the control plane. Network errors, 5xx and 429
// are returned as errTelemetryRetry so run() keeps the batch and backs off.
// Telemetry must never break the proxy: nothing here touches the query path.
func (tc *TelemetryClient) postBatch(events []TelemetryEvent) error {
	if len(events) == 0 {
		return nil
	}
	body, err := json.Marshal(telemetryPayload{
		InstallationID: tc.cfg.InstallationID,
		Events:         events,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(tc.cfg.URL, "/")+"/v1/telemetry", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tc.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := tc.http.Do(req)
	if err != nil {
		return errTelemetryRetry{err}
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
		return errTelemetryRetry{fmt.Errorf("control plane HTTP %d", resp.StatusCode)}
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("control plane HTTP %d", resp.StatusCode)
	}
	return nil
}

// sendHeartbeat posts a single heartbeat (called periodically by a goroutine).
func (tc *TelemetryClient) sendHeartbeat() {
	if tc == nil {
		return
	}
	hb := map[string]interface{}{"installation_id": tc.cfg.InstallationID}
	// Rev 5: report the enforced (accepted, signed) policy version.
	if v := policySyncer.AcceptedPolicyVersion(); v > 0 {
		hb["policy_version"] = v
	}
	body, _ := json.Marshal(hb)
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
