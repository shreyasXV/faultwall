package main

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

const plantedSecret = "secret-xyz"

// TestQueryShapeStripsAllLiterals is the privacy guard for query_shape: a
// planted literal must never survive, whatever syntax carries it.
func TestQueryShapeStripsAllLiterals(t *testing.T) {
	cases := []string{
		"UPDATE orders SET status='secret-xyz' WHERE id = 4412",
		"UPDATE orders SET status = 'x' /* secret-xyz */ WHERE id = 1 -- secret-xyz",
		"SELECT $$secret-xyz$$, $tag$secret-xyz$tag$, E'secret-xyz', U&'secret-xyz'",
		"CREATE TABLE t (a text DEFAULT 'secret-xyz')",
		"COMMENT ON TABLE orders IS 'secret-xyz'",
		"COPY orders FROM '/tmp/secret-xyz.csv'",
		"PREPARE p AS SELECT * FROM t WHERE a = 'secret-xyz'",
		"DO $$ BEGIN PERFORM 'secret-xyz'; END $$",
		"ALTER ROLE bob PASSWORD 'secret-xyz'",
		"SET application_name = 'secret-xyz'",
		"SELECT 1; UPDATE x SET y = 'secret-xyz'",
		"EXPLAIN ANALYZE SELECT * FROM t WHERE a = 'secret-xyz'",
		"INSERT INTO refunds (reason) VALUES ('secret-xyz'), ('secret-xyz')",
		"SELECT interval '1 day secret-xyz'",
		"SELECT 'unterminated secret-xyz",                  // scan error -> empty
		"SELECT * FROM t WHERE a = 'secret-xyz' AND b = 1", // plain
	}
	for _, q := range cases {
		got := normalizeQueryShape(q)
		if strings.Contains(got, plantedSecret) || strings.Contains(got, "4412") {
			t.Errorf("literal leaked into shape:\n  q=%s\n  shape=%s", q, got)
		}
		if strings.Contains(got, "'") {
			t.Errorf("quote in shape %q", got)
		}
	}
}

func TestQueryShapeReadable(t *testing.T) {
	cases := map[string]string{
		"UPDATE orders SET status = 'refunded' WHERE id = 4412":             "UPDATE orders SET status = ? WHERE id = ?",
		"SELECT id, total_cents FROM orders WHERE customer_id = $1 LIMIT 5": "SELECT id, total_cents FROM orders WHERE customer_id = ? LIMIT ?",
		"select * from t where flag = true":                                 "select * from t where flag = ?",
		"SELECT * FROM t WHERE id IN (1,2,3,4,5,6,7,8,9,10,11,12,13)":       "SELECT * FROM t WHERE id IN (?, ...)",
	}
	for q, want := range cases {
		if got := normalizeQueryShape(q); got != want {
			t.Errorf("shape(%q)\n got %q\nwant %q", q, got, want)
		}
	}
}

func TestQueryShapeDefaultResolution(t *testing.T) {
	tr, fa := true, false
	if telemetryQueryShapeEnabled("", nil) != telemetryQueryShapeDefault {
		t.Fatal("unset env + unset config must use telemetryQueryShapeDefault")
	}
	if telemetryQueryShapeEnabled("off", &tr) {
		t.Fatal("env off must win over config")
	}
	if !telemetryQueryShapeEnabled("on", &fa) {
		t.Fatal("env on must win over config")
	}
	if telemetryQueryShapeEnabled("", &fa) {
		t.Fatal("config false must be honoured")
	}
}

// TestTelemetryEventActivityFieldsNoRawText: the widened event carries the
// activity metadata but no raw text, and every key is on the allowlist.
func TestTelemetryEventActivityFieldsNoRawText(t *testing.T) {
	q := "UPDATE orders SET status = 'secret-xyz' WHERE customer_id = 77"
	pq := ParseQuery(q)
	c := &telemetryConn{agent: "support-agent", mission: "refunds"}
	it := c.baseItem("allowed", "allow", nil, pq, q, 0.2)
	it.ev.RowsAffected, it.ev.RowsKnown = 3, true
	for _, shape := range []bool{true, false} {
		ev := finalizeTelemetryItem(it, shape)
		b, _ := json.Marshal(ev)
		s := string(b)
		if strings.Contains(s, plantedSecret) || strings.Contains(s, "77") {
			t.Fatalf("literal in telemetry JSON: %s", s)
		}
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		allowed := map[string]bool{"ts": true, "event_type": true, "decision": true, "table_name": true,
			"op_type": true, "latency_ms": true, "cost_flag": true, "risk_score": true, "p99_breach_prob": true,
			"qwm_threshold_ms": true, "agent_id": true, "agent_unnamed": true, "mission": true, "tables": true,
			"rows_affected": true, "rows_known": true, "failed": true, "flags": true, "reasons": true,
			"fingerprint": true, "query_shape": true}
		for k := range m {
			if !allowed[k] {
				t.Errorf("unexpected telemetry key %q", k)
			}
		}
		for _, f := range []string{"query", "sql", "params", "row_data", "text"} {
			if _, ok := m[f]; ok {
				t.Errorf("forbidden key %q", f)
			}
		}
		if ev.AgentID != "support-agent" || ev.OpType != "UPDATE" || ev.TableName != "orders" || ev.RowsAffected != 3 {
			t.Errorf("bad metadata: %+v", ev)
		}
		if shape && ev.QueryShape != "UPDATE orders SET status = ? WHERE customer_id = ?" {
			t.Errorf("shape = %q", ev.QueryShape)
		}
		if !shape && ev.QueryShape != "" {
			t.Errorf("shape sent while disabled: %q", ev.QueryShape)
		}
		if ev.Fingerprint == "" {
			t.Error("missing fingerprint")
		}
	}
}

func TestFinalizeFlags(t *testing.T) {
	c := &telemetryConn{agent: "a"}
	q := "DELETE FROM sessions"
	it := c.baseItem("allowed", "allow", nil, ParseQuery(q), q, 0)
	it.ev.RowsAffected, it.ev.RowsKnown = 500, true
	ev := finalizeTelemetryItem(it, true)
	if strings.Join(ev.Flags, ",") != "no_where,mass_write" {
		t.Fatalf("flags = %v", ev.Flags)
	}
	if len(ev.Reasons) != 2 || ev.Reasons[1] != tryFlagReasons["mass_write"] {
		t.Fatalf("reasons = %v", ev.Reasons)
	}
	v := &PolicyViolation{Reason: "blocked_table", Table: "users"}
	q2 := "SELECT password_hash FROM users WHERE id = 1"
	ev2 := finalizeTelemetryItem(c.baseItem("monitored", "flag", v, ParseQuery(q2), q2, 0), false)
	if strings.Join(ev2.Flags, ",") != "secret_read,policy" || ev2.Reasons[1] != "policy: blocked_table (users)" {
		t.Fatalf("flags=%v reasons=%v", ev2.Flags, ev2.Reasons)
	}
}

// captureTelemetry installs a client whose flushFn records events.
func captureTelemetry(t *testing.T) (*[]TelemetryEvent, func() []TelemetryEvent) {
	t.Helper()
	var mu sync.Mutex
	var got []TelemetryEvent
	old := telemetryClient
	tc := &TelemetryClient{cfg: ControlPlaneConfig{QueryShape: true}, ch: make(chan telemetryItem, 256), stop: make(chan struct{})}
	tc.flushFn = func(evs []TelemetryEvent) error {
		mu.Lock()
		got = append(got, evs...)
		mu.Unlock()
		return nil
	}
	tc.wg.Add(1)
	go tc.run()
	telemetryClient = tc
	t.Cleanup(func() { telemetryClient = old })
	return &got, func() []TelemetryEvent {
		tc.Close()
		mu.Lock()
		defer mu.Unlock()
		return append([]TelemetryEvent{}, got...)
	}
}

// TestTelemetryConnRowAttribution drives the wire-order bookkeeping the
// proxy uses: simple query, multi-statement, pipelined extended protocol
// with an error, and an unnamed connection.
func TestTelemetryConnRowAttribution(t *testing.T) {
	_, done := captureTelemetry(t)
	id := ParseAgentIdentity("agent:support-agent:mission:refunds")
	c := newTelemetryConn(id, "support-agent/refunds")

	// 1. simple Q: UPDATE 3
	q := "UPDATE orders SET status = 'refunded' WHERE customer_id = 9"
	c.enqueue("allowed", "allow", nil, ParseQuery(q), q, 0, 1)
	c.onSyncPoint()
	c.onCommandComplete([]byte("UPDATE 3\x00"))
	c.onReady()

	// 2. multi-statement Q: BEGIN; UPDATE 2; COMMIT -> one event, 2 rows
	q2 := "BEGIN; UPDATE tickets SET status = 'closed' WHERE id = 1; COMMIT"
	pq2 := ParseQuery(q2)
	c.enqueue("allowed", "allow", nil, pq2, q2, 0, len(pq2.Operations))
	c.onSyncPoint()
	c.onCommandComplete([]byte("BEGIN\x00"))
	c.onCommandComplete([]byte("UPDATE 2\x00"))
	c.onCommandComplete([]byte("COMMIT\x00"))
	c.onReady()

	// 3. pipeline: Execute A (SELECT 5), Execute B (error), Execute C (skipped), Sync
	sa := &preparedStmt{query: "SELECT * FROM orders WHERE id = $1", pq: ParseQuery("SELECT * FROM orders WHERE id = $1")}
	sb := &preparedStmt{query: "INSERT INTO refunds (order_id) VALUES ($1)", pq: ParseQuery("INSERT INTO refunds (order_id) VALUES ($1)")}
	c.enqueueStmt(sa)
	c.enqueueStmt(sb)
	c.enqueueStmt(sa)
	c.onSyncPoint()
	c.onCommandComplete([]byte("SELECT 5\x00"))
	c.onError()
	c.onReady()

	// 4. next batch must not be confused by the previous error
	c.enqueueStmt(sb)
	c.onSyncPoint()
	c.onCommandComplete([]byte("INSERT 0 1\x00"))
	c.onReady()

	// unnamed connection
	u := newTelemetryConn(nil, "psql")
	u.emitNow("blocked", "block", &PolicyViolation{Reason: "blocked_operation", Operation: "DROP"}, ParseQuery("DROP TABLE x"), "DROP TABLE x", 0.1)

	evs := done()
	if len(evs) != 7 {
		t.Fatalf("want 7 events, got %d: %+v", len(evs), evs)
	}
	type exp struct {
		op     string
		rows   int64
		failed bool
		known  bool
	}
	want := []exp{{"UPDATE", 3, false, true}, {"UPDATE", 2, false, true}, {"SELECT", 5, false, true},
		{"INSERT", 0, true, false}, {"SELECT", 0, true, false}, {"INSERT", 1, false, true}, {"DROP", 0, false, true}}
	for i, w := range want {
		e := evs[i]
		if e.OpType != w.op || e.RowsAffected != w.rows || e.Failed != w.failed || e.RowsKnown != w.known {
			t.Errorf("event %d: got op=%s rows=%d failed=%v known=%v; want %+v", i, e.OpType, e.RowsAffected, e.Failed, e.RowsKnown, w)
		}
		if i < 6 && (e.AgentID != "support-agent" || e.Mission != "refunds" || e.AgentUnnamed) {
			t.Errorf("event %d agent = %q/%q unnamed=%v", i, e.AgentID, e.Mission, e.AgentUnnamed)
		}
	}
	if evs[6].AgentID != "psql" || !evs[6].AgentUnnamed || evs[6].Decision != "block" {
		t.Errorf("unnamed event: %+v", evs[6])
	}
	for _, e := range evs {
		if strings.Contains(e.QueryShape, "refunded") || strings.Contains(e.QueryShape, "closed") {
			t.Errorf("literal in shape %q", e.QueryShape)
		}
	}
}

// TestTelemetryRetryBackoff: a failing control plane keeps events and
// delivers them once it recovers; Emit never blocks meanwhile.
func TestTelemetryRetryBackoff(t *testing.T) {
	var mu sync.Mutex
	fail := true
	var delivered, attempts int
	tc := &TelemetryClient{ch: make(chan telemetryItem, 64), stop: make(chan struct{}),
		backoffBase: 5 * time.Millisecond, backoffMax: 20 * time.Millisecond}
	tc.flushFn = func(evs []TelemetryEvent) error {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if fail {
			return errTelemetryRetry{errors.New("down")}
		}
		delivered += len(evs)
		return nil
	}
	tc.wg.Add(1)
	go tc.run()
	for i := 0; i < 10; i++ {
		tc.Emit(TelemetryEvent{EventType: "allowed"})
	}
	time.Sleep(2500 * time.Millisecond) // > one flush tick
	mu.Lock()
	fail = false
	mu.Unlock()
	tc.Close()
	mu.Lock()
	defer mu.Unlock()
	if delivered != 10 {
		t.Fatalf("want 10 delivered after recovery, got %d (attempts %d)", delivered, attempts)
	}
	if attempts < 2 {
		t.Fatalf("expected a retry, attempts=%d", attempts)
	}
}
