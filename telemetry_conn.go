package main

// telemetry_conn.go — per-connection telemetry bookkeeping for the hosted
// activity feed.
//
// A statement's telemetry event is not emitted when the query is parsed but
// when its result arrives, so the event can carry the affected-row count from
// CommandComplete ("UPDATE 12") and the mass_write flag. Statements are queued
// FIFO in wire order. Postgres answers in the same order, so CommandComplete,
// EmptyQueryResponse and ErrorResponse each settle the oldest pending
// statement. ReadyForQuery flushes anything the server skipped (statements
// after an error in an extended-protocol pipeline).
//
// Hot-path cost is a mutex and a slice append. Flag rules (tryStaticFlags)
// and the literal-free shape (normalizeQueryShape) run on the telemetry
// goroutine, not here. The raw query text travels in memory only, inside
// telemetryItem, which is never serialized.

import (
	"strings"
	"sync"
	"time"
)

// maxPendingTelemetry bounds per-connection pending statements (a client that
// pipelines thousands of Executes without reading results).
const maxPendingTelemetry = 1024

// telemetryItem is what goes on the client channel: the wire event plus the
// in-memory-only inputs the background goroutine needs to finish it. raw is
// NEVER copied into TelemetryEvent; only its literal-free shape is, and only
// when query shapes are enabled.
type telemetryItem struct {
	ev  TelemetryEvent
	raw string
	pq  *ParsedQuery
	v   *PolicyViolation
}

type pendingTelemetry struct {
	item      telemetryItem
	epoch     int64 // client Sync/Query boundary count when queued
	remaining int   // CommandCompletes still expected (multi-statement 'Q')
	rowsWrite int64
	rowsRead  int64
	anyWrite  bool
	known     bool
}

// telemetryConn is nil when telemetry is off; every method is nil-safe.
type telemetryConn struct {
	mu      sync.Mutex
	agent   string
	mission string
	unnamed bool
	pending []*pendingTelemetry
	// sent counts client-side sync points (Sync 'S', simple Query 'Q'); recv
	// counts ReadyForQuery from upstream. A response belongs to the pending
	// statement only if their epochs match, so an error in one pipelined
	// batch is never pinned on a statement from the next batch.
	sent int64
	recv int64
}

func newTelemetryConn(identity *AgentIdentity, agentLabel string) *telemetryConn {
	if telemetryClient == nil {
		return nil
	}
	c := &telemetryConn{}
	if identity != nil {
		c.agent, c.mission = identity.AgentID, identity.MissionID
	} else {
		c.agent, c.unnamed = agentLabel, true
		if c.agent == "" {
			c.agent = "unknown"
		}
	}
	return c
}

// baseItem builds the metadata event for one statement run.
func (c *telemetryConn) baseItem(eventType, decision string, v *PolicyViolation, pq *ParsedQuery, query string, latencyMs float64) telemetryItem {
	var table, op string
	if v != nil {
		table, op = v.Table, v.Operation
	}
	var tables []string
	var fp string
	if pq != nil {
		if op == "" {
			op = pq.Operation
		}
		// "BEGIN; DELETE …; COMMIT" -> DELETE, not TRANSACTION (same as try).
		for _, o := range pq.Operations {
			if o != "" && !strings.EqualFold(o, "TRANSACTION") {
				if v == nil || v.Operation == "" {
					op = o
				}
				break
			}
		}
		if table == "" && len(pq.Tables) > 0 {
			table = pq.Tables[0]
		}
		tables = append(tables, pq.Tables...)
		fp = pq.Fingerprint
	}
	var risk float64
	if qwmScorer != nil && pq != nil {
		risk = qwmScorer.Score(pq, QWMInfraState{})
	}
	return telemetryItem{
		ev: TelemetryEvent{
			TS:        time.Now().UTC().Format(time.RFC3339Nano),
			EventType: eventType, Decision: decision,
			TableName: table, OpType: op, LatencyMs: latencyMs,
			CostFlag:  decision == "flag",
			RiskScore: risk, QWMThresholdMs: qwmTelemetrySLOMs,
			AgentID: c.agent, AgentUnnamed: c.unnamed, Mission: c.mission,
			Tables: tables, Fingerprint: fp,
		},
		raw: query, pq: pq, v: v,
	}
}

// emitNow sends an event that will never reach upstream (blocked).
func (c *telemetryConn) emitNow(eventType, decision string, v *PolicyViolation, pq *ParsedQuery, query string, latencyMs float64) {
	if c == nil {
		return
	}
	it := c.baseItem(eventType, decision, v, pq, query, latencyMs)
	it.ev.RowsKnown = true // nothing ran
	telemetryClient.emitItem(it)
}

// enqueue registers a statement run that was forwarded upstream. statements
// is the number of CommandCompletes expected (len(pq.Operations) for 'Q').
func (c *telemetryConn) enqueue(eventType, decision string, v *PolicyViolation, pq *ParsedQuery, query string, latencyMs float64, statements int) {
	if c == nil {
		return
	}
	if statements < 1 {
		statements = 1
	}
	p := &pendingTelemetry{item: c.baseItem(eventType, decision, v, pq, query, latencyMs), remaining: statements}
	c.mu.Lock()
	p.epoch = c.sent
	var overflow *pendingTelemetry
	if len(c.pending) >= maxPendingTelemetry {
		overflow = c.pending[0]
		c.pending = c.pending[1:]
	}
	c.pending = append(c.pending, p)
	c.mu.Unlock()
	if overflow != nil {
		c.finish(overflow, false)
	}
}

// enqueueStmt registers one run of a prepared statement (Execute).
func (c *telemetryConn) enqueueStmt(st *preparedStmt) {
	if c == nil || st == nil {
		return
	}
	eventType, decision := "allowed", "allow"
	if st.violation != nil {
		eventType, decision = "monitored", "flag"
	}
	c.enqueue(eventType, decision, st.violation, st.pq, st.query, st.decisionMs, 1)
}

func (c *telemetryConn) finish(p *pendingTelemetry, failed bool) {
	it := p.item
	it.ev.Failed = failed
	it.ev.RowsKnown = p.known
	if p.anyWrite {
		it.ev.RowsAffected = p.rowsWrite
	} else {
		it.ev.RowsAffected = p.rowsRead
	}
	telemetryClient.emitItem(it)
}

// onCommandComplete handles upstream 'C' (payload = tag) and 'I' (nil).
func (c *telemetryConn) onCommandComplete(payload []byte) {
	if c == nil {
		return
	}
	c.mu.Lock()
	if len(c.pending) == 0 || c.pending[0].epoch != c.recv {
		c.mu.Unlock()
		return
	}
	p := c.pending[0]
	if payload != nil {
		if rows, isWrite, ok := parseCommandCompleteRows(payload); ok {
			if isWrite {
				p.anyWrite = true
				p.rowsWrite += rows
			} else {
				p.rowsRead += rows
			}
		}
	}
	p.known = true
	p.remaining--
	done := p.remaining <= 0
	if done {
		c.pending = c.pending[1:]
	}
	c.mu.Unlock()
	if done {
		c.finish(p, false)
	}
}

// onError handles upstream ErrorResponse: the oldest pending statement failed.
// (In a multi-statement 'Q', later statements are skipped by the server.)
func (c *telemetryConn) onError() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if len(c.pending) == 0 || c.pending[0].epoch != c.recv {
		c.mu.Unlock()
		return
	}
	p := c.pending[0]
	c.pending = c.pending[1:]
	c.mu.Unlock()
	c.finish(p, true)
}

// onSyncPoint is called after the proxy forwards a Sync or simple Query: the
// upstream will answer everything before it with one ReadyForQuery.
func (c *telemetryConn) onSyncPoint() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.sent++
	c.mu.Unlock()
}

// onReady handles ReadyForQuery: statements of the finished batch that got
// no CommandComplete were skipped by the server (after an error).
func (c *telemetryConn) onReady() {
	if c == nil {
		return
	}
	c.mu.Lock()
	i := 0
	for i < len(c.pending) && c.pending[i].epoch <= c.recv {
		i++
	}
	done := c.pending[:i:i]
	c.pending = c.pending[i:]
	c.recv++
	c.mu.Unlock()
	for _, p := range done {
		c.finish(p, true)
	}
}

// flush emits everything pending (ReadyForQuery, connection close).
func (c *telemetryConn) flush() {
	if c == nil {
		return
	}
	c.mu.Lock()
	rest := c.pending
	c.pending = nil
	c.mu.Unlock()
	for _, p := range rest {
		c.finish(p, false)
	}
}

// finalizeTelemetryItem runs on the telemetry goroutine: flag rules,
// mass_write, and the gated literal-free shape. Returns the wire event.
func finalizeTelemetryItem(it telemetryItem, withShape bool) TelemetryEvent {
	ev := it.ev
	flags := tryStaticFlags(it.pq, it.raw)
	if ev.RowsKnown && ev.RowsAffected > tryMassWriteThreshold && isWriteOp(ev.OpType) {
		flags = append(flags, "mass_write")
	}
	reasons := make([]string, 0, len(flags)+1)
	for _, f := range flags {
		reasons = append(reasons, tryFlagReasons[f])
	}
	if it.v != nil && it.v.Reason != "" {
		flags = append(flags, "policy")
		r := "policy: " + it.v.Reason
		if it.v.Table != "" && !strings.Contains(it.v.Reason, it.v.Table) {
			r += " (" + it.v.Table + ")"
		}
		reasons = append(reasons, r)
	}
	if len(flags) > 0 {
		ev.Flags, ev.Reasons = flags, reasons
	}
	if withShape && it.raw != "" {
		ev.QueryShape = normalizeQueryShape(it.raw)
	}
	return ev
}

func isWriteOp(op string) bool {
	switch strings.ToUpper(op) {
	case "INSERT", "UPDATE", "DELETE", "MERGE", "COPY":
		return true
	}
	return false
}
