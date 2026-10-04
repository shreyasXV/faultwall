package main

// policy_expiry.go: slice 2 of POLICY-WIRE-CONTRACT Rev C.1. Protected
// operations are denied once the offline window has expired, or when no valid
// signed policy was ever accepted. Also covers C5, expiry while a transaction
// is open.
//
// Decision point (C5): the moment the proxy forwards a client message
// upstream. holdGate.next() returns messages to proxyQueryLoop, which writes
// them to Postgres straight away, so the check happens in next(). Messages
// buffered in the proxy, such as a held group approved after expiry, are
// judged when they are released, not when they arrived.
//
//   - Already forwarded before expiry: authorized. It runs to completion and
//     may become durable after expiry. FaultWall never cancels or undoes it.
//   - After expiry, everything is protected except transaction control that
//     cannot make earlier work durable: BEGIN, ROLLBACK, SAVEPOINT, RELEASE,
//     ROLLBACK TO, ROLLBACK PREPARED, and the empty query.
//   - Plain reads are denied too until the C4 session check lands. There is no
//     name-snapshot fallback.
//   - COMMIT/END after expiry goes through only when it cannot make work
//     durable: no transaction (a no-op), an aborted transaction (Postgres
//     rolls it back), or an open transaction in which no statement has run.
//     Otherwise it is denied through Postgres, so the transaction aborts and
//     can only be rolled back.
//   - PREPARE TRANSACTION and COMMIT PREPARED are denied.
//   - The proxy never sends its own COMMIT or ROLLBACK, and never replays,
//     splits or rewraps a client's transaction.
//
// Denials use the same mechanism as a denied hold. The statement is replaced
// by one that fails with a marker, or the Execute is pointed at a portal that
// does not exist. Postgres raises the error and aborts an open transaction,
// and rewriteUpstream swaps the marker error for the FaultWall message.

import (
	"log"
	"strings"
	"sync"
	"sync/atomic"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

const (
	expDeny   = 0
	expAllow  = 1
	expCommit = 2
)

// classifyAfterExpiry decides what a statement may do after expiry.
func classifyAfterExpiry(q string) int {
	q = strings.TrimSpace(q)
	if q == "" || q == ";" {
		return expAllow
	}
	tree, err := pg_query.Parse(q)
	if err != nil {
		return expDeny
	}
	if len(tree.GetStmts()) == 0 {
		return expAllow
	}
	res := expAllow
	for _, s := range tree.GetStmts() {
		ts := s.GetStmt().GetTransactionStmt()
		if ts == nil {
			return expDeny
		}
		switch ts.GetKind() {
		case pg_query.TransactionStmtKind_TRANS_STMT_BEGIN, pg_query.TransactionStmtKind_TRANS_STMT_START,
			pg_query.TransactionStmtKind_TRANS_STMT_ROLLBACK, pg_query.TransactionStmtKind_TRANS_STMT_SAVEPOINT,
			pg_query.TransactionStmtKind_TRANS_STMT_RELEASE, pg_query.TransactionStmtKind_TRANS_STMT_ROLLBACK_TO,
			pg_query.TransactionStmtKind_TRANS_STMT_ROLLBACK_PREPARED:
		case pg_query.TransactionStmtKind_TRANS_STMT_COMMIT:
			res = expCommit
		default: // PREPARE TRANSACTION, COMMIT PREPARED, unknown
			return expDeny
		}
	}
	return res
}

// txnWork tracks, per connection, whether the open transaction has run any
// statement (C5), and how many sync points are still in flight.
type txnWork struct {
	mu      sync.Mutex
	worked  bool // a non-transaction-control statement was forwarded since the last idle
	pending int  // forwarded Q/Sync/FunctionCall not yet answered by ReadyForQuery
}

// noteForwarded is called by the loop after each message reaches upstream.
func (g *holdGate) noteForwarded(t byte, payload []byte) {
	g.work.mu.Lock()
	defer g.work.mu.Unlock()
	switch t {
	case 'Q':
		g.work.pending++
		if len(payload) > 0 && classifyAfterExpiry(string(payload[:len(payload)-1])) == expDeny {
			g.work.worked = true
		}
	case 'E', 'F':
		// Conservative: any Execute or fast-path call counts as work.
		g.work.worked = true
		if t == 'F' {
			g.work.pending++
		}
	case 'S':
		g.work.pending++
	}
}

// onReadyWork runs in the relay goroutine for each ReadyForQuery.
func (g *holdGate) onReadyWork(status byte) {
	g.work.mu.Lock()
	defer g.work.mu.Unlock()
	if g.work.pending > 0 {
		g.work.pending--
	}
	// Only forget the work once idle with nothing else in flight, so a
	// pipelined later transaction is never under-counted.
	if status == 'I' && g.work.pending == 0 {
		g.work.worked = false
	}
}

// commitIsHarmless reports whether a COMMIT now cannot make work durable.
func (g *holdGate) commitIsHarmless() bool {
	g.work.mu.Lock()
	worked, pending := g.work.worked, g.work.pending
	g.work.mu.Unlock()
	if pending > 0 {
		return false // state unknown while earlier sync points are in flight
	}
	status, _ := g.txn.snapshot()
	switch status {
	case 'I', 'E':
		return true // no transaction (no-op) / aborted (Postgres rolls it back)
	}
	return !worked
}

// policyExpired: deny (enforce) or would-deny (watch) state.
func (g *holdGate) expiryState() (deny, wouldDeny bool) {
	pg := policyGuardG
	if g.guard != nil {
		pg = g.guard
	}
	if pg == nil {
		return false, false
	}
	if pg.Expired() {
		return true, false
	}
	return false, pg.windowLapsed()
}

func (g *holdGate) guardRef() *policyGuard {
	if g.guard != nil {
		return g.guard
	}
	return policyGuardG
}

// allowedAfterExpiry: classification of q with the C5 COMMIT rule applied.
func (g *holdGate) allowedAfterExpiry(q string) bool {
	switch classifyAfterExpiry(q) {
	case expAllow:
		return true
	case expCommit:
		return g.commitIsHarmless()
	}
	return false
}

func (g *holdGate) expiryDenyMarker(query string) string {
	marker := "fwhold_" + newHoldID()
	g.rewrites.Store(marker, holdErr{Code: "42501", Msg: "[BLOCKED by FaultWall] " + g.guardRef().ExpiryMessage() +
		". Protected operations are denied until FaultWall reaches the control plane again. It did not run."})
	atomic.AddInt32(&g.nRewrites, 1)
	log.Printf("%s%s[DENIED: policy expired]%s agent=%-20s query=%s", colorRed, colorBold, colorReset, g.agentLabel, querySnippet(query))
	return marker
}

// expiryFilterSimple handles one simple-protocol Query. handled=true means a
// denial was already written upstream and the loop must not see m.
func (g *holdGate) expiryFilterSimple(m wireMsg) (wireMsg, bool, error) {
	deny, would := g.expiryState()
	if !deny && !would {
		return m, false, nil
	}
	q := ""
	if len(m.p) > 0 {
		q = string(m.p[:len(m.p)-1])
	}
	if g.allowedAfterExpiry(q) {
		return m, false, nil
	}
	if would {
		log.Printf("%s[WOULD DENY: policy expired]%s agent=%-20s (watch mode, not blocked) query=%s", colorYellow, colorReset, g.agentLabel, querySnippet(q))
		return m, false, nil
	}
	marker := g.expiryDenyMarker(q)
	repl := append([]byte("SELECT '"+marker+"'::pg_catalog.int4"), 0)
	if err := writeWireMessage(g.upstream, 'Q', repl); err != nil {
		return m, false, err
	}
	g.noteForwarded('Q', repl)
	return m, true, nil
}

// expiryFilterFunctionCall: a fast-path call after expiry becomes a failing
// query (Postgres answers ErrorResponse + ReadyForQuery, as for 'F').
func (g *holdGate) expiryFilterFunctionCall(m wireMsg) (wireMsg, bool, error) {
	deny, would := g.expiryState()
	if !deny {
		if would {
			log.Printf("%s[WOULD DENY: policy expired]%s agent=%-20s (watch mode) fast-path function call", colorYellow, colorReset, g.agentLabel)
		}
		return m, false, nil
	}
	marker := g.expiryDenyMarker("<fast-path function call>")
	repl := append([]byte("SELECT '"+marker+"'::pg_catalog.int4"), 0)
	if err := writeWireMessage(g.upstream, 'Q', repl); err != nil {
		return m, false, err
	}
	g.noteForwarded('Q', repl)
	return m, true, nil
}

// expiryFilterGroup rewrites the first non-allowed Execute of an extended
// group to the marker portal. Postgres errors there, skips to Sync, and reports
// the real transaction state. An Execute whose statement text is unknown is
// denied (unproven).
func (g *holdGate) expiryFilterGroup(group []wireMsg) []wireMsg {
	deny, would := g.expiryState()
	if !deny && !would {
		return group
	}
	for _, e := range g.groupExecutes(group) {
		if e.known && g.allowedAfterExpiry(e.query) {
			continue
		}
		if would {
			log.Printf("%s[WOULD DENY: policy expired]%s agent=%-20s (watch mode, not blocked) query=%s", colorYellow, colorReset, g.agentLabel, querySnippet(e.query))
			return group
		}
		marker := g.expiryDenyMarker(e.query)
		out := make([]wireMsg, len(group))
		copy(out, group)
		out[e.idx] = wireMsg{t: 'E', p: append([]byte(marker), 0, 0, 0, 0, 0)}
		return out
	}
	return group
}

type groupExec struct {
	idx   int
	query string
	known bool
}

// groupExecutes resolves each Execute in a group to its statement text, from
// this group's Parse/Bind or the connection's statement tracker.
func (g *holdGate) groupExecutes(group []wireMsg) []groupExec {
	parsed := map[string]string{}
	bound := map[string]string{}
	var out []groupExec
	for i, m := range group {
		switch m.t {
		case 'P':
			name, q := extractParseMessage(m.p)
			parsed[name] = q
		case 'B':
			portal, stmt := extractBindNames(m.p)
			bound[portal] = stmt
		case 'E':
			portal := extractNullTerminated(m.p, 0)
			stmt, ok := bound[portal]
			if !ok && g.stmts != nil {
				if bp := g.stmts.portals[portal]; bp != nil {
					stmt, ok = bp.stmt, true
				}
			}
			q, qok := parsed[stmt]
			if !qok && ok && g.stmts != nil {
				if st := g.stmts.stmts[stmt]; st != nil {
					q, qok = st.query, true
				}
			}
			out = append(out, groupExec{idx: i, query: q, known: ok && qok})
		}
	}
	return out
}
