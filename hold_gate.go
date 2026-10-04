package main

// hold_gate.go — where statements are actually held.
//
// The gate sits between the client socket and proxyQueryLoop. The loop asks
// gate.next() for the next client message instead of reading the socket, so
// the existing per-message policy logic is unchanged. The gate:
//
//   - owns a dedicated reader goroutine for the client socket, so a client
//     that hangs up or sends Terminate ('X') while a statement is held is seen
//     immediately (no polling) and the held statement is dropped, never run;
//   - for the extended protocol, buffers the whole message group
//     (Parse/Bind/Describe/Execute/Close) up to Sync or Flush BEFORE anything
//     reaches Postgres. That means a held statement's Parse/Bind are not at
//     the server yet, so the client's statement_timeout doesn't start
//     counting during the hold. It also means cached prepared statements
//     (Bind/Execute only, no Parse) are matched via the per-connection
//     statement tracker and can't bypass a hold;
//   - on approve, releases the group unchanged;
//   - on deny, releases the group with the held Execute pointed at a portal
//     that doesn't exist ("fwhold_<id>"). Postgres raises an error, aborts the
//     transaction if there is one (so the next statement gets 25P02), skips
//     to the client's own Sync and sends one ReadyForQuery with the real
//     transaction status. The relay goroutine rewrites that one error into
//     the FaultWall message (see takeRewrite);
//   - for simple 'Q', a denied query is replaced by a statement that fails
//     with the same marker ('fwhold_<id>'::int4), giving the same real
//     transaction semantics without needing plpgsql.

import (
	"bytes"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgproto3/v2"
)

type wireMsg struct {
	t   byte
	p   []byte
	err error
}

const (
	clientReaderBuf   = 64
	holdBacklogMaxMsg = 4096
)

// clientReader is the dedicated reader goroutine for one client connection.
type clientReader struct {
	ch      chan wireMsg
	done    chan struct{}
	backlog []wireMsg
	dead    bool
}

func startClientReader(r io.Reader) *clientReader {
	c := &clientReader{ch: make(chan wireMsg, clientReaderBuf), done: make(chan struct{})}
	go func() {
		for {
			t, p, err := readWireMessage(r)
			select {
			case c.ch <- wireMsg{t: t, p: p, err: err}:
			case <-c.done:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return c
}

func (c *clientReader) stop() {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
}

func (c *clientReader) read() wireMsg {
	if len(c.backlog) > 0 {
		m := c.backlog[0]
		c.backlog = c.backlog[1:]
		return m
	}
	if c.dead {
		return wireMsg{err: io.EOF}
	}
	m := <-c.ch
	if m.err != nil {
		c.dead = true
	}
	return m
}

// stash queues a message that arrived while a statement was held.
func (c *clientReader) stash(m wireMsg) bool {
	if len(c.backlog) >= holdBacklogMaxMsg {
		return false
	}
	c.backlog = append(c.backlog, m)
	return true
}

// backlogHasExit reports whether the client already queued Terminate / EOF.
func (c *clientReader) backlogHasExit() bool {
	for _, m := range c.backlog {
		if m.err != nil || m.t == 'X' {
			return true
		}
	}
	return false
}

// txnTracker follows the upstream ReadyForQuery status so a hold can show the
// approver whether the agent's transaction is open (and holding locks).
type txnTracker struct {
	mu     sync.Mutex
	status byte
	since  time.Time
}

func (t *txnTracker) onReady(status byte) {
	t.mu.Lock()
	if status == 'I' {
		t.since = time.Time{}
	} else if t.status == 'I' || t.status == 0 || t.since.IsZero() {
		t.since = time.Now()
	}
	t.status = status
	t.mu.Unlock()
}

func (t *txnTracker) snapshot() (byte, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.status == 0 {
		return 'I', 0
	}
	if t.since.IsZero() {
		return t.status, 0
	}
	return t.status, time.Since(t.since)
}

// holdGate is per-connection hold state.
type holdGate struct {
	pe         *PolicyEngine
	identity   *AgentIdentity
	agentLabel string
	client     net.Conn
	upstream   net.Conn
	cr         *clientReader
	stmts      *stmtTracker
	txn        txnTracker
	queue      []wireMsg

	rewrites   sync.Map // marker -> holdErr
	nRewrites  int32
	upstreamMu *sync.Mutex // nil: the loop goroutine is the only upstream writer
}

func newHoldGate(pe *PolicyEngine, identity *AgentIdentity, agentLabel string, client, upstream net.Conn, stmts *stmtTracker) *holdGate {
	return &holdGate{
		pe: pe, identity: identity, agentLabel: agentLabel,
		client: client, upstream: upstream, stmts: stmts,
		cr: startClientReader(client),
	}
}

func (g *holdGate) close() { g.cr.stop() }

func (g *holdGate) agentID() string {
	if g.identity != nil {
		return g.identity.AgentID
	}
	return ""
}

func (g *holdGate) mission() string {
	if g.identity != nil {
		return g.identity.MissionID
	}
	return ""
}

func (g *holdGate) connKey() string {
	if v, ok := connBackendKeys.Load(g.client); ok {
		return v.(string)
	}
	return ""
}

// isExtendedMsg reports whether a frontend message belongs to an
// extended-protocol group that ends at Sync ('S') or Flush ('H').
func isExtendedMsg(t byte) bool {
	switch t {
	case 'P', 'B', 'D', 'E', 'C', 'S', 'H':
		return true
	}
	return false
}

// next returns the next client message for proxyQueryLoop.
func (g *holdGate) next() (byte, []byte, error) {
	for {
		if len(g.queue) > 0 {
			m := g.queue[0]
			g.queue = g.queue[1:]
			return m.t, m.p, m.err
		}
		m := g.cr.read()
		if m.err != nil {
			return 0, nil, m.err
		}
		rules, mode := holdRules(g.pe)
		if len(rules) == 0 {
			return m.t, m.p, nil
		}
		switch {
		case m.t == 'Q':
			out, forwarded, err := g.gateSimple(m, rules, mode)
			if err != nil {
				return 0, nil, err
			}
			if forwarded {
				continue
			}
			return out.t, out.p, nil
		case isExtendedMsg(m.t):
			group := []wireMsg{m}
			for m.t != 'S' && m.t != 'H' {
				m = g.cr.read()
				if m.err != nil {
					return 0, nil, m.err // client went away mid-group: nothing of it reaches PG
				}
				group = append(group, m)
				if !isExtendedMsg(m.t) {
					break // e.g. CopyData after an Execute of COPY FROM STDIN
				}
			}
			out, err := g.gateGroup(group, rules, mode)
			if err != nil {
				return 0, nil, err
			}
			g.queue = append(g.queue, out...)
		default:
			return m.t, m.p, nil
		}
	}
}

// holdCandidate is one statement in a message group that matched a hold rule.
type holdCandidate struct {
	idx   int // index of the Execute (or Q) in the group
	query string
	pq    *ParsedQuery
	match *HoldMatch
}

// candidateFor checks one query against the rules. Statements the policy
// engine will block anyway are not held (they'd be held, then blocked).
func (g *holdGate) candidateFor(rules []HoldRule, query string) (*ParsedQuery, *HoldMatch) {
	pq := ParseQuery(query)
	hm := matchHoldRules(rules, g.agentID(), query, pq)
	if hm == nil {
		return pq, nil
	}
	if g.pe != nil && g.pe.GetEnforcement() == "enforce" {
		if v, _ := safeCheckQuery(g.pe, g.identity, query); v != nil {
			return pq, nil
		}
	}
	return pq, hm
}

func (g *holdGate) gateGroup(group []wireMsg, rules []HoldRule, mode string) ([]wireMsg, error) {
	parsed := map[string]string{} // stmt name -> query, from Parse in this group
	bound := map[string]string{}  // portal -> stmt name, from Bind in this group
	var cands []holdCandidate
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
			if !ok {
				if bp := g.stmts.portals[portal]; bp != nil {
					stmt = bp.stmt
				} else {
					continue
				}
			}
			q, ok := parsed[stmt]
			if !ok {
				if st := g.stmts.stmts[stmt]; st != nil {
					q = st.query
				}
			}
			if strings.TrimSpace(q) == "" {
				continue
			}
			pq, hm := g.candidateFor(rules, q)
			if hm != nil {
				cands = append(cands, holdCandidate{idx: i, query: q, pq: pq, match: hm})
			}
		}
	}
	if len(cands) == 0 {
		return group, nil
	}
	if !holdsEnforced(g.pe, mode) {
		g.logWouldHold(cands)
		return group, nil
	}
	if status, _ := g.txn.snapshot(); status == 'E' {
		return group, nil // txn already aborted: PG will reject it anyway
	}
	h := g.newHold(cands)
	res := g.wait(h)
	if res.ClientGone {
		return nil, io.EOF
	}
	if res.Decision.Approve {
		return group, nil
	}
	marker := "fwhold_" + h.ID
	g.rewrites.Store(marker, denyError(h, res.Decision, holdTimeout(g.pe)))
	atomic.AddInt32(&g.nRewrites, 1)
	out := make([]wireMsg, len(group))
	copy(out, group)
	// Point the first held Execute at a portal that doesn't exist. PG errors
	// there, skips the rest of the group to Sync and reports real txn state.
	// Earlier statements of the group are rolled back with the implicit
	// transaction (or stay in the explicit txn, which is now aborted).
	out[cands[0].idx] = wireMsg{t: 'E', p: append([]byte(marker), 0, 0, 0, 0, 0)}
	return out, nil
}

// gateSimple handles a simple-protocol query. forwarded=true means the gate
// already sent the (denied) replacement upstream and the loop must not see it.
func (g *holdGate) gateSimple(m wireMsg, rules []HoldRule, mode string) (wireMsg, bool, error) {
	if len(m.p) < 2 {
		return m, false, nil
	}
	query := string(m.p[:len(m.p)-1])
	pq, hm := g.candidateFor(rules, query)
	if hm == nil {
		return m, false, nil
	}
	c := []holdCandidate{{idx: 0, query: query, pq: pq, match: hm}}
	if !holdsEnforced(g.pe, mode) {
		g.logWouldHold(c)
		return m, false, nil
	}
	if status, _ := g.txn.snapshot(); status == 'E' {
		return m, false, nil
	}
	h := g.newHold(c)
	res := g.wait(h)
	if res.ClientGone {
		return m, false, io.EOF
	}
	if res.Decision.Approve {
		return m, false, nil
	}
	marker := "fwhold_" + h.ID
	g.rewrites.Store(marker, denyError(h, res.Decision, holdTimeout(g.pe)))
	atomic.AddInt32(&g.nRewrites, 1)
	repl := append([]byte("SELECT '"+marker+"'::pg_catalog.int4"), 0)
	if err := writeWireMessage(g.upstream, 'Q', repl); err != nil {
		return m, false, err
	}
	return m, true, nil
}

func (g *holdGate) newHold(cands []holdCandidate) *Hold {
	status, age := g.txn.snapshot()
	h := &Hold{
		Agent:      nonEmpty(g.agentID(), g.agentLabel),
		Mission:    g.mission(),
		Operation:  cands[0].match.Operation,
		Rule:       cands[0].match.Rule,
		Statements: len(cands),
		InTxn:      status == 'T',
		TxnAgeMs:   age.Milliseconds(),
		connKey:    g.connKey(),
	}
	var qs []string
	for _, c := range cands {
		qs = append(qs, strings.TrimSpace(c.query))
		for _, t := range c.match.Tables {
			if !containsStr(h.Tables, t) {
				h.Tables = append(h.Tables, t)
			}
		}
	}
	h.Query = strings.Join(qs, ";\n")
	if cands[0].pq != nil {
		h.Fingerprint = cands[0].pq.Fingerprint
	}
	return h
}

func (g *holdGate) wait(h *Hold) holdWaitResult {
	if g.cr.backlogHasExit() {
		d := holdDecision{By: "client", Kind: "client_gone", Reason: "client disconnected"}
		log.Printf("%s%s[HOLD]%s client already sent Terminate, dropping held statement (never executed)", colorRed, colorBold, colorReset)
		return holdWaitResult{Decision: d, ClientGone: true}
	}
	var events <-chan wireMsg = g.cr.ch
	if g.cr.dead {
		events = nil
	}
	res := awaitHold(g.pe, h, events, func(m wireMsg) bool {
		return g.cr.stash(m)
	})
	if res.ClientGone {
		g.cr.dead = true
	}
	return res
}

func (g *holdGate) logWouldHold(cands []holdCandidate) {
	for _, c := range cands {
		log.Printf("%s%s[WOULD HOLD]%s agent=%-20s rule=%q (monitor mode, not paused) query=%s",
			colorYellow, colorBold, colorReset, g.agentLabel, c.match.Rule, querySnippet(c.query))
	}
}

// rewriteUpstream is called by the relay goroutine for each backend message.
// It swaps the error raised by a denied hold for the FaultWall message.
func (g *holdGate) rewriteUpstream(msgType byte, payload []byte) []byte {
	if msgType != 'E' || atomic.LoadInt32(&g.nRewrites) == 0 {
		return payload
	}
	i := bytes.Index(payload, []byte("fwhold_h_"))
	if i < 0 {
		return payload
	}
	j := i + len("fwhold_h_")
	for j < len(payload) && ((payload[j] >= '0' && payload[j] <= '9') || (payload[j] >= 'a' && payload[j] <= 'f')) {
		j++
	}
	marker := string(payload[i:j])
	v, ok := g.rewrites.LoadAndDelete(marker)
	if !ok {
		return payload
	}
	atomic.AddInt32(&g.nRewrites, -1)
	he := v.(holdErr)
	er := &pgproto3.ErrorResponse{Severity: "ERROR", Code: he.Code, Message: he.Msg}
	b, err := er.Encode(nil)
	if err != nil || len(b) < 5 {
		return payload
	}
	return b[5:]
}
