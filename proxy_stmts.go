package main

// proxy_stmts.go — per-connection prepared-statement tracking.
//
// Drivers that cache prepared statements (psycopg3 after prepare_threshold=5,
// pgx's statement cache, JDBC, lib/pq db.Prepare) send Parse ONCE and then
// only Bind/Execute for every later run. The policy decision is made at Parse
// (the SQL text is only on the wire there), but logging, per-agent counts,
// violations (monitor mode) and observations must happen per execution or the
// audit trail undercounts (a real psycopg run counted 47 of 144 statements).
//
// Accounting rule: Parse accounts for the first run of a statement (as
// before). Every further Execute of that statement — a repeat run of a cached
// prepared statement — is logged and counted here. Re-sending Execute on a
// suspended portal (row-limited fetch) continues the same run and is not
// counted again.

import "time"

// maxTrackedStmts bounds per-connection state for clients that never Close.
const maxTrackedStmts = 4096

type preparedStmt struct {
	query     string
	pq        *ParsedQuery
	violation *PolicyViolation // monitored (non-blocking) violation from Parse, or nil
	runs      int
	// decisionMs is the policy decision latency measured at Parse; repeat
	// Executes reuse it for telemetry (no re-check happens on Execute).
	decisionMs float64
}

type boundPortal struct {
	stmt     string
	executed bool
}

type stmtTracker struct {
	stmts   map[string]*preparedStmt
	portals map[string]*boundPortal
}

func newStmtTracker() *stmtTracker {
	return &stmtTracker{stmts: map[string]*preparedStmt{}, portals: map[string]*boundPortal{}}
}

// parse records a non-blocked Parse. Re-parsing a name (always the case for
// the unnamed statement) starts a fresh run count.
func (t *stmtTracker) parse(name, query string, pq *ParsedQuery, v *PolicyViolation) {
	t.parseTimed(name, query, pq, v, 0)
}

// parseTimed is parse plus the decision latency (for telemetry).
func (t *stmtTracker) parseTimed(name, query string, pq *ParsedQuery, v *PolicyViolation, decisionMs float64) {
	if _, exists := t.stmts[name]; !exists && len(t.stmts) >= maxTrackedStmts {
		return
	}
	var vc *PolicyViolation
	if v != nil {
		cp := *v
		vc = &cp
	}
	t.stmts[name] = &preparedStmt{query: query, pq: pq, violation: vc, decisionMs: decisionMs}
}

func (t *stmtTracker) bind(portal, stmt string) {
	if _, exists := t.portals[portal]; !exists && len(t.portals) >= maxTrackedStmts {
		return
	}
	t.portals[portal] = &boundPortal{stmt: stmt}
}

// execute returns the statement behind portal and whether this Execute is a
// repeat run that Parse did not already account for.
func (t *stmtTracker) execute(portal string) (*preparedStmt, bool) {
	st, repeat, _ := t.executeRun(portal)
	return st, repeat
}

// executeRun is execute plus newRun: false only when this Execute resumes a
// suspended portal (same run, no new CommandComplete accounting needed).
func (t *stmtTracker) executeRun(portal string) (st *preparedStmt, repeat, newRun bool) {
	p, ok := t.portals[portal]
	if !ok {
		return nil, false, false
	}
	st = t.stmts[p.stmt]
	if st == nil {
		return nil, false, false
	}
	if p.executed { // resumed suspended portal — same run
		return st, false, false
	}
	p.executed = true
	st.runs++
	return st, st.runs > 1, true
}

func (t *stmtTracker) close(kind byte, name string) {
	switch kind {
	case 'S':
		delete(t.stmts, name)
	case 'P':
		delete(t.portals, name)
	}
}

// accountRepeatExecute logs and counts a repeat run of a cached prepared
// statement exactly like a first run: agent query count, [ALLOWED]/[MONITOR]
// log line, monitored violation and observation. Control-plane telemetry for
// the run is queued by the caller (telemetryConn.enqueueStmt) so it can carry
// the CommandComplete row count.
func accountRepeatExecute(pe *PolicyEngine, st *preparedStmt, agentLabel string, identity *AgentIdentity) {
	if agentTracker != nil && identity != nil {
		agentTracker.RecordQuery(identity.AgentID)
	}
	if st.violation != nil {
		v := *st.violation
		v.Action = "monitored"
		v.Timestamp = time.Now()
		pe.addViolation(v)
		logMonitored(agentLabel, st.query, &v)
	} else {
		logAllowed(agentLabel, st.query)
	}
	recordObservation(agentLabel, identity, st.query, st.pq, false)
}
