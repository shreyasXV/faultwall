package main

// try_activity.go — in-memory live activity feed + zero-config "would flag"
// rules used by `faultwall try` (monitor mode, never blocks).
//
// The default try policy observes everything and flags, without blocking:
//   - ddl            CREATE / ALTER / DROP / TRUNCATE (and DCL like GRANT)
//   - no_where       UPDATE / DELETE with no WHERE clause (or WHERE 1=1)
//   - secret_read    SELECT referencing password / token / secret / ssn / api_key columns
//   - mass_write     INSERT / UPDATE / DELETE / MERGE / COPY affecting > 100 rows
//   - server_func    pg_read_file, dblink, lo_export, pg_terminate_backend, …
//
// The proxy hot path only calls tryRecordQuery / tryRecordCommandComplete,
// both no-ops unless tryActivity is non-nil (i.e. `faultwall try` is running).

import (
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
)

// tryMassWriteThreshold is the row count above which a write is flagged.
const tryMassWriteThreshold = 100

// tryActivity is non-nil only while `faultwall try` is running.
var tryActivity *TryActivityStore

// TryEvent is one query observed by the proxy.
type TryEvent struct {
	ID        int64     `json:"id"`
	Time      time.Time `json:"time"`
	Agent     string    `json:"agent"`
	Mission   string    `json:"mission,omitempty"`
	Query     string    `json:"query"`
	Operation string    `json:"operation"`
	Tables    []string  `json:"tables,omitempty"`
	Rows      int64     `json:"rows"`
	RowsKnown bool      `json:"rows_known"`
	Flags     []string  `json:"flags"`
	Reasons   []string  `json:"reasons"`
}

// TryAgentStats is the per-agent rollup shown in the live view.
type TryAgentStats struct {
	Agent    string         `json:"agent"`
	Queries  int64          `json:"queries"`
	Flagged  int64          `json:"flagged"`
	Ops      map[string]int `json:"ops"`
	LastSeen time.Time      `json:"last_seen"`
	// Unnamed is true when the agent connected without
	// application_name=agent:<name>:… (the label is a fallback like "unknown").
	Unnamed bool `json:"unnamed"`
}

// TryActivityStore is a bounded ring of recent events plus per-agent stats.
type TryActivityStore struct {
	mu     sync.RWMutex
	max    int
	nextID int64
	events []*TryEvent
	agents map[string]*TryAgentStats
	onFlag func(ev *TryEvent, newFlags []string)
	// unnamedSeen: labels that connected without an agent:<name> identity.
	unnamedSeen map[string]bool
}

func NewTryActivityStore(max int) *TryActivityStore {
	if max <= 0 {
		max = 500
	}
	return &TryActivityStore{max: max, agents: map[string]*TryAgentStats{}}
}

// tryFlagReasons maps a flag code to a human-readable explanation.
var tryFlagReasons = map[string]string{
	"ddl":         "schema change (DDL/DCL)",
	"no_where":    "write without a WHERE clause",
	"secret_read": "reads a secret-looking column",
	"mass_write":  "write touched more than 100 rows",
	"server_func": "calls a dangerous server function (file/process/admin)",
}

// tryDangerousFunctions are server-side functions an agent should never need.
var tryDangerousFunctions = []string{
	"pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_execute_server_program",
	"lo_export", "lo_import", "dblink", "dblink_exec", "pg_terminate_backend",
	"pg_cancel_backend", "pg_reload_conf",
}

// secretColumnTokens are matched against `_`-separated parts of a column name,
// so `password_hash`, `api_token`, `client_secret`, `user_ssn` all match but
// `lessons` or `tokenizer_version` do not.
var secretColumnTokens = map[string]bool{
	"password": true, "passwd": true, "pwd": true,
	"token": true, "secret": true, "ssn": true,
	"apikey": true, "privatekey": true,
}

func isSecretColumn(col string) bool {
	c := strings.ToLower(strings.Trim(col, `"`))
	if c == "api_key" || c == "private_key" || c == "access_key" {
		return true
	}
	for _, part := range strings.FieldsFunc(c, func(r rune) bool { return r == '_' || r == '.' }) {
		if secretColumnTokens[part] {
			return true
		}
		// plural / suffixed forms: tokens, passwords, secrets
		if strings.HasSuffix(part, "s") && secretColumnTokens[strings.TrimSuffix(part, "s")] {
			return true
		}
	}
	return false
}

// tryStaticFlags evaluates the query-shape rules (everything except
// mass_write, which needs the row count from CommandComplete).
func tryStaticFlags(pq *ParsedQuery, query string) []string {
	if pq == nil {
		return nil
	}
	ops := pq.Operations
	if len(ops) == 0 && pq.Operation != "" {
		ops = []string{pq.Operation}
	}
	var flags []string
	add := func(f string) {
		for _, x := range flags {
			if x == f {
				return
			}
		}
		flags = append(flags, f)
	}
	upper := strings.ToUpper(query)
	hasSelect := false
	for _, op := range ops {
		opU := strings.ToUpper(op)
		switch OperationCategory[opU] {
		case "DDL", "DCL":
			add("ddl")
		}
		if opU == "UPDATE" || opU == "DELETE" {
			if !strings.Contains(upper, "WHERE") || hasTrivialWhere(query) {
				add("no_where")
			}
		}
		if opU == "SELECT" {
			hasSelect = true
		}
	}
	for _, fn := range pq.Functions {
		if isFunctionBlocked(strings.ToLower(fn), tryDangerousFunctions) {
			add("server_func")
			break
		}
	}
	if hasSelect {
		for _, col := range pq.Columns {
			if isSecretColumn(col) {
				add("secret_read")
				break
			}
		}
	}
	return flags
}

// parseCommandCompleteRows extracts the affected-row count from a
// CommandComplete tag ("UPDATE 150", "INSERT 0 200", "DELETE 3", "COPY 10").
// isWrite reports whether the tag is a data-modifying command.
func parseCommandCompleteRows(payload []byte) (rows int64, isWrite bool, ok bool) {
	tag := strings.TrimRight(string(payload), "\x00")
	fields := strings.Fields(tag)
	if len(fields) < 2 {
		return 0, false, false
	}
	n, err := strconv.ParseInt(fields[len(fields)-1], 10, 64)
	if err != nil {
		return 0, false, false
	}
	switch strings.ToUpper(fields[0]) {
	case "INSERT", "UPDATE", "DELETE", "MERGE", "COPY":
		return n, true, true
	}
	return n, false, true
}

func (s *TryActivityStore) Record(agent, mission, query string, pq *ParsedQuery, v *PolicyViolation) int64 {
	if s == nil {
		return 0
	}
	flags := tryStaticFlags(pq, query)
	policyReason := ""
	if v != nil && v.Reason != "" {
		flags = append(flags, "policy")
		policyReason = "policy: " + v.Reason
		if v.Table != "" {
			policyReason += " (" + v.Table + ")"
		}
	}
	op := "UNKNOWN"
	var tables []string
	if pq != nil {
		if pq.Operation != "" {
			op = pq.Operation
		}
		// "BEGIN; DELETE …; COMMIT" → show DELETE, not TRANSACTION.
		for _, o := range pq.Operations {
			if o != "" && !strings.EqualFold(o, "TRANSACTION") {
				op = o
				break
			}
		}
		tables = append(tables, pq.Tables...)
	}
	s.mu.Lock()
	s.nextID++
	ev := &TryEvent{
		ID: s.nextID, Time: time.Now(), Agent: agent, Mission: mission,
		Query: truncateQuery(query), Operation: op, Tables: tables,
		Flags: []string{}, Reasons: []string{},
	}
	s.events = append(s.events, ev)
	if len(s.events) > s.max {
		s.events = s.events[len(s.events)-s.max:]
	}
	st := s.agents[agent]
	if st == nil {
		st = &TryAgentStats{Agent: agent, Ops: map[string]int{}}
		s.agents[agent] = st
	}
	st.Queries++
	st.Ops[op]++
	st.LastSeen = ev.Time
	added := s.addFlagsLocked(ev, flags)
	if policyReason != "" {
		for i, f := range ev.Flags {
			if f == "policy" {
				ev.Reasons[i] = policyReason
			}
		}
	}
	cb := s.onFlag
	s.mu.Unlock()
	if cb != nil && len(added) > 0 {
		cb(ev, added)
	}
	return ev.ID
}

// addFlagsLocked adds new flags to ev and returns the ones that were new.
func (s *TryActivityStore) addFlagsLocked(ev *TryEvent, flags []string) []string {
	var added []string
	wasFlagged := len(ev.Flags) > 0
	for _, f := range flags {
		dup := false
		for _, x := range ev.Flags {
			if x == f {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		ev.Flags = append(ev.Flags, f)
		ev.Reasons = append(ev.Reasons, tryFlagReasons[f])
		added = append(added, f)
	}
	if !wasFlagged && len(ev.Flags) > 0 {
		if st := s.agents[ev.Agent]; st != nil {
			st.Flagged++
		}
	}
	return added
}

// RecordCommandComplete attaches the affected-row count to an event and
// applies the mass_write rule.
func (s *TryActivityStore) RecordCommandComplete(id int64, payload []byte) {
	if s == nil || id == 0 {
		return
	}
	rows, isWrite, ok := parseCommandCompleteRows(payload)
	if !ok {
		return
	}
	s.mu.Lock()
	var ev *TryEvent
	for i := len(s.events) - 1; i >= 0; i-- {
		if s.events[i].ID == id {
			ev = s.events[i]
			break
		}
		if s.events[i].ID < id {
			break
		}
	}
	if ev == nil {
		s.mu.Unlock()
		return
	}
	if rows > ev.Rows {
		ev.Rows = rows
	}
	ev.RowsKnown = true
	var added []string
	if isWrite && rows > tryMassWriteThreshold {
		added = s.addFlagsLocked(ev, []string{"mass_write"})
	}
	cb := s.onFlag
	s.mu.Unlock()
	if cb != nil && len(added) > 0 {
		cb(ev, added)
	}
}

// Snapshot returns events with ID > since (newest last) and all agent stats.
func (s *TryActivityStore) Snapshot(since int64) ([]TryEvent, []TryAgentStats, int64, int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	events := []TryEvent{}
	for _, ev := range s.events {
		if ev.ID > since {
			cp := *ev
			cp.Flags = append([]string{}, ev.Flags...)
			cp.Reasons = append([]string{}, ev.Reasons...)
			events = append(events, cp)
		}
	}
	agents := make([]TryAgentStats, 0, len(s.agents))
	var total, flagged int64
	for _, st := range s.agents {
		cp := *st
		cp.Unnamed = s.unnamedSeen[st.Agent]
		cp.Ops = map[string]int{}
		for k, v := range st.Ops {
			cp.Ops[k] = v
		}
		agents = append(agents, cp)
		total += st.Queries
		flagged += st.Flagged
	}
	return events, agents, total, flagged
}

// tryRecordQuery is the proxy hook (no-op unless `faultwall try` is running).
func tryRecordQuery(agentLabel string, identity *AgentIdentity, query string, pq *ParsedQuery, v *PolicyViolation) int64 {
	if tryActivity == nil {
		return 0
	}
	agent, mission := agentLabel, ""
	if identity != nil {
		agent, mission = identity.AgentID, identity.MissionID
	} else {
		tryActivity.noteUnnamed(agentLabel)
	}
	return tryActivity.Record(agent, mission, query, pq, v)
}

// noteUnnamed marks agent as unidentified and, the first time it is seen,
// prints how to name it. Without a name the See feed reads "unknown ran
// 3 UPDATEs", which is the one thing the live view must not say.
func (s *TryActivityStore) noteUnnamed(agent string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	first := !s.unnamedSeen[agent]
	if s.unnamedSeen == nil {
		s.unnamedSeen = map[string]bool{}
	}
	s.unnamedSeen[agent] = true
	s.mu.Unlock()
	if first {
		log.Printf("%s%s[NAME YOUR AGENT]%s a connection arrived as %q. Add application_name=agent:<name>:mission:<task> to its connection string so the feed shows who ran what.",
			colorYellow, colorBold, colorReset, agent)
	}
}

// tryRecordCommandComplete is the proxy hook for upstream CommandComplete.
func tryRecordCommandComplete(id int64, payload []byte) {
	if tryActivity == nil {
		return
	}
	tryActivity.RecordCommandComplete(id, payload)
}

// tryConnState is per-connection bookkeeping for the try feed. It maps
// prepared statements → query text and portals → statements so that cached
// prepared statements (pgx, psycopg3, JDBC) are recorded on every Execute,
// not just on the first Parse.
type tryConnState struct {
	mu       sync.Mutex
	stmts    map[string]tryStmt
	portals  map[string]string
	executed map[string]bool // portal already ran (resumed Execute = same run)
	lastID   int64
}

type tryStmt struct {
	query string
	pq    *ParsedQuery
	v     *PolicyViolation
}

func newTryConnState() *tryConnState {
	if tryActivity == nil {
		return nil
	}
	return &tryConnState{stmts: map[string]tryStmt{}, portals: map[string]string{}, executed: map[string]bool{}}
}

func (c *tryConnState) setLast(id int64) {
	c.mu.Lock()
	c.lastID = id
	c.mu.Unlock()
}

func (c *tryConnState) last() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastID
}

// onSimpleQuery records a simple-protocol ('Q') query.
func (c *tryConnState) onSimpleQuery(agentLabel string, identity *AgentIdentity, query string, pq *ParsedQuery, v *PolicyViolation) {
	if c == nil {
		return
	}
	c.setLast(tryRecordQuery(agentLabel, identity, query, pq, v))
}

func (c *tryConnState) onParse(stmtName, query string, pq *ParsedQuery, v *PolicyViolation) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.stmts[stmtName] = tryStmt{query: query, pq: pq, v: v}
	c.mu.Unlock()
}

func (c *tryConnState) onBind(portal, stmtName string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.portals[portal] = stmtName
	delete(c.executed, portal)
	c.mu.Unlock()
}

func (c *tryConnState) onExecute(agentLabel string, identity *AgentIdentity, portal string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	st, ok := c.stmts[c.portals[portal]]
	resumed := c.executed[portal]
	c.executed[portal] = true
	c.mu.Unlock()
	if !ok || st.query == "" || resumed {
		return
	}
	c.setLast(tryRecordQuery(agentLabel, identity, st.query, st.pq, st.v))
}

func (c *tryConnState) onClose(kind byte, name string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	if kind == 'S' {
		delete(c.stmts, name)
	} else if kind == 'P' {
		delete(c.portals, name)
		delete(c.executed, name)
	}
	c.mu.Unlock()
}

// onCommandComplete handles an upstream CommandComplete ('C') message.
func (c *tryConnState) onCommandComplete(payload []byte) {
	if c == nil {
		return
	}
	tryRecordCommandComplete(c.last(), payload)
}
