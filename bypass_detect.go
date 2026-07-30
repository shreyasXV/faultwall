package main

// REAL F9 — runtime bypass detection via pg_stat_activity reconciliation.
//
// The shipped F9 (RunDBIsolationProbe in guards.go) is a single-host TCP
// dial: it tells you whether the proxy *can* reach the upstream from its
// own host. That's a topology hint, not detection — it cannot prove an
// agent has bypassed the proxy.
//
// This file implements actual bypass detection: it reconciles the set of
// backends the proxy has originated against pg_stat_activity. Sessions
// that look like agent connections (`application_name LIKE 'agent:%'`) but
// whose PID is NOT in the proxy-owned set are strong evidence of a
// bypass — the agent connected directly to the database port instead of
// going through the proxy.
//
// This is OBSERVE-ONLY: we emit loud WARNINGs but do not kill or block
// sessions (that would require privileged DB access, and is out of scope
// for what FaultWall enforces today). The detection is gated by
// `bypassDetectionOn` (default ON, observe-only is non-destructive) and
// disablable via `FW_BYPASS_DETECTION=false`.

import (
	"database/sql"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Proxy-owned PID registry
// ─────────────────────────────────────────────────────────────────────────────

// ProxyBackendRegistry tracks the upstream backend PIDs the proxy has
// originated. Each upstream connection learns its PID from the
// BackendKeyData ('K') wire message during auth; the proxy records it
// here for the lifetime of the connection and removes it on close.
//
// The classifier uses this set as the ground truth for "the proxy
// originated this session." A session whose PID is in this set was
// established through the proxy. A session whose PID is NOT here, but
// whose application_name claims to be an agent, is a candidate bypass.
type ProxyBackendRegistry struct {
	mu   sync.RWMutex
	pids map[int]struct{}
}

// NewProxyBackendRegistry builds an empty registry.
func NewProxyBackendRegistry() *ProxyBackendRegistry {
	return &ProxyBackendRegistry{pids: make(map[int]struct{})}
}

// Register marks pid as proxy-owned. PID 0 is rejected (Postgres never
// uses it; receiving 0 means we failed to parse BackendKeyData and we
// don't want to claim every malformed session as ours).
func (r *ProxyBackendRegistry) Register(pid int) {
	if r == nil || pid <= 0 {
		return
	}
	r.mu.Lock()
	r.pids[pid] = struct{}{}
	r.mu.Unlock()
}

// Deregister removes pid from the proxy-owned set. Safe to call with a
// PID that was never registered (e.g. when BackendKeyData parsing failed
// upstream).
func (r *ProxyBackendRegistry) Deregister(pid int) {
	if r == nil || pid <= 0 {
		return
	}
	r.mu.Lock()
	delete(r.pids, pid)
	r.mu.Unlock()
}

// Has reports whether pid is currently registered.
func (r *ProxyBackendRegistry) Has(pid int) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	_, ok := r.pids[pid]
	r.mu.RUnlock()
	return ok
}

// Size returns the current number of registered PIDs (for diagnostics).
func (r *ProxyBackendRegistry) Size() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.pids)
}

// proxyBackendRegistry is the package-global instance the proxy and the
// detector share. Initialized in main.go.
var proxyBackendRegistry = NewProxyBackendRegistry()

// ─────────────────────────────────────────────────────────────────────────────
// Classifier
// ─────────────────────────────────────────────────────────────────────────────

// SessionRow is one row from pg_stat_activity, as the detector reads it.
// Fields are kept narrow so the classifier is hermetic and unit-testable
// without a real DB.
type SessionRow struct {
	PID             int
	Username        string
	ApplicationName string
	ClientAddr      string
	BackendType     string // 'client backend', 'autovacuum worker', 'walsender', etc.
	State           string
	Query           string
}

// BypassVerdict is what the classifier decides for one row.
type BypassVerdict int

const (
	// VerdictProxyOwned means the session is one of the proxy's own
	// upstream backends — never flag.
	VerdictProxyOwned BypassVerdict = iota
	// VerdictSystem means the session is a system/admin process Postgres
	// runs internally (autovacuum, walsender, archiver, etc.) — never
	// flag.
	VerdictSystem
	// VerdictBypassSuspected means the session looks like an agent
	// connecting directly to the DB port (application_name has the
	// `agent:` prefix and the PID is not proxy-owned) — flag.
	VerdictBypassSuspected
	// VerdictUnknown means we have no opinion: the session is not
	// proxy-owned, doesn't claim an agent identity, and isn't a system
	// process. We don't flag these to avoid false positives on
	// legitimate maintenance/admin connections.
	VerdictUnknown
)

// systemBackendTypes are pg_stat_activity backend_type values that are
// internal Postgres machinery and never represent agent traffic.
var systemBackendTypes = map[string]struct{}{
	"autovacuum launcher":   {},
	"autovacuum worker":     {},
	"logical replication launcher": {},
	"logical replication worker":   {},
	"walsender":             {},
	"walreceiver":           {},
	"walwriter":             {},
	"checkpointer":          {},
	"background writer":     {},
	"archiver":              {},
	"startup":               {},
	"background worker":     {},
}

// systemUsernames are role names Postgres / cloud providers use for
// internal maintenance. Defensive: do not flag a bypass for these even
// if backend_type is empty (some pg versions / proxies omit it).
var systemUsernames = map[string]struct{}{
	"rdsadmin":     {},
	"rdsrepladmin": {},
	"rds_superuser": {},
	"cloudsqladmin": {},
	"cloudsqlsuperuser": {},
}

// ClassifySession returns the bypass verdict for one pg_stat_activity row.
// The function is pure: same inputs → same output, and it never panics
// on empty/garbage data.
func ClassifySession(row SessionRow, registry *ProxyBackendRegistry) BypassVerdict {
	// Recover defensively in case future Postgres surfaces unexpected
	// data — the loop must NEVER crash the proxy.
	defer func() { _ = recover() }()

	// (1) Anything the proxy registered is proxy-owned, full stop.
	if registry != nil && registry.Has(row.PID) {
		return VerdictProxyOwned
	}
	// (2) System backends.
	if _, ok := systemBackendTypes[strings.ToLower(strings.TrimSpace(row.BackendType))]; ok {
		return VerdictSystem
	}
	if _, ok := systemUsernames[strings.ToLower(strings.TrimSpace(row.Username))]; ok {
		return VerdictSystem
	}
	// (3) Agent-looking session that the proxy did NOT originate.
	app := strings.TrimSpace(row.ApplicationName)
	if strings.HasPrefix(app, "agent:") {
		return VerdictBypassSuspected
	}
	// (4) Unknown legitimate connection (psql admin, monitoring tools,
	// migration scripts, etc.). We deliberately do not flag these — the
	// security promise is that AGENTS go through the proxy. Other DB
	// users have their own access controls.
	return VerdictUnknown
}

// ─────────────────────────────────────────────────────────────────────────────
// Guard + poller
// ─────────────────────────────────────────────────────────────────────────────

// bypassDetectionOn gates the runtime poller. Default ON because the
// detector is observe-only (non-destructive). Operators can disable it
// with FW_BYPASS_DETECTION=false.
var bypassDetectionOn atomic.Bool

// IsBypassDetectionOn reports the current gate state.
func IsBypassDetectionOn() bool { return bypassDetectionOn.Load() }

// setBypassDetection is the test seam.
func setBypassDetection(on bool) { bypassDetectionOn.Store(on) }

// InitBypassDetectionGuard reads FW_BYPASS_DETECTION and runs the
// classifier self-check. Self-check failure → gate OFF + WARNING (we
// would rather not warn at all than emit bogus alerts; operators will
// re-investigate). Default ON unless explicitly disabled.
func InitBypassDetectionGuard() {
	want := strings.ToLower(strings.TrimSpace(os.Getenv("FW_BYPASS_DETECTION")))
	if want == "false" || want == "0" || want == "off" {
		bypassDetectionOn.Store(false)
		log.Printf("REAL-F9 bypass detection DISABLED via FW_BYPASS_DETECTION=%s. " +
			"FaultWall will not warn on direct-to-DB agent connections; verify network "+
			"isolation through external means.", want)
		return
	}
	if !bypassClassifierSelfCheckFn() {
		bypassDetectionOn.Store(false)
		log.Printf("WARN: REAL-F9 self-check FAILED: bypass classifier gave incorrect verdicts on "+
			"synthetic input. Detection disabled (gate OFF) so we don't emit bogus warnings. " +
			"DB-port isolation remains a HARD REQUIREMENT regardless — verify externally.")
		return
	}
	bypassDetectionOn.Store(true)
	log.Printf("REAL-F9 guard active: bypass detection runs on each pg_stat_activity poll. "+
		"Observe-only — agents that connect direct-to-DB will be logged as suspected " +
		"bypasses, not blocked. Disable with FW_BYPASS_DETECTION=false.")
}

// bypassClassifierSelfCheckFn is the test seam for fault injection.
var bypassClassifierSelfCheckFn = bypassDetectionClassifierSelfCheckPass

// bypassDetectionClassifierSelfCheckPass exercises the four classifier
// contracts the spec calls out:
//
//	(a) a proxy-owned backend is NOT flagged
//	(b) an agent-looking session not in the tracked set IS flagged
//	(c) system/replication/autovacuum sessions are NOT flagged
//	(d) classifier never panics on empty/garbage rows
func bypassDetectionClassifierSelfCheckPass() bool {
	reg := NewProxyBackendRegistry()
	reg.Register(123)

	// (a)
	v := ClassifySession(SessionRow{PID: 123, ApplicationName: "agent:x:mission:m"}, reg)
	if v != VerdictProxyOwned {
		return false
	}
	// (b)
	v = ClassifySession(SessionRow{PID: 999, ApplicationName: "agent:x:mission:m", BackendType: "client backend"}, reg)
	if v != VerdictBypassSuspected {
		return false
	}
	// (c)
	v = ClassifySession(SessionRow{PID: 222, BackendType: "autovacuum worker"}, reg)
	if v != VerdictSystem {
		return false
	}
	v = ClassifySession(SessionRow{PID: 333, BackendType: "walsender", Username: "rds_replication"}, reg)
	if v != VerdictSystem {
		return false
	}
	// (d) garbage input must not panic and must classify as Unknown
	v = ClassifySession(SessionRow{}, reg)
	if v != VerdictUnknown {
		return false
	}
	v = ClassifySession(SessionRow{PID: -1, ApplicationName: "\x00\x01garbage", BackendType: "\x00"}, reg)
	if v != VerdictUnknown {
		return false
	}
	return true
}

// ─────────────────────────────────────────────────────────────────────────────
// Poller + warning dedupe
// ─────────────────────────────────────────────────────────────────────────────

// BypassDetector runs a background poll loop, calling out to a row source
// (function pointer / interface — for hermetic testing). Production wires
// it up to a real *sql.DB; tests inject synthetic rows.
type BypassDetector struct {
	registry *ProxyBackendRegistry
	source   BypassRowSource
	interval time.Duration

	mu    sync.Mutex
	seen  map[int]bool // pids we've already warned about this appearance

	stopOnce sync.Once
	stop     chan struct{}
}

// BypassRowSource abstracts the pg_stat_activity read so tests can inject
// synthetic rows. A returned error logs a warning and the loop continues
// (graceful degradation — never crashes the proxy).
type BypassRowSource interface {
	Snapshot() ([]SessionRow, error)
}

// NewBypassDetector builds a detector. interval <=0 defaults to 30s.
func NewBypassDetector(reg *ProxyBackendRegistry, src BypassRowSource, interval time.Duration) *BypassDetector {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &BypassDetector{
		registry: reg,
		source:   src,
		interval: interval,
		seen:     make(map[int]bool),
		stop:     make(chan struct{}),
	}
}

// Start launches the poll goroutine. Safe to call once. The detector
// runs only when the gate is ON; if the gate is flipped OFF after start,
// the loop short-circuits each tick.
func (d *BypassDetector) Start() {
	if d == nil || d.source == nil {
		return
	}
	go func() {
		// Prime once so operators get fast feedback in dev.
		d.tick()
		ticker := time.NewTicker(d.interval)
		defer ticker.Stop()
		for {
			select {
			case <-d.stop:
				return
			case <-ticker.C:
				d.tick()
			}
		}
	}()
}

// Stop ends the poll goroutine.
func (d *BypassDetector) Stop() {
	if d == nil {
		return
	}
	d.stopOnce.Do(func() { close(d.stop) })
}

// tick performs one poll cycle. Public-on-receiver because tests drive it
// directly (deterministic) instead of waiting on the ticker.
func (d *BypassDetector) Tick() { d.tick() }

func (d *BypassDetector) tick() {
	if !IsBypassDetectionOn() {
		return
	}
	rows, err := d.source.Snapshot()
	if err != nil {
		// Per spec: a query error is non-fatal. Log a warning, continue.
		log.Printf("WARN: REAL-F9 bypass detector: pg_stat_activity snapshot failed: %v "+
			"(non-fatal; will retry on next tick)", err)
		return
	}
	d.classifyAndWarn(rows)
}

// classifyAndWarn applies the classifier to each row and emits warnings
// for newly-seen bypass suspects. Dedupe rule: warn ONCE per (pid,
// appearance). If a pid disappears from a subsequent poll and reappears,
// it is warned again.
func (d *BypassDetector) classifyAndWarn(rows []SessionRow) {
	currentSuspects := make(map[int]bool)
	for _, row := range rows {
		v := ClassifySession(row, d.registry)
		if v != VerdictBypassSuspected {
			continue
		}
		currentSuspects[row.PID] = true
		d.mu.Lock()
		alreadyWarned := d.seen[row.PID]
		if !alreadyWarned {
			d.seen[row.PID] = true
		}
		d.mu.Unlock()
		if !alreadyWarned {
			log.Printf("ALERT: REAL-F9 BYPASS SUSPECTED: agent-like session NOT originated by proxy. "+
				"pid=%d application_name=%q usename=%q client_addr=%q backend_type=%q. "+
				"This session reaches the database WITHOUT FaultWall in front of it — the "+
				"SQL-level enforcement promise is VOID for this session. Verify network "+
				"isolation: the agent should not be able to reach the DB port directly. "+
				"FaultWall is observe-only here; it will not kill the session.",
				row.PID, row.ApplicationName, row.Username, row.ClientAddr, row.BackendType)
		}
	}
	// Sweep `seen`: drop pids that have disappeared since the last poll
	// so a returning bypass is warned again. We rebuild the map from the
	// intersection of current suspects + previously-seen still-present.
	d.mu.Lock()
	for pid := range d.seen {
		if !currentSuspects[pid] {
			delete(d.seen, pid)
		}
	}
	d.mu.Unlock()
}

// ─────────────────────────────────────────────────────────────────────────────
// Real DB-backed row source
// ─────────────────────────────────────────────────────────────────────────────

// dbBypassRowSource is the production BypassRowSource backed by a
// monitoring sql.DB connection.
type dbBypassRowSource struct {
	db *sql.DB
}

// NewDBBypassRowSource wraps an *sql.DB.
func NewDBBypassRowSource(db *sql.DB) BypassRowSource {
	return &dbBypassRowSource{db: db}
}

// Snapshot reads pg_stat_activity. backend_type was added in pg10; we
// COALESCE it to '' for older versions so the classifier sees a stable
// shape.
func (s *dbBypassRowSource) Snapshot() ([]SessionRow, error) {
	rows, err := s.db.Query(`
		SELECT pid,
		       COALESCE(usename, ''),
		       COALESCE(application_name, ''),
		       COALESCE(client_addr::text, ''),
		       COALESCE(backend_type, ''),
		       COALESCE(state, ''),
		       COALESCE(query, '')
		FROM pg_stat_activity
		WHERE pid <> pg_backend_pid()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionRow
	for rows.Next() {
		var r SessionRow
		if err := rows.Scan(&r.PID, &r.Username, &r.ApplicationName, &r.ClientAddr,
			&r.BackendType, &r.State, &r.Query); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
