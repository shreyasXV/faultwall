package main

import (
	"database/sql"
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ── RFC-003 §4.1A: live DB-state sampler ──
//
// StateSampler polls pg_stat_activity on a short interval (~1s) in a background
// goroutine and caches a QWMInfraState snapshot. The query hot path reads the
// cached snapshot with an atomic load — it NEVER queries the DB inline, so the
// hot-path cost is a pointer load (RFC §7 / acceptance: <0.2ms/query in shadow).
//
// Utilization (ρ) is a FAST signal: active backends / configured cores. We avoid
// loadavg deliberately — its 1-min smoothing lags real load by ~a minute and
// produces stale rejections (one of the two hard lessons in the RFC).

// StateSampler owns the monitoring connection and the cached snapshot.
type StateSampler struct {
	db       *sql.DB
	cores    float64
	interval time.Duration

	snap atomic.Value // holds QWMInfraState

	stopOnce sync.Once
	stop     chan struct{}

	// for TPS delta computation between samples
	lastXact   int64
	lastSample time.Time

	// cached once from SHOW max_connections (rarely changes)
	maxConns int
}

// NewStateSampler builds a sampler. cores is the configured core count used as
// the utilization denominator; if <=0 it defaults to 1 (single-core assumption,
// conservative — utilization reads higher, so we err toward caution).
func NewStateSampler(db *sql.DB, cores float64, interval time.Duration) *StateSampler {
	if cores <= 0 {
		cores = 1
	}
	if interval <= 0 {
		interval = time.Second
	}
	s := &StateSampler{db: db, cores: cores, interval: interval, stop: make(chan struct{})}
	s.snap.Store(QWMInfraState{}) // zero = unknown until first sample
	return s
}

// Snapshot returns the most recent cached state. Hot-path safe (atomic load).
func (s *StateSampler) Snapshot() QWMInfraState {
	if v, ok := s.snap.Load().(QWMInfraState); ok {
		return v
	}
	return QWMInfraState{}
}

// Start launches the sampling goroutine. Safe to call once.
func (s *StateSampler) Start() {
	if s.db == nil {
		log.Printf("WARN: QWM state sampler: no monitoring DB — world model runs on queuing prior only")
		return
	}
	go func() {
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		// Prime once immediately so the first queries get real state quickly.
		s.sampleOnce()
		for {
			select {
			case <-s.stop:
				return
			case <-ticker.C:
				s.sampleOnce()
			}
		}
	}()
}

// Stop ends the sampling goroutine.
func (s *StateSampler) Stop() {
	s.stopOnce.Do(func() { close(s.stop) })
}

// sampleOnce reads pg_stat_activity + a couple of cheap stat views and updates
// the cached snapshot. Errors are logged at low volume and leave the previous
// snapshot in place (graceful degradation).
func (s *StateSampler) sampleOnce() {
	var (
		active   int
		blocked  int
		longest  float64
		cacheHit float64
		xact     int64
	)

	// active + blocked backends and the longest active query age, in one pass.
	// Note: FILTER attaches to aggregates only, so min(query_start) is filtered
	// (valid) and the EXTRACT/now() math is applied to the aggregate result.
	row := s.db.QueryRow(`
		SELECT
		  count(*) FILTER (WHERE state = 'active') AS active,
		  count(*) FILTER (WHERE wait_event_type = 'Lock') AS blocked,
		  COALESCE(EXTRACT(EPOCH FROM (now() - min(query_start) FILTER (WHERE state = 'active'))), 0) * 1000 AS longest_ms
		FROM pg_stat_activity
		WHERE pid <> pg_backend_pid()`)
	if err := row.Scan(&active, &blocked, &longest); err != nil {
		s.logSampleErr("activity", err)
		return
	}

	// cache hit ratio (cheap, db-wide).
	_ = s.db.QueryRow(`
		SELECT CASE WHEN blks_hit + blks_read = 0 THEN 1.0
		            ELSE blks_hit::float8 / (blks_hit + blks_read) END
		FROM pg_stat_database WHERE datname = current_database()`).Scan(&cacheHit)

	// transactions for TPS delta.
	_ = s.db.QueryRow(`
		SELECT COALESCE(sum(xact_commit + xact_rollback), 0)
		FROM pg_stat_database WHERE datname = current_database()`).Scan(&xact)

	now := time.Now()
	var tps float64
	if !s.lastSample.IsZero() && xact >= s.lastXact {
		dt := now.Sub(s.lastSample).Seconds()
		if dt > 0 {
			tps = float64(xact-s.lastXact) / dt
		}
	}
	s.lastXact = xact
	s.lastSample = now

	util := float64(active) / s.cores

	// Query max_connections once and cache it (rarely changes, cheap to hold).
	if s.maxConns == 0 {
		var mcStr string
		if err := s.db.QueryRow(`SHOW max_connections`).Scan(&mcStr); err == nil {
			if mc, err := strconv.Atoi(mcStr); err == nil && mc > 0 {
				s.maxConns = mc
			}
		}
		if s.maxConns == 0 {
			s.maxConns = 100 // safe default
		}
	}

	// Bridge blocked-backend signals into the shape-scorer legacy fields.
	// LockContentionMs: longest active query age is the best pg_stat_activity
	// proxy for lock-wait duration (eBPF would give exact lock hold times).
	// AnomalyRateAgent: fraction of active backends that are lock-waiting;
	// >0 means contention is happening right now.
	var lockContentionMs float64
	if blocked > 0 {
		lockContentionMs = longest
	}
	anomalyRate := float64(blocked) / math.Max(1, float64(active))

	s.snap.Store(QWMInfraState{
		ActiveBackends:  active,
		BlockedBackends: blocked,
		LongestActiveMs: longest,
		CacheHitRatio:   cacheHit,
		TPS:             tps,
		Utilization:     util,
		// shape-scorer fields — bridged from pg_stat_activity
		ActiveConnections:   active,
		MaxConnections:      s.maxConns,
		LockContentionMs:    lockContentionMs,
		AnomalyRateAgent:    anomalyRate,
		AvgQueryTime60sMs:   longest, // best proxy available without eBPF
		BaselineQueryTimeMs: 50,      // conservative baseline (queries under ~50ms are normal)
	})
}

var stateSampleErrCount int64

func (s *StateSampler) logSampleErr(which string, err error) {
	// Log the first error and then every 60th to avoid spam if the monitoring
	// connection is down (proxy keeps serving on the queuing prior meanwhile).
	n := atomic.AddInt64(&stateSampleErrCount, 1)
	if n == 1 || n%60 == 0 {
		log.Printf("WARN: QWM state sample (%s) failed (#%d): %v", which, n, err)
	}
}

// monitoringDSNFromUpstream builds a libpq DSN for the monitoring connection.
// Preference order: DATABASE_URL (operator-provided, full creds) → a best-effort
// DSN from the upstream host:port (works when the proxy can auth as the same
// role, e.g. trust/peer on loopback). Returns ("", false) if nothing usable.
func monitoringDSNFromUpstream(upstreamAddr string) (string, bool) {
	if env := strings.TrimSpace(getenv("DATABASE_URL")); env != "" {
		return env, true
	}
	host, port := splitHostPort(upstreamAddr)
	if host == "" {
		return "", false
	}
	user := firstNonEmpty(getenv("FW_MONITOR_USER"), getenv("PGUSER"), "postgres")
	dbname := firstNonEmpty(getenv("FW_MONITOR_DB"), getenv("PGDATABASE"), user)
	dsn := fmt.Sprintf("host=%s port=%s user=%s dbname=%s sslmode=disable connect_timeout=3",
		host, port, user, dbname)
	if pw := getenv("FW_MONITOR_PASSWORD"); pw != "" {
		dsn += " password=" + pw
	} else if pw := getenv("PGPASSWORD"); pw != "" {
		dsn += " password=" + pw
	}
	return dsn, true
}

// openMonitoringDB opens (but does not verify) a small monitoring pool. The
// caller pings; on failure the sampler simply runs without live state.
func openMonitoringDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)
	return db, nil
}

// ── small helpers (kept local to avoid colliding with existing utils) ──

func getenv(k string) string { return strings.TrimSpace(os.Getenv(k)) }

func splitHostPort(addr string) (string, string) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", ""
	}
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		host := addr[:i]
		port := addr[i+1:]
		if host == "" {
			host = "localhost"
		}
		if _, err := strconv.Atoi(port); err != nil {
			port = "5432"
		}
		return host, port
	}
	return addr, "5432"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
