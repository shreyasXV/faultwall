package main

import (
	"database/sql"
	"fmt"
	"log"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// TenantMetrics holds aggregated metrics for a single tenant
type TenantMetrics struct {
	TenantID    string  `json:"tenant_id"`
	Queries     int64   `json:"queries"`
	AvgTimeMs   float64 `json:"avg_time_ms"`
	P50Ms       float64 `json:"p50_ms"`
	P95Ms       float64 `json:"p95_ms"`
	P99Ms       float64 `json:"p99_ms"`
	RowsRead    int64   `json:"rows_read"`
	RowsWritten int64   `json:"rows_written"`
	Connections int     `json:"connections"`
	IOBytes     int64   `json:"io_bytes"`
	CacheHit    float64 `json:"cache_hit_ratio"`
}

// QueryStat holds stats for a single query
type QueryStat struct {
	Query            string  `json:"query"`
	QueryFingerprint string  `json:"query_fingerprint"`
	TenantID         string  `json:"tenant_id"`
	Calls            int64   `json:"calls"`
	AvgTimeMs        float64 `json:"avg_time_ms"`
	TotalMs          float64 `json:"total_ms"`
	Rows             int64   `json:"rows"`
}

var (
	schemaQualAllRe = regexp.MustCompile(`(?i)(?:FROM|JOIN|INTO|UPDATE)\s+([a-zA-Z_][a-zA-Z0-9_]*)\.`)
)

// Overview holds global resource stats
type Overview struct {
	TotalConnections int     `json:"total_connections"`
	MaxConnections   int     `json:"max_connections"`
	QueriesPerSec    float64 `json:"queries_per_sec"`
	CacheHitRatio    float64 `json:"cache_hit_ratio"`
	CollectedAt      string  `json:"collected_at"`
	DBSize           string  `json:"db_size"`
}

// CollectorData is the full snapshot returned by Collect
type CollectorData struct {
	Tenants  []TenantMetrics `json:"tenants"`
	Queries  []QueryStat     `json:"queries"`
	Overview Overview        `json:"overview"`
}

// Collector manages metric collection from PostgreSQL
type Collector struct {
	db   *sql.DB
	mu   sync.RWMutex
	data CollectorData

	// track previous call counts for QPS calculation
	prevCalls    int64
	prevCallTime time.Time
}

func NewCollector(db *sql.DB) *Collector {
	return &Collector{
		db:           db,
		prevCallTime: time.Now(),
	}
}

func (c *Collector) GetData() CollectorData {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data
}

func (c *Collector) Collect(d *Detector) error {
	tenants, err := c.collectTenantMetrics(d)
	if err != nil {
		log.Printf("tenant metrics error: %v", err)
	}

	queries, err := c.collectTopQueries(d)
	if err != nil {
		log.Printf("query stats error: %v", err)
	}

	overview, err := c.collectOverview()
	if err != nil {
		log.Printf("overview error: %v", err)
	}

	c.mu.Lock()
	c.data = CollectorData{
		Tenants:  tenants,
		Queries:  queries,
		Overview: overview,
	}
	c.mu.Unlock()
	return nil
}

func (c *Collector) collectOverview() (Overview, error) {
	ov := Overview{
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// Active connections
	err := c.db.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE state IS NOT NULL`).Scan(&ov.TotalConnections)
	if err != nil {
		return ov, fmt.Errorf("connection count: %w", err)
	}

	// Max connections
	err = c.db.QueryRow(`SHOW max_connections`).Scan(&ov.MaxConnections)
	if err != nil {
		ov.MaxConnections = 100
	}

	// Cache hit ratio
	var blksHit, blksRead sql.NullInt64
	err = c.db.QueryRow(`
		SELECT sum(blks_hit), sum(blks_read) FROM pg_stat_database WHERE datname = current_database()
	`).Scan(&blksHit, &blksRead)
	if err == nil && blksHit.Valid && blksRead.Valid && (blksHit.Int64+blksRead.Int64) > 0 {
		ov.CacheHitRatio = float64(blksHit.Int64) / float64(blksHit.Int64+blksRead.Int64) * 100
	}

	// DB size
	var dbSize string
	err = c.db.QueryRow(`SELECT pg_size_pretty(pg_database_size(current_database()))`).Scan(&dbSize)
	if err == nil {
		ov.DBSize = dbSize
	}

	// QPS from pg_stat_statements
	var totalCalls sql.NullInt64
	err = c.db.QueryRow(`SELECT COALESCE(sum(calls), 0) FROM pg_stat_statements`).Scan(&totalCalls)
	if err == nil && totalCalls.Valid {
		now := time.Now()
		elapsed := now.Sub(c.prevCallTime).Seconds()
		if elapsed > 0 && c.prevCalls > 0 {
			ov.QueriesPerSec = math.Max(0, float64(totalCalls.Int64-c.prevCalls)/elapsed)
		}
		c.prevCalls = totalCalls.Int64
		c.prevCallTime = now
	}

	return ov, nil
}

func (c *Collector) collectTopQueries(d *Detector) ([]QueryStat, error) {
	rows, err := c.db.Query(`
		SELECT 
			query,
			calls,
			ROUND((total_exec_time / NULLIF(calls, 0))::numeric, 2) AS avg_time_ms,
			ROUND(total_exec_time::numeric, 2) AS total_ms,
			rows
		FROM pg_stat_statements
		WHERE calls > 0
		  AND query NOT LIKE '%pg_stat%'
		  AND query NOT LIKE '%information_schema%'
		  AND query NOT LIKE '%pg_database_size%'
		  AND query NOT LIKE '%pg_size_pretty%'
		  AND query NOT LIKE '%max_connections%'
		  AND query NOT LIKE 'CREATE%'
		  AND query NOT LIKE 'DROP%'
		  AND query NOT LIKE 'ALTER%'
		  AND query NOT LIKE 'DO $$%'
		  AND query NOT LIKE 'INSERT INTO%generate_series%'
		  AND query NOT LIKE 'ANALYZE%'
		  AND query NOT LIKE 'COPY%'
		  AND query NOT LIKE 'SET%'
		  AND query NOT LIKE 'SHOW%'
		ORDER BY total_exec_time DESC
		LIMIT 50
	`)
	if err != nil {
		if strings.Contains(err.Error(), "pg_stat_statements") {
			return []QueryStat{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	var stats []QueryStat
	for rows.Next() {
		var qs QueryStat
		if err := rows.Scan(&qs.Query, &qs.Calls, &qs.AvgTimeMs, &qs.TotalMs, &qs.Rows); err != nil {
			continue
		}
		if len(qs.Query) > 300 {
			qs.Query = qs.Query[:300] + "…"
		}
		qs.QueryFingerprint = FingerprintQuery(qs.Query)
		qs.TenantID = extractTenantFromQuery(qs.Query, d)
		stats = append(stats, qs)
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].TotalMs > stats[j].TotalMs
	})
	if len(stats) > 15 {
		stats = stats[:15]
	}
	return stats, nil
}

func (c *Collector) collectTenantMetrics(d *Detector) ([]TenantMetrics, error) {
	switch d.Pattern {
	case PatternSchema:
		return c.collectSchemaMetrics(d)
	case PatternRowLevel:
		return c.collectRowLevelMetrics(d)
	default:
		return c.collectDefaultMetrics()
	}
}

func (c *Collector) collectSchemaMetrics(d *Detector) ([]TenantMetrics, error) {
	var metrics []TenantMetrics

	for _, schema := range d.TenantSchemas {
		m := TenantMetrics{TenantID: schema}

		// Table row stats from pg_stat_user_tables
		err := c.db.QueryRow(`
			SELECT 
				COALESCE(sum(seq_tup_read + idx_tup_fetch), 0),
				COALESCE(sum(n_tup_ins + n_tup_upd + n_tup_del), 0)
			FROM pg_stat_user_tables
			WHERE schemaname = $1
		`, schema).Scan(&m.RowsRead, &m.RowsWritten)
		if err != nil {
			log.Printf("schema row stats for %s: %v", schema, err)
		}

		// I/O stats from pg_statio_user_tables (separate view!)
		err = c.db.QueryRow(`
			SELECT COALESCE(sum(
				COALESCE(heap_blks_read, 0) + 
				COALESCE(idx_blks_read, 0) + 
				COALESCE(toast_blks_read, 0) + 
				COALESCE(tidx_blks_read, 0)
			) * 8192, 0)
			FROM pg_statio_user_tables
			WHERE schemaname = $1
		`, schema).Scan(&m.IOBytes)
		if err != nil {
			log.Printf("schema I/O for %s: %v", schema, err)
		}

		// Cache hit ratio for this schema
		var hits, reads sql.NullInt64
		err = c.db.QueryRow(`
			SELECT 
				sum(COALESCE(heap_blks_hit, 0) + COALESCE(idx_blks_hit, 0)),
				sum(COALESCE(heap_blks_read, 0) + COALESCE(idx_blks_read, 0))
			FROM pg_statio_user_tables
			WHERE schemaname = $1
		`, schema).Scan(&hits, &reads)
		if err == nil && hits.Valid && reads.Valid && (hits.Int64+reads.Int64) > 0 {
			m.CacheHit = float64(hits.Int64) / float64(hits.Int64+reads.Int64) * 100
		}

		// Connections — check pg_stat_activity for queries referencing this schema
		err = c.db.QueryRow(`
			SELECT count(*)
			FROM pg_stat_activity
			WHERE state = 'active'
			  AND (query ILIKE $1 OR query ILIKE $2)
		`, "%"+schema+".%", "%search_path%"+schema+"%").Scan(&m.Connections)
		if err != nil {
			m.Connections = 0
		}

		// Query stats from pg_stat_statements
		qrows, err := c.db.Query(`
			SELECT calls, total_exec_time, rows
			FROM pg_stat_statements
			WHERE (query ILIKE $1 OR query ILIKE $2)
			  AND calls > 0
			  AND query NOT LIKE 'CREATE%'
			  AND query NOT LIKE 'INSERT INTO%generate_series%'
			  AND query NOT LIKE 'DO $$%'
		`, "%"+schema+".%", "%search_path%"+schema+"%")
		if err == nil {
			var totalCalls int64
			var totalTime float64
			var times []float64
			for qrows.Next() {
				var calls int64
				var execTime float64
				var r int64
				if scanErr := qrows.Scan(&calls, &execTime, &r); scanErr != nil {
					continue
				}
				totalCalls += calls
				totalTime += execTime
				if calls > 0 {
					times = append(times, execTime/float64(calls))
				}
			}
			qrows.Close()
			m.Queries = totalCalls
			if totalCalls > 0 {
				m.AvgTimeMs = totalTime / float64(totalCalls)
			}
			percentiles := calcPercentiles(times)
			m.P50Ms = percentiles[0]
			m.P95Ms = percentiles[1]
			m.P99Ms = percentiles[2]
		}

		metrics = append(metrics, m)
	}

	// Sort by queries descending
	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].Queries > metrics[j].Queries
	})

	return metrics, nil
}

func (c *Collector) collectRowLevelMetrics(d *Detector) ([]TenantMetrics, error) {
	if d.TenantColumn == "" || len(d.Tenants) == 0 {
		return c.collectDefaultMetrics()
	}

	tenantMetrics := make(map[string]*TenantMetrics)
	for _, t := range d.Tenants {
		displayName := ResolveTenantName(t)
		tenantMetrics[t] = &TenantMetrics{TenantID: displayName}
	}

	// Strategy 1: Direct per-tenant table stats via SQL
	// For each tenant, count rows and estimate I/O from the biggest tables
	for _, t := range d.Tenants {
		m := tenantMetrics[t]

		// Count rows per tenant across main tables
		for _, tbl := range d.TenantTables {
			parts := strings.SplitN(tbl, ".", 2)
			schema := "public"
			tableName := tbl
			if len(parts) == 2 {
				schema = parts[0]
				tableName = parts[1]
			}
			safeSchema := sanitizeIdentifier(schema)
			safeTable := sanitizeIdentifier(tableName)
			safeCol := sanitizeIdentifier(d.TenantColumn)

			var count int64
			query := fmt.Sprintf(
				`SELECT count(*) FROM %s.%s WHERE %s::text = $1`,
				safeSchema, safeTable, safeCol,
			)
			err := c.db.QueryRow(query, t).Scan(&count)
			if err == nil {
				m.RowsRead += count
			}
		}
	}

	// Strategy 2: Query stats from pg_stat_statements
	// pg_stat_statements normalizes to $1, so we can't directly see tenant IDs
	// But we CAN look at queries that mention the tenant column and aggregate total load
	qrows, err := c.db.Query(`
		SELECT query, calls, total_exec_time, rows
		FROM pg_stat_statements
		WHERE calls > 0
		  AND query NOT LIKE 'CREATE%'
		  AND query NOT LIKE 'INSERT INTO%generate_series%'
		  AND query NOT LIKE 'DO $$%'
		  AND query NOT LIKE 'ANALYZE%'
		  AND (query ILIKE $1 OR query ILIKE $2)
		ORDER BY total_exec_time DESC
		LIMIT 200
	`, "%"+d.TenantColumn+"%", "%WHERE%"+d.TenantColumn+"%")
	if err == nil {
		defer qrows.Close()

		// Distribute query stats proportionally based on row counts
		var totalQueryCalls int64
		var totalQueryTime float64
		var totalQueryRows int64
		var queryTimes []float64

		for qrows.Next() {
			var query string
			var calls int64
			var execTime float64
			var r int64
			if scanErr := qrows.Scan(&query, &calls, &execTime, &r); scanErr != nil {
				continue
			}
			totalQueryCalls += calls
			totalQueryTime += execTime
			totalQueryRows += r
			if calls > 0 {
				queryTimes = append(queryTimes, execTime/float64(calls))
			}
		}

		// Distribute proportionally by row count
		var totalRows int64
		for _, m := range tenantMetrics {
			totalRows += m.RowsRead
		}

		if totalRows > 0 {
			for _, m := range tenantMetrics {
				proportion := float64(m.RowsRead) / float64(totalRows)
				m.Queries = int64(float64(totalQueryCalls) * proportion)
				m.AvgTimeMs = totalQueryTime / math.Max(1, float64(totalQueryCalls))
				// Scale P99 by proportion (heavier tenants get worse latency estimate)
				percentiles := calcPercentiles(queryTimes)
				m.P50Ms = percentiles[0]
				m.P95Ms = percentiles[1]
				m.P99Ms = percentiles[2] * (1 + proportion) // heavier tenants get proportionally worse P99
			}
		}
	}

	// Strategy 3: Active connections from pg_stat_activity
	connRows, err := c.db.Query(`
		SELECT query FROM pg_stat_activity 
		WHERE state = 'active' AND query != ''
	`)
	if err == nil {
		defer connRows.Close()
		for connRows.Next() {
			var query string
			if scanErr := connRows.Scan(&query); scanErr != nil {
				continue
			}
			// Try to extract tenant from active query
			tid := extractTenantIDFromSQL(query, d.TenantColumn)
			if m, ok := tenantMetrics[tid]; ok {
				m.Connections++
			}
		}
	}

	// Strategy 4: Per-tenant I/O estimation
	// Total I/O from pg_statio_user_tables, distributed by row proportion
	var totalIOBytes int64
	err = c.db.QueryRow(`
		SELECT COALESCE(sum(
			COALESCE(heap_blks_read, 0) + 
			COALESCE(idx_blks_read, 0) + 
			COALESCE(toast_blks_read, 0)
		) * 8192, 0)
		FROM pg_statio_user_tables
	`).Scan(&totalIOBytes)
	if err == nil {
		var totalRows int64
		for _, m := range tenantMetrics {
			totalRows += m.RowsRead
		}
		if totalRows > 0 {
			for _, m := range tenantMetrics {
				m.IOBytes = int64(float64(totalIOBytes) * float64(m.RowsRead) / float64(totalRows))
			}
		}
	}

	// Convert to sorted slice
	var result []TenantMetrics
	for _, m := range tenantMetrics {
		result = append(result, *m)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].RowsRead > result[j].RowsRead
	})

	if len(result) > 50 {
		result = result[:50]
	}
	return result, nil
}

func (c *Collector) collectDefaultMetrics() ([]TenantMetrics, error) {
	m := TenantMetrics{TenantID: "default"}

	err := c.db.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE state IS NOT NULL`).Scan(&m.Connections)
	if err != nil {
		return nil, err
	}

	err = c.db.QueryRow(`
		SELECT 
			COALESCE(sum(calls), 0),
			COALESCE(sum(total_exec_time) / NULLIF(sum(calls), 0), 0),
			COALESCE(sum(rows), 0)
		FROM pg_stat_statements
		WHERE calls > 0
	`).Scan(&m.Queries, &m.AvgTimeMs, &m.RowsRead)
	if err != nil {
		m.Queries = 0
	}

	err = c.db.QueryRow(`
		SELECT COALESCE(sum(
			COALESCE(heap_blks_read, 0) + COALESCE(idx_blks_read, 0)
		) * 8192, 0)
		FROM pg_statio_user_tables
	`).Scan(&m.IOBytes)
	if err != nil {
		m.IOBytes = 0
	}

	return []TenantMetrics{m}, nil
}

// extractTenantFromQuery tries to extract a tenant identifier from a SQL query
func extractTenantFromQuery(query string, d *Detector) string {
	lowerQ := strings.ToLower(query)
	if d.Pattern == PatternSchema {
		// Look for schema.table pattern anywhere in the query (handles subqueries, JOINs, pg_sleep wrappers)
		for _, schema := range d.TenantSchemas {
			if strings.Contains(lowerQ, strings.ToLower(schema)+".") {
				return schema
			}
		}
	}
	if d.TenantColumn != "" {
		tid := extractTenantIDFromSQL(query, d.TenantColumn)
		if tid != "unknown" {
			return tid
		}
	}
	// Last resort: try regex for any schema-qualified table reference
	allMatches := schemaQualAllRe.FindAllStringSubmatch(query, -1)
	for _, m := range allMatches {
		if len(m) >= 2 {
			schema := strings.ToLower(m[1])
			if schema != "public" && schema != "pg_catalog" && schema != "information_schema" && schema != "pg_toast" {
				return m[1]
			}
		}
	}
	return "unknown"
}

// extractTenantIDFromSQL parses SQL to find tenant_id = 'value' or tenant_id = N patterns
var tenantValRe = regexp.MustCompile(`(?i)(tenant_id|org_id|organization_id|account_id|workspace_id|team_id|company_id|customer_id|client_id)\s*=\s*'?(\d+|[a-zA-Z0-9_-]+)'?`)
var searchPathRe = regexp.MustCompile(`(?i)SET\s+search_path\s*(?:=|TO)\s*([a-zA-Z0-9_,\s]+)`)
var schemaQualRe = regexp.MustCompile(`(?i)FROM\s+([a-zA-Z_][a-zA-Z0-9_]*)\.`)

func extractTenantIDFromSQL(query, column string) string {
	// Check for column = value pattern
	m := tenantValRe.FindStringSubmatch(query)
	if len(m) >= 3 && m[2] != "$1" && m[2] != "$2" {
		return m[2]
	}

	// Check for search_path
	m2 := searchPathRe.FindStringSubmatch(query)
	if len(m2) >= 2 {
		parts := strings.Split(m2[1], ",")
		if len(parts) > 0 {
			sp := strings.TrimSpace(parts[0])
			if sp != "public" && sp != "pg_catalog" {
				return sp
			}
		}
	}

	// Check for schema-qualified table names
	m3 := schemaQualRe.FindStringSubmatch(query)
	if len(m3) >= 2 {
		schema := strings.ToLower(m3[1])
		if schema != "public" && schema != "pg_catalog" && schema != "information_schema" {
			return m3[1]
		}
	}

	return "unknown"
}

// calcPercentiles returns [p50, p95, p99] from a slice of latencies
func calcPercentiles(times []float64) [3]float64 {
	if len(times) == 0 {
		return [3]float64{0, 0, 0}
	}
	sort.Float64s(times)
	n := len(times)
	p50 := times[int(math.Floor(float64(n)*0.50))]
	p95Idx := int(math.Floor(float64(n) * 0.95))
	if p95Idx >= n {
		p95Idx = n - 1
	}
	p99Idx := int(math.Floor(float64(n) * 0.99))
	if p99Idx >= n {
		p99Idx = n - 1
	}
	return [3]float64{
		math.Round(p50*100) / 100,
		math.Round(times[p95Idx]*100) / 100,
		math.Round(times[p99Idx]*100) / 100,
	}
}
