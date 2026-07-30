package main

import (
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

type TenantProfile struct {
	Name       string
	Schema     string
	BaseQPS    float64
	HeavyRatio float64 // % of queries that are expensive
	PeakHours  []int   // hours when tenant is most active (UTC)
	Industry   string  // for realistic query patterns
}

var profiles = []TenantProfile{
	// E-commerce — heavy during business hours, lots of order queries
	{Name: "Acme Corp", Schema: "acme_corp", BaseQPS: 8, HeavyRatio: 0.3, PeakHours: []int{14, 15, 16, 17, 18, 19, 20}, Industry: "ecommerce"},
	// SaaS dashboard — steady throughout day, analytics-heavy
	{Name: "Hooli", Schema: "hooli", BaseQPS: 3, HeavyRatio: 0.1, PeakHours: []int{9, 10, 11, 14, 15, 16}, Industry: "saas"},
	// Startup — light usage, occasional spikes
	{Name: "Pied Piper", Schema: "pied_piper", BaseQPS: 1, HeavyRatio: 0.05, PeakHours: []int{16, 17, 18, 19, 20, 21, 22, 23}, Industry: "startup"},
	// Enterprise — heavy analytics, batch jobs
	{Name: "Wayne Enterprises", Schema: "wayne_enterprises", BaseQPS: 5, HeavyRatio: 0.25, PeakHours: []int{8, 9, 10, 11, 12, 13, 14}, Industry: "enterprise"},
	// Mid-market — moderate, predictable
	{Name: "Stark Industries", Schema: "stark_industries", BaseQPS: 3, HeavyRatio: 0.15, PeakHours: []int{10, 11, 12, 13, 14, 15, 16}, Industry: "enterprise"},
	// Small business — very light
	{Name: "Globex Inc", Schema: "globex_inc", BaseQPS: 0.5, HeavyRatio: 0.02, PeakHours: []int{9, 10, 11, 12, 13, 14}, Industry: "smb"},
	// Dev/staging tenant — erratic, sometimes nothing, sometimes heavy
	{Name: "Initech", Schema: "initech", BaseQPS: 0.3, HeavyRatio: 0.4, PeakHours: []int{}, Industry: "dev"},
}

// Realistic query templates per industry
var queryTemplates = map[string][]struct {
	sql     string
	heavy   bool
	name    string
	delayMs int
}{
	"ecommerce": {
		{sql: "SELECT * FROM %s.orders WHERE status = 'pending' LIMIT 20", name: "pending orders", delayMs: 5},
		{sql: "SELECT * FROM %s.users WHERE email LIKE '%%@gmail.com' LIMIT 10", name: "user lookup", delayMs: 3},
		{sql: "SELECT count(*) FROM %s.orders WHERE created_at > now() - interval '1 hour'", name: "hourly orders", delayMs: 8},
		{sql: "SELECT * FROM %s.orders ORDER BY id DESC LIMIT 5", name: "recent orders", delayMs: 2},
		{sql: "INSERT INTO %s.orders (user_id, amount, status) VALUES ($1, $2, 'pending')", name: "new order", delayMs: 1},
		{sql: "UPDATE %s.orders SET status = 'completed' WHERE id = $1", name: "complete order", delayMs: 1},
		// Heavy queries
		{sql: "SELECT u.*, count(o.id) as order_count, sum(o.amount) as total FROM %s.users u LEFT JOIN %s.orders o ON u.id = o.user_id GROUP BY u.id ORDER BY total DESC", name: "customer report", heavy: true, delayMs: 80},
		{sql: "SELECT * FROM %s.orders o JOIN %s.users u ON o.user_id = u.id WHERE o.amount > 500 ORDER BY o.amount DESC", name: "high value scan", heavy: true, delayMs: 50},
		{sql: "SELECT date_trunc('hour', created_at), count(*), avg(amount) FROM %s.orders GROUP BY 1 ORDER BY 1", name: "hourly analytics", heavy: true, delayMs: 60},
	},
	"saas": {
		{sql: "SELECT * FROM %s.users WHERE id = $1", name: "auth check", delayMs: 1},
		{sql: "SELECT count(*) FROM %s.users", name: "user count", delayMs: 2},
		{sql: "SELECT * FROM %s.orders WHERE user_id = $1 ORDER BY created_at DESC LIMIT 10", name: "user activity", delayMs: 5},
		{sql: "SELECT * FROM %s.users ORDER BY created_at DESC LIMIT 20", name: "recent users", delayMs: 3},
		// Heavy
		{sql: "SELECT u.*, count(o.id) FROM %s.users u LEFT JOIN %s.orders o ON u.id = o.user_id GROUP BY u.id", name: "usage report", heavy: true, delayMs: 40},
	},
	"startup": {
		{sql: "SELECT * FROM %s.users LIMIT 10", name: "list users", delayMs: 1},
		{sql: "SELECT count(*) FROM %s.orders", name: "order count", delayMs: 1},
		{sql: "INSERT INTO %s.users (name, email) VALUES ($1, $2)", name: "signup", delayMs: 1},
		// Heavy — dev accidentally runs full scan
		{sql: "SELECT * FROM %s.orders ORDER BY random()", name: "OOPS full scan", heavy: true, delayMs: 100},
	},
	"enterprise": {
		{sql: "SELECT * FROM %s.users WHERE id = $1", name: "user fetch", delayMs: 1},
		{sql: "SELECT * FROM %s.orders WHERE id > $1 LIMIT 50", name: "batch read", delayMs: 5},
		{sql: "SELECT count(*), status FROM %s.orders GROUP BY status", name: "status summary", delayMs: 8},
		{sql: "SELECT * FROM %s.orders WHERE created_at > now() - interval '24 hours'", name: "daily orders", delayMs: 10},
		// Heavy — analytics and reporting
		{sql: "SELECT u.name, count(o.id), sum(o.amount), avg(o.amount) FROM %s.users u JOIN %s.orders o ON u.id = o.user_id GROUP BY u.name ORDER BY sum(o.amount) DESC", name: "revenue report", heavy: true, delayMs: 90},
		{sql: "SELECT * FROM %s.orders o1 WHERE o1.amount > (SELECT avg(amount) FROM %s.orders o2 WHERE o2.user_id = o1.user_id)", name: "above-avg query", heavy: true, delayMs: 120},
	},
	"smb": {
		{sql: "SELECT * FROM %s.users LIMIT 5", name: "user list", delayMs: 1},
		{sql: "SELECT * FROM %s.orders ORDER BY id DESC LIMIT 5", name: "recent orders", delayMs: 2},
		{sql: "SELECT count(*) FROM %s.users", name: "user count", delayMs: 1},
	},
	"dev": {
		{sql: "SELECT * FROM %s.users", name: "SELECT * (no limit!)", delayMs: 2},
		{sql: "SELECT * FROM %s.orders", name: "SELECT * orders (no limit!)", delayMs: 3},
		{sql: "SELECT 1", name: "health check", delayMs: 0},
		// Heavy — dev testing, bad queries
		{sql: "SELECT * FROM %s.orders o CROSS JOIN %s.users u LIMIT 1000", name: "CROSS JOIN oops", heavy: true, delayMs: 200},
		{sql: "SELECT * FROM %s.orders ORDER BY random() LIMIT 100", name: "random sort", heavy: true, delayMs: 150},
	},
}

// Incident scenarios that happen during the simulation
type Incident struct {
	StartSec    int
	EndSec      int
	TenantIdx   int
	QPSMulti    float64
	HeavyBoost  float64
	Description string
}

var incidents = []Incident{
	// Acme Corp runs a bad analytics report at 45s
	{StartSec: 45, EndSec: 75, TenantIdx: 0, QPSMulti: 3, HeavyBoost: 0.6, Description: "Acme Corp: Customer runs massive analytics export"},
	// Calm period 75-120s
	// Wayne Enterprises batch job hits at 120s
	{StartSec: 120, EndSec: 150, TenantIdx: 3, QPSMulti: 4, HeavyBoost: 0.5, Description: "Wayne Enterprises: End-of-day batch reporting job"},
	// Initech dev runs a CROSS JOIN at 170s
	{StartSec: 170, EndSec: 190, TenantIdx: 6, QPSMulti: 20, HeavyBoost: 0.8, Description: "Initech: Developer accidentally runs CROSS JOIN in production"},
	// Acme Corp flash sale at 220s — SUSTAINED heavy load
	{StartSec: 220, EndSec: 300, TenantIdx: 0, QPSMulti: 5, HeavyBoost: 0.4, Description: "Acme Corp: FLASH SALE — massive traffic spike"},
	// Multiple tenants spike at once at 330s
	{StartSec: 330, EndSec: 360, TenantIdx: 0, QPSMulti: 3, HeavyBoost: 0.3, Description: "Acme Corp: Continued high traffic"},
	{StartSec: 330, EndSec: 360, TenantIdx: 3, QPSMulti: 3, HeavyBoost: 0.4, Description: "Wayne Enterprises: Overlapping batch job"},
	{StartSec: 330, EndSec: 360, TenantIdx: 4, QPSMulti: 3, HeavyBoost: 0.3, Description: "Stark Industries: Monthly report generation"},
}

var (
	mu              sync.RWMutex
	activeIncidents = make(map[int]Incident) // tenantIdx -> incident
	startTime       time.Time
)

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://ec2-user@localhost:5432/sg_test_schema?sslmode=disable"
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(60)
	db.SetMaxIdleConns(20)

	if err := db.Ping(); err != nil {
		log.Fatal("Cannot connect:", err)
	}

	// Seed data
	for _, p := range profiles {
		ensureSchema(db, p.Schema)
	}

	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              FaultWall Load Simulator v2.0                   ║")
	fmt.Println("║            Realistic Multi-Tenant Workload                   ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	fmt.Println("║                                                               ║")
	fmt.Println("║  7 tenants with realistic industry query patterns             ║")
	fmt.Println("║  5 incident scenarios over 6 minutes                          ║")
	fmt.Println("║                                                               ║")
	fmt.Println("║  WATCH THESE:                                                 ║")
	fmt.Println("║    http://localhost:8080/                    (dashboard)       ║")
	fmt.Println("║    http://localhost:8080/api/agents/status   (health)          ║")
	fmt.Println("║    http://localhost:8080/api/costs           (who pays)        ║")
	fmt.Println("║    http://localhost:8080/api/anomalies       (AI detection)    ║")
	fmt.Println("║    http://localhost:8080/api/predictions     (forecasts)       ║")
	fmt.Println("║    http://localhost:8080/api/agents/recommendation            ║")
	fmt.Println("║                                                               ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	startTime = time.Now()

	// Incident announcer
	go runIncidentEngine()

	// Stats reporter
	go runStatsReporter(db)

	// Launch tenant workers
	var wg sync.WaitGroup
	for i, profile := range profiles {
		wg.Add(1)
		go func(idx int, p TenantProfile) {
			defer wg.Done()
			runTenant(db, idx, p)
		}(i, profile)
	}

	wg.Wait()
}

func runIncidentEngine() {
	announced := make(map[string]bool)
	for {
		elapsed := int(time.Since(startTime).Seconds())
		if elapsed > 400 {
			fmt.Println("\n Simulation complete (6+ minutes). Press Ctrl+C to stop.")
			return
		}

		mu.Lock()
		// Clear expired incidents
		for idx, inc := range activeIncidents {
			if elapsed > inc.EndSec {
				delete(activeIncidents, idx)
				fmt.Printf("\n [%3ds] RESOLVED: %s\n\n", elapsed, inc.Description)
			}
		}
		// Activate new incidents
		for _, inc := range incidents {
			key := fmt.Sprintf("%d-%d", inc.StartSec, inc.TenantIdx)
			if elapsed >= inc.StartSec && elapsed <= inc.EndSec && !announced[key] {
				activeIncidents[inc.TenantIdx] = inc
				announced[key] = true
				fmt.Printf("\n [%3ds] INCIDENT: %s\n\n", elapsed, inc.Description)
			}
		}
		mu.Unlock()

		time.Sleep(1 * time.Second)
	}
}

func runStatsReporter(db *sql.DB) {
	counts := make(map[string]int64)
	var countMu sync.Mutex

	// Global counter — tenants increment this
	go func() {
		for {
			time.Sleep(15 * time.Second)
			elapsed := int(time.Since(startTime).Seconds())
			countMu.Lock()
			fmt.Printf("[%3ds] Queries: ", elapsed)
			total := int64(0)
			for _, p := range profiles {
				c := counts[p.Schema]
				total += c
			}
			// Show top 3 by query count
			type kv struct {
				k string
				v int64
			}
			var sorted []kv
			for _, p := range profiles {
				sorted = append(sorted, kv{p.Name, counts[p.Schema]})
			}
			for i := 0; i < len(sorted); i++ {
				for j := i + 1; j < len(sorted); j++ {
					if sorted[j].v > sorted[i].v {
						sorted[i], sorted[j] = sorted[j], sorted[i]
					}
				}
			}
			for i := 0; i < 3 && i < len(sorted); i++ {
				if i > 0 {
					fmt.Print(" | ")
				}
				fmt.Printf("%s: %d", sorted[i].k, sorted[i].v)
			}
			fmt.Printf(" (total: %d)\n", total)
			countMu.Unlock()
		}
	}()

	// Expose counter to tenants via closure
	counterInc = func(schema string) {
		countMu.Lock()
		counts[schema]++
		countMu.Unlock()
	}
}

var counterInc func(string)

func runTenant(db *sql.DB, idx int, p TenantProfile) {
	templates := queryTemplates[p.Industry]
	if templates == nil {
		templates = queryTemplates["smb"]
	}

	for {
		elapsed := time.Since(startTime).Seconds()
		if elapsed > 400 {
			return
		}

		// Calculate current QPS based on base + incidents
		qps := p.BaseQPS
		heavyRatio := p.HeavyRatio

		// Add some natural variance (+/- 30%)
		qps *= 0.7 + rand.Float64()*0.6

		// Check for active incidents
		mu.RLock()
		if inc, ok := activeIncidents[idx]; ok {
			qps *= inc.QPSMulti
			heavyRatio += inc.HeavyBoost
		}
		mu.RUnlock()

		if qps < 0.1 {
			qps = 0.1
		}

		// Sleep between queries
		sleepMs := int(1000.0 / qps)
		if sleepMs < 10 {
			sleepMs = 10
		}
		time.Sleep(time.Duration(sleepMs) * time.Millisecond)

		// Pick a query
		var tmpl struct {
			sql     string
			heavy   bool
			name    string
			delayMs int
		}

		if rand.Float64() < heavyRatio {
			// Pick a heavy query
			heavyOnes := []int{}
			for i, t := range templates {
				if t.heavy {
					heavyOnes = append(heavyOnes, i)
				}
			}
			if len(heavyOnes) > 0 {
				tmpl = templates[heavyOnes[rand.Intn(len(heavyOnes))]]
			} else {
				tmpl = templates[rand.Intn(len(templates))]
			}
		} else {
			// Pick a light query
			lightOnes := []int{}
			for i, t := range templates {
				if !t.heavy {
					lightOnes = append(lightOnes, i)
				}
			}
			if len(lightOnes) > 0 {
				tmpl = templates[lightOnes[rand.Intn(len(lightOnes))]]
			} else {
				tmpl = templates[rand.Intn(len(templates))]
			}
		}

		go func(t struct {
			sql     string
			heavy   bool
			name    string
			delayMs int
		}) {
			executeQuery(db, p.Schema, t)
			if counterInc != nil {
				counterInc(p.Schema)
			}
		}(tmpl)
	}
}

func executeQuery(db *sql.DB, schema string, tmpl struct {
	sql     string
	heavy   bool
	name    string
	delayMs int
}) {
	// Build the query — some templates have two %s (for JOINs)
	var query string
	switch countPercent(tmpl.sql) {
	case 1:
		query = fmt.Sprintf(tmpl.sql, schema)
	case 2:
		query = fmt.Sprintf(tmpl.sql, schema, schema)
	default:
		query = tmpl.sql
	}

	// Execute the query directly — no pg_sleep wrapper
	// pg_sleep hides queries from pg_stat_statements tracking

	// Count how many $N params the query expects
	paramCount := countParams(query)
	args := make([]interface{}, paramCount)
	for i := range args {
		if i%2 == 0 {
			args[i] = rand.Intn(100) + 1
		} else {
			args[i] = fmt.Sprintf("user_%d@test.com", rand.Intn(100))
		}
	}

	var result interface{}
	_ = db.QueryRow(query, args...).Scan(&result)
}

func countParams(s string) int {
	max := 0
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '$' && s[i+1] >= '1' && s[i+1] <= '9' {
			n := int(s[i+1] - '0')
			if n > max {
				max = n
			}
		}
	}
	return max
}

func countPercent(s string) int {
	count := 0
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '%' && s[i+1] == 's' {
			count++
		}
	}
	return count
}

func ensureSchema(db *sql.DB, schema string) {
	db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema))

	db.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.users (
		id SERIAL PRIMARY KEY,
		name TEXT NOT NULL,
		email TEXT NOT NULL,
		plan TEXT DEFAULT 'free',
		created_at TIMESTAMP DEFAULT now(),
		last_login TIMESTAMP DEFAULT now()
	)`, schema))

	db.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.orders (
		id SERIAL PRIMARY KEY,
		user_id INTEGER REFERENCES %s.users(id),
		amount DECIMAL(10,2) NOT NULL,
		status TEXT DEFAULT 'pending',
		item_count INTEGER DEFAULT 1,
		created_at TIMESTAMP DEFAULT now(),
		updated_at TIMESTAMP DEFAULT now()
	)`, schema, schema))

	// Create indexes for realistic query plans
	db.Exec(fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_orders_status ON %s.orders(status)", schema, schema))
	db.Exec(fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_orders_user ON %s.orders(user_id)", schema, schema))
	db.Exec(fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_orders_created ON %s.orders(created_at)", schema, schema))
	db.Exec(fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_users_email ON %s.users(email)", schema, schema))

	var count int
	db.QueryRow(fmt.Sprintf("SELECT count(*) FROM %s.users", schema)).Scan(&count)
	if count == 0 {
		plans := []string{"free", "starter", "pro", "enterprise"}
		for i := 0; i < 200; i++ {
			db.Exec(fmt.Sprintf("INSERT INTO %s.users (name, email, plan) VALUES ($1, $2, $3)", schema),
				fmt.Sprintf("User %d", i),
				fmt.Sprintf("user%d@%s.com", i, schema),
				plans[rand.Intn(len(plans))])
		}
		statuses := []string{"pending", "completed", "cancelled", "refunded", "processing"}
		for i := 0; i < 2000; i++ {
			db.Exec(fmt.Sprintf("INSERT INTO %s.orders (user_id, amount, status, item_count) VALUES ($1, $2, $3, $4)", schema),
				rand.Intn(200)+1,
				5+rand.Float64()*995,
				statuses[rand.Intn(len(statuses))],
				rand.Intn(10)+1)
		}
		fmt.Printf("Seeded %s: 200 users, 2000 orders\n", schema)
	}
}
