package main

// try.go — `faultwall try`: zero-config, one-command monitor mode.
//
//   faultwall try                         # bundled demo Postgres + scripted demo agent
//   faultwall try postgres://u:p@h/db     # monitor-mode proxy in front of your DB
//
// No YAML. Starts the L7 proxy in MONITOR mode (never blocks), prints the
// connection string to hand to your agent, and serves a live activity view
// (per-agent queries + what FaultWall would have flagged).

import (
	"context"
	"crypto/tls"
	"database/sql"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
)

//go:embed templates/try.html
var tryPageHTML []byte

// tryOptions are the parsed `faultwall try` flags.
type tryOptions struct {
	DatabaseURL string
	FromEnv     bool
	Demo        bool
	DemoAgent   bool
	Listen      string // proxy listen addr (host:port); port auto-bumps if busy
	UIPort      int    // live view port; auto-bumps if busy
	Agent       string // agent name used in the printed connection string
	Open        bool
	Duration    time.Duration // 0 = run until Ctrl+C
}

func inContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	return os.Getenv("container") != "" || os.Getenv("FAULTWALL_IN_CONTAINER") == "1"
}

func parseTryArgs(args []string, getenv func(string) string) (*tryOptions, error) {
	o := &tryOptions{DemoAgent: true, Agent: "my-agent", Open: true, UIPort: 8080}
	bindHost := "127.0.0.1"
	if inContainer() {
		bindHost = "0.0.0.0" // reachable through `docker run -p`
		o.Open = false
	}
	listenPort := 5433
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", a)
			}
			i++
			return args[i], nil
		}
		switch {
		case a == "--demo":
			o.Demo = true
		case a == "--no-demo-agent":
			o.DemoAgent = false
		case a == "--no-open":
			o.Open = false
		case a == "--listen", a == "--port", a == "--ui-port", a == "--agent", a == "--db", a == "--for":
			v, err := next()
			if err != nil {
				return nil, err
			}
			switch a {
			case "--listen":
				if !strings.Contains(v, ":") {
					v = bindHost + ":" + v
				} else if strings.HasPrefix(v, ":") {
					v = "0.0.0.0" + v
				}
				o.Listen = v
			case "--port":
				p, err := strconv.Atoi(v)
				if err != nil {
					return nil, fmt.Errorf("invalid --port %q", v)
				}
				listenPort = p
			case "--ui-port":
				p, err := strconv.Atoi(v)
				if err != nil {
					return nil, fmt.Errorf("invalid --ui-port %q", v)
				}
				o.UIPort = p
			case "--agent":
				if strings.ContainsAny(v, ": \t\n") {
					return nil, fmt.Errorf("agent name %q must not contain spaces or colons", v)
				}
				o.Agent = v
			case "--db":
				o.DatabaseURL = v
			case "--for":
				d, err := time.ParseDuration(v)
				if err != nil {
					return nil, fmt.Errorf("invalid --for %q", v)
				}
				o.Duration = d
			}
		case a == "-h" || a == "--help":
			return nil, errTryHelp
		case strings.HasPrefix(a, "postgres://") || strings.HasPrefix(a, "postgresql://"):
			o.DatabaseURL = a
		case strings.HasPrefix(a, "-"):
			return nil, fmt.Errorf("unknown flag %s (see: faultwall try --help)", a)
		default:
			return nil, fmt.Errorf("expected a postgres:// URL, got %q", a)
		}
	}
	if o.Listen == "" {
		o.Listen = net.JoinHostPort(bindHost, strconv.Itoa(listenPort))
	}
	if o.DatabaseURL == "" && !o.Demo {
		if env := strings.TrimSpace(getenv("DATABASE_URL")); env != "" {
			o.DatabaseURL = env
			o.FromEnv = true
		}
	}
	if o.DatabaseURL == "" {
		o.Demo = true
	}
	if o.Demo {
		o.DatabaseURL = ""
		o.FromEnv = false
	}
	return o, nil
}

var errTryHelp = errors.New("help")

func printTryHelp() {
	fmt.Println(`faultwall try — see your agent's queries in 60 seconds. No YAML.

Usage:
  faultwall try                          # demo: bundled Postgres + a scripted demo agent
  faultwall try postgres://user:pass@host:5432/db
  DATABASE_URL=postgres://... faultwall try

Runs FaultWall in MONITOR mode (observes, never blocks), prints a connection
string to give your agent, and serves a live activity view.

Flagged out of the box (flag only, nothing is blocked):
  • DDL / DCL (CREATE, ALTER, DROP, TRUNCATE, GRANT…)
  • UPDATE / DELETE without a WHERE clause
  • writes that touch more than 100 rows
  • reads of secret-looking columns (password, token, secret, ssn, api_key…)

Flags:
  --port N           Proxy port for your agent (default 5433; next free port if busy)
  --ui-port N        Live view port (default 8080; next free port if busy)
  --agent NAME       Agent name in the printed connection string (default my-agent)
  --demo             Force demo mode even if DATABASE_URL is set
  --no-demo-agent    Demo Postgres only, no scripted agent
  --no-open          Don't open the browser
  --for DURATION     Exit after DURATION (e.g. 2m); default runs until Ctrl+C`)
}

// upstreamTarget is the parsed DATABASE_URL.
type upstreamTarget struct {
	Host, Port, User, Password, DB string
	SSLMode                        string
	Extra                          url.Values // other params, passed through to the agent URL
}

func (u upstreamTarget) Addr() string { return net.JoinHostPort(u.Host, u.Port) }

func parseUpstreamURL(raw string) (*upstreamTarget, error) {
	pu, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("could not parse DATABASE_URL: %v", err)
	}
	if pu.Scheme != "postgres" && pu.Scheme != "postgresql" {
		return nil, fmt.Errorf("DATABASE_URL must start with postgres:// (got %q)", pu.Scheme)
	}
	t := &upstreamTarget{Host: pu.Hostname(), Port: pu.Port(), DB: strings.TrimPrefix(pu.Path, "/")}
	if t.Host == "" {
		t.Host = "localhost"
	}
	if t.Port == "" {
		t.Port = "5432"
	}
	if pu.User != nil {
		t.User = pu.User.Username()
		t.Password, _ = pu.User.Password()
	}
	if t.User == "" {
		t.User = "postgres"
	}
	if t.DB == "" {
		t.DB = t.User
	}
	q := pu.Query()
	t.SSLMode = strings.ToLower(q.Get("sslmode"))
	// Client → FaultWall is local plaintext; these must not be forwarded.
	for _, k := range []string{"sslmode", "application_name", "channel_binding", "sslrootcert", "sslcert", "sslkey"} {
		q.Del(k)
	}
	t.Extra = q
	return t, nil
}

// agentConnString is the URL the user hands to their agent.
func agentConnString(t *upstreamTarget, proxyHostPort, agent string) string {
	u := url.URL{Scheme: "postgres", Host: proxyHostPort, Path: "/" + t.DB}
	if t.Password != "" {
		u.User = url.UserPassword(t.User, t.Password)
	} else {
		u.User = url.User(t.User)
	}
	q := url.Values{}
	for k, v := range t.Extra {
		q[k] = v
	}
	q.Set("sslmode", "disable")
	q.Set("application_name", "agent:"+agent+":mission:default")
	// keep application_name readable (colons) for copy/paste
	u.RawQuery = strings.ReplaceAll(q.Encode(), "%3A", ":")
	return u.String()
}

// probeUpstreamTLS decides whether to speak TLS upstream. require/verify-* →
// TLS; disable → plaintext; prefer/allow/unset → TLS if the server offers it.
func probeUpstreamTLS(addr, sslmode string) (useTLS bool, skipVerify bool, err error) {
	switch sslmode {
	case "disable":
		return false, false, nil
	case "require":
		return true, true, nil // libpq semantics: require = encrypt, don't verify
	case "verify-ca", "verify-full":
		return true, false, nil
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, false, err
	}
	defer conn.Close()
	var req [8]byte
	binary.BigEndian.PutUint32(req[0:4], 8)
	binary.BigEndian.PutUint32(req[4:8], 80877103)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(req[:]); err != nil {
		return false, false, err
	}
	var resp [1]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return false, false, err
	}
	return resp[0] == 'S', true, nil
}

// listenWithFallback binds addr, or the next free port (up to +20).
func listenWithFallback(addr string) (net.Listener, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)
	var lastErr error
	for i := 0; i < 20; i++ {
		p := strconv.Itoa(port + i)
		// On macOS, 127.0.0.1:P can bind even when another process owns
		// [::]:P — and "localhost" then resolves to the other process. Skip
		// any port where something already answers.
		if c, err := net.DialTimeout("tcp", net.JoinHostPort("localhost", p), 200*time.Millisecond); err == nil {
			c.Close()
			lastErr = fmt.Errorf("port %s already in use", p)
			continue
		}
		ln, err := net.Listen("tcp", net.JoinHostPort(host, p))
		if err == nil {
			return ln, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// displayHost is the host printed in URLs: the exact loopback address we
// bound when local (avoids localhost → ::1 surprises), "localhost" when bound
// to all interfaces (e.g. inside Docker with -p).
func displayHost(bound string) string {
	if ip := net.ParseIP(bound); ip != nil && ip.IsLoopback() {
		return bound
	}
	return "localhost"
}

func freePort(start int) int {
	for p := start; p < start+50; p++ {
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err == nil {
			ln.Close()
			return p
		}
	}
	return start
}

// tryPolicyEngine is an in-memory, observe-only policy: every agent allowed,
// unidentified connections allowed, dangerous server functions flagged.
func tryPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		enforcement:  "monitor",
		filePath:     filepath.Join(os.TempDir(), "faultwall-try-policies.yaml"),
		pausedAgents: map[string]bool{},
		config: &PolicyConfig{
			DefaultPolicy: "allow",
			Agents:        map[string]AgentPolicy{},
			Unidentified:  UnidentifiedPolicy{Policy: "allow"},
		},
	}
}

// ── demo Postgres ──

type demoDB struct {
	stop func()
	url  string
}

func startDemoPostgres() (*demoDB, error) {
	home, _ := os.UserHomeDir()
	if home == "" {
		home = os.TempDir()
	}
	base := filepath.Join(home, ".faultwall", "try")
	port := freePort(54329)
	pw := "faultwall-demo"
	if runtime.GOOS == "linux" && os.Geteuid() == 0 && dockerAvailable() {
		// initdb refuses to run as root; prefer Docker if present.
		return startDemoPostgresDocker(port, pw)
	}
	logf, _ := os.Create(filepath.Join(os.TempDir(), "faultwall-try-postgres.log"))
	var logw io.Writer = io.Discard
	if logf != nil {
		logw = logf
	}
	fmt.Println("→ Starting demo Postgres (first run downloads ~15-30MB, cached after)…")
	cfg := embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(uint32(port)).
		Username("postgres").Password(pw).Database("demo").
		// UTF8, not the SQL_ASCII initdb default: SQLAlchemy and other
		// drivers that read server_encoding fail on SQL_ASCII.
		Encoding("UTF8").Locale("C").
		RuntimePath(filepath.Join(base, "pg-runtime")).
		CachePath(filepath.Join(home, ".faultwall", "cache")).
		StartTimeout(60 * time.Second).
		Logger(logw)
	pg := embeddedpostgres.NewDatabase(cfg)
	if err := pg.Start(); err != nil {
		if dockerAvailable() {
			fmt.Printf("  embedded Postgres failed (%v); trying Docker…\n", firstLine(err.Error()))
			return startDemoPostgresDocker(port, pw)
		}
		return nil, fmt.Errorf("could not start demo Postgres: %v", firstLine(err.Error()))
	}
	return &demoDB{
		stop: func() { _ = pg.Stop() },
		url:  fmt.Sprintf("postgres://postgres:%s@127.0.0.1:%d/demo?sslmode=disable", pw, port),
	}, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func dockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	return exec.Command("docker", "info").Run() == nil
}

func startDemoPostgresDocker(port int, pw string) (*demoDB, error) {
	if !dockerAvailable() {
		return nil, fmt.Errorf("demo Postgres can't run as root without Docker — re-run as a normal user, or pass your own DATABASE_URL")
	}
	name := fmt.Sprintf("faultwall-try-pg-%d", port)
	fmt.Println("→ Starting demo Postgres in Docker…")
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name,
		"-e", "POSTGRES_PASSWORD="+pw, "-e", "POSTGRES_DB=demo",
		"-p", fmt.Sprintf("127.0.0.1:%d:5432", port), "postgres:16-alpine").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker run postgres failed: %s", strings.TrimSpace(string(out)))
	}
	u := fmt.Sprintf("postgres://postgres:%s@127.0.0.1:%d/demo?sslmode=disable", pw, port)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if db, err := sql.Open("postgres", u); err == nil {
			if db.Ping() == nil {
				db.Close()
				return &demoDB{url: u, stop: func() { _ = exec.Command("docker", "rm", "-f", name).Run() }}, nil
			}
			db.Close()
		}
		time.Sleep(500 * time.Millisecond)
	}
	_ = exec.Command("docker", "rm", "-f", name).Run()
	return nil, fmt.Errorf("demo Postgres container did not become ready")
}

const demoSeedSQL = `
DROP TABLE IF EXISTS orders, customers, support_tickets, api_keys CASCADE;
CREATE TABLE customers (id serial PRIMARY KEY, name text, email text, password_hash text, ssn text, created_at timestamptz DEFAULT now());
CREATE TABLE orders (id serial PRIMARY KEY, customer_id int, amount_cents int, status text, created_at timestamptz DEFAULT now());
CREATE TABLE support_tickets (id serial PRIMARY KEY, customer_id int, subject text, body text, status text DEFAULT 'open');
CREATE TABLE api_keys (id serial PRIMARY KEY, customer_id int, token text);
INSERT INTO customers (name, email, password_hash, ssn)
  SELECT 'Customer ' || g, 'user' || g || '@example.com', md5('pw' || g), lpad((g*7919 % 1000000000)::text, 9, '0') FROM generate_series(1, 250) g;
INSERT INTO orders (customer_id, amount_cents, status)
  SELECT 1 + (g % 250), 500 + (g * 37 % 20000), (ARRAY['paid','shipped','refunded'])[1 + g % 3] FROM generate_series(1, 1200) g;
INSERT INTO support_tickets (customer_id, subject, body)
  SELECT 1 + (g % 250), 'Ticket #' || g, 'My order is late' FROM generate_series(1, 60) g;
INSERT INTO api_keys (customer_id, token) SELECT g, md5('tok' || g) FROM generate_series(1, 250) g;
`

func seedDemo(u string) error {
	db, err := sql.Open("postgres", u)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(demoSeedSQL)
	return err
}

// demoStep is one scripted query from the demo agent.
type demoStep struct {
	agent, mission, sql string
	args                []interface{}
	tx                  bool // run inside BEGIN … ROLLBACK so the demo is repeatable
}

var demoScript = []demoStep{
	{agent: "support-bot", mission: "triage", sql: "SELECT id, subject FROM support_tickets WHERE status = $1 ORDER BY id LIMIT 10", args: []interface{}{"open"}},
	{agent: "support-bot", mission: "triage", sql: "SELECT name, email FROM customers WHERE id = $1", args: []interface{}{42}},
	{agent: "support-bot", mission: "triage", sql: "SELECT id, amount_cents, status FROM orders WHERE customer_id = $1", args: []interface{}{42}},
	{agent: "support-bot", mission: "triage", sql: "SELECT email, password_hash FROM customers WHERE email LIKE '%@example.com' LIMIT 20"},
	{agent: "analytics-agent", mission: "weekly-report", sql: "SELECT status, count(*), sum(amount_cents) FROM orders GROUP BY status"},
	{agent: "analytics-agent", mission: "weekly-report", sql: "CREATE TABLE IF NOT EXISTS tmp_weekly_report AS SELECT customer_id, sum(amount_cents) AS total FROM orders GROUP BY customer_id"},
	{agent: "support-bot", mission: "triage", sql: "UPDATE support_tickets SET status = 'closed' WHERE id = $1", args: []interface{}{7}, tx: true},
	{agent: "support-bot", mission: "triage", sql: "UPDATE orders SET status = 'refunded'", tx: true},
	{agent: "analytics-agent", mission: "weekly-report", sql: "SELECT customer_id, token FROM api_keys LIMIT 5"},
	{agent: "analytics-agent", mission: "weekly-report", sql: "DROP TABLE IF EXISTS tmp_weekly_report"},
	{agent: "support-bot", mission: "triage", sql: "DELETE FROM support_tickets", tx: true},
	{agent: "analytics-agent", mission: "weekly-report", sql: "SELECT date_trunc('day', created_at) d, count(*) FROM orders GROUP BY d ORDER BY d DESC LIMIT 7"},
}

// runDemoAgent loops the scripted agents through the proxy until ctx is done.
func runDemoAgent(ctx context.Context, t *upstreamTarget, proxyHostPort string) {
	pools := map[string]*sql.DB{}
	defer func() {
		for _, p := range pools {
			p.Close()
		}
	}()
	get := func(agent, mission string) (*sql.DB, error) {
		key := agent + "/" + mission
		if p, ok := pools[key]; ok {
			return p, nil
		}
		u := strings.Replace(agentConnString(t, proxyHostPort, agent), "mission:default", "mission:"+mission, 1)
		p, err := sql.Open("postgres", u)
		if err != nil {
			return nil, err
		}
		p.SetMaxOpenConns(1)
		pools[key] = p
		return p, nil
	}
	for loop := 0; ; loop++ {
		for _, st := range demoScript {
			select {
			case <-ctx.Done():
				return
			case <-time.After(700 * time.Millisecond):
			}
			db, err := get(st.agent, st.mission)
			if err != nil {
				continue
			}
			if st.tx {
				tx, err := db.BeginTx(ctx, nil)
				if err != nil {
					continue
				}
				_, _ = tx.ExecContext(ctx, st.sql, st.args...)
				_ = tx.Rollback()
				continue
			}
			rows, err := db.QueryContext(ctx, st.sql, st.args...)
			if err == nil {
				for rows.Next() {
				}
				rows.Close()
			}
		}
		// After the first pass, slow down so the feed stays readable.
		select {
		case <-ctx.Done():
			return
		case <-time.After(8 * time.Second):
		}
	}
}

func openBrowser(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "linux":
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return
		}
		cmd = exec.Command("xdg-open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		return
	}
	_ = cmd.Start()
}

// tryInfo is served at /api/try/info for the live view.
type tryInfo struct {
	Mode           string   `json:"mode"`
	Demo           bool     `json:"demo"`
	AgentURL       string   `json:"agent_url"`
	AgentURLMasked string   `json:"agent_url_masked"`
	Upstream       string   `json:"upstream"`
	UpstreamTLS    bool     `json:"upstream_tls"`
	Rules          []string `json:"rules"`
	Version        string   `json:"version"`
}

func maskURLPassword(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return s
	}
	if _, ok := u.User.Password(); ok {
		u.User = url.UserPassword(u.User.Username(), "xxxxx")
		return strings.Replace(u.String(), "xxxxx", "****", 1)
	}
	return s
}

func tryMux(info *tryInfo) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/try" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(tryPageHTML)
	})
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		handleDashboard(w, r2)
	})
	mux.HandleFunc("/api/try/info", func(w http.ResponseWriter, r *http.Request) {
		// Only reveal the unmasked string to loopback clients.
		out := *info
		// The demo DB password is not a secret, so it is always shown.
		if host, _, err := net.SplitHostPort(r.RemoteAddr); !info.Demo && (err != nil || !net.ParseIP(host).IsLoopback()) {
			out.AgentURL = info.AgentURLMasked
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("/api/try/activity", func(w http.ResponseWriter, r *http.Request) {
		since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
		events, agents, total, flagged := tryActivity.Snapshot(since)
		writeJSON(w, map[string]interface{}{
			"events": events, "agents": agents, "total": total, "flagged": flagged,
		})
	})
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"status": "ok", "mode": "try"})
	})
	mux.HandleFunc("/api/firewall/agents", handleFirewallAgents)
	mux.HandleFunc("/api/violations", handleViolations)
	mux.HandleFunc("/api/policies", handlePolicies)
	mux.HandleFunc("/api/agents/stats", handleAgentStats)
	mux.HandleFunc("/api/tenants", handleTenants)
	mux.HandleFunc("/api/queries", handleQueries)
	mux.HandleFunc("/api/config", handleConfig)
	mux.HandleFunc("/favicon.png", handleFavicon)
	mux.HandleFunc("/favicon.ico", handleFavicon)
	return mux
}

func runTry(args []string) error {
	opts, err := parseTryArgs(args, os.Getenv)
	if errors.Is(err, errTryHelp) {
		printTryHelp()
		return nil
	}
	if err != nil {
		return err
	}
	if opts.Demo && runtime.GOOS == "linux" && os.Geteuid() == 0 && !dockerAvailable() {
		if handled, code, rerr := maybeReexecDemoAsUnprivileged(args); handled {
			if rerr != nil {
				return rerr
			}
			if code != 0 {
				os.Exit(code)
			}
			return nil
		} else if rerr != nil {
			return fmt.Errorf("demo Postgres can't run as root and dropping privileges failed: %v (re-run as a normal user, or pass your own DATABASE_URL)", rerr)
		}
	}
	start := time.Now()
	fmt.Println("🛡️  FaultWall try — monitor mode (observes and flags, never blocks)")
	fmt.Println()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if opts.Duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Duration)
		defer cancel()
	}

	dbURL := opts.DatabaseURL
	var demo *demoDB
	if opts.Demo {
		demo, err = startDemoPostgres()
		if err != nil {
			return err
		}
		defer demo.stop()
		if err := seedDemo(demo.url); err != nil {
			return fmt.Errorf("seeding demo data: %v", err)
		}
		dbURL = demo.url
		fmt.Printf("  ✓ demo Postgres ready with sample data (%.1fs)\n", time.Since(start).Seconds())
	} else if opts.FromEnv {
		fmt.Println("  using DATABASE_URL from your environment")
	}

	target, err := parseUpstreamURL(dbURL)
	if err != nil {
		return err
	}
	useTLS, skipVerify, err := probeUpstreamTLS(target.Addr(), target.SSLMode)
	if err != nil {
		return fmt.Errorf("can't reach your database at %s: %v\n  (from Docker, use host.docker.internal instead of localhost)", target.Addr(), err)
	}

	// Globals the proxy + API handlers use.
	policyEngine = tryPolicyEngine()
	agentTracker = NewAgentTracker()
	tryActivity = NewTryActivityStore(1000)
	tryActivity.onFlag = func(ev *TryEvent, flags []string) {
		reasons := make([]string, 0, len(flags))
		for _, f := range flags {
			if f == "policy" {
				continue // already logged + recorded by the policy engine
			}
			reasons = append(reasons, tryFlagReasons[f])
			policyEngine.addViolation(PolicyViolation{
				AgentID: ev.Agent, MissionID: ev.Mission, Query: ev.Query,
				Reason: "would_flag:" + f, Operation: ev.Operation, Action: "monitored", Timestamp: time.Now(),
			})
		}
		if len(reasons) > 0 {
			log.Printf("%s%s[WOULD FLAG]%s agent=%-20s %s — %s", colorYellow, colorBold, colorReset,
				ev.Agent, strings.Join(reasons, ", "), querySnippet(ev.Query))
		}
	}

	// Proxy listener (auto-bump port if busy).
	ln, err := listenWithFallback(opts.Listen)
	if err != nil {
		return fmt.Errorf("could not open proxy port: %v", err)
	}
	proxyBound, proxyPort, _ := net.SplitHostPort(ln.Addr().String())
	proxyHostPort := net.JoinHostPort(displayHost(proxyBound), proxyPort)

	var upstreamTLSConfig *tls.Config
	if useTLS {
		upstreamTLSConfig = &tls.Config{ServerName: target.Host, InsecureSkipVerify: skipVerify, MinVersion: tls.VersionTLS12}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			go handleProxyConn(c, target.Addr(), policyEngine, nil, upstreamTLSConfig)
		}
	}()

	// Live view.
	uiHost, _, _ := net.SplitHostPort(opts.Listen)
	uiLn, err := listenWithFallback(net.JoinHostPort(uiHost, strconv.Itoa(opts.UIPort)))
	if err != nil {
		return fmt.Errorf("could not open live-view port: %v", err)
	}
	uiBound, uiPort, _ := net.SplitHostPort(uiLn.Addr().String())
	uiURL := "http://" + net.JoinHostPort(displayHost(uiBound), uiPort)
	agentURL := agentConnString(target, proxyHostPort, opts.Agent)
	info := &tryInfo{
		Mode: "monitor", Demo: opts.Demo, AgentURL: agentURL, AgentURLMasked: maskURLPassword(agentURL),
		Upstream: target.Addr(), UpstreamTLS: useTLS, Version: Version,
		Rules: []string{"DDL / DCL", "UPDATE/DELETE without WHERE", "writes > 100 rows", "reads of password/token/secret/ssn columns"},
	}
	srv := &http.Server{Handler: tryMux(info)}
	go func() { _ = srv.Serve(uiLn) }()

	tlsNote := "plaintext"
	if useTLS {
		tlsNote = "TLS"
	}
	fmt.Println()
	fmt.Printf("  %sLive activity:%s   %s\n", colorBold, colorReset, uiURL)
	fmt.Printf("  %sGive your agent:%s %s\n", colorBold, colorReset, agentURL)
	fmt.Printf("  %sName your agent:%s  keep %sapplication_name=agent:<name>:mission:<task>%s on whatever connection string\n", colorBold, colorReset, colorCyan, colorReset)
	fmt.Println("                    you use, or its queries show up as \"unknown\". Python: psycopg.connect(url, application_name=\"agent:support-bot:mission:triage\")")
	fmt.Printf("  %sUpstream:%s        %s (%s)\n", colorBold, colorReset, target.Addr(), tlsNote)
	fmt.Printf("  %sFlags (no YAML):%s DDL · UPDATE/DELETE without WHERE · writes >100 rows · secret-column reads\n", colorBold, colorReset)
	fmt.Println()
	if opts.Demo && opts.DemoAgent {
		fmt.Println("  Demo agents 'support-bot' and 'analytics-agent' are querying through FaultWall now.")
	} else {
		fmt.Println("  Point your agent at the connection string above. Queries appear here and in the live view.")
	}
	fmt.Printf("  Ready in %.1fs. Ctrl+C to stop.\n\n", time.Since(start).Seconds())

	if opts.Open {
		openBrowser(uiURL)
	}
	if opts.Demo && opts.DemoAgent {
		go runDemoAgent(ctx, target, proxyHostPort)
	}

	<-ctx.Done()
	fmt.Println()
	_, _, total, flagged := tryActivity.Snapshot(0)
	fmt.Printf("Stopping. Saw %d queries, %d would have been flagged.\n", total, flagged)
	ln.Close()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	return nil
}
