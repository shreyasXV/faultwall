package main

// End-to-end check of the watch-only proxy against a real Postgres.
// Opt-in (downloads ~30MB of Postgres binaries on first run):
//
//	FW_E2E=1 go test -run TestE2E -v .

import (
	"database/sql"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
)

func TestE2EMonitorProxyCountsEveryPreparedExecute(t *testing.T) {
	if os.Getenv("FW_E2E") != "1" {
		t.Skip("set FW_E2E=1 to run (starts an embedded Postgres)")
	}
	port := freePort(55471)
	dir := t.TempDir()
	home, _ := os.UserHomeDir()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).Port(uint32(port)).
		Username("postgres").Password("pw").Database("app").
		RuntimePath(filepath.Join(dir, "rt")).
		CachePath(filepath.Join(home, ".faultwall", "cache")).
		StartTimeout(60 * time.Second).Logger(io.Discard))
	if err := pg.Start(); err != nil {
		t.Fatalf("embedded postgres: %v", err)
	}
	defer pg.Stop()

	upstream := fmt.Sprintf("127.0.0.1:%d", port)
	direct, _ := sql.Open("postgres", fmt.Sprintf("postgres://postgres:pw@%s/app?sslmode=disable", upstream))
	defer direct.Close()
	if _, err := direct.Exec(`CREATE TABLE users(id int primary key, email text, password_hash text);
		INSERT INTO users SELECT g, 'u'||g||'@x', md5(g::text) FROM generate_series(1,20) g`); err != nil {
		t.Fatal(err)
	}

	// (2) the monitoring DSN users actually paste: libpq default sslmode=prefer.
	mdb, err := openMonitoringDB(fmt.Sprintf("postgres://postgres:pw@%s/app?sslmode=prefer", upstream))
	if err != nil {
		t.Fatal(err)
	}
	if err := mdb.Ping(); err != nil {
		t.Fatalf("monitoring DSN with sslmode=prefer must work (QWM sampler / bypass detector): %v", err)
	}
	mdb.Close()

	// (1) watch-only proxy: env/flag honoured, never blocks.
	mode, _, err := resolveProxyEnforcement("monitor", "")
	if err != nil || mode != "monitor" {
		t.Fatalf("mode: %q %v", mode, err)
	}
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"support-agent": {
				Profile:        "standard",
				Missions:       map[string]MissionPolicy{"work": {Tables: []string{"public.users"}}},
				BlockedColumns: map[string][]string{"users": {"password_hash"}},
			},
		},
		Unidentified: UnidentifiedPolicy{Policy: "deny"},
	})
	pe.enforcement = mode

	oldTracker := agentTracker
	agentTracker = NewAgentTracker()
	defer func() { agentTracker = oldTracker }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleProxyConn(c, upstream, pe, nil, nil)
		}
	}()

	agentDB, _ := sql.Open("postgres", fmt.Sprintf(
		"postgres://postgres:pw@%s/app?sslmode=disable&application_name=agent:support-agent:mission:work", ln.Addr()))
	defer agentDB.Close()
	agentDB.SetMaxOpenConns(1)

	// (3) Parse once, Bind/Execute many — what psycopg3/pgx/JDBC do with a
	// cached prepared statement.
	okStmt, err := agentDB.Prepare("SELECT email FROM users WHERE id = $1")
	if err != nil {
		t.Fatal(err)
	}
	badStmt, err := agentDB.Prepare("SELECT password_hash FROM users WHERE id = $1")
	if err != nil {
		t.Fatalf("monitor mode must not block Parse: %v", err)
	}
	const runs = 10
	for i := 1; i <= runs; i++ {
		var s string
		if err := okStmt.QueryRow(i).Scan(&s); err != nil {
			t.Fatalf("ok run %d: %v", i, err)
		}
		if err := badStmt.QueryRow(i).Scan(&s); err != nil {
			t.Fatalf("monitor mode must not block execute %d: %v", i, err)
		}
	}
	okStmt.Close()
	badStmt.Close()
	time.Sleep(200 * time.Millisecond)

	rec := agentTracker.GetAgent("support-agent")
	if rec == nil {
		t.Fatal("agent not tracked")
	}
	if rec.TotalQueries != 2*runs {
		t.Errorf("prepared-statement runs undercounted: got %d queries, sent %d", rec.TotalQueries, 2*runs)
	}
	flagged := 0
	for _, v := range pe.GetViolations() {
		if v.Reason == "blocked_column:users.password_hash" {
			flagged++
			if v.Action != "monitored" {
				t.Errorf("watch-only violation action = %q", v.Action)
			}
		}
	}
	if flagged != runs {
		t.Errorf("each run of the flagged statement must be recorded: got %d, want %d", flagged, runs)
	}
}
