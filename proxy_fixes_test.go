package main

import (
	"database/sql"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// ── (1) --proxy enforcement mode ──

func TestResolveProxyEnforcement(t *testing.T) {
	cases := []struct {
		flag, env, want string
		warn, err       bool
	}{
		{"", "", "enforce", false, false},        // default unchanged: fail closed
		{"", "monitor", "monitor", false, false}, // env now honoured (was overwritten)
		{"", "enforce", "enforce", false, false},
		{"", "MONITOR", "monitor", false, false},
		{"", "bogus", "enforce", true, false}, // bad env → enforce + warning
		{"monitor", "", "monitor", false, false},
		{"monitor", "enforce", "monitor", false, false}, // flag beats env
		{"enforce", "monitor", "enforce", false, false},
		{"watch", "", "monitor", false, false},
		{"bogus", "", "", false, true},
	}
	for _, c := range cases {
		got, warn, err := resolveProxyEnforcement(c.flag, c.env)
		if (err != nil) != c.err || got != c.want || (warn != "") != c.warn {
			t.Errorf("flag=%q env=%q: got (%q, warn=%q, err=%v) want %q warn=%v err=%v",
				c.flag, c.env, got, warn, err, c.want, c.warn, c.err)
		}
	}
}

func TestTryDefaultsToMonitor(t *testing.T) {
	if pe := tryPolicyEngine(); pe.GetEnforcement() != "monitor" {
		t.Fatalf("try must default to monitor, got %s", pe.GetEnforcement())
	}
}

// ── (2) sslmode=prefer normalization ──

func withTLSProbe(t *testing.T, tls bool, err error) {
	t.Helper()
	orig := serverSupportsTLS
	serverSupportsTLS = func(string, time.Duration) (bool, error) { return tls, err }
	t.Cleanup(func() { serverSupportsTLS = orig })
}

func TestNormalizeLibPQSSLMode(t *testing.T) {
	withTLSProbe(t, false, nil) // server says 'N'
	cases := map[string]string{
		"postgres://u:p@db:5432/x?sslmode=prefer":            "sslmode=disable",
		"postgres://u:p@db:5432/x?sslmode=allow":             "sslmode=disable",
		"postgres://u:p@db:5432/x":                           "sslmode=disable",
		"host=db port=5432 user=u sslmode=prefer":            "sslmode=disable",
		"host=db port=5432 user=u sslmode='prefer' dbname=x": "sslmode=disable",
		"host=db user=u":                                     "sslmode=disable",
	}
	for in, want := range cases {
		out := normalizeLibPQSSLMode(in)
		if !strings.Contains(out, want) || strings.Contains(out, "prefer") || strings.Contains(out, "allow") {
			t.Errorf("%q → %q, want %s", in, out, want)
		}
	}
	// Supported modes are untouched.
	for _, in := range []string{
		"postgres://u:p@db/x?sslmode=require",
		"postgres://u:p@db/x?sslmode=verify-full",
		"host=db user=u sslmode=disable",
	} {
		if out := normalizeLibPQSSLMode(in); out != in {
			t.Errorf("%q should be unchanged, got %q", in, out)
		}
	}
	// kv DSN keeps its other params.
	out := normalizeLibPQSSLMode("host=db port=6543 user=u password=secret sslmode=prefer connect_timeout=3")
	for _, want := range []string{"host=db", "port=6543", "password=secret", "connect_timeout=3", "sslmode=disable"} {
		if !strings.Contains(out, want) {
			t.Errorf("kv rewrite lost %q: %q", want, out)
		}
	}
}

func TestNormalizeLibPQSSLModeTLSServer(t *testing.T) {
	withTLSProbe(t, true, nil) // server says 'S'
	if out := normalizeLibPQSSLMode("postgres://u:p@rds.example.com/x?sslmode=prefer"); !strings.Contains(out, "sslmode=require") {
		t.Errorf("TLS server: want require, got %q", out)
	}
}

func TestNormalizeLibPQSSLModeUnreachable(t *testing.T) {
	withTLSProbe(t, false, errTestDial)
	if out := normalizeLibPQSSLMode("postgres://u:p@localhost/x?sslmode=prefer"); !strings.Contains(out, "sslmode=disable") {
		t.Errorf("unreachable loopback: want disable, got %q", out)
	}
	if out := normalizeLibPQSSLMode("postgres://u:p@db.example.com/x?sslmode=prefer"); !strings.Contains(out, "sslmode=require") {
		t.Errorf("unreachable remote: want require (conservative), got %q", out)
	}
}

type testDialErr struct{}

func (testDialErr) Error() string { return "dial failed" }

var errTestDial = testDialErr{}

// fakePGListener accepts TCP connections, answers SSLRequest with 'N' and
// then closes. Enough for lib/pq to get past dial (where it validates sslmode)
// and for serverSupportsTLS to get a real answer.
func fakePGListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(2 * time.Second))
				var hdr [8]byte
				if _, err := io.ReadFull(c, hdr[:]); err != nil {
					return
				}
				if binary.BigEndian.Uint32(hdr[4:8]) == 80877103 {
					c.Write([]byte{'N'})
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// The exact failure from the real activity run: lib/pq rejected the
// monitoring DSN with `unsupported sslmode "prefer"`. Uses the real SSLRequest
// probe against a local fake server.
func TestMonitoringDSNAcceptedByLibPQ(t *testing.T) {
	addr := fakePGListener(t)
	host, port, _ := net.SplitHostPort(addr)
	urlDSN := "postgres://u:p@" + addr + "/x?sslmode=prefer&connect_timeout=2"
	kvDSN := "host=" + host + " port=" + port + " user=u sslmode=prefer connect_timeout=2"

	// Baseline: unpatched lib/pq really rejects prefer.
	raw, _ := sql.Open("postgres", urlDSN)
	err := raw.Ping()
	raw.Close()
	if err == nil || !strings.Contains(err.Error(), "unsupported sslmode") {
		t.Fatalf("expected lib/pq to reject raw prefer, got %v", err)
	}

	for _, dsn := range []string{urlDSN, kvDSN} {
		if got := sslModeOf(normalizeLibPQSSLMode(dsn)); got != "disable" {
			t.Errorf("%q: server answered N, want disable, got %q", dsn, got)
		}
		db, err := openMonitoringDB(dsn)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		err = db.Ping() // fake server hangs up after startup → some error, but NOT sslmode
		db.Close()
		if err != nil && strings.Contains(err.Error(), "unsupported sslmode") {
			t.Errorf("%q still rejected by lib/pq: %v", dsn, err)
		}
	}
}

// ── (3) repeat Executes of prepared statements ──

func TestStmtTrackerRepeatExecutes(t *testing.T) {
	tr := newStmtTracker()
	q := "SELECT * FROM orders WHERE id = $1"
	tr.parse("s1", q, ParseQuery(q), nil)

	repeats := 0
	for i := 0; i < 10; i++ { // psycopg3-style: Parse once, Bind/Execute ×10
		tr.bind("", "s1")
		st, repeat := tr.execute("")
		if st == nil || st.query != q {
			t.Fatalf("run %d: statement not found", i)
		}
		if repeat {
			repeats++
		}
	}
	if repeats != 9 { // first run already accounted at Parse
		t.Fatalf("want 9 repeat runs, got %d", repeats)
	}

	// Suspended portal: Execute(max_rows) twice on one Bind is ONE run.
	tr.bind("p", "s1")
	_, r1 := tr.execute("p")
	_, r2 := tr.execute("p")
	if !r1 || r2 {
		t.Fatalf("suspended portal: first=%v (want true) second=%v (want false)", r1, r2)
	}

	// Unnamed statement re-parsed each time (no cache): never a repeat.
	for i := 0; i < 3; i++ {
		tr.parse("", "SELECT 1", ParseQuery("SELECT 1"), nil)
		tr.bind("", "")
		if _, repeat := tr.execute(""); repeat {
			t.Fatalf("re-parsed unnamed statement must not double count")
		}
	}

	// Close removes state.
	tr.close('S', "s1")
	tr.bind("", "s1")
	if st, _ := tr.execute(""); st != nil {
		t.Fatalf("closed statement still tracked")
	}
}

func TestAccountRepeatExecuteCountsAndFlags(t *testing.T) {
	oldTracker := agentTracker
	agentTracker = NewAgentTracker()
	defer func() { agentTracker = oldTracker }()
	pe := tryPolicyEngine()
	id := ParseAgentIdentity("agent:support-agent:mission:work")

	ok := &preparedStmt{query: "SELECT 1", pq: ParseQuery("SELECT 1")}
	flagged := &preparedStmt{query: "SELECT password_hash FROM users WHERE id=$1",
		pq:        ParseQuery("SELECT password_hash FROM users WHERE id=$1"),
		violation: &PolicyViolation{AgentID: "support-agent", Reason: "blocked_column:users.password_hash", Table: "users"}}
	for i := 0; i < 4; i++ {
		accountRepeatExecute(pe, ok, "support-agent/work", id)
		accountRepeatExecute(pe, flagged, "support-agent/work", id)
	}
	rec := agentTracker.GetAgent("support-agent")
	if rec == nil || rec.TotalQueries != 8 {
		t.Fatalf("want 8 counted queries, got %+v", rec)
	}
	if n := len(pe.GetViolations()); n != 4 {
		t.Fatalf("each repeat run of a monitored statement must be recorded: want 4 violations, got %d", n)
	}
	if pe.GetViolations()[0].Action != "monitored" {
		t.Fatalf("repeat violation action = %q", pe.GetViolations()[0].Action)
	}
}
