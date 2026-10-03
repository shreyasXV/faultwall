package main

import (
	"strings"
	"testing"
)

func flagsFor(q string) []string { return tryStaticFlags(ParseQuery(q), q) }

func has(fs []string, f string) bool {
	for _, x := range fs {
		if x == f {
			return true
		}
	}
	return false
}

func TestTryStaticFlags(t *testing.T) {
	cases := []struct {
		q    string
		want []string
		not  []string
	}{
		{"SELECT id, name FROM customers WHERE id = 1", nil, []string{"ddl", "no_where", "secret_read"}},
		{"SELECT email, password_hash FROM customers", []string{"secret_read"}, nil},
		{"SELECT token FROM api_keys", []string{"secret_read"}, nil},
		{"SELECT u.ssn FROM users u WHERE id=1", []string{"secret_read"}, nil},
		{"SELECT client_secret FROM oauth_apps", []string{"secret_read"}, nil},
		{"SELECT lessons, tokenizer_version FROM courses", nil, []string{"secret_read"}},
		{"DELETE FROM orders", []string{"no_where"}, nil},
		{"DELETE FROM orders WHERE id = 3", nil, []string{"no_where"}},
		{"UPDATE orders SET status='x' WHERE 1=1", []string{"no_where"}, nil},
		{"UPDATE orders SET status='x' WHERE id = 3", nil, []string{"no_where"}},
		{"DROP TABLE orders", []string{"ddl"}, nil},
		{"CREATE TABLE t (a int)", []string{"ddl"}, nil},
		{"ALTER TABLE t ADD COLUMN b int", []string{"ddl"}, nil},
		{"TRUNCATE orders", []string{"ddl"}, nil},
		{"GRANT ALL ON orders TO bob", []string{"ddl"}, nil},
		{"BEGIN", nil, []string{"ddl", "no_where"}},
		{"SELECT dblink('host=x', 'select 1')", []string{"server_func"}, nil},
		{"SELECT lower(name) FROM customers", nil, []string{"server_func"}},
	}
	for _, c := range cases {
		got := flagsFor(c.q)
		for _, w := range c.want {
			if !has(got, w) {
				t.Errorf("%q: want flag %s, got %v", c.q, w, got)
			}
		}
		for _, n := range c.not {
			if has(got, n) {
				t.Errorf("%q: unexpected flag %s, got %v", c.q, n, got)
			}
		}
	}
}

func TestParseCommandCompleteRows(t *testing.T) {
	cases := []struct {
		tag   string
		rows  int64
		write bool
		ok    bool
	}{
		{"UPDATE 150\x00", 150, true, true},
		{"INSERT 0 200\x00", 200, true, true},
		{"DELETE 3\x00", 3, true, true},
		{"SELECT 1000\x00", 1000, false, true},
		{"BEGIN\x00", 0, false, false},
	}
	for _, c := range cases {
		r, w, ok := parseCommandCompleteRows([]byte(c.tag))
		if r != c.rows || w != c.write || ok != c.ok {
			t.Errorf("%q: got (%d,%v,%v) want (%d,%v,%v)", c.tag, r, w, ok, c.rows, c.write, c.ok)
		}
	}
}

func TestTryActivityMassWrite(t *testing.T) {
	s := NewTryActivityStore(10)
	var flagged []string
	s.onFlag = func(ev *TryEvent, f []string) { flagged = append(flagged, f...) }
	q := "UPDATE orders SET status='x' WHERE customer_id = 7"
	id := s.Record("bot", "m", q, ParseQuery(q), nil)
	s.RecordCommandComplete(id, []byte("UPDATE 50\x00"))
	if len(flagged) != 0 {
		t.Fatalf("50-row write should not flag, got %v", flagged)
	}
	id = s.Record("bot", "m", q, ParseQuery(q), nil)
	s.RecordCommandComplete(id, []byte("UPDATE 101\x00"))
	if !has(flagged, "mass_write") {
		t.Fatalf("101-row write should flag mass_write, got %v", flagged)
	}
	// SELECT of many rows is not a write.
	sq := "SELECT * FROM orders"
	id = s.Record("bot", "m", sq, ParseQuery(sq), nil)
	s.RecordCommandComplete(id, []byte("SELECT 5000\x00"))
	events, agents, total, nflag := s.Snapshot(0)
	if total != 3 || nflag != 1 || len(agents) != 1 || len(events) != 3 {
		t.Fatalf("snapshot: total=%d flagged=%d agents=%d events=%d", total, nflag, len(agents), len(events))
	}
	if events[2].Rows != 5000 || len(events[2].Flags) != 0 {
		t.Fatalf("select event: %+v", events[2])
	}
}

func TestTryActivityRingBound(t *testing.T) {
	s := NewTryActivityStore(5)
	for i := 0; i < 12; i++ {
		s.Record("a", "", "SELECT 1", ParseQuery("SELECT 1"), nil)
	}
	ev, _, total, _ := s.Snapshot(0)
	if len(ev) != 5 || total != 12 || ev[0].ID != 8 {
		t.Fatalf("ring: len=%d total=%d first=%d", len(ev), total, ev[0].ID)
	}
	ev, _, _, _ = s.Snapshot(10)
	if len(ev) != 2 {
		t.Fatalf("since=10 want 2 got %d", len(ev))
	}
}

func TestTryPolicyEngineNeverBlocksAndAllowsAll(t *testing.T) {
	pe := tryPolicyEngine()
	if pe.GetEnforcement() != "monitor" {
		t.Fatalf("try must be monitor mode, got %s", pe.GetEnforcement())
	}
	id := ParseAgentIdentity("agent:random-bot:mission:x")
	for _, q := range []string{"SELECT * FROM users", "DELETE FROM orders", "DROP TABLE x"} {
		if v := pe.CheckQuery(id, q, 0); v != nil {
			t.Errorf("%q: try policy should not create a policy violation (flags come from try rules), got %s", q, v.Reason)
		}
		if v := pe.CheckQuery(nil, q, 0); v != nil {
			t.Errorf("unidentified %q: should be allowed in try mode, got %s", q, v.Reason)
		}
	}
	if f := flagsFor("SELECT pg_read_file('/etc/passwd')"); !has(f, "server_func") {
		t.Errorf("dangerous server function should be flagged by try rules, got %v", f)
	}
}

func TestParseTryArgs(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	o, err := parseTryArgs(nil, env(nil))
	if err != nil || !o.Demo {
		t.Fatalf("no args → demo: %+v %v", o, err)
	}
	o, err = parseTryArgs([]string{"postgres://u:p@db:6543/app"}, env(nil))
	if err != nil || o.Demo || o.DatabaseURL != "postgres://u:p@db:6543/app" {
		t.Fatalf("url arg: %+v %v", o, err)
	}
	o, _ = parseTryArgs(nil, env(map[string]string{"DATABASE_URL": "postgres://x@y/z"}))
	if o.Demo || !o.FromEnv {
		t.Fatalf("env: %+v", o)
	}
	o, _ = parseTryArgs([]string{"--demo"}, env(map[string]string{"DATABASE_URL": "postgres://x@y/z"}))
	if !o.Demo || o.DatabaseURL != "" {
		t.Fatalf("--demo overrides env: %+v", o)
	}
	o, _ = parseTryArgs([]string{"--port", "6000", "--agent", "cursor"}, env(nil))
	if !strings.HasSuffix(o.Listen, ":6000") || o.Agent != "cursor" {
		t.Fatalf("flags: %+v", o)
	}
	if _, err := parseTryArgs([]string{"--agent", "bad:name"}, env(nil)); err == nil {
		t.Fatalf("bad agent name should error")
	}
	if _, err := parseTryArgs([]string{"mysql://x"}, env(nil)); err == nil {
		t.Fatalf("non-postgres url should error")
	}
}

func TestAgentConnString(t *testing.T) {
	tg, err := parseUpstreamURL("postgres://alice:s%40cret@db.example.com:6543/app?sslmode=require&connect_timeout=5&application_name=old")
	if err != nil {
		t.Fatal(err)
	}
	if tg.Addr() != "db.example.com:6543" || tg.SSLMode != "require" || tg.Password != "s@cret" {
		t.Fatalf("parsed: %+v", tg)
	}
	got := agentConnString(tg, "localhost:5433", "my-agent")
	for _, want := range []string{"postgres://alice:s%40cret@localhost:5433/app", "sslmode=disable", "application_name=agent:my-agent:mission:default", "connect_timeout=5"} {
		if !strings.Contains(got, want) {
			t.Errorf("agent url %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "sslmode=require") || strings.Contains(got, "application_name=old") {
		t.Errorf("agent url should drop upstream sslmode/application_name: %q", got)
	}
	if m := maskURLPassword(got); strings.Contains(m, "s%40cret") || !strings.Contains(m, "****") {
		t.Errorf("mask: %q", m)
	}
	d, _ := parseUpstreamURL("postgres://localhost")
	if d.Port != "5432" || d.User != "postgres" || d.DB != "postgres" {
		t.Errorf("defaults: %+v", d)
	}
}
