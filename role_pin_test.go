package main

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRoleChangeAttempt(t *testing.T) {
	blocked := []string{
		"SET ROLE fwproxy",
		"set role 'fwproxy'",
		"SET SESSION ROLE fwproxy",
		"SET LOCAL ROLE fwproxy",
		"SET ROLE NONE",
		"RESET ROLE",
		"reset role",
		"SET SESSION AUTHORIZATION fwproxy",
		"SET SESSION AUTHORIZATION DEFAULT",
		"RESET SESSION AUTHORIZATION",
		"RESET ALL",
		"DISCARD ALL",
		"SELECT set_config('role', 'fwproxy', false)",
		"select pg_catalog.set_config('ROLE'::text, 'fwproxy', false)",
		"SELECT set_config('session_authorization', 'fwproxy', false)",
		"SELECT set_config(name, 'x', false) FROM (VALUES ('role')) v(name)",
		"SELECT 1; RESET ROLE",
		"SELECT 1; SET ROLE fwproxy; SELECT 2",
		"BEGIN; SET LOCAL ROLE fwproxy; UPDATE orders SET status='x'; COMMIT",
		"PREPARE p AS SELECT set_config('role','fwproxy',false)",
		"WITH x AS (SELECT set_config('role','fwproxy',false)) SELECT * FROM x",
		"DO $$ BEGIN EXECUTE 'RESET ROLE'; END $$",
		"DO $$ BEGIN PERFORM set_config('ro'||'le','fwproxy',false); END $$",
		"CREATE FUNCTION f() RETURNS void LANGUAGE sql AS $$ RESET ROLE $$",
		"CREATE FUNCTION f() RETURNS int LANGUAGE sql SET role = fwproxy AS 'select 1'",
		"ALTER FUNCTION f() SET role = fwproxy",
		"EXPLAIN ANALYZE SELECT set_config('role','fwproxy',false)",
		"RESET ROLE garbage garbage", // unparseable, mentions role
	}
	for _, q := range blocked {
		if hit, why := roleChangeAttempt(q); !hit {
			t.Errorf("not blocked: %q", q)
		} else if why == "" {
			t.Errorf("no reason for %q", q)
		}
	}
	allowed := []string{
		"SELECT * FROM orders",
		"UPDATE orders SET status='x' WHERE id=1",
		"SET search_path TO public",
		"SET statement_timeout = 5000",
		"RESET statement_timeout",
		"DISCARD PLANS",
		"DISCARD TEMP",
		"SELECT set_config('search_path', 'public', false)",
		"SELECT current_user, session_user",
		"SELECT rolname FROM pg_roles", // mentions role-ish names but changes nothing
		"SHOW role",
		"",
	}
	for _, q := range allowed {
		if hit, why := roleChangeAttempt(q); hit {
			t.Errorf("wrongly blocked %q (%s)", q, why)
		}
	}
}

func TestQuoteIdentAndRoleName(t *testing.T) {
	if quoteIdent(`fw_ro`) != `"fw_ro"` || quoteIdent(`a"b`) != `"a""b"` {
		t.Fatal("quoteIdent")
	}
	if dbRoleRe.MatchString(`x"; RESET ROLE; --`) || !dbRoleRe.MatchString("fw_ro_support_agent") {
		t.Fatal("dbRoleRe")
	}
}

func TestDBRoleSyncAndRoleChangeKill(t *testing.T) {
	ks := NewAgentKeyStore()
	ks.Replace([]AgentKeyEntry{
		{Agent: "ro", KeySHA256: HashAgentKey("fw_ak_ro"), DBRole: "fw_ro"},
		{Agent: "ro", KeySHA256: HashAgentKey("fw_ak_old"), Revoked: true, DBRole: "zzz"},
		{Agent: "rw", KeySHA256: HashAgentKey("fw_ak_rw")},
	})
	if ks.DBRole("ro") != "fw_ro" || ks.DBRole("rw") != "" || ks.DBRole("nobody") != "" {
		t.Fatalf("DBRole: %q %q", ks.DBRole("ro"), ks.DBRole("rw"))
	}
	r := &agentSessionRegistry{byID: map[uint64]agentSession{}}
	killed := map[string]string{}
	r.Register("ro", "fw_ro", func(m string) { killed["ro"] = m })
	r.Register("rw", "", func(m string) { killed["rw"] = m })
	if n := r.KillRevoked(ks); n != 0 {
		t.Fatalf("unchanged roles must not kill, killed %d", n)
	}
	// Role cleared on the control plane: the pinned session ends.
	ks.Replace([]AgentKeyEntry{
		{Agent: "ro", KeySHA256: HashAgentKey("fw_ak_ro")},
		{Agent: "rw", KeySHA256: HashAgentKey("fw_ak_rw")},
	})
	if n := r.KillRevoked(ks); n != 1 || !strings.Contains(killed["ro"], "database role") || killed["rw"] != "" {
		t.Fatalf("n=%d killed=%v", n, killed)
	}
	// Role newly set on an unpinned agent: that session ends too.
	ks.Replace([]AgentKeyEntry{{Agent: "rw", KeySHA256: HashAgentKey("fw_ak_rw"), DBRole: "fw_ro"}})
	if n := r.KillRevoked(ks); n != 1 || killed["rw"] == "" {
		t.Fatalf("set role: n=%d killed=%v", n, killed)
	}
}

func TestParseManagedPolicyKeepsDBRoleJSON(t *testing.T) {
	var r policySyncResponse
	if err := json.Unmarshal([]byte(`{"agent_keys":[{"agent":"ro","key_sha256":"ab","revoked":false,"db_role":"fw_ro"}]}`), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.AgentKeys) != 1 || r.AgentKeys[0].DBRole != "fw_ro" {
		t.Fatalf("db_role not decoded: %+v", r.AgentKeys)
	}
}

// fakeUpstream accepts one connection, does cleartext auth, then records
// every simple-protocol query and answers it. failRole makes SET SESSION
// ROLE fail like Postgres does when the login isn't a member of the role.
type fakeUpstream struct {
	ln       net.Listener
	mu       sync.Mutex
	queries  []string
	msgTypes []byte
	failRole bool
}

func newFakeUpstream(t *testing.T, failRole bool) *fakeUpstream {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeUpstream{ln: ln, failRole: failRole}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		readStartupMessage(c)
		req := make([]byte, 4)
		binary.BigEndian.PutUint32(req, 3)
		writeWireMessage(c, 'R', req)
		readWireMessage(c)
		writeWireMessage(c, 'R', make([]byte, 4))
		writeWireMessage(c, 'S', []byte("server_version\x0016.4\x00"))
		writeWireMessage(c, 'Z', []byte{'I'})
		for {
			typ, p, err := readWireMessage(c)
			if err != nil {
				return
			}
			f.mu.Lock()
			f.msgTypes = append(f.msgTypes, typ)
			if typ == 'Q' {
				f.queries = append(f.queries, strings.TrimRight(string(p), "\x00"))
			}
			f.mu.Unlock()
			switch typ {
			case 'Q':
				q := string(p)
				if strings.HasPrefix(q, "SET SESSION ROLE") && f.failRole {
					writeWireMessage(c, 'E', []byte("SERROR\x00C42501\x00Mpermission denied to set role \"fw_ro\"\x00\x00"))
				} else {
					writeWireMessage(c, 'C', []byte("SET\x00"))
				}
				writeWireMessage(c, 'Z', []byte{'I'})
			case 'S':
				writeWireMessage(c, 'Z', []byte{'I'})
			case 'X':
				return
			}
		}
	}()
	return f
}

func (f *fakeUpstream) seen() ([]string, []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...), append([]byte(nil), f.msgTypes...)
}

func pinnedSession(t *testing.T, role string, failRole bool) (net.Conn, *fakeUpstream, byte, string) {
	t.Helper()
	const key = "fw_ak_rolepin000000000000000000000000000000000000000"
	ks := NewAgentKeyStore()
	ks.Replace([]AgentKeyEntry{{Agent: "ro-agent", KeySHA256: HashAgentKey(key), Scram: makeVerifier(t, key), DBRole: role}})
	old := agentKeys
	agentKeys = ks
	t.Cleanup(func() { agentKeys = old })
	t.Setenv("FW_UPSTREAM_USER", "fwproxy")
	t.Setenv("FW_UPSTREAM_PASSWORD", "x")
	up := newFakeUpstream(t, failRole)
	t.Cleanup(func() { up.ln.Close() })
	pe := &PolicyEngine{enforcement: "monitor", pausedAgents: map[string]bool{}, config: &PolicyConfig{Agents: map[string]AgentPolicy{}}}
	a, b := net.Pipe()
	go handleProxyConn(b, up.ln.Addr().String(), pe, nil, nil)
	t.Cleanup(func() { a.Close() })
	_ = a.SetDeadline(time.Now().Add(10 * time.Second))
	a.Write(startup("user", "ro-agent", "database", "prod"))
	typ, msg, _ := scramClientLogin(t, a, "ro-agent", key)
	return a, up, typ, msg
}

func sendQ(c net.Conn, q string) { writeWireMessage(c, 'Q', append([]byte(q), 0)) }

// readUntilZ returns the message types seen and the concatenated payloads.
func readUntilZ(t *testing.T, c net.Conn) (string, string) {
	t.Helper()
	var types, body strings.Builder
	for {
		typ, p, err := readWireMessage(c)
		if err != nil {
			t.Fatalf("read: %v (so far %q)", err, types.String())
		}
		types.WriteByte(typ)
		body.Write(p)
		if typ == 'Z' {
			return types.String(), body.String()
		}
	}
}

func TestPinnedRoleWire(t *testing.T) {
	a, up, typ, msg := pinnedSession(t, "fw_ro", false)
	if typ != 'Z' {
		t.Fatalf("login: %c %q", typ, msg)
	}
	q, _ := up.seen()
	if len(q) != 1 || q[0] != `SET SESSION ROLE "fw_ro"` {
		t.Fatalf("SET SESSION ROLE must run before the client gets ReadyForQuery; upstream saw %q", q)
	}

	// Simple protocol: refused with 42501, connection survives, nothing forwarded.
	for _, bad := range []string{"SET ROLE fwproxy", "RESET ROLE", "DISCARD ALL", "SELECT set_config('role','fwproxy',false)"} {
		sendQ(a, bad)
		types, body := readUntilZ(t, a)
		if types != "EZ" || !strings.Contains(body, "42501") || !strings.Contains(body, roleFixedMessage) {
			t.Fatalf("%q: got %q %q", bad, types, body)
		}
	}
	sendQ(a, "SELECT 1")
	if types, _ := readUntilZ(t, a); types != "CZ" {
		t.Fatalf("connection must stay usable, got %q", types)
	}
	// Extended protocol: Parse of a role change is refused at Sync.
	writeWireMessage(a, 'P', []byte("\x00RESET ROLE\x00\x00\x00"))
	writeWireMessage(a, 'B', []byte("\x00\x00\x00\x00\x00\x00\x00\x00"))
	writeWireMessage(a, 'E', []byte("\x00\x00\x00\x00\x00"))
	writeWireMessage(a, 'S', nil)
	if types, body := readUntilZ(t, a); types != "EZ" || !strings.Contains(body, roleFixedMessage) {
		t.Fatalf("extended: got %q %q", types, body)
	}
	// Fast-path FunctionCall is refused too.
	writeWireMessage(a, 'F', []byte{0, 0, 0x08, 0x2a, 0, 0, 0, 0, 0, 1})
	if types, _ := readUntilZ(t, a); types != "EZ" {
		t.Fatalf("fast-path: got %q", types)
	}
	sendQ(a, "SELECT 2")
	if types, _ := readUntilZ(t, a); types != "CZ" {
		t.Fatalf("still usable after extended block, got %q", types)
	}
	q, mt := up.seen()
	for _, s := range q {
		if strings.Contains(strings.ToUpper(s), "RESET") || strings.Contains(s, "fwproxy") || strings.Contains(s, "DISCARD") {
			t.Fatalf("role change reached upstream: %q", q)
		}
	}
	for _, m := range mt {
		if m == 'P' || m == 'F' {
			t.Fatalf("blocked Parse/FunctionCall reached upstream: %q", mt)
		}
	}
}

func TestPinnedRoleFailureIsFatal(t *testing.T) {
	a, _, typ, msg := pinnedSession(t, "fw_ro", true)
	if typ != 'E' || !strings.Contains(msg, "FATAL") || !strings.Contains(msg, `"fw_ro"`) ||
		!strings.Contains(msg, "permission denied to set role") || !strings.Contains(msg, "GRANT fw_ro TO") {
		t.Fatalf("want FATAL explaining the role failure, got %c %q", typ, msg)
	}
	if _, _, err := readWireMessage(a); err == nil {
		t.Fatal("connection must close after the FATAL")
	}
}

func TestNoRoleNoSetRole(t *testing.T) {
	a, up, typ, msg := pinnedSession(t, "", false)
	if typ != 'Z' {
		t.Fatalf("login: %c %q", typ, msg)
	}
	sendQ(a, "SET ROLE other")
	if types, _ := readUntilZ(t, a); types != "CZ" {
		t.Fatalf("agents without db_role are not restricted by the pin, got %q", types)
	}
	if q, _ := up.seen(); len(q) != 1 || q[0] != "SET ROLE other" {
		t.Fatalf("upstream saw %q", q)
	}
}
