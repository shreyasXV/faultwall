package main

import (
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// enforcedSession logs "ro-agent" into an enforce-mode proxy in front of a
// fake upstream. The caller mutates pe.config to change policy mid-session.
func enforcedSession(t *testing.T) (net.Conn, *fakeUpstream, *PolicyEngine) {
	t.Helper()
	const key = "fw_ak_stmtenf0000000000000000000000000000000000000000"
	ks := NewAgentKeyStore()
	ks.Replace([]AgentKeyEntry{{Agent: "ro-agent", KeySHA256: HashAgentKey(key), Scram: makeVerifier(t, key)}})
	old := agentKeys
	agentKeys = ks
	t.Cleanup(func() { agentKeys = old })
	t.Setenv("FW_UPSTREAM_USER", "fwproxy")
	t.Setenv("FW_UPSTREAM_PASSWORD", "x")
	up := newFakeUpstream(t, false)
	t.Cleanup(func() { up.ln.Close() })
	pe := &PolicyEngine{enforcement: "enforce", pausedAgents: map[string]bool{}, config: &PolicyConfig{Agents: map[string]AgentPolicy{"ro-agent": {}}}}
	a, b := net.Pipe()
	go handleProxyConn(b, up.ln.Addr().String(), pe, nil, nil)
	t.Cleanup(func() { a.Close() })
	_ = a.SetDeadline(time.Now().Add(20 * time.Second))
	a.Write(startup("user", "ro-agent", "database", "prod"))
	if typ, msg, _ := scramClientLogin(t, a, "ro-agent", key); typ != 'Z' {
		t.Fatalf("login: %c %q", typ, msg)
	}
	return a, up, pe
}

// Payload-only builders (hold_test.go's parseMsg & co. return framed bytes).
func parsePayload(name, q string) []byte { return []byte(name + "\x00" + q + "\x00\x00\x00") }

func bindPayload(portal, stmt string) []byte {
	return append([]byte(portal+"\x00"+stmt+"\x00"), 0, 0, 0, 0, 0, 0)
}

func execPayload(portal string) []byte { return append([]byte(portal+"\x00"), 0, 0, 0, 0) }

func countType(mt []byte, want byte) int {
	n := 0
	for _, m := range mt {
		if m == want {
			n++
		}
	}
	return n
}

// waitSeen polls the fake upstream until it has seen n messages of type want.
func waitSeen(t *testing.T, up *fakeUpstream, want byte, n int) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if _, mt := up.seen(); countType(mt, want) >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, mt := up.seen()
	t.Fatalf("upstream saw %d %q, want %d (all: %q)", countType(mt, want), want, n, mt)
}

// readUntilClosed returns everything the client receives until the proxy
// closes the connection.
func readUntilClosed(c net.Conn) (string, string) {
	var types, body strings.Builder
	for {
		typ, p, err := readWireMessage(c)
		if err != nil {
			return types.String(), body.String()
		}
		types.WriteByte(typ)
		body.Write(p)
	}
}

// A driver-cached prepared statement must not keep running a write after the
// agent's permission to write is removed (review finding #2).
func TestCachedStatementRecheckedAfterPolicyTightens(t *testing.T) {
	a, up, pe := enforcedSession(t)
	const upd = "UPDATE orders SET status = $1 WHERE id = $2"

	// Batch 1: prepare. Batch 2: run it while UPDATE is allowed.
	writeWireMessage(a, 'P', parsePayload("s1", upd))
	writeWireMessage(a, 'S', nil)
	readUntilZ(t, a)
	writeWireMessage(a, 'B', bindPayload("", "s1"))
	writeWireMessage(a, 'E', execPayload(""))
	writeWireMessage(a, 'S', nil)
	readUntilZ(t, a)
	waitSeen(t, up, 'E', 1)

	// Writes are now blocked for this agent (what a policy sync does).
	pe.mu.Lock()
	pe.config = &PolicyConfig{Agents: map[string]AgentPolicy{"ro-agent": {BlockedOperations: []string{"UPDATE"}}}}
	pe.mu.Unlock()

	// Batch 3: the cached statement again, no new Parse.
	writeWireMessage(a, 'B', bindPayload("", "s1"))
	writeWireMessage(a, 'E', execPayload(""))
	writeWireMessage(a, 'S', nil)
	types, body := readUntilClosed(a)
	if !strings.Contains(types, "E") || !strings.Contains(body, "no longer permitted") {
		t.Fatalf("want an error then close, got %q %q", types, body)
	}
	time.Sleep(50 * time.Millisecond)
	if _, mt := up.seen(); countType(mt, 'E') != 1 {
		t.Fatalf("blocked cached Execute reached upstream: %q", mt)
	}
}

// Same batch Parse+Bind+Execute keeps the Parse-time decision (no re-check
// needed) and a still-permitted cached statement keeps working.
func TestCachedStatementStillAllowedKeepsWorking(t *testing.T) {
	a, up, _ := enforcedSession(t)
	writeWireMessage(a, 'P', parsePayload("s1", "SELECT * FROM orders WHERE id = $1"))
	writeWireMessage(a, 'B', bindPayload("", "s1"))
	writeWireMessage(a, 'E', execPayload(""))
	writeWireMessage(a, 'S', nil)
	readUntilZ(t, a)
	for i := 0; i < 3; i++ {
		writeWireMessage(a, 'B', bindPayload("", "s1"))
		writeWireMessage(a, 'E', execPayload(""))
		writeWireMessage(a, 'S', nil)
		if types, _ := readUntilZ(t, a); types != "Z" {
			t.Fatalf("run %d: got %q", i, types)
		}
	}
	waitSeen(t, up, 'E', 4)
}

// Filling the statement tracker must not let a later statement run unchecked
// (review finding #3): the proxy closes the session instead of forwarding a
// Parse it can't track.
func TestStatementTrackerOverflowFailsClosed(t *testing.T) {
	a, up, _ := enforcedSession(t)
	go func() {
		for i := 0; i < maxTrackedStmts; i++ {
			writeWireMessage(a, 'P', parsePayload("s"+itoa(i), "SELECT 1"))
		}
		writeWireMessage(a, 'P', parsePayload("overflow", "UPDATE orders SET status = $1 WHERE id = $2"))
		writeWireMessage(a, 'B', bindPayload("", "overflow"))
		writeWireMessage(a, 'E', execPayload(""))
		writeWireMessage(a, 'S', nil)
	}()
	types, body := readUntilClosed(a)
	if !strings.Contains(types, "E") || !strings.Contains(body, "too many open prepared statements") {
		t.Fatalf("want an error then close, got %q %q", types, body)
	}
	time.Sleep(50 * time.Millisecond)
	_, mt := up.seen()
	if countType(mt, 'P') != maxTrackedStmts || countType(mt, 'E') != 0 {
		t.Fatalf("untracked statement reached upstream: P=%d E=%d", countType(mt, 'P'), countType(mt, 'E'))
	}
}

func TestStmtTrackerReportsOverflowAndFreshness(t *testing.T) {
	tr := newStmtTracker()
	for i := 0; i < maxTrackedStmts; i++ {
		if !tr.parse("s"+itoa(i), "SELECT 1", nil, nil) {
			t.Fatalf("parse %d refused below the cap", i)
		}
	}
	if tr.parse("one-more", "SELECT 1", nil, nil) {
		t.Fatal("parse past the cap must report false")
	}
	tr.syncPoint()
	if !tr.parse("s0", "SELECT 2", nil, nil) {
		t.Fatal("re-parsing an existing name must still work at the cap")
	}
	if tr.bind("p", "unknown") {
		t.Fatal("bind to an untracked statement must report false")
	}
	if !tr.stmts["s0"].fresh {
		t.Fatal("statement must be fresh until Sync")
	}
	tr.syncPoint()
	if tr.stmts["s0"].fresh || len(tr.freshSince) != 0 {
		t.Fatal("Sync must clear freshness")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

func TestBindStartupDatabase(t *testing.T) {
	get := func(ps []startupParam) string {
		for _, p := range ps {
			if p.Key == "database" {
				return p.Val
			}
		}
		return ""
	}
	t.Setenv("DATABASE_URL", "postgres://u:p@db:5432/appdb?sslmode=disable")
	t.Setenv("FW_UPSTREAM_DATABASE", "")
	if ps, err := bindStartupDatabase([]startupParam{{"user", "a"}, {"database", "appdb"}}); err != nil || get(ps) != "appdb" {
		t.Fatalf("matching database: %v %v", ps, err)
	}
	if ps, err := bindStartupDatabase([]startupParam{{"user", "a"}}); err != nil || get(ps) != "appdb" {
		t.Fatalf("missing database must default to the bound one: %v %v", ps, err)
	}
	if _, err := bindStartupDatabase([]startupParam{{"user", "a"}, {"database", "postgres"}}); err == nil || !strings.Contains(err.Error(), `only serves database "appdb"`) {
		t.Fatalf("other database must be refused, got %v", err)
	}
	t.Setenv("FW_UPSTREAM_DATABASE", "other")
	if _, err := bindStartupDatabase([]startupParam{{"database", "appdb"}}); err == nil {
		t.Fatal("FW_UPSTREAM_DATABASE must override DATABASE_URL")
	}
	t.Setenv("FW_UPSTREAM_DATABASE", "*")
	if ps, err := bindStartupDatabase([]startupParam{{"database", "anything"}}); err != nil || get(ps) != "anything" {
		t.Fatalf("* must allow any database: %v %v", ps, err)
	}
}

// End to end: a key-authenticated agent can't switch databases by editing
// its DSN (review finding #4). The upstream never sees the connection.
func TestKeyAgentRefusedForOtherDatabase(t *testing.T) {
	const key = "fw_ak_dbbind00000000000000000000000000000000000000000"
	ks := NewAgentKeyStore()
	ks.Replace([]AgentKeyEntry{{Agent: "ro-agent", KeySHA256: HashAgentKey(key), Scram: makeVerifier(t, key)}})
	old := agentKeys
	agentKeys = ks
	t.Cleanup(func() { agentKeys = old })
	t.Setenv("FW_UPSTREAM_USER", "fwproxy")
	t.Setenv("FW_UPSTREAM_PASSWORD", "x")
	t.Setenv("FW_UPSTREAM_DATABASE", "staging")
	up := newFakeUpstream(t, false)
	t.Cleanup(func() { up.ln.Close() })
	pe := &PolicyEngine{enforcement: "enforce", pausedAgents: map[string]bool{}, config: &PolicyConfig{Agents: map[string]AgentPolicy{}}}
	a, b := net.Pipe()
	go handleProxyConn(b, up.ln.Addr().String(), pe, nil, nil)
	t.Cleanup(func() { a.Close() })
	_ = a.SetDeadline(time.Now().Add(10 * time.Second))
	a.Write(startup("user", "ro-agent", "database", "prod"))
	typ, msg, _ := scramClientLogin(t, a, "ro-agent", key)
	if typ != 'E' || !strings.Contains(msg, `only serves database "staging"`) {
		t.Fatalf("want refusal naming the bound database, got %c %q", typ, msg)
	}
	if _, mt := up.seen(); len(mt) != 0 {
		t.Fatalf("upstream must not receive anything, saw %q", mt)
	}
}

// Fast-path FunctionCall carries no SQL, so it is refused for every enforced
// session, not only role-pinned ones (review finding: write by function OID).
func TestFastPathFunctionCallRefusedWhenEnforcing(t *testing.T) {
	a, up, _ := enforcedSession(t)
	writeWireMessage(a, 'F', []byte{0, 0, 0x08, 0x2a, 0, 0, 0, 0, 0, 1})
	types, body := readUntilZ(t, a)
	if types != "EZ" || !strings.Contains(body, "fast-path function calls are not allowed") {
		t.Fatalf("got %q %q", types, body)
	}
	sendQ(a, "SELECT 1")
	if types, _ := readUntilZ(t, a); types != "CZ" {
		t.Fatalf("session must stay usable, got %q", types)
	}
	if _, mt := up.seen(); countType(mt, 'F') != 0 {
		t.Fatalf("FunctionCall reached upstream: %q", mt)
	}
}

// Revoking a key and re-creating the agent under the same name must still end
// sessions opened with the old key.
func TestRevokedKeySessionEndsWhenAgentRecreated(t *testing.T) {
	ks := NewAgentKeyStore()
	ks.Replace([]AgentKeyEntry{{Agent: "a", KeySHA256: HashAgentKey("fw_ak_old")}})
	r := &agentSessionRegistry{byID: map[uint64]agentSession{}}
	killed := map[string]string{}
	r.RegisterKey("a", "", HashAgentKey("fw_ak_old"), func(m string) { killed["old"] = m })
	ks.Replace([]AgentKeyEntry{
		{Agent: "a", KeySHA256: HashAgentKey("fw_ak_old"), Revoked: true},
		{Agent: "a", KeySHA256: HashAgentKey("fw_ak_new")},
	})
	r.RegisterKey("a", "", HashAgentKey("fw_ak_new"), func(m string) { killed["new"] = m })
	if n := r.KillRevoked(ks); n != 1 || killed["old"] == "" || killed["new"] != "" {
		t.Fatalf("n=%d killed=%v", n, killed)
	}
}

func TestLoadCABundle(t *testing.T) {
	dir := t.TempDir()
	bad := dir + "/bad.pem"
	_ = os.WriteFile(bad, []byte("not a cert"), 0o600)
	if _, err := loadCABundle(bad); err == nil {
		t.Fatal("non-PEM bundle must be rejected")
	}
	if _, err := loadCABundle(dir + "/missing.pem"); err == nil {
		t.Fatal("missing file must be rejected")
	}
	// The system roots on macOS/Linux test hosts aren't a file; use a test cert.
	cert := httptestCertPEM(t)
	good := dir + "/good.pem"
	_ = os.WriteFile(good, cert, 0o600)
	if pool, err := loadCABundle(good); err != nil || pool == nil {
		t.Fatalf("valid bundle: %v", err)
	}
}

func httptestCertPEM(t *testing.T) []byte {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}
