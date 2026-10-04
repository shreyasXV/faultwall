package main

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testKeyLive    = "fw_ak_live000000000000000000000000000000000000000000"
	testKeyRevoked = "fw_ak_revoked0000000000000000000000000000000000000000"
)

func testKeyStore() *AgentKeyStore {
	ks := NewAgentKeyStore()
	ks.Replace([]AgentKeyEntry{
		{Agent: "support-agent", KeySHA256: HashAgentKey(testKeyLive)},
		{Agent: "old-agent", KeySHA256: HashAgentKey(testKeyRevoked), Revoked: true},
	})
	return ks
}

func startup(params ...string) []byte {
	var ps []startupParam
	for i := 0; i+1 < len(params); i += 2 {
		ps = append(ps, startupParam{params[i], params[i+1]})
	}
	return buildStartupMessage(196608, ps)
}

func TestStartupParamsRoundTrip(t *testing.T) {
	buf := startup("user", "u", "database", "d", "application_name", "agent:a:mission:m")
	proto, ps := parseStartupParams(buf)
	if proto != 196608 || len(ps) != 3 || startupGet(ps, "database") != "d" {
		t.Fatalf("proto=%d ps=%v", proto, ps)
	}
	if extractAppName(buf) != "agent:a:mission:m" {
		t.Fatalf("extractAppName = %q", extractAppName(buf))
	}
	if int(binary.BigEndian.Uint32(buf[:4])) != len(buf) {
		t.Fatal("bad length prefix")
	}
}

func TestStartupAgentAuthModes(t *testing.T) {
	ks := testKeyStore()

	// Legacy identity: untouched passthrough.
	d := startupAgentAuth(startup("user", "postgres", "application_name", "agent:legacy:mission:m"), ks)
	if d.Err != "" || d.Mode != authPassthrough || d.Identity == nil || d.Identity.AgentID != "legacy" {
		t.Fatalf("legacy: %+v", d)
	}
	// No identity at all: passthrough, unidentified.
	d = startupAgentAuth(startup("user", "postgres"), ks)
	if d.Err != "" || d.Mode != authPassthrough || d.Identity != nil {
		t.Fatalf("plain: %+v", d)
	}

	// Key as password: user = managed agent.
	d = startupAgentAuth(startup("user", "support-agent", "database", "prod"), ks)
	if d.Err != "" || d.Mode != authKeyPassword || d.Identity.AgentID != "support-agent" || d.Identity.Raw != "agent:support-agent:mission:default" {
		t.Fatalf("password mode: %+v", d)
	}
	if verifyAgentPassword("support-agent", testKeyLive, ks) != "" {
		t.Fatal("valid key refused")
	}
	if m := verifyAgentPassword("support-agent", "fw_ak_nope", ks); !strings.Contains(m, "unknown agent key") {
		t.Fatalf("unknown: %q", m)
	}
	if m := verifyAgentPassword("support-agent", "", ks); !strings.Contains(m, "needs its key") {
		t.Fatalf("empty: %q", m)
	}
	if m := verifyAgentPassword("old-agent", testKeyRevoked, ks); !strings.Contains(m, "revoked") {
		t.Fatalf("revoked: %q", m)
	}
	if m := verifyAgentPassword("old-agent", testKeyLive, ks); !strings.Contains(m, "different agent") {
		t.Fatalf("cross-agent: %q", m)
	}

	// Key as application_name token: verified + stripped before forwarding.
	d = startupAgentAuth(startup("user", "app", "application_name", "agent:support-agent:mission:triage:token:"+testKeyLive), ks)
	if d.Err != "" || d.Mode != authKeyToken || d.Identity.MissionID != "triage" {
		t.Fatalf("token mode: %+v", d)
	}
	if got := extractAppName(d.Startup); got != "agent:support-agent:mission:triage" || strings.Contains(string(d.Startup), testKeyLive) {
		t.Fatalf("forwarded application_name = %q (key must be stripped)", got)
	}
	d = startupAgentAuth(startup("user", "app", "application_name", "agent:old-agent:mission:m:token:"+testKeyRevoked), ks)
	if !strings.Contains(d.Err, "revoked") {
		t.Fatalf("revoked token: %+v", d)
	}
	d = startupAgentAuth(startup("user", "app", "application_name", "agent:x:mission:m:token:fw_ak_unknown"), ks)
	if !strings.Contains(d.Err, "unknown agent key") {
		t.Fatalf("unknown token: %+v", d)
	}

	// Managed agent claimed by name without a key: refused (spoofing gap).
	d = startupAgentAuth(startup("user", "app", "application_name", "agent:support-agent:mission:m"), ks)
	if !strings.Contains(d.Err, "needs its key") {
		t.Fatalf("spoof: %+v", d)
	}
	// Legacy (non fw_ak_) token stays on the legacy auth_token path.
	d = startupAgentAuth(startup("user", "app", "application_name", "agent:legacy:mission:m:token:abc"), ks)
	if d.Err != "" || d.Mode != authPassthrough {
		t.Fatalf("legacy token: %+v", d)
	}
}

const testAgentsYAML = `agents:
  support-agent:
    description: "managed"
    profile: standard
    profile_overrides:
      block: [CREATE, ALTER, DROP, TRUNCATE]
approvals:
  rules:
    - name: support-agent-writes-ask-first
      action: hold
      agents: [support-agent]
      operations: [INSERT, UPDATE, DELETE, MERGE]
`

func TestManagedOverlayAndFlagRules(t *testing.T) {
	pe := &PolicyEngine{
		enforcement:  "enforce",
		pausedAgents: map[string]bool{},
		config: &PolicyConfig{DefaultPolicy: "deny", Agents: map[string]AgentPolicy{
			"local": {Profile: "permissive"},
		}},
	}
	// This test covers the flag path, so simulate a proxy without hold support.
	defer func(old bool) { proxyHoldCapable = old }(proxyHoldCapable)
	proxyHoldCapable = false
	m, err := parseManagedPolicy("v1", testAgentsYAML, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.FlagRules) != 1 || len(m.HoldRules) != 0 {
		t.Fatalf("hold must degrade to flag without hold support: %+v", m)
	}
	pe.SetManaged(m)
	cfg := pe.GetConfig()
	if _, ok := cfg.Agents["support-agent"]; !ok || cfg.Agents["local"].Profile != "permissive" {
		t.Fatalf("overlay: %+v", cfg.Agents)
	}
	id := &AgentIdentity{AgentID: "support-agent", MissionID: "default"}

	// Read: allowed.
	if v, _ := safeCheckQuery(pe, id, "SELECT id FROM orders WHERE id = 1"); v != nil {
		t.Fatalf("read flagged: %+v", v)
	}
	// Write: flag-only (never blocks).
	v, _ := safeCheckQuery(pe, id, "UPDATE orders SET status = 'x' WHERE id = 1")
	if v == nil || !v.FlagOnly || !strings.HasPrefix(v.Reason, "needs_approval:") {
		t.Fatalf("write: %+v", v)
	}
	// DDL: hard block.
	v, _ = safeCheckQuery(pe, id, "DROP TABLE orders")
	if v == nil || v.FlagOnly || v.Reason != "blocked_operation" {
		t.Fatalf("ddl: %+v", v)
	}

	// Removing the agent from the managed set removes it from the policy.
	pe.SetManaged(&ManagedPolicy{Agents: map[string]AgentPolicy{}})
	if _, ok := pe.GetConfig().Agents["support-agent"]; ok {
		t.Fatal("stale managed agent not removed")
	}
	if v, _ := safeCheckQuery(pe, id, "UPDATE orders SET status = 'x' WHERE id = 1"); v == nil || v.Reason != "agent_not_in_policy" {
		t.Fatalf("after removal: %+v", v)
	}
}

func TestManagedShadowsAndRestoresLocalAgent(t *testing.T) {
	pe := &PolicyEngine{pausedAgents: map[string]bool{}, config: &PolicyConfig{Agents: map[string]AgentPolicy{
		"support-agent": {Description: "local"},
	}}}
	m, _ := parseManagedPolicy("v1", testAgentsYAML, nil)
	pe.SetManaged(m)
	if pe.GetConfig().Agents["support-agent"].Description != "managed" {
		t.Fatal("managed should win")
	}
	pe.SetManaged(nil)
	if pe.GetConfig().Agents["support-agent"].Description != "local" {
		t.Fatal("local definition not restored")
	}
}

func TestSaveToFileExcludesManagedAgents(t *testing.T) {
	path := t.TempDir() + "/policies.yaml"
	pe := &PolicyEngine{filePath: path, pausedAgents: map[string]bool{}, config: &PolicyConfig{Agents: map[string]AgentPolicy{"local": {}}}}
	m, _ := parseManagedPolicy("v1", testAgentsYAML, nil)
	pe.SetManaged(m)
	if err := pe.SaveToFile(); err != nil {
		t.Fatal(err)
	}
	if err := pe.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}
	// Reload re-applies the overlay, but the file itself has no managed agent.
	if _, ok := pe.GetConfig().Agents["support-agent"]; !ok {
		t.Fatal("overlay not re-applied after reload")
	}
	pe.SetManaged(nil)
	if _, ok := pe.GetConfig().Agents["support-agent"]; ok {
		t.Fatal("managed agent was persisted to the local policy file")
	}
}

func TestPolicySyncerPicksUpChanges(t *testing.T) {
	var calls int32
	var body atomic.Value
	body.Store(policySyncResponse{AgentsVersion: "a", AgentsYAML: "agents: {}\n", SyncIntervalSeconds: 1})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.Header.Get("Authorization") != "Bearer tok" || !strings.Contains(r.Header.Get("X-FaultWall-Capabilities"), "agent-keys") {
			http.Error(w, "unauthorized", 401)
			return
		}
		_ = json.NewEncoder(w).Encode(body.Load())
	}))
	defer srv.Close()

	t.Setenv("FW_AGENT_CACHE", t.TempDir()+"/cache.json")
	pe := &PolicyEngine{pausedAgents: map[string]bool{}, config: &PolicyConfig{Agents: map[string]AgentPolicy{}}}
	ks := NewAgentKeyStore()
	ps := NewPolicySyncer(srv.URL, "tok", pe, ks)
	next, err := ps.SyncOnce()
	if err != nil || next != time.Second || ks.Len() != 0 {
		t.Fatalf("first sync: next=%v err=%v", next, err)
	}

	body.Store(policySyncResponse{AgentsVersion: "b", AgentsYAML: testAgentsYAML, SyncIntervalSeconds: 1,
		AgentKeys: []AgentKeyEntry{{Agent: "support-agent", KeySHA256: HashAgentKey(testKeyLive)}}})
	if _, err := ps.SyncOnce(); err != nil {
		t.Fatal(err)
	}
	if e, ok := ks.Lookup(testKeyLive); !ok || e.Agent != "support-agent" {
		t.Fatal("new key not picked up")
	}
	if _, ok := pe.GetConfig().Agents["support-agent"]; !ok {
		t.Fatal("new agent not merged")
	}

	// Cache: a fresh syncer against a dead control plane still knows the key.
	ks2 := NewAgentKeyStore()
	ps2 := NewPolicySyncer("http://127.0.0.1:1", "tok", nil, ks2)
	if _, err := ps2.SyncOnce(); err == nil {
		t.Fatal("expected network error")
	}
	if !ps2.LoadCache() || ks2.Len() != 1 {
		t.Fatal("cache fallback failed")
	}
}

// TestKeyPasswordAuthWire drives handleProxyConn end to end over the wire:
// the client sends the agent key as its password, the proxy verifies it and
// logs in to a fake upstream with its own credentials (cleartext), and the
// upstream sees the agent label in application_name.
func TestKeyPasswordAuthWire(t *testing.T) {
	old := agentKeys
	agentKeys = testKeyStore()
	defer func() { agentKeys = old }()
	t.Setenv("FW_ALLOW_CLEARTEXT_KEY", "1") // legacy keys without a SCRAM verifier
	t.Setenv("FW_UPSTREAM_USER", "fwproxy")
	t.Setenv("FW_UPSTREAM_PASSWORD", "upstream-secret")

	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	gotStartup := make(chan []startupParam, 1)
	gotPassword := make(chan string, 1)
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf, err := readStartupMessage(c)
		if err != nil {
			return
		}
		_, ps := parseStartupParams(buf)
		gotStartup <- ps
		req := make([]byte, 4)
		binary.BigEndian.PutUint32(req, 3)
		_ = writeWireMessage(c, 'R', req)
		_, pw, _ := readWireMessage(c)
		gotPassword <- strings.TrimRight(string(pw), "\x00")
		_ = writeWireMessage(c, 'R', make([]byte, 4)) // AuthenticationOk
		k := make([]byte, 8)
		binary.BigEndian.PutUint32(k, 4242)
		_ = writeWireMessage(c, 'K', k)
		_ = writeWireMessage(c, 'Z', []byte{'I'})
		time.Sleep(200 * time.Millisecond)
	}()

	pe := &PolicyEngine{enforcement: "monitor", pausedAgents: map[string]bool{}, config: &PolicyConfig{Agents: map[string]AgentPolicy{}}}

	dial := func(user, password string) (byte, string) {
		a, b := net.Pipe()
		go handleProxyConn(b, up.Addr().String(), pe, nil, nil)
		defer a.Close()
		_ = a.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := a.Write(startup("user", user, "database", "prod")); err != nil {
			t.Fatal(err)
		}
		typ, payload, err := readWireMessage(a)
		if err != nil {
			t.Fatal(err)
		}
		if typ != 'R' || binary.BigEndian.Uint32(payload[:4]) != 3 {
			return typ, string(payload)
		}
		_ = writeWireMessage(a, 'p', append([]byte(password), 0))
		for {
			typ, payload, err = readWireMessage(a)
			if err != nil {
				t.Fatal(err)
			}
			if typ == 'E' || typ == 'Z' {
				return typ, string(payload)
			}
		}
	}

	// Revoked / unknown keys never reach upstream.
	if typ, msg := dial("support-agent", "fw_ak_wrong"); typ != 'E' || !strings.Contains(msg, "unknown agent key") {
		t.Fatalf("wrong key: %c %q", typ, msg)
	}
	if typ, msg := dial("old-agent", testKeyRevoked); typ != 'E' || !strings.Contains(msg, "revoked") {
		t.Fatalf("revoked key: %c %q", typ, msg)
	}
	// Valid key: proxy logs in upstream as itself, labeled as the agent.
	if typ, msg := dial("support-agent", testKeyLive); typ != 'Z' {
		t.Fatalf("valid key: %c %q", typ, msg)
	}
	ps := <-gotStartup
	if startupGet(ps, "user") != "fwproxy" || startupGet(ps, "application_name") != "agent:support-agent:mission:default" || startupGet(ps, "database") != "prod" {
		t.Fatalf("upstream startup = %v", ps)
	}
	if pw := <-gotPassword; pw != "upstream-secret" {
		t.Fatalf("upstream password = %q (agent key must never be forwarded)", pw)
	}
}

// Wave 2 pulled forward (Soumya, 2026-10-04): control-plane "ask first" pauses
// the statement until a person approves. Held statements still leave the
// proxy only as a literal-free shape (hold_cp.go).
func TestAskFirstPausesByDefault(t *testing.T) {
	if !proxyHoldCapable {
		t.Fatal("control-plane ask-first must pause (hold), not just flag")
	}
}

// When hold support is switched on (wave 2), a managed "ask first" rule
// reaches the hold gate via holdRules() and is not degraded to flag.
func TestManagedHoldRulesReachGate(t *testing.T) {
	defer func(old bool) { proxyHoldCapable = old }(proxyHoldCapable)
	proxyHoldCapable = true
	pe := &PolicyEngine{enforcement: "enforce", pausedAgents: map[string]bool{}, config: &PolicyConfig{Agents: map[string]AgentPolicy{}}}
	m, err := parseManagedPolicy("v1", testAgentsYAML, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.HoldRules) != 1 || len(m.FlagRules) != 0 {
		t.Fatalf("hold rule should stay hold: %+v", m)
	}
	pe.SetManaged(m)
	rules, _ := holdRules(pe)
	hm := matchHoldRules(rules, "support-agent", "UPDATE orders SET status = 'x' WHERE id = 1", ParseQuery("UPDATE orders SET status = 'x' WHERE id = 1"))
	if hm == nil {
		t.Fatalf("managed ask-first write not held; rules=%+v", rules)
	}
	if hm := matchHoldRules(rules, "support-agent", "SELECT 1", ParseQuery("SELECT 1")); hm != nil {
		t.Fatal("read must not be held")
	}
}
