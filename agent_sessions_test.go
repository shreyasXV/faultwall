package main

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func TestKillRevokedEndsOnlyRevokedAgents(t *testing.T) {
	ks := NewAgentKeyStore()
	ks.Replace([]AgentKeyEntry{
		{Agent: "a", KeySHA256: HashAgentKey("fw_ak_a")},
		{Agent: "b", KeySHA256: HashAgentKey("fw_ak_b")},
	})
	r := &agentSessionRegistry{byID: map[uint64]agentSession{}}
	killed := map[string]string{}
	r.Register("a", func(m string) { killed["a"] = m })
	r.Register("b", func(m string) { killed["b"] = m })
	if n := r.KillRevoked(ks); n != 0 {
		t.Fatalf("nothing revoked yet, killed %d", n)
	}
	ks.Replace([]AgentKeyEntry{
		{Agent: "a", KeySHA256: HashAgentKey("fw_ak_a"), Revoked: true},
		{Agent: "b", KeySHA256: HashAgentKey("fw_ak_b")},
	})
	if n := r.KillRevoked(ks); n != 1 || !strings.Contains(killed["a"], "revoked") || killed["b"] != "" {
		t.Fatalf("n=%d killed=%v", n, killed)
	}
	// Agent deleted entirely (no keys at all) also ends its sessions.
	ks.Replace(nil)
	if n := r.KillRevoked(ks); n != 1 || killed["b"] == "" {
		t.Fatalf("deleted agent: n=%d killed=%v", n, killed)
	}
	if r.Count("") != 0 {
		t.Fatal("registry not emptied")
	}
}

// TestRevokeEndsOpenSessionWire: a key-authenticated session through
// handleProxyConn gets a FATAL and is closed when its key is revoked.
func TestRevokeEndsOpenSessionWire(t *testing.T) {
	const key = "fw_ak_revokewire0000000000000000000000000000000000000"
	ks := NewAgentKeyStore()
	ks.Replace([]AgentKeyEntry{{Agent: "support-agent", KeySHA256: HashAgentKey(key), Scram: makeVerifier(t, key)}})
	old := agentKeys
	agentKeys = ks
	defer func() { agentKeys = old }()
	t.Setenv("FW_UPSTREAM_USER", "fwproxy")
	t.Setenv("FW_UPSTREAM_PASSWORD", "x")

	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		c, err := up.Accept()
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
		writeWireMessage(c, 'Z', []byte{'I'})
		for {
			if _, _, err := readWireMessage(c); err != nil {
				return
			}
		}
	}()
	pe := &PolicyEngine{enforcement: "monitor", pausedAgents: map[string]bool{}, config: &PolicyConfig{Agents: map[string]AgentPolicy{}}}
	a, b := net.Pipe()
	go handleProxyConn(b, up.Addr().String(), pe, nil, nil)
	defer a.Close()
	_ = a.SetDeadline(time.Now().Add(10 * time.Second))
	a.Write(startup("user", "support-agent", "database", "prod"))
	if typ, msg, _ := scramClientLogin(t, a, "support-agent", key); typ != 'Z' {
		t.Fatalf("login: %c %q", typ, msg)
	}
	deadline := time.Now().Add(2 * time.Second)
	for agentSessions.Count("support-agent") == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if agentSessions.Count("support-agent") != 1 {
		t.Fatal("session not registered")
	}
	ks.Replace([]AgentKeyEntry{{Agent: "support-agent", KeySHA256: HashAgentKey(key), Revoked: true}})
	if n := agentSessions.KillRevoked(ks); n != 1 {
		t.Fatalf("killed %d", n)
	}
	typ, payload, err := readWireMessage(a)
	if err != nil || typ != 'E' || !strings.Contains(string(payload), "FATAL") || !strings.Contains(string(payload), "revoked") {
		t.Fatalf("expected FATAL revoked, got %c %q %v", typ, payload, err)
	}
	if _, _, err := readWireMessage(a); err == nil {
		t.Fatal("connection should be closed after FATAL")
	}
}
