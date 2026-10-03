package main

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq/scram"
)

// makeVerifier derives a verifier the same way the control plane does.
func makeVerifier(t *testing.T, key string) *ScramVerifier {
	t.Helper()
	salt := make([]byte, 16)
	rand.Read(salt)
	salted, err := pbkdf2.Key(sha256.New, key, salt, 4096, 32)
	if err != nil {
		t.Fatal(err)
	}
	mac := func(k []byte, m string) []byte { h := hmac.New(sha256.New, k); h.Write([]byte(m)); return h.Sum(nil) }
	ck := mac(salted, "Client Key")
	sk := sha256.Sum256(ck)
	enc := base64.StdEncoding.EncodeToString
	return &ScramVerifier{Salt: enc(salt), Iterations: 4096, StoredKey: enc(sk[:]), ServerKey: enc(mac(salted, "Server Key"))}
}

// scramClientLogin runs a real SCRAM client (lib/pq) against the proxy side.
// Returns the final message type and payload.
func scramClientLogin(t *testing.T, c net.Conn, user, key string) (byte, string, bool) {
	t.Helper()
	typ, payload, err := readWireMessage(c)
	if err != nil {
		t.Fatal(err)
	}
	if typ != 'R' || binary.BigEndian.Uint32(payload[:4]) != authSASL {
		return typ, string(payload), false
	}
	if !strings.Contains(string(payload[4:]), "SCRAM-SHA-256\x00") || strings.Contains(string(payload[4:]), "PLUS") {
		t.Fatalf("mechanisms = %q", payload[4:])
	}
	sc := scram.NewClient(sha256.New, user, key)
	sc.Step(nil)
	first := sc.Out()
	msg := append([]byte("SCRAM-SHA-256"), 0)
	l := make([]byte, 4)
	binary.BigEndian.PutUint32(l, uint32(len(first)))
	writeWireMessage(c, 'p', append(append(msg, l...), first...))
	verifiedServer := false
	for {
		typ, payload, err = readWireMessage(c)
		if err != nil {
			t.Fatal(err)
		}
		if typ == 'R' {
			switch binary.BigEndian.Uint32(payload[:4]) {
			case authSASLContinue:
				sc.Step(payload[4:])
				if sc.Err() != nil {
					t.Fatal(sc.Err())
				}
				writeWireMessage(c, 'p', sc.Out())
			case authSASLFinal:
				sc.Step(payload[4:])
				if sc.Err() != nil {
					t.Fatalf("client rejected server signature: %v", sc.Err())
				}
				verifiedServer = true
			}
			continue
		}
		if typ == 'E' || typ == 'Z' {
			return typ, string(payload), verifiedServer
		}
	}
}

func TestScramServerAuthDirect(t *testing.T) {
	key := "fw_ak_scram_direct_0000000000000000000000000000000000"
	v := makeVerifier(t, key)
	for _, tc := range []struct {
		key  string
		want error
	}{{key, nil}, {"fw_ak_wrong", errScramBadProof}} {
		a, b := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- scramServerAuth(b, b, v) }()
		go func() {
			defer a.Close()
			_ = a.SetDeadline(time.Now().Add(5 * time.Second))
			typ, payload, _ := readWireMessage(a)
			if typ != 'R' {
				return
			}
			_ = payload
			sc := scram.NewClient(sha256.New, "", tc.key)
			sc.Step(nil)
			first := sc.Out()
			msg := append([]byte("SCRAM-SHA-256"), 0)
			l := make([]byte, 4)
			binary.BigEndian.PutUint32(l, uint32(len(first)))
			writeWireMessage(a, 'p', append(append(msg, l...), first...))
			_, payload, _ = readWireMessage(a)
			sc.Step(payload[4:])
			writeWireMessage(a, 'p', sc.Out())
			readWireMessage(a)
		}()
		err := <-done
		if err != tc.want {
			t.Fatalf("key %q: err=%v want %v", tc.key, err, tc.want)
		}
		b.Close()
	}
}

// TestKeyPasswordScramWire: end to end through handleProxyConn. A SCRAM
// client logs in with its key, the proxy verifies it against the synced
// verifier (never seeing the key) and logs in upstream as itself. Wrong and
// revoked keys never open an upstream connection; a legacy key without a
// verifier is refused unless FW_ALLOW_CLEARTEXT_KEY is set.
func TestKeyPasswordScramWire(t *testing.T) {
	const key = "fw_ak_scramwire00000000000000000000000000000000000000"
	const legacy = "fw_ak_legacy0000000000000000000000000000000000000000"
	ks := NewAgentKeyStore()
	ks.Replace([]AgentKeyEntry{
		{Agent: "support-agent", KeySHA256: HashAgentKey(key), Scram: makeVerifier(t, key)},
		{Agent: "old-agent", KeySHA256: HashAgentKey("fw_ak_revoked_x"), Revoked: true, Scram: makeVerifier(t, "fw_ak_revoked_x")},
		{Agent: "legacy-agent", KeySHA256: HashAgentKey(legacy)},
	})
	old := agentKeys
	agentKeys = ks
	defer func() { agentKeys = old }()
	os.Unsetenv("FW_ALLOW_CLEARTEXT_KEY")
	t.Setenv("FW_UPSTREAM_USER", "fwproxy")
	t.Setenv("FW_UPSTREAM_PASSWORD", "upstream-secret")

	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	upstreamConns := make(chan []startupParam, 4)
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf, err := readStartupMessage(c)
				if err != nil {
					return
				}
				_, ps := parseStartupParams(buf)
				upstreamConns <- ps
				req := make([]byte, 4)
				binary.BigEndian.PutUint32(req, 3)
				_ = writeWireMessage(c, 'R', req)
				readWireMessage(c)
				_ = writeWireMessage(c, 'R', make([]byte, 4))
				_ = writeWireMessage(c, 'Z', []byte{'I'})
				time.Sleep(200 * time.Millisecond)
			}(c)
		}
	}()
	pe := &PolicyEngine{enforcement: "monitor", pausedAgents: map[string]bool{}, config: &PolicyConfig{Agents: map[string]AgentPolicy{}}}
	dial := func(user, k string) (byte, string, bool) {
		a, b := net.Pipe()
		go handleProxyConn(b, up.Addr().String(), pe, nil, nil)
		defer a.Close()
		_ = a.SetDeadline(time.Now().Add(10 * time.Second))
		a.Write(startup("user", user, "database", "prod"))
		return scramClientLogin(t, a, user, k)
	}

	if typ, msg, _ := dial("support-agent", "fw_ak_wrong"); typ != 'E' || !strings.Contains(msg, "28P01") || !strings.Contains(msg, "wrong key") {
		t.Fatalf("wrong key: %c %q", typ, msg)
	}
	if typ, msg, _ := dial("old-agent", "fw_ak_revoked_x"); typ != 'E' || !strings.Contains(msg, "revoked") {
		t.Fatalf("revoked: %c %q", typ, msg)
	}
	if typ, msg, _ := dial("legacy-agent", legacy); typ != 'E' || !strings.Contains(msg, "before SCRAM support") {
		t.Fatalf("legacy without opt-in: %c %q", typ, msg)
	}
	select {
	case ps := <-upstreamConns:
		t.Fatalf("refused logins must not open upstream, got %v", ps)
	default:
	}
	typ, msg, serverOK := dial("support-agent", key)
	if typ != 'Z' || !serverOK {
		t.Fatalf("valid key: %c %q serverVerified=%v", typ, msg, serverOK)
	}
	ps := <-upstreamConns
	if startupGet(ps, "user") != "fwproxy" || startupGet(ps, "application_name") != "agent:support-agent:mission:default" {
		t.Fatalf("upstream startup = %v", ps)
	}
}
