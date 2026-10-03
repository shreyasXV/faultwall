package main

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
)

func TestParseHoldSpec(t *testing.T) {
	rules, err := parseHoldSpec("UPDATE,DELETE:orders; WRITE@support-agent,ops ; *:payments")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("want 3 rules, got %d", len(rules))
	}
	if got := strings.Join(rules[0].Operations, ","); got != "UPDATE,DELETE" || rules[0].Tables[0] != "orders" {
		t.Fatalf("rule0 = %+v", rules[0])
	}
	if rules[1].Operations[0] != "WRITE" || len(rules[1].Agents) != 2 || len(rules[1].Tables) != 0 {
		t.Fatalf("rule1 = %+v", rules[1])
	}
	if rules[2].Operations != nil || rules[2].Tables[0] != "payments" {
		t.Fatalf("rule2 = %+v", rules[2])
	}
	if _, err := parseHoldSpec(":"); err == nil {
		t.Fatal("empty rule should fail")
	}
}

func TestMatchHoldRules(t *testing.T) {
	rules := []HoldRule{
		{Name: "orders-writes", Action: "hold", Operations: []string{"UPDATE", "DELETE"}, Tables: []string{"orders"}},
		{Name: "support-any-write", Action: "hold", Agents: []string{"support-agent"}, Operations: []string{"WRITE"}},
	}
	cases := []struct {
		agent, q string
		want     string // rule name or ""
	}{
		{"a", "UPDATE orders SET status='x' WHERE id=1", "orders-writes"},
		{"a", "update public.orders set status='x'", "orders-writes"},
		{"a", "DELETE FROM orders WHERE id=$1", "orders-writes"},
		{"a", "SELECT * FROM orders", ""},
		{"a", "UPDATE customers SET name='x' FROM orders WHERE orders.id=customers.id", ""}, // writes customers, reads orders
		{"a", "WITH x AS (UPDATE orders SET a=1 RETURNING id) SELECT * FROM x", "orders-writes"},
		{"a", "EXPLAIN ANALYZE DELETE FROM orders", "orders-writes"},
		{"a", "BEGIN; UPDATE orders SET a=1; COMMIT", "orders-writes"},
		{"a", "INSERT INTO orders VALUES (1)", ""},
		{"support-agent", "INSERT INTO customers VALUES (1)", "support-any-write"},
		{"support-agent", "TRUNCATE customers", "support-any-write"},
		{"support-agent", "SELECT 1", ""},
		{"other", "INSERT INTO customers VALUES (1)", ""},
		{"a", "   ", ""},
	}
	for _, c := range cases {
		hm := matchHoldRules(rules, c.agent, c.q, ParseQuery(c.q))
		got := ""
		if hm != nil {
			got = hm.Rule
		}
		if got != c.want {
			t.Errorf("agent=%s %q: got rule %q, want %q", c.agent, c.q, got, c.want)
		}
	}
	hm := matchHoldRules(rules, "a", "UPDATE orders SET a=1", nil)
	if hm == nil || hm.Operation != "UPDATE" || len(hm.Tables) != 1 || hm.Tables[0] != "orders" {
		t.Fatalf("match detail = %+v", hm)
	}
}

func TestHoldsEnforcedAndTimeout(t *testing.T) {
	pe := &PolicyEngine{enforcement: "monitor", config: &PolicyConfig{Approvals: ApprovalsConfig{Timeout: "45s"}}}
	if holdsEnforced(pe, "") {
		t.Fatal("monitor mode must not pause unless mode=always")
	}
	if !holdsEnforced(pe, "always") {
		t.Fatal("mode=always pauses in monitor mode")
	}
	pe.enforcement = "enforce"
	if !holdsEnforced(pe, "") {
		t.Fatal("enforce mode pauses")
	}
	t.Setenv("FW_HOLD_TIMEOUT", "")
	if d := holdTimeout(pe); d != 45*time.Second {
		t.Fatalf("policy timeout: %s", d)
	}
	t.Setenv("FW_HOLD_TIMEOUT", "7")
	if d := holdTimeout(pe); d != 7*time.Second {
		t.Fatalf("env timeout: %s", d)
	}
	t.Setenv("FW_HOLD_TIMEOUT", "")
	if d := holdTimeout(&PolicyEngine{config: &PolicyConfig{}}); d != 120*time.Second {
		t.Fatalf("default timeout: %s", d)
	}
}

func TestHoldRegistryResolveAndCancel(t *testing.T) {
	h := &Hold{ID: "h_test1", connKey: "deadbeef"}
	holdReg.add(h)
	defer holdReg.remove(h)
	if holdReg.resolve("nope", holdDecision{}) {
		t.Fatal("unknown id resolved")
	}
	if !holdReg.cancelByKey("deadbeef") {
		t.Fatal("cancel by key failed")
	}
	if holdReg.resolve("h_test1", holdDecision{Approve: true}) {
		t.Fatal("second decision must be rejected (already decided)")
	}
	d := <-h.decision
	if d.Approve || d.Kind != "cancelled" {
		t.Fatalf("decision = %+v", d)
	}
	if e := denyError(&Hold{Operation: "UPDATE", Tables: []string{"orders"}}, d, time.Second); e.Code != "57014" {
		t.Fatalf("cancel code = %s", e.Code)
	}
}

func TestHoldLocalAPI(t *testing.T) {
	h := &Hold{ID: "h_api1", Agent: "a", Query: "UPDATE orders SET a=1"}
	holdReg.add(h)
	defer holdReg.remove(h)
	rec := httptest.NewRecorder()
	handleHolds(rec, httptest.NewRequest("GET", "/api/holds", nil))
	if !strings.Contains(rec.Body.String(), "h_api1") {
		t.Fatalf("list: %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	handleHoldAction(rec, httptest.NewRequest("POST", "/api/holds/h_api1/deny", strings.NewReader(`{"by":"dana","reason":"too broad"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body.String())
	}
	d := <-h.decision
	if d.Approve || d.By != "dana" || d.Reason != "too broad" {
		t.Fatalf("decision = %+v", d)
	}
	rec = httptest.NewRecorder()
	handleHoldAction(rec, httptest.NewRequest("POST", "/api/holds/h_missing/approve", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing hold: %d", rec.Code)
	}
}

func TestRewriteUpstreamSwapsMarkerError(t *testing.T) {
	g := &holdGate{}
	g.rewrites.Store("fwhold_h_abc123", holdErr{Code: "42501", Msg: "[BLOCKED by FaultWall] denied"})
	g.nRewrites = 1
	pgErr := &pgproto3.ErrorResponse{Severity: "ERROR", Code: "34000", Message: `portal "fwhold_h_abc123" does not exist`}
	b, _ := pgErr.Encode(nil)
	out := g.rewriteUpstream('E', b[5:])
	var er pgproto3.ErrorResponse
	if err := er.Decode(out); err != nil {
		t.Fatal(err)
	}
	if er.Code != "42501" || !strings.Contains(er.Message, "BLOCKED by FaultWall") {
		t.Fatalf("rewritten = %+v", er)
	}
	other := &pgproto3.ErrorResponse{Severity: "ERROR", Code: "23505", Message: "dup"}
	b2, _ := other.Encode(nil)
	if got := g.rewriteUpstream('E', b2[5:]); string(got) != string(b2[5:]) {
		t.Fatal("unrelated errors must pass through untouched")
	}
}

// ── gate tests over net.Pipe ──

func wire(t byte, payload []byte) []byte {
	b := make([]byte, 5+len(payload))
	b[0] = t
	binary.BigEndian.PutUint32(b[1:5], uint32(len(payload)+4))
	copy(b[5:], payload)
	return b
}

func parseMsg(name, q string) []byte { return wire('P', append(append([]byte(name+"\x00"), q...), 0, 0, 0)) }
func bindMsg(portal, stmt string) []byte {
	return wire('B', append([]byte(portal+"\x00"+stmt+"\x00"), 0, 0, 0, 0, 0, 0))
}
func execMsg(portal string) []byte { return wire('E', append([]byte(portal+"\x00"), 0, 0, 0, 0)) }

// gateHarness runs gate.next() in a loop and forwards to an "upstream" slice.
func gateHarness(t *testing.T, pe *PolicyEngine, identity *AgentIdentity) (clientSide net.Conn, out chan wireMsg, g *holdGate) {
	t.Helper()
	cl, srv := net.Pipe()
	stmts := newStmtTracker()
	g = newHoldGate(pe, identity, "agent", srv, nil, stmts)
	out = make(chan wireMsg, 64)
	go func() {
		for {
			mt, p, err := g.next()
			if err != nil {
				out <- wireMsg{err: err}
				return
			}
			out <- wireMsg{t: mt, p: p}
		}
	}()
	t.Cleanup(func() { cl.Close(); srv.Close(); g.close() })
	return cl, out, g
}

func waitHold(t *testing.T) *Hold {
	t.Helper()
	for i := 0; i < 100; i++ {
		if hs := holdReg.list(); len(hs) > 0 {
			return hs[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no hold appeared")
	return nil
}

func holdPE() *PolicyEngine {
	return &PolicyEngine{enforcement: "enforce", pausedAgents: map[string]bool{}, config: &PolicyConfig{
		DefaultPolicy: "allow", Agents: map[string]AgentPolicy{}, Unidentified: UnidentifiedPolicy{Policy: "allow"},
		Approvals: ApprovalsConfig{Timeout: "5s", Rules: []HoldRule{{Action: "hold", Operations: []string{"UPDATE"}, Tables: []string{"orders"}}}},
	}}
}

func TestGateBuffersGroupUntilDecisionAndDenyRewritesExecute(t *testing.T) {
	cl, out, _ := gateHarness(t, holdPE(), &AgentIdentity{AgentID: "a"})
	go cl.Write(append(append(append(parseMsg("", "UPDATE orders SET a=1"), bindMsg("", "")...), execMsg("")...), wire('S', nil)...))
	h := waitHold(t)
	select {
	case m := <-out:
		t.Fatalf("message %q released before the decision", m.t)
	case <-time.After(100 * time.Millisecond):
	}
	if !holdReg.resolve(h.ID, holdDecision{Kind: "denied", By: "t"}) {
		t.Fatal("resolve failed")
	}
	var types []byte
	var execPayload []byte
	for i := 0; i < 4; i++ {
		m := <-out
		types = append(types, m.t)
		if m.t == 'E' {
			execPayload = m.p
		}
	}
	if string(types) != "PBES" {
		t.Fatalf("released %q, want PBES", types)
	}
	if !strings.HasPrefix(string(execPayload), "fwhold_"+h.ID) {
		t.Fatalf("denied Execute must target the marker portal, got %q", execPayload)
	}
}

func TestGateApproveReleasesUnchangedAndCachedStmtIsHeld(t *testing.T) {
	cl, out, g := gateHarness(t, holdPE(), &AgentIdentity{AgentID: "a"})
	// Named statement parsed earlier (e.g. by a driver statement cache).
	g.stmts.parse("s1", "UPDATE orders SET a=$1", nil, nil)
	go cl.Write(append(append(bindMsg("", "s1"), execMsg("")...), wire('S', nil)...))
	h := waitHold(t)
	holdReg.resolve(h.ID, holdDecision{Approve: true, Kind: "approved"})
	for _, want := range []byte("BES") {
		m := <-out
		if m.t != want {
			t.Fatalf("got %q want %q", m.t, want)
		}
		if m.t == 'E' && string(m.p) != string(execMsg("")[5:]) {
			t.Fatalf("approved Execute was modified: %q", m.p)
		}
	}
}

func TestGateClientTerminateWhileHeldDropsStatement(t *testing.T) {
	cl, out, _ := gateHarness(t, holdPE(), &AgentIdentity{AgentID: "a"})
	go cl.Write(wire('Q', append([]byte("UPDATE orders SET a=1"), 0)))
	waitHold(t)
	go cl.Write(wire('X', nil))
	select {
	case m := <-out:
		if m.err != io.EOF {
			t.Fatalf("want EOF (statement dropped), got %q %v", m.t, m.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client Terminate not noticed while held")
	}
	if len(holdReg.list()) != 0 {
		t.Fatal("hold left behind")
	}
}

func TestGatePassesThroughWhenNoRules(t *testing.T) {
	pe := holdPE()
	pe.config.Approvals.Rules = nil
	cl, out, _ := gateHarness(t, pe, nil)
	go cl.Write(wire('Q', append([]byte("UPDATE orders SET a=1"), 0)))
	select {
	case m := <-out:
		if m.t != 'Q' {
			t.Fatalf("got %q", m.t)
		}
	case <-time.After(time.Second):
		t.Fatal("query was held without rules")
	}
}

func TestGateMonitorModeOnlyLogs(t *testing.T) {
	pe := holdPE()
	pe.enforcement = "monitor"
	cl, out, _ := gateHarness(t, pe, nil)
	go cl.Write(wire('Q', append([]byte("UPDATE orders SET a=1"), 0)))
	select {
	case m := <-out:
		if m.t != 'Q' {
			t.Fatalf("got %q", m.t)
		}
	case <-time.After(time.Second):
		t.Fatal("monitor mode must not pause (would-hold only)")
	}
}
