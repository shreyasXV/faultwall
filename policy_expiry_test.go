package main

import (
	"testing"
	"time"
)

func TestRevC_ExpiryClassifier(t *testing.T) {
	cases := map[string]int{
		"": expAllow, "BEGIN": expAllow, "begin isolation level serializable": expAllow, "ROLLBACK": expAllow,
		"SAVEPOINT a": expAllow, "ROLLBACK TO SAVEPOINT a": expAllow, "RELEASE a": expAllow, "ROLLBACK PREPARED 'x'": expAllow,
		"COMMIT": expCommit, "END": expCommit, "commit and chain": expCommit,
		"PREPARE TRANSACTION 'x'": expDeny, "COMMIT PREPARED 'x'": expDeny,
		"SELECT 1": expDeny, "SELECT count(*) FROM orders": expDeny, "SHOW search_path": expDeny,
		"UPDATE orders SET a=1": expDeny, "BEGIN; UPDATE orders SET a=1; COMMIT": expDeny,
		"SET search_path = public": expDeny, "not sql at all ((": expDeny,
	}
	for q, want := range cases {
		if got := classifyAfterExpiry(q); got != want {
			t.Errorf("%q: got %d want %d", q, got, want)
		}
	}
}

// COMMIT after expiry: harmless only with no transaction, an aborted one, or
// an open transaction in which nothing ran; never while earlier work is in flight.
func TestRevC_C5_CommitHarmlessRule(t *testing.T) {
	g := &holdGate{}
	g.txn.onReady('I')
	if !g.commitIsHarmless() {
		t.Fatal("idle COMMIT is a no-op")
	}
	g.noteForwarded('Q', []byte("BEGIN\x00"))
	g.onReadyWork('T')
	g.txn.onReady('T')
	if !g.commitIsHarmless() {
		t.Fatal("BEGIN only: nothing to make durable")
	}
	g.noteForwarded('Q', []byte("UPDATE orders SET a=1\x00"))
	if g.commitIsHarmless() {
		t.Fatal("UPDATE in flight: not harmless")
	}
	g.onReadyWork('T')
	if g.commitIsHarmless() {
		t.Fatal("txn ran a write: COMMIT must be denied")
	}
	g.txn.onReady('E')
	if !g.commitIsHarmless() {
		t.Fatal("aborted txn: COMMIT only rolls back")
	}
	g.noteForwarded('Q', []byte("ROLLBACK\x00"))
	g.onReadyWork('I')
	g.txn.onReady('I')
	g.noteForwarded('Q', []byte("BEGIN\x00"))
	g.onReadyWork('T')
	g.txn.onReady('T')
	if !g.commitIsHarmless() {
		t.Fatal("work flag must reset after the transaction ends")
	}
	g.noteForwarded('E', nil)
	g.noteForwarded('S', nil)
	g.onReadyWork('T')
	if g.commitIsHarmless() {
		t.Fatal("extended Execute counts as work")
	}
}

// Watch mode never denies; it only logs would_deny.
func TestRevC_WatchModeNeverDenies(t *testing.T) {
	clk := &fakeClock{wall: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
	cp := newFakeCP(t, clk)
	g := newPolicyGuard(cp.env4(), false, cp.pub, "", clk)
	if err := acceptOnce(t, g, cp, clk); err != nil {
		t.Fatal(err)
	}
	clk.advance(2 * time.Hour)
	if g.Expired() || !g.windowLapsed() {
		t.Fatalf("watch: Expired=%v lapsed=%v", g.Expired(), g.windowLapsed())
	}
	cl, out, gate := gateHarness(t, &PolicyEngine{enforcement: "monitor", config: &PolicyConfig{}}, &AgentIdentity{AgentID: "a"})
	gate.guard = g
	go cl.Write(wire('Q', []byte("UPDATE orders SET a=1\x00")))
	m := <-out
	if m.t != 'Q' || string(m.p) != "UPDATE orders SET a=1\x00" {
		t.Fatalf("watch mode altered the query: %q %q", m.t, m.p)
	}
}

// Local cap can only shorten the signed window.
func TestRevC_LocalMaxOfflineOnlyShortens(t *testing.T) {
	t.Setenv("FW_POLICY_MAX_OFFLINE_SECONDS", "60")
	clk := &fakeClock{wall: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
	cp := newFakeCP(t, clk)
	g := newPolicyGuard(cp.env4(), true, cp.pub, "", clk)
	if err := acceptOnce(t, g, cp, clk); err != nil {
		t.Fatal(err)
	}
	if g.window() != time.Minute {
		t.Fatalf("cap 60s on a 1h signed window: %s", g.window())
	}
	t.Setenv("FW_POLICY_MAX_OFFLINE_SECONDS", "999999")
	g2 := newPolicyGuard(cp.env4(), true, cp.pub, "", clk)
	g2.st.WindowSeconds = 3600
	if g2.window() != time.Hour {
		t.Fatalf("cap must never lengthen: %s", g2.window())
	}
}
