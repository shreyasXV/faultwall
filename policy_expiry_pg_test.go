package main

// Slice 2 tests (POLICY-WIRE-CONTRACT Rev C.1): protected-operation denial
// after expiry, and C5. These run against a real Postgres, through the real
// proxy connection handler (handleProxyConn), as a key-authenticated agent.
// The upstream is the scram-sha-256-only scratch cluster.
//
//	FW_SCRAM_PG=127.0.0.1:55440 FW_SCRAM_PG_SU=fwsu FW_SCRAM_PG_SUPW_FILE=/tmp/fw-scram-pg.su \
//	  go test -run 'RevC_C5|RevC_Expiry' -v .
//
// Each test checks the client-visible result (error text, SQLSTATE) and checks
// the row state separately, with a direct superuser connection that does not
// go through the proxy.

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"net/http/httptest"

	"github.com/lib/pq"
)

// upstreamRecorder is a TCP relay that logs the statement text of every
// frontend Query and Parse message the proxy sends to Postgres.
type upstreamRecorder struct {
	addr string
	mu   sync.Mutex
	qs   []string
}

func (r *upstreamRecorder) statements() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.qs...)
}

func startUpstreamRecorder(t *testing.T, upstream string) *upstreamRecorder {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	r := &upstreamRecorder{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				u, err := net.Dial("tcp", upstream)
				if err != nil {
					c.Close()
					return
				}
				go func() { _, _ = io.Copy(c, u); c.Close() }()
				// startup message: 4-byte length, no type byte
				var hdr [4]byte
				if _, err := io.ReadFull(c, hdr[:]); err != nil {
					u.Close()
					return
				}
				n := int(binary.BigEndian.Uint32(hdr[:]))
				body := make([]byte, n-4)
				if _, err := io.ReadFull(c, body); err != nil {
					u.Close()
					return
				}
				_, _ = u.Write(append(hdr[:], body...))
				for {
					mt, p, err := readWireMessage(c)
					if err != nil {
						u.Close()
						return
					}
					switch mt {
					case 'Q':
						r.mu.Lock()
						r.qs = append(r.qs, strings.TrimRight(string(p), "\x00"))
						r.mu.Unlock()
					case 'P':
						_, q := extractParseMessage(p)
						r.mu.Lock()
						r.qs = append(r.qs, q)
						r.mu.Unlock()
					}
					if err := writeWireMessage(u, mt, p); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return r
}

type c5Env struct {
	t        *testing.T
	upstream string
	db       string
	su       *sql.DB // direct, superuser, not through the proxy
	proxy    string  // proxy listen addr
	clk      *fakeClock
	guard    *policyGuard
	pe       *PolicyEngine
	agentKey string
	cp       *fakeCP
	rec      *upstreamRecorder
}

const c5AgentKey = "fw_ak_c5test00000000000000000000000000000000000000000"

func scramPG(t *testing.T) (addr, user, pw string) {
	addr = os.Getenv("FW_SCRAM_PG")
	if addr == "" {
		t.Skip("set FW_SCRAM_PG=host:port (scram-sha-256-only Postgres) to run")
	}
	user = os.Getenv("FW_SCRAM_PG_SU")
	b, err := os.ReadFile(os.Getenv("FW_SCRAM_PG_SUPW_FILE"))
	if err != nil {
		t.Fatalf("superuser password file: %v", err)
	}
	return addr, user, strings.TrimSpace(string(b))
}

var c5Once sync.Mutex

func newC5Env(t *testing.T) *c5Env {
	c5Once.Lock()
	t.Cleanup(c5Once.Unlock)
	addr, suUser, suPw := scramPG(t)
	host, port, _ := net.SplitHostPort(addr)
	dsn := func(user, pw, db string) string {
		return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", host, port, user, pw, db)
	}
	admin, err := sql.Open("postgres", dsn(suUser, suPw, "postgres"))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()

	// The upstream must enforce SCRAM, so a trust setup can't pass this test.
	var methods string
	if err := admin.QueryRow(`SELECT string_agg(DISTINCT auth_method, ',') FROM pg_hba_file_rules WHERE type IN ('host','hostssl','hostnossl')`).Scan(&methods); err != nil {
		t.Fatal(err)
	}
	if methods != "scram-sha-256" {
		t.Fatalf("upstream host auth is %q, need scram-sha-256 only", methods)
	}
	bad, _ := sql.Open("postgres", dsn(suUser, suPw+"x", "postgres"))
	if err := bad.Ping(); err == nil || !strings.Contains(err.Error(), "password authentication failed") {
		t.Fatalf("wrong upstream password must fail, got %v", err)
	}
	bad.Close()

	db := fmt.Sprintf("fw_c5_%d", time.Now().UnixNano()%1e9)
	proxyRole := "fw_c5_proxy"
	proxyPw := fmt.Sprintf("c5-%d", time.Now().UnixNano())
	for _, q := range []string{
		"DROP DATABASE IF EXISTS " + db + " WITH (FORCE)", "CREATE DATABASE " + db,
		"DROP ROLE IF EXISTS " + proxyRole,
		"SET password_encryption='scram-sha-256'; CREATE ROLE " + proxyRole + " LOGIN PASSWORD '" + proxyPw + "'",
	} {
		if _, err := admin.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	t.Cleanup(func() {
		a, _ := sql.Open("postgres", dsn(suUser, suPw, "postgres"))
		_, _ = a.Exec("DROP DATABASE IF EXISTS " + db + " WITH (FORCE)")
		_, _ = a.Exec("DROP ROLE IF EXISTS " + proxyRole)
		a.Close()
	})
	su, err := sql.Open("postgres", dsn(suUser, suPw, db))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { su.Close() })
	if _, err := su.Exec(`CREATE TABLE orders (id int PRIMARY KEY, status text);
		INSERT INTO orders VALUES (1043,'processing'),(1044,'processing'),(1045,'processing');
		GRANT SELECT, INSERT, UPDATE, DELETE ON orders TO ` + proxyRole); err != nil {
		t.Fatal(err)
	}
	// The proxy's own login works with the right password and fails with a
	// wrong one (SCRAM on the proxy -> Postgres leg).
	okp, _ := sql.Open("postgres", dsn(proxyRole, proxyPw, db))
	if err := okp.Ping(); err != nil {
		t.Fatalf("proxy role with correct password must log in: %v", err)
	}
	okp.Close()
	badp, _ := sql.Open("postgres", dsn(proxyRole, "wrong-"+proxyPw, db))
	if err := badp.Ping(); err == nil {
		t.Fatal("proxy role with wrong password logged in: upstream is not enforcing SCRAM")
	}
	badp.Close()

	t.Setenv("FW_UPSTREAM_USER", proxyRole)
	t.Setenv("FW_UPSTREAM_PASSWORD", proxyPw)
	t.Setenv("FW_ALLOW_CLEARTEXT_KEY", "1") // test key has no SCRAM verifier; key auth is still required

	oldKeys := agentKeys
	agentKeys = NewAgentKeyStore()
	agentKeys.Replace([]AgentKeyEntry{{Agent: "support-agent", KeySHA256: HashAgentKey(c5AgentKey)}})
	t.Cleanup(func() { agentKeys = oldKeys })

	pe := &PolicyEngine{enforcement: "enforce", pausedAgents: map[string]bool{}, config: &PolicyConfig{
		DefaultPolicy: "allow", Agents: map[string]AgentPolicy{}, Unidentified: UnidentifiedPolicy{Policy: "deny"},
	}}
	oldTracker := agentTracker
	agentTracker = NewAgentTracker()
	t.Cleanup(func() { agentTracker = oldTracker })

	// A signed, fresh policy: accept one doc + freshness from the fake CP.
	clk := &fakeClock{wall: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
	cp := newFakeCP(t, clk)
	g := newPolicyGuard(cp.env4(), true, cp.pub, t.TempDir()+"/state.json", clk)
	if err := acceptOnce(t, g, cp, clk); err != nil {
		t.Fatalf("initial signed sync: %v", err)
	}
	oldG := policyGuardG
	policyGuardG = g
	t.Cleanup(func() { policyGuardG = oldG })

	rec := startUpstreamRecorder(t, addr) // records every statement the proxy sends upstream (C5-d)
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
			go handleProxyConn(c, rec.addr, pe, nil, nil)
		}
	}()
	return &c5Env{t: t, upstream: addr, db: db, su: su, proxy: ln.Addr().String(), clk: clk, guard: g, pe: pe,
		agentKey: c5AgentKey, cp: cp, rec: rec}
}

// acceptOnce drives one signed doc + freshness token into the guard.
func acceptOnce(t *testing.T, g *policyGuard, cp *fakeCP, clk *fakeClock) error {
	srv := httptest.NewServer(cp)
	defer srv.Close()
	ps := NewPolicySyncer(srv.URL, "tok", nil, NewAgentKeyStore())
	ps.installationID = tInst
	ps.guard = g
	ps.cachePath = ""
	_, err := ps.SyncOnce()
	return err
}

// agent opens a connection THROUGH the proxy as the key-authenticated agent.
func (e *c5Env) agent(key string) *sql.DB {
	host, port, _ := net.SplitHostPort(e.proxy)
	db, err := sql.Open("postgres", fmt.Sprintf("host=%s port=%s user=support-agent password=%s dbname=%s sslmode=disable", host, port, key, e.db))
	if err != nil {
		e.t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	e.t.Cleanup(func() { db.Close() })
	return db
}

func (e *c5Env) status(id int) string {
	var s string
	if err := e.su.QueryRow("SELECT status FROM orders WHERE id = $1", id).Scan(&s); err != nil {
		e.t.Fatalf("direct read %d: %v", id, err)
	}
	return s
}

// expire moves the monotonic clock past the window.
func (e *c5Env) expire() { e.clk.advance(2 * time.Hour) }

func pqCode(err error) string {
	if pe, ok := err.(*pq.Error); ok {
		return string(pe.Code)
	}
	return ""
}

func mustDenied(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected FaultWall expiry denial, got success", what)
	}
	if !strings.Contains(err.Error(), "[BLOCKED by FaultWall] policy expired at") || pqCode(err) != "42501" {
		t.Fatalf("%s: expected 42501 policy-expired denial, got %q (code %s)", what, err, pqCode(err))
	}
}

// Credentials: the agent key is required (proxy auth), and the proxy logs
// in upstream with SCRAM (checked in newC5Env).
func TestRevC_Expiry_AuthControls(t *testing.T) {
	e := newC5Env(t)
	var one int
	if err := e.agent(e.agentKey).QueryRow("SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatalf("correct agent key through proxy: %v", err)
	}
	err := e.agent("fw_ak_wrong000000000000000000000000000000000000000000").Ping()
	if err == nil {
		t.Fatal("wrong agent key accepted by the proxy")
	}
	t.Logf("auth ok: upstream hba scram-sha-256 only; proxy role right password ok / wrong password refused; agent key ok; wrong agent key -> %v", err)
}

// No valid signed policy (never accepted) = protected operations denied.
func TestRevC_Expiry_NoValidPolicyDenies(t *testing.T) {
	e := newC5Env(t)
	fresh := newPolicyGuard(policyAnchor{TenantID: tTenant, DatabaseID: tDB, Environment: tEnv}, true, e.guard.pub, "", e.clk)
	policyGuardG = fresh
	db := e.agent(e.agentKey)
	_, err := db.Exec("UPDATE orders SET status = 'refunded' WHERE id = 1043")
	if err == nil || !strings.Contains(err.Error(), "no valid signed policy is in force") {
		t.Fatalf("want no-valid-policy denial, got %v", err)
	}
	var n int
	err2 := db.QueryRow("SELECT count(*) FROM orders").Scan(&n)
	if err2 == nil {
		t.Fatal("read allowed with no valid policy (C4 not landed: reads must be denied)")
	}
	if e.status(1043) != "processing" {
		t.Fatal("row changed")
	}
	t.Logf("no valid policy: write -> %q; read -> %q; row 1043 still processing (direct check)", err, err2)
}

// After expiry: write and read both denied (reads denied until C4).
func TestRevC_Expiry_WriteAndReadDenied(t *testing.T) {
	e := newC5Env(t)
	db := e.agent(e.agentKey)
	var n int
	if err := db.QueryRow("SELECT count(*) FROM orders").Scan(&n); err != nil || n != 3 {
		t.Fatalf("fresh read: %v", err)
	}
	e.expire()
	_, err := db.Exec("UPDATE orders SET status = 'refunded' WHERE id = 1043")
	mustDenied(t, "write after expiry", err)
	err = db.QueryRow("SELECT count(*) FROM orders").Scan(&n)
	mustDenied(t, "read after expiry (C4 not landed)", err)
	// Extended protocol / prepared statement parsed before expiry.
	if e.status(1043) != "processing" {
		t.Fatal("row changed")
	}
	t.Logf("after expiry: UPDATE and SELECT both denied with 42501 (%q); row 1043 still processing", err)
}

// Prepared statement parsed while fresh, executed after expiry: denied.
func TestRevC_Expiry_PreparedBeforeExpiry(t *testing.T) {
	e := newC5Env(t)
	db := e.agent(e.agentKey)
	st, err := db.Prepare("UPDATE orders SET status = $1 WHERE id = $2")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	e.expire()
	_, err = st.Exec("refunded", 1043)
	mustDenied(t, "prepared before, executed after", err)
	if e.status(1043) != "processing" {
		t.Fatal("row changed")
	}
	t.Logf("prepared-before-expiry execute denied: %q", err)
}

// C5-a: BEGIN; UPDATE (fresh); expiry; COMMIT -> COMMIT denied; row unchanged.
func TestRevC_C5a_CommitAfterExpiryDenied(t *testing.T) {
	e := newC5Env(t)
	tx, err := e.agent(e.agentKey).Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("UPDATE orders SET status = 'refunded' WHERE id = 1043"); err != nil {
		t.Fatalf("fresh UPDATE in txn: %v", err)
	}
	e.expire()
	err = tx.Commit()
	mustDenied(t, "COMMIT after expiry", err)
	_ = tx.Rollback()
	if got := e.status(1043); got != "processing" {
		t.Fatalf("row 1043 = %q after denied COMMIT, want processing", got)
	}
	t.Logf("C5-a ok: COMMIT -> %q; row 1043 still processing (direct check)", err)
}

// C5-b: BEGIN; SELECT (fresh); expiry; COMMIT. Contract: a following read
// is allowed only by the C4 session check, which is not built yet, so that read
// is DENIED (UNSUPPORTED-DENIED). The COMMIT of a transaction that ran only
// reads goes through.
func TestRevC_C5b_ReadOnlyTxnAfterExpiry(t *testing.T) {
	e := newC5Env(t)
	tx, err := e.agent(e.agentKey).Begin()
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := tx.QueryRow("SELECT count(*) FROM orders").Scan(&n); err != nil {
		t.Fatal(err)
	}
	e.expire()
	err = tx.QueryRow("SELECT count(*) FROM orders").Scan(&n)
	mustDenied(t, "read in txn after expiry (C4 not landed)", err)
	cerr := tx.Commit()
	t.Logf("C5-b UNSUPPORTED-DENIED (until C4): read after expiry -> %q; then COMMIT of the (now aborted) txn -> %v", err, cerr)
}

// C5-c: autocommit UPDATE forwarded ~1s before expiry, still running at expiry,
// completes and is durable (documented, not undone).
func TestRevC_C5c_ForwardedBeforeExpiryCompletes(t *testing.T) {
	e := newC5Env(t)
	db := e.agent(e.agentKey)
	done := make(chan error, 1)
	go func() {
		_, err := db.Exec("UPDATE orders SET status = 'refunded' WHERE id = 1043 AND pg_sleep(3) IS NOT NULL")
		done <- err
	}()
	time.Sleep(1 * time.Second) // forwarded, running
	e.expire()
	if err := <-done; err != nil {
		t.Fatalf("statement forwarded before expiry must complete: %v", err)
	}
	if got := e.status(1043); got != "refunded" {
		t.Fatalf("row 1043 = %q, want refunded (authorized effect is durable)", got)
	}
	t.Log("C5-c ok: UPDATE forwarded 1s before expiry completed after it; row 1043 = refunded (durable, not undone)")
}

// C5-d: the proxy never sends a COMMIT or ROLLBACK of its own. A recording
// relay between the proxy and Postgres captures every statement sent
// upstream. In the C5-a flow (COMMIT denied) followed by the client's own
// ROLLBACK, Postgres must see no COMMIT at all, and exactly the one ROLLBACK
// the client sent.
func TestRevC_C5d_NoProxyOriginatedTxnControl(t *testing.T) {
	e := newC5Env(t)
	ctx := context.Background()
	conn, err := e.agent(e.agentKey).Conn(ctx) // one session, explicit statements
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, q := range []string{"BEGIN", "UPDATE orders SET status = 'refunded' WHERE id = 1043"} {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	e.expire()
	_, err = conn.ExecContext(ctx, "COMMIT")
	mustDenied(t, "COMMIT after expiry", err)
	if _, err := conn.ExecContext(ctx, "ROLLBACK"); err != nil { // the client's own ROLLBACK
		t.Fatalf("client ROLLBACK after expiry: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	stmts := e.rec.statements()
	var commits, rollbacks int
	for _, q := range stmts {
		u := strings.ToUpper(strings.TrimSpace(q))
		if strings.HasPrefix(u, "COMMIT") || strings.HasPrefix(u, "END") {
			commits++
		}
		if strings.HasPrefix(u, "ROLLBACK") || strings.HasPrefix(u, "ABORT") {
			rollbacks++
		}
	}
	if commits != 0 {
		t.Fatalf("upstream saw %d COMMIT(s): %q", commits, stmts)
	}
	if rollbacks != 1 {
		t.Fatalf("upstream saw %d ROLLBACK(s), want exactly the client's 1: %q", rollbacks, stmts)
	}
	if e.status(1043) != "processing" {
		t.Fatal("row changed")
	}
	t.Logf("C5-d ok: statements Postgres received from the proxy: %q (the client's COMMIT replaced by the failing marker; no COMMIT reached Postgres; the 1 ROLLBACK is the client's)", stmts)
}

// C5-e: COMMIT forwarded before expiry, still running at expiry: commits.
func TestRevC_C5e_CommitForwardedBeforeExpiry(t *testing.T) {
	e := newC5Env(t)
	tx, err := e.agent(e.agentKey).Begin()
	if err != nil {
		t.Fatal(err)
	}
	// A deferred constraint trigger makes COMMIT itself slow, so it is still
	// running when the window expires.
	if _, err := e.su.Exec(`CREATE OR REPLACE FUNCTION slow_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(3); RETURN NULL; END $$;
		CREATE CONSTRAINT TRIGGER slow_commit AFTER UPDATE ON orders DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION slow_commit();`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("UPDATE orders SET status = 'refunded' WHERE id = 1044"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- tx.Commit() }()
	time.Sleep(1 * time.Second) // COMMIT forwarded, trigger sleeping
	e.expire()
	if err := <-done; err != nil {
		t.Fatalf("COMMIT forwarded before expiry must commit: %v", err)
	}
	if got := e.status(1044); got != "refunded" {
		t.Fatalf("row 1044 = %q, want refunded", got)
	}
	t.Log("C5-e ok: COMMIT forwarded 1s before expiry (deferred trigger running) committed; row 1044 = refunded")
}

// C5-f: BEGIN; UPDATE; COMMIT pipelined as one simple-query string but
// buffered by the proxy past expiry -> denied, row unchanged.
// Buffering is forced with an ask-first hold on the UPDATE, approved only
// after expiry: the group is judged when it is released.
func TestRevC_C5f_BufferedPastExpiryDenied(t *testing.T) {
	e := newC5Env(t)
	e.pe.config.Approvals = ApprovalsConfig{Timeout: "30s", Rules: []HoldRule{{Action: "hold", Operations: []string{"UPDATE"}, Tables: []string{"orders"}}}}
	db := e.agent(e.agentKey)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := tx.Exec("UPDATE orders SET status = 'refunded' WHERE id = 1045")
		done <- err
	}()
	h := waitHold(t)
	e.expire() // expires while the UPDATE is buffered in the proxy
	if !holdReg.resolve(h.ID, holdDecision{Approve: true, By: "late-approver", Kind: "approved"}) {
		t.Fatal("resolve")
	}
	err = <-done
	mustDenied(t, "held UPDATE released after expiry", err)
	cerr := tx.Commit()
	if got := e.status(1045); got != "processing" {
		t.Fatalf("row 1045 = %q, want processing", got)
	}
	t.Logf("C5-f ok: UPDATE approved after expiry is judged at release -> %q; COMMIT -> %v; row 1045 still processing", err, cerr)
}

// C5-g: new autocommit UPDATE after expiry: denied.
func TestRevC_C5g_AutocommitAfterExpiryDenied(t *testing.T) {
	e := newC5Env(t)
	db := e.agent(e.agentKey)
	e.expire()
	_, err := db.Exec("UPDATE orders SET status = 'refunded' WHERE id = 1043")
	mustDenied(t, "autocommit UPDATE after expiry", err)
	if e.status(1043) != "processing" {
		t.Fatal("row changed")
	}
	t.Logf("C5-g ok: %q; row 1043 still processing", err)
}

// ROLLBACK is always forwarded after expiry, and recovers the connection.
func TestRevC_C5_RollbackAlwaysForwarded(t *testing.T) {
	e := newC5Env(t)
	db := e.agent(e.agentKey)
	tx, _ := db.Begin()
	if _, err := tx.Exec("UPDATE orders SET status = 'refunded' WHERE id = 1043"); err != nil {
		t.Fatal(err)
	}
	e.expire()
	if err := tx.Rollback(); err != nil {
		t.Fatalf("ROLLBACK after expiry must pass: %v", err)
	}
	if e.status(1043) != "processing" {
		t.Fatal("row changed")
	}
	t.Log("ROLLBACK after expiry forwarded; row 1043 still processing")
}

// Recovery: a fresh signed sync after expiry lifts the denial.
func TestRevC_Expiry_RecoversAfterFreshSync(t *testing.T) {
	e := newC5Env(t)
	db := e.agent(e.agentKey)
	e.expire()
	var n int
	mustDenied(t, "read while expired", db.QueryRow("SELECT count(*) FROM orders").Scan(&n))
	// The control plane is reachable again.
	if err := acceptOnce(t, e.guard, e.cp, e.clk); err != nil {
		t.Fatalf("fresh sync: %v", err)
	}
	if err := db.QueryRow("SELECT count(*) FROM orders").Scan(&n); err != nil || n != 3 {
		t.Fatalf("read after a fresh sync: %v", err)
	}
	t.Log("recovery ok: denied while expired; a fresh signed sync re-enables queries on the same connection")
}
