package main

// Slice 1 tests: POLICY-WIRE-CONTRACT Rev C.1 C1 (freshness, clocks, version
// conflict), C3 (local trust anchor, scope) and B3 (no unsigned downgrade).
// The control plane is an httptest server that signs exactly like
// faultwall-control-plane bc9da4e (canonical JSON, base64url no padding,
// key_id = first 16 hex of sha256(pub)).

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock: wall and monotonic time move independently.
type fakeClock struct {
	mu   sync.Mutex
	wall time.Time
	mono time.Duration
}

func (c *fakeClock) Wall() time.Time     { c.mu.Lock(); defer c.mu.Unlock(); return c.wall }
func (c *fakeClock) Mono() time.Duration { c.mu.Lock(); defer c.mu.Unlock(); return c.mono }
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.wall = c.wall.Add(d)
	c.mono += d
	c.mu.Unlock()
}
func (c *fakeClock) jumpWall(d time.Duration) { c.mu.Lock(); c.wall = c.wall.Add(d); c.mu.Unlock() }

const (
	tTenant = "11111111-1111-1111-1111-111111111111"
	tDB     = "22222222-2222-2222-2222-222222222222"
	tEnv    = "production"
	tInst   = "33333333-3333-3333-3333-333333333333"
)

// fakeCP signs policy + freshness. Knobs let tests alter what is served.
type fakeCP struct {
	t    *testing.T
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	clk  *fakeClock

	mu          sync.Mutex
	version     int64
	tenant, db  string
	env, inst   string
	yaml        string
	issuedAt    time.Time
	unsigned    bool
	extraField  string // changes signed content without changing version
	echoNonce   string // "" = echo the request nonce
	delay       time.Duration
	freshVer    int64 // 0 = version
	served      [][]byte
	lastNonce   string
	sendNoFresh bool
}

func newFakeCP(t *testing.T, clk *fakeClock) *fakeCP {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeCP{t: t, priv: priv, pub: pub, clk: clk, version: 3, tenant: tTenant, db: tDB, env: tEnv,
		inst: tInst, yaml: "agents: {}\n", issuedAt: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeCP) pubB64() string { return base64.RawURLEncoding.EncodeToString(c.pub) }

func (c *fakeCP) env4() policyAnchor {
	return policyAnchor{TenantID: tTenant, DatabaseID: tDB, Environment: tEnv, PubKey: c.pubB64()}
}

func canon(t *testing.T, v map[string]interface{}) []byte {
	b, err := json.Marshal(v) // encoding/json sorts map keys
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (c *fakeCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.delay > 0 {
		c.clk.advance(c.delay) // the response "arrives" this much later
	}
	keys := []byte(`[]`)
	ks := sha256.Sum256(keys)
	doc := map[string]interface{}{
		"schema": 1, "tenant_id": c.tenant, "database_id": c.db, "environment": c.env, "version": c.version,
		"issued_at": "2026-10-04T12:00:00Z", "offline_window_seconds": 3600, "deny_all_on_expiry": false,
		"agents_yaml": c.yaml, "agent_keys_sha256": hex.EncodeToString(ks[:]), "grants": []interface{}{},
		"sensitive": []interface{}{}, "frozen_agents": []interface{}{},
	}
	if c.extraField != "" {
		doc["frozen_agents"] = []interface{}{c.extraField}
	}
	nonce := r.URL.Query().Get("nonce")
	c.lastNonce = nonce
	resp := map[string]interface{}{
		"template": "balanced", "version": 1, "agents_version": "v" + string(rune('0'+c.version%10)),
		"agents_yaml": c.yaml, "agent_keys": json.RawMessage(keys), "hold_compiled_as": "hold",
		"sync_interval_seconds": 30, "policy_version": c.version, "tenant_id": c.tenant,
		"database_id": c.db, "environment": c.env, "installation_id": c.inst,
	}
	if !c.unsigned {
		payload := canon(c.t, doc)
		c.served = append(c.served, payload)
		resp["signed_policy"] = signBlob(c.priv, payload)
		if !c.sendNoFresh && nonce != "" {
			echo := nonce
			if c.echoNonce != "" {
				echo = c.echoNonce
			}
			fv := c.version
			if c.freshVer != 0 {
				fv = c.freshVer
			}
			c.issuedAt = c.issuedAt.Add(time.Second)
			fresh := canon(c.t, map[string]interface{}{"tenant_id": c.tenant, "installation_id": c.inst,
				"policy_version": fv, "nonce": echo, "issued_at": c.issuedAt.Format(time.RFC3339Nano)})
			resp["signed_freshness"] = signBlob(c.priv, fresh)
		}
	}
	_ = json.NewEncoder(w).Encode(resp)
}

type guardRig struct {
	t     *testing.T
	clk   *fakeClock
	cp    *fakeCP
	srv   *httptest.Server
	dir   string
	ps    *PolicySyncer
	keys  *AgentKeyStore
	pe    *PolicyEngine
	state string
}

func newGuardRig(t *testing.T) *guardRig {
	clk := &fakeClock{wall: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
	cp := newFakeCP(t, clk)
	srv := httptest.NewServer(cp)
	t.Cleanup(srv.Close)
	g := &guardRig{t: t, clk: clk, cp: cp, srv: srv, dir: t.TempDir()}
	g.state = filepath.Join(g.dir, "policy-state.json")
	t.Setenv("FW_AGENT_CACHE", filepath.Join(g.dir, "managed-agents.json"))
	g.restart()
	return g
}

// restart builds a fresh syncer+guard over the same state/cache (a proxy restart).
func (g *guardRig) restart() {
	g.pe = &PolicyEngine{pausedAgents: map[string]bool{}, config: &PolicyConfig{Agents: map[string]AgentPolicy{}}}
	g.keys = NewAgentKeyStore()
	g.ps = NewPolicySyncer(g.srv.URL, "tok", g.pe, g.keys)
	g.ps.installationID = tInst
	g.ps.guard = newPolicyGuard(g.cp.env4(), true, g.cp.pub, g.state, g.clk)
}

func (g *guardRig) sync() error { _, err := g.ps.SyncOnce(); return err }

func (g *guardRig) mustSync() {
	g.t.Helper()
	if err := g.sync(); err != nil {
		g.t.Fatalf("sync: %v", err)
	}
}

func (g *guardRig) left() time.Duration {
	g.ps.guard.mu.Lock()
	defer g.ps.guard.mu.Unlock()
	return g.ps.guard.remainingLocked()
}

// C1-a: connected on unchanged policy across more than the window = fresh.
func TestRevC_C1a_ConnectedUnchangedStaysFresh(t *testing.T) {
	g := newGuardRig(t)
	g.mustSync()
	for i := 0; i < 10; i++ { // 10 x 30 min = 5h > 1h window
		g.clk.advance(30 * time.Minute)
		g.mustSync()
		if g.ps.guard.Expired() {
			t.Fatalf("expired after %d syncs on unchanged policy", i+1)
		}
	}
	t.Logf("C1-a ok: 5h connected on v%d with a 1h window, still fresh (%s left)", g.ps.guard.AcceptedVersion(), g.left())
}

// C1-b: a replayed response (old nonce) never refreshes the window.
func TestRevC_C1b_ReplayDoesNotRefresh(t *testing.T) {
	g := newGuardRig(t)
	g.mustSync()
	old := g.cp.lastNonce
	g.clk.advance(50 * time.Minute)
	before := g.left()
	g.cp.echoNonce = old // attacker replays the earlier response
	err := g.sync()
	if err == nil && g.left() > before {
		t.Fatal("replayed freshness refreshed the window")
	}
	g.clk.advance(11 * time.Minute)
	if !g.ps.guard.Expired() {
		t.Fatal("window should have expired: replay must not extend it")
	}
	t.Logf("C1-b ok: replayed nonce rejected (%v); expired on schedule", g.ps.lastErr)
}

// C1-c: delayed 31s = discarded; delayed 20s = refreshes only from send time.
func TestRevC_C1c_DelayedResponses(t *testing.T) {
	g := newGuardRig(t)
	g.mustSync()
	g.clk.advance(40 * time.Minute)
	before := g.left()
	g.cp.delay = 31 * time.Second
	_ = g.sync()
	if g.left() > before {
		t.Fatalf("31s-late response refreshed the window (%s -> %s)", before, g.left())
	}
	if !strings.Contains(g.ps.lastErr, "policy_freshness_late") {
		t.Fatalf("want policy_freshness_late, got %q", g.ps.lastErr)
	}
	g.cp.delay = 20 * time.Second
	sendWall := g.clk.Wall()
	g.mustSync()
	want := time.Hour - 20*time.Second // counted from the SEND time, not receipt
	if got := g.left(); got != want {
		t.Fatalf("20s-late refresh: %s left, want %s (window from send time)", got, want)
	}
	if fa := g.ps.guard.st.FreshAt; !fa.Equal(sendWall) {
		t.Fatalf("fresh_at %s, want send time %s", fa, sendWall)
	}
	t.Logf("C1-c ok: 31s late discarded; 20s late refreshed from send time (%s left)", g.left())
}

// C1-d: restart keeps the original fresh_at.
func TestRevC_C1d_RestartKeepsFreshAt(t *testing.T) {
	g := newGuardRig(t)
	g.mustSync()
	fa := g.ps.guard.st.FreshAt
	g.clk.advance(45 * time.Minute)
	g.ps.guard.touch()
	g.restart()
	if !g.ps.guard.st.FreshAt.Equal(fa) {
		t.Fatalf("fresh_at changed on restart: %s -> %s", fa, g.ps.guard.st.FreshAt)
	}
	if got := g.left(); got != 15*time.Minute {
		t.Fatalf("after restart %s left, want 15m (no reset)", got)
	}
	g.clk.advance(16 * time.Minute)
	if !g.ps.guard.Expired() {
		t.Fatal("restart reset the window")
	}
	t.Log("C1-d ok: restart resumed from persisted fresh_at; expired 60m after it")
}

// C1-e: wall clock set back before restart = expired.
func TestRevC_C1e_ClockSetBackBeforeRestart(t *testing.T) {
	g := newGuardRig(t)
	g.mustSync()
	g.clk.advance(10 * time.Minute)
	g.ps.guard.touch()
	g.clk.jumpWall(-30 * time.Minute) // operator sets the clock back, restarts
	g.restart()
	if !g.ps.guard.Expired() {
		t.Fatal("clock set backwards across restart must read as expired")
	}
	if g.ps.guard.health != "policy_clock_rollback" {
		t.Fatalf("health %q", g.ps.guard.health)
	}
	g.mustSync() // a genuine fresh token recovers
	if g.ps.guard.Expired() {
		t.Fatal("fresh token after rollback should recover")
	}
	t.Log("C1-e ok: rollback across restart = expired (policy_clock_rollback); next real token recovers")
}

// C1-f: wall clock jump while running does not change expiry.
func TestRevC_C1f_WallJumpWhileRunning(t *testing.T) {
	g := newGuardRig(t)
	g.mustSync()
	g.clk.jumpWall(-10 * time.Hour)
	if g.left() != time.Hour {
		t.Fatalf("backward wall jump changed remaining to %s", g.left())
	}
	g.clk.jumpWall(+20 * time.Hour)
	if g.left() != time.Hour || g.ps.guard.Expired() {
		t.Fatalf("forward wall jump changed remaining to %s", g.left())
	}
	g.clk.advance(61 * time.Minute)
	if !g.ps.guard.Expired() {
		t.Fatal("monotonic expiry did not fire")
	}
	t.Log("C1-f ok: +/-wall jumps ignored while running; expiry on the monotonic clock")
}

// C1-g: same version, different content = rejected, last good kept.
func TestRevC_C1g_SameVersionDifferentContent(t *testing.T) {
	g := newGuardRig(t)
	g.mustSync()
	g.cp.extraField = "intruder-agent"
	err := g.sync()
	if err == nil || !strings.Contains(err.Error(), "policy_version_conflict") {
		t.Fatalf("want policy_version_conflict, got %v", err)
	}
	if g.ps.guard.doc == nil || len(g.ps.guard.doc.FrozenAgents) != 0 {
		t.Fatal("last good doc not kept")
	}
	if g.ps.guard.status()["policy_health"] != "policy_version_conflict" {
		t.Fatal("health not reported")
	}
	t.Logf("C1-g ok: %v", err)
}

// C1-h: freshness token with an older issued_at = rejected.
func TestRevC_C1h_OlderIssuedAtRejected(t *testing.T) {
	g := newGuardRig(t)
	g.mustSync()
	g.clk.advance(30 * time.Minute)
	before := g.left()
	g.cp.issuedAt = g.cp.issuedAt.Add(-time.Hour) // server time goes backwards
	_ = g.sync()
	if !strings.Contains(g.ps.lastErr, "freshness_regressed") {
		t.Fatalf("want freshness_regressed, got %q", g.ps.lastErr)
	}
	if g.left() > before {
		t.Fatal("regressed token refreshed the window")
	}
	t.Logf("C1-h ok: %s", g.ps.lastErr)
}

// Version gaps are fine (versions are unique per tenant); going back is not.
func TestRevC_C1_VersionGapsAndRollback(t *testing.T) {
	g := newGuardRig(t)
	g.mustSync()
	g.cp.version = 8 // skips 4..7 (other database's versions)
	g.mustSync()
	g.cp.version = 5
	if err := g.sync(); err == nil || !strings.Contains(err.Error(), "policy_rollback") {
		t.Fatalf("want policy_rollback, got %v", err)
	}
	if g.ps.guard.AcceptedVersion() != 8 {
		t.Fatal("rollback changed the accepted version")
	}
	t.Log("C1 ok: v3 -> v8 (gap) accepted; v5 after v8 rejected as policy_rollback")
}

// C3-a: enforce refuses to start without any one anchor value.
func TestRevC_C3a_EnforceNeedsFullAnchor(t *testing.T) {
	_, pub, _ := func() (ed25519.PrivateKey, string, error) {
		p, k, e := ed25519.GenerateKey(rand.Reader)
		return k, base64.RawURLEncoding.EncodeToString(p), e
	}()
	full := policyAnchor{TenantID: tTenant, DatabaseID: tDB, Environment: tEnv, PubKey: pub}
	if _, err := policyStartupCheck("enforce", true, full); err != nil {
		t.Fatalf("full anchor refused: %v", err)
	}
	for _, name := range []string{"FW_TENANT_ID", "FW_DATABASE_ID", "FW_ENVIRONMENT", "FW_POLICY_PUBKEY"} {
		a := full
		switch name {
		case "FW_TENANT_ID":
			a.TenantID = ""
		case "FW_DATABASE_ID":
			a.DatabaseID = ""
		case "FW_ENVIRONMENT":
			a.Environment = ""
		case "FW_POLICY_PUBKEY":
			a.PubKey = ""
		}
		_, err := policyStartupCheck("enforce", true, a)
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Fatalf("missing %s: got %v", name, err)
		}
	}
	if _, err := policyStartupCheck("monitor", true, policyAnchor{}); err != nil {
		t.Fatalf("watch mode must not require the anchor: %v", err)
	}
	if _, err := policyStartupCheck("enforce", true, policyAnchor{TenantID: tTenant, DatabaseID: tDB, Environment: tEnv, PubKey: "nope"}); err == nil {
		t.Fatal("bad key accepted")
	}
	t.Log("C3-a ok (proxy side): enforce refuses each missing anchor var; watch mode does not require it")
}

// Env wins over config.toml for the anchor.
func TestRevC_C3a_AnchorEnvOverridesFile(t *testing.T) {
	t.Setenv("FW_ENVIRONMENT", "staging")
	a := loadPolicyAnchor(ControlPlaneConfig{TenantID: "t", DatabaseID: "d", Environment: "production", PolicyPubKey: "k"})
	if a.Environment != "staging" || a.TenantID != "t" || a.DatabaseID != "d" || a.PubKey != "k" {
		t.Fatalf("anchor %+v", a)
	}
}

// C3-b: unsigned doc on first boot is rejected in enforce mode.
func TestRevC_C3b_UnsignedFirstBootRejected(t *testing.T) {
	g := newGuardRig(t)
	g.cp.unsigned = true
	err := g.sync()
	if err == nil || !strings.Contains(err.Error(), "policy_signature_invalid") {
		t.Fatalf("want policy_signature_invalid, got %v", err)
	}
	if g.keys.Len() != 0 || g.ps.guard.AcceptedVersion() != 0 || !g.ps.guard.Expired() {
		t.Fatal("unsigned first-boot policy was applied or counted as fresh")
	}
	t.Logf("C3-b ok: %v", err)
}

// B3: an old unsigned update cannot downgrade an enrolled proxy.
func TestRevC_B3_NoUnsignedDowngrade(t *testing.T) {
	g := newGuardRig(t)
	g.mustSync()
	g.cp.unsigned = true
	g.cp.yaml = "agents:\n  evil: {}\n"
	if err := g.sync(); err == nil {
		t.Fatal("unsigned update accepted after a signed one")
	}
	if g.ps.guard.AcceptedVersion() != 3 {
		t.Fatal("accepted version changed")
	}
	t.Log("B3 ok: unsigned update after enrollment refused, v3 kept")
}

// C3-c: same database_id, other environment = rejected.
func TestRevC_C3c_OtherEnvironmentRejected(t *testing.T) {
	g := newGuardRig(t)
	g.cp.env = "staging"
	err := g.sync()
	if err == nil || !strings.Contains(err.Error(), "policy_scope_mismatch") || !strings.Contains(err.Error(), "environment") {
		t.Fatalf("want environment policy_scope_mismatch, got %v", err)
	}
	t.Logf("C3-c ok: %v", err)
}

// C3-d: other database_id = rejected.
func TestRevC_C3d_OtherDatabaseRejected(t *testing.T) {
	g := newGuardRig(t)
	g.cp.db = "99999999-9999-9999-9999-999999999999"
	err := g.sync()
	if err == nil || !strings.Contains(err.Error(), "database_id") {
		t.Fatalf("want database_id policy_scope_mismatch, got %v", err)
	}
	t.Logf("C3-d ok: %v", err)
}

// C3-e: freshness for another installation or tenant = rejected.
func TestRevC_C3e_FreshnessOtherInstallationOrTenant(t *testing.T) {
	g := newGuardRig(t)
	g.mustSync()
	g.clk.advance(30 * time.Minute)
	before := g.left()
	g.cp.inst = "44444444-4444-4444-4444-444444444444"
	_ = g.sync()
	if !strings.Contains(g.ps.lastErr, "installation") || g.left() > before {
		t.Fatalf("other installation: err %q, left %s (before %s)", g.ps.lastErr, g.left(), before)
	}
	msgInst := g.ps.lastErr
	g.cp.inst = tInst
	g.cp.tenant = "55555555-5555-5555-5555-555555555555"
	err := g.sync()
	if err == nil || !strings.Contains(err.Error(), "tenant_id") {
		t.Fatalf("other tenant: %v", err)
	}
	t.Logf("C3-e ok: installation -> %s; tenant -> %v", msgInst, err)
}

// Wrong key = rejected (key pin).
func TestRevC_WrongKeyRejected(t *testing.T) {
	g := newGuardRig(t)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	g.ps.guard.pub = other
	err := g.sync()
	if err == nil || !strings.Contains(err.Error(), "policy_signature_invalid") {
		t.Fatalf("want policy_signature_invalid, got %v", err)
	}
	t.Logf("wrong key ok: %v", err)
}

// Freshness for a version other than the enforced one does not refresh.
func TestRevC_FreshnessWrongVersion(t *testing.T) {
	g := newGuardRig(t)
	g.mustSync()
	g.clk.advance(30 * time.Minute)
	before := g.left()
	g.cp.freshVer = 2
	_ = g.sync()
	if !strings.Contains(g.ps.lastErr, "policy_freshness_version") || g.left() > before {
		t.Fatalf("err %q", g.ps.lastErr)
	}
}

// Corrupt / missing state on restart = expired until a fresh token.
func TestRevC_CorruptStateExpired(t *testing.T) {
	g := newGuardRig(t)
	g.mustSync()
	if err := os.WriteFile(g.state, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	g.restart()
	if !g.ps.guard.Expired() {
		t.Fatal("corrupt state must read as expired")
	}
}

// The cache is re-verified on load: a tampered cache is refused.
func TestRevC_TamperedCacheRefused(t *testing.T) {
	g := newGuardRig(t)
	g.mustSync()
	cache := os.Getenv("FW_AGENT_CACHE")
	b, err := os.ReadFile(cache)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, []byte(strings.Replace(string(b), `agents: {}`, `agents: {evil: {}}`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	g.restart()
	if g.ps.LoadCache() {
		t.Fatal("tampered cache accepted")
	}
}

// Re-enrolment under another key/scope: old state is discarded, not used to
// reject the new control plane's versions (found in the slice 1 e2e rerun).
func TestRevC_StateFromOtherAnchorDiscarded(t *testing.T) {
	g := newGuardRig(t)
	g.mustSync()
	if g.ps.guard.AcceptedVersion() != 3 {
		t.Fatal("setup")
	}
	cp2 := newFakeCP(t, g.clk) // new tenant key, same version number, different bytes
	g.cp = cp2
	g.srv.Config.Handler = cp2
	g.restart()
	if g.ps.guard.AcceptedVersion() != 0 || !g.ps.guard.Expired() {
		t.Fatal("state from another anchor was kept")
	}
	g.mustSync()
	if g.ps.guard.AcceptedVersion() != 3 || g.ps.guard.Expired() {
		t.Fatal("new anchor's policy not accepted")
	}
	t.Log("re-enrol ok: state from another key discarded; new key's v3 accepted and fresh")
}
