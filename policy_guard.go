package main

// policy_guard.go — proxy side of POLICY-WIRE-CONTRACT Rev B/C.1, slice 1:
// signed policy acceptance (C1, C3, B3) and the offline-window clock.
//
// Local trust anchor (C3): FW_TENANT_ID, FW_DATABASE_ID, FW_ENVIRONMENT and
// FW_POLICY_PUBKEY (env wins over ~/.faultwall/config.toml, written by
// install.sh). Nothing from the network can change them. Enforce mode with a
// control plane refuses to start unless all four are set.
//
// A signed doc is accepted only when: the Ed25519 signature over the raw
// payload verifies with the pinned key; tenant/database/environment equal the
// anchor; agents_yaml equals the served copy; sha256(raw agent_keys bytes)
// equals agent_keys_sha256; version >= last accepted; and the same version
// never arrives with different bytes (policy_version_conflict).
//
// Freshness (C1): every poll carries a fresh 16-byte nonce. The window
// refreshes only on a signed_freshness that verifies, echoes that nonce,
// names this installation and tenant, names the version we enforce, has an
// issued_at no older than the last accepted one, and arrives within 30s of
// the request. The window then starts at the request's SEND time. While
// running, expiry is measured on the monotonic clock; across restarts the
// persisted fresh_at/last_seen_wall detect a clock set backwards (=> expired).

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// maxFreshnessDelay: a response later than this after its request never
// refreshes the window (C1).
const maxFreshnessDelay = 30 * time.Second

// policyAnchor is the locally trusted scope (C3).
type policyAnchor struct {
	TenantID, DatabaseID, Environment, PubKey string
}

func loadPolicyAnchor(cfg ControlPlaneConfig) policyAnchor {
	pick := func(env, file string) string {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			return v
		}
		return strings.TrimSpace(file)
	}
	return policyAnchor{
		TenantID:    pick("FW_TENANT_ID", cfg.TenantID),
		DatabaseID:  pick("FW_DATABASE_ID", cfg.DatabaseID),
		Environment: pick("FW_ENVIRONMENT", cfg.Environment),
		PubKey:      pick("FW_POLICY_PUBKEY", cfg.PolicyPubKey),
	}
}

// policyStartupCheck (C3-a, B3): enforce mode with a control plane needs the
// whole anchor and a valid key. Returns the parsed key (nil in watch mode
// without one).
func policyStartupCheck(enforcement string, cpConfigured bool, a policyAnchor) (ed25519.PublicKey, error) {
	if !cpConfigured {
		return nil, nil
	}
	var pub ed25519.PublicKey
	if a.PubKey != "" {
		k, err := parsePolicyPubKey(a.PubKey)
		if err != nil {
			return nil, fmt.Errorf("FW_POLICY_PUBKEY is not a valid Ed25519 public key: %v", err)
		}
		pub = k
	}
	if enforcement != "enforce" {
		return pub, nil
	}
	var missing []string
	for _, kv := range [][2]string{{"FW_TENANT_ID", a.TenantID}, {"FW_DATABASE_ID", a.DatabaseID},
		{"FW_ENVIRONMENT", a.Environment}, {"FW_POLICY_PUBKEY", a.PubKey}} {
		if kv[1] == "" {
			missing = append(missing, kv[0])
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("enforce mode needs %s (from the app's Add-database install command). "+
			"Refusing to start: without the full local trust anchor this proxy cannot tell a real policy for this database from a forged or foreign one. "+
			"Set them, or run with --mode monitor", strings.Join(missing, ", "))
	}
	return pub, nil
}

// policyClock separates wall time (persisted, comparable across restarts)
// from monotonic time (immune to wall-clock jumps while running).
type policyClock interface {
	Wall() time.Time
	Mono() time.Duration
}

type realPolicyClock struct{ start time.Time }

func (c realPolicyClock) Wall() time.Time     { return time.Now().Round(0) }
func (c realPolicyClock) Mono() time.Duration { return time.Since(c.start) }

// guardState is persisted (0600, atomic) next to the policy cache.
type guardState struct {
	// Anchor the state was written under (tenant/database/environment/key id).
	// State from another anchor (re-enrolled proxy) is discarded on load.
	Anchor          string            `json:"anchor"`
	AcceptedVersion int64             `json:"accepted_version"`
	PayloadSHA      map[string]string `json:"payload_sha256"` // version -> sha256(signed payload)
	InstallationID  string            `json:"installation_id,omitempty"`
	FreshAt         time.Time         `json:"fresh_at"`
	LastSeenWall    time.Time         `json:"last_seen_wall"`
	LastIssuedAt    time.Time         `json:"last_issued_at"`
	WindowSeconds   int64             `json:"window_seconds"`
	DenyAllOnExpiry bool              `json:"deny_all_on_expiry"`
}

// policyGuard owns acceptance + the offline window for one proxy.
type policyGuard struct {
	mu        sync.Mutex
	anchor    policyAnchor
	enforce   bool
	pub       ed25519.PublicKey
	clock     policyClock
	statePath string
	maxWindow time.Duration // local cap (FW_POLICY_MAX_OFFLINE_SECONDS), 0 = none

	st        guardState
	monoBase  time.Duration // Mono() at the start of the current window
	haveFresh bool          // monoBase valid
	doc       *PolicyDoc    // last accepted doc
	lastErr   string
	health    string // "", policy_signature_invalid, policy_scope_mismatch, policy_version_conflict, ...
	warned24  bool
	warned1   bool
}

func newPolicyGuard(a policyAnchor, enforce bool, pub ed25519.PublicKey, statePath string, clk policyClock) *policyGuard {
	if clk == nil {
		clk = realPolicyClock{start: time.Now()}
	}
	g := &policyGuard{anchor: a, enforce: enforce, pub: pub, clock: clk, statePath: statePath, maxWindow: maxOfflineFromEnv()}
	g.st.PayloadSHA = map[string]string{}
	g.load()
	return g
}

func guardStatePath(cachePath string) string {
	if p := os.Getenv("FW_POLICY_STATE_FILE"); p != "" {
		return p
	}
	if cachePath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(cachePath), "policy-state.json")
}

// load restores persisted state. Missing/corrupt state or a wall clock that
// went backwards = expired until the next accepted freshness token.
func (g *policyGuard) load() {
	if g.statePath == "" {
		return
	}
	b, err := os.ReadFile(g.statePath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("⚠️  policy state unreadable (%v): treating the offline window as expired", err)
		}
		return
	}
	var st guardState
	if err := json.Unmarshal(b, &st); err != nil {
		log.Printf("⚠️  policy state corrupt (%v): treating the offline window as expired", err)
		return
	}
	if st.PayloadSHA == nil {
		st.PayloadSHA = map[string]string{}
	}
	if st.Anchor != g.anchorKey() {
		log.Printf("⚠️  policy state was written for another scope or key (%s, now %s): discarding it; offline window expired until the next signed sync",
			st.Anchor, g.anchorKey())
		return
	}
	g.st = st
	now := g.clock.Wall()
	switch {
	case st.FreshAt.IsZero():
	case now.Before(st.LastSeenWall) || now.Before(st.FreshAt):
		log.Printf("⚠️  wall clock is behind the last recorded time (now %s, last seen %s): offline window treated as expired",
			now.UTC().Format(time.RFC3339), st.LastSeenWall.UTC().Format(time.RFC3339))
		g.health = "policy_clock_rollback"
	default:
		g.monoBase = g.clock.Mono() - now.Sub(st.FreshAt)
		g.haveFresh = true
	}
}

// anchorKey identifies the local trust anchor the state belongs to.
func (g *policyGuard) anchorKey() string {
	kid := ""
	if g.pub != nil {
		kid = policyKeyID(g.pub)
	}
	return g.anchor.TenantID + "/" + g.anchor.DatabaseID + "/" + g.anchor.Environment + "/" + kid
}

func (g *policyGuard) saveLocked() {
	if g.statePath == "" {
		return
	}
	g.st.Anchor = g.anchorKey()
	now := g.clock.Wall()
	if now.After(g.st.LastSeenWall) {
		g.st.LastSeenWall = now
	}
	b, err := json.Marshal(g.st)
	if err == nil {
		err = writeFileAtomic(g.statePath, b)
	}
	if err != nil {
		log.Printf("⚠️  could not persist policy state: %v", err)
	}
}

// touch records last_seen_wall (called every sync and every 60s) and emits
// the 24h / 1h expiry warnings.
func (g *policyGuard) touch() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.saveLocked()
	if !g.enforce {
		return
	}
	left := g.remainingLocked()
	switch {
	case left <= 0:
	case left < time.Hour && !g.warned1:
		g.warned1, g.warned24 = true, true
		log.Printf("⚠️  WARN policy expires in %s: FaultWall has not reached the control plane since %s", left.Round(time.Second), g.st.FreshAt.UTC().Format(time.RFC3339))
	case left < 24*time.Hour && !g.warned24:
		g.warned24 = true
		log.Printf("⚠️  WARN policy expires in %s: FaultWall has not reached the control plane since %s", left.Round(time.Second), g.st.FreshAt.UTC().Format(time.RFC3339))
	}
}

func (g *policyGuard) window() time.Duration {
	w := time.Duration(defaultOfflineWindowSeconds) * time.Second
	if g.st.WindowSeconds > 0 {
		w = time.Duration(g.st.WindowSeconds) * time.Second
	}
	// FW_POLICY_MAX_OFFLINE_SECONDS: a local operator cap. It can only make
	// the window SHORTER than the signed one (stricter), never longer.
	if g.maxWindow > 0 && g.maxWindow < w {
		w = g.maxWindow
	}
	return w
}

func maxOfflineFromEnv() time.Duration {
	if v := strings.TrimSpace(os.Getenv("FW_POLICY_MAX_OFFLINE_SECONDS")); v != "" {
		var n int64
		if _, err := fmt.Sscan(v, &n); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 0
}

func (g *policyGuard) remainingLocked() time.Duration {
	if !g.haveFresh {
		return 0
	}
	return g.window() - (g.clock.Mono() - g.monoBase)
}

// Expired reports whether the offline window has run out (enforce mode).
// Watch mode never expires anything (it would only log would_deny).
func (g *policyGuard) Expired() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.enforce && g.remainingLocked() <= 0
}

// windowLapsed: watch mode past its window (would_deny logging only).
func (g *policyGuard) windowLapsed() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.enforce && g.pub != nil && g.remainingLocked() <= 0
}

// ExpiryMessage is the contract error text.
func (g *policyGuard) ExpiryMessage() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.st.FreshAt.IsZero() || !g.haveFresh && g.health == "policy_clock_rollback" {
		return "no valid signed policy is in force: FaultWall has not accepted a verified, current policy from the control plane" + func() string {
			if g.health != "" {
				return " (" + g.health + ")"
			}
			return ""
		}()
	}
	since := "never (no accepted freshness token)"
	at := "unknown"
	if !g.st.FreshAt.IsZero() {
		since = g.st.FreshAt.UTC().Format(time.RFC3339)
		at = g.st.FreshAt.Add(g.window()).UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("policy expired at %s: FaultWall has not reached the control plane since %s", at, since)
}

func (g *policyGuard) AcceptedVersion() int64 {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.st.AcceptedVersion
}

func (g *policyGuard) InstallationID() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.st.InstallationID
}

func (g *policyGuard) status() map[string]interface{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	left := g.remainingLocked()
	state := "fresh"
	if !g.haveFresh {
		state = "unknown"
	}
	if left <= 0 {
		state = "expired"
	}
	m := map[string]interface{}{
		"policy_version":            g.st.AcceptedVersion,
		"policy_state":              state,
		"policy_expires_in_seconds": int64(left / time.Second),
		"policy_fresh_at":           g.st.FreshAt,
		"policy_signed":             g.pub != nil,
		"policy_enforce":            g.enforce,
	}
	if g.health != "" {
		m["policy_health"] = g.health
	}
	if g.lastErr != "" {
		m["policy_error"] = g.lastErr
	}
	return m
}

func (g *policyGuard) failLocked(health, msg string) error {
	g.health, g.lastErr = health, msg
	log.Printf("❌ ERROR policy rejected (%s): %s. Keeping the last good policy (v%d).", health, msg, g.st.AcceptedVersion)
	return errors.New(health + ": " + msg)
}

// policyFetch is one poll's request metadata.
type policyFetch struct {
	nonce    string
	sentWall time.Time
	sentMono time.Duration
}

// acceptDoc verifies the signed doc against the anchor. Returns ok=false with
// an error when it must not be applied. unsignedOK is true only for a
// watch-mode proxy without a key (legacy compatibility, no protection claim).
func (g *policyGuard) acceptDoc(r *policySyncResponse) (applied bool, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if r.SignedPolicy == nil {
		if g.enforce || g.pub != nil {
			return false, g.failLocked("policy_signature_invalid", "unsigned policy refused (enforce mode or a pinned key: no downgrade to unsigned)")
		}
		return true, nil // watch mode, no key: legacy unsigned
	}
	if g.pub == nil {
		// Watch mode without FW_POLICY_PUBKEY: cannot verify, so no claim.
		return true, nil
	}
	payload, verr := verifyBlob(r.SignedPolicy, g.pub)
	if verr != nil {
		return false, g.failLocked("policy_signature_invalid", verr.Error())
	}
	var doc PolicyDoc
	if err := json.Unmarshal(payload, &doc); err != nil {
		return false, g.failLocked("policy_signature_invalid", "signed payload is not a policy doc: "+err.Error())
	}
	a := g.anchor
	for _, c := range [][3]string{{"tenant_id", doc.TenantID, a.TenantID}, {"database_id", doc.DatabaseID, a.DatabaseID}, {"environment", doc.Environment, a.Environment}} {
		if c[2] == "" && !g.enforce {
			continue
		}
		if c[1] != c[2] {
			return false, g.failLocked("policy_scope_mismatch", fmt.Sprintf("signed %s %q does not match this proxy's %q", c[0], c[1], c[2]))
		}
	}
	if doc.AgentsYAML != r.AgentsYAML {
		return false, g.failLocked("policy_signature_invalid", "agents_yaml differs from the signed copy")
	}
	ks := sha256.Sum256(r.agentKeysRaw)
	if hex.EncodeToString(ks[:]) != doc.AgentKeysSHA256 {
		return false, g.failLocked("policy_signature_invalid", "agent_keys bytes do not match agent_keys_sha256")
	}
	if r.PolicyVersion != 0 && r.PolicyVersion != doc.Version {
		return false, g.failLocked("policy_signature_invalid", fmt.Sprintf("policy_version %d differs from signed version %d", r.PolicyVersion, doc.Version))
	}
	ps := sha256.Sum256(payload)
	sha := hex.EncodeToString(ps[:])
	vkey := fmt.Sprint(doc.Version)
	switch {
	case doc.Version < g.st.AcceptedVersion:
		return false, g.failLocked("policy_rollback", fmt.Sprintf("version %d is older than accepted %d", doc.Version, g.st.AcceptedVersion))
	case g.st.PayloadSHA[vkey] != "" && g.st.PayloadSHA[vkey] != sha:
		return false, g.failLocked("policy_version_conflict", fmt.Sprintf("version %d arrived with different content", doc.Version))
	}
	newer := doc.Version > g.st.AcceptedVersion || g.doc == nil
	g.st.AcceptedVersion = doc.Version
	g.st.PayloadSHA[vkey] = sha
	g.st.WindowSeconds = int64(doc.window() / time.Second)
	g.st.DenyAllOnExpiry = doc.DenyAllOnExpiry
	if g.st.InstallationID == "" && r.InstallationID != "" {
		g.st.InstallationID = r.InstallationID // first signed sync binds it
	}
	g.doc = &doc
	if g.health == "policy_signature_invalid" || g.health == "policy_scope_mismatch" || g.health == "policy_version_conflict" || g.health == "policy_rollback" {
		g.health, g.lastErr = "", ""
	}
	g.saveLocked()
	return newer, nil
}

// acceptFreshness refreshes the window from a verified token (C1).
func (g *policyGuard) acceptFreshness(r *policySyncResponse, f policyFetch, localInstallation string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pub == nil || r.SignedFreshness == nil {
		if r.FreshnessError != "" {
			g.lastErr = "no freshness token: " + r.FreshnessError
		}
		return nil
	}
	if d := g.clock.Mono() - f.sentMono; d > maxFreshnessDelay {
		return g.failLocked("policy_freshness_late", fmt.Sprintf("response arrived %s after the request (limit %s); window not refreshed", d.Round(time.Millisecond), maxFreshnessDelay))
	}
	payload, err := verifyBlob(r.SignedFreshness, g.pub)
	if err != nil {
		return g.failLocked("policy_signature_invalid", "freshness: "+err.Error())
	}
	var tok FreshnessToken
	if err := json.Unmarshal(payload, &tok); err != nil {
		return g.failLocked("policy_signature_invalid", "freshness payload: "+err.Error())
	}
	inst := localInstallation
	if inst == "" {
		inst = g.st.InstallationID
	}
	switch {
	case tok.Nonce != f.nonce:
		return g.failLocked("policy_freshness_replay", "freshness token does not echo this poll's nonce")
	case tok.TenantID != g.anchor.TenantID && (g.enforce || g.anchor.TenantID != ""):
		return g.failLocked("policy_scope_mismatch", fmt.Sprintf("freshness tenant %q is not %q", tok.TenantID, g.anchor.TenantID))
	case inst == "" || tok.InstallationID != inst:
		return g.failLocked("policy_scope_mismatch", fmt.Sprintf("freshness names installation %q, this proxy is %q", tok.InstallationID, inst))
	case tok.PolicyVersion != g.st.AcceptedVersion:
		return g.failLocked("policy_freshness_version", fmt.Sprintf("freshness is for v%d, enforcing v%d", tok.PolicyVersion, g.st.AcceptedVersion))
	}
	issued, err := time.Parse(time.RFC3339Nano, tok.IssuedAt)
	if err != nil {
		return g.failLocked("policy_signature_invalid", "freshness issued_at: "+err.Error())
	}
	if issued.Before(g.st.LastIssuedAt) {
		return g.failLocked("freshness_regressed", fmt.Sprintf("issued_at %s is older than the last accepted %s", tok.IssuedAt, g.st.LastIssuedAt.UTC().Format(time.RFC3339Nano)))
	}
	g.st.LastIssuedAt = issued
	g.st.FreshAt = f.sentWall
	g.monoBase = f.sentMono
	g.haveFresh = true
	g.warned24, g.warned1 = false, false
	if strings.HasPrefix(g.health, "policy_freshness") || g.health == "freshness_regressed" || g.health == "policy_clock_rollback" {
		g.health, g.lastErr = "", ""
	}
	g.saveLocked()
	return nil
}

// policyGuardG is the process-global guard (nil when signed policy is not in
// use). The query path (slice 2) consults it for expiry.
var policyGuardG *policyGuard
