package main

// agent_keys.go — per-agent keys issued by the control plane (the Connect screen).
//
// The control plane stores only sha256(key) and ships those hashes to the
// proxy on GET /v1/policy, together with the agents' compiled policies
// (policies.yaml `agents:` shape + `approvals.rules`). The proxy:
//
//   - authenticates an agent at connection startup by its key, presented
//     either as the Postgres password (user = agent name) or as the token in
//     application_name (agent:<id>:mission:<m>:token:fw_ak_...);
//   - merges the managed agents over its local policies.yaml;
//   - polls for changes every sync interval and caches the last good copy on
//     disk so a control-plane outage doesn't lock agents out after a restart.
//
// The raw key never leaves the agent's config: we only ever compare hashes.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// AgentKeyPrefix marks control-plane issued agent keys.
const AgentKeyPrefix = "fw_ak_"

// proxyHoldCapable is advertised to the control plane. When false (this
// build), "ask first" toggles are compiled to action: flag — the statement
// runs, and is logged + flagged as needing approval. The approvals lane flips
// this once hold-at-Execute ships, and consumes ManagedPolicy.HoldRules.
var proxyHoldCapable = false

// AgentKeyEntry is one issued key, by hash.
type AgentKeyEntry struct {
	Agent     string `json:"agent"`
	KeySHA256 string `json:"key_sha256"`
	Revoked   bool   `json:"revoked"`
	// SCRAM-SHA-256 verifier of the key (nil for keys created before SCRAM
	// support; those need FW_ALLOW_CLEARTEXT_KEY=*** for key-as-password).
	Scram *ScramVerifier `json:"scram,omitempty"`
	// DBRole: Postgres role key-authenticated sessions of this agent are
	// switched to (SET SESSION ROLE) and pinned to. "" = no switch.
	DBRole string `json:"db_role,omitempty"`
}

// ManagedRule mirrors the control plane's approvals rule shape.
type ManagedRule struct {
	Name       string   `yaml:"name" json:"name"`
	Action     string   `yaml:"action" json:"action"` // hold | flag
	Agents     []string `yaml:"agents" json:"agents"`
	Operations []string `yaml:"operations" json:"operations"`
	Tables     []string `yaml:"tables,omitempty" json:"tables,omitempty"`
}

// ManagedPolicy is everything the control plane manages for this proxy.
type ManagedPolicy struct {
	Version   string                 `json:"version"`
	Agents    map[string]AgentPolicy `json:"-"`
	FlagRules []ManagedRule          `json:"flag_rules"`
	HoldRules []ManagedRule          `json:"hold_rules"`
	Keys      []AgentKeyEntry        `json:"-"`
}

// managedYAML is the agents_yaml fragment sent by the control plane.
type managedYAML struct {
	Agents    map[string]AgentPolicy `yaml:"agents"`
	Approvals struct {
		Rules []ManagedRule `yaml:"rules"`
	} `yaml:"approvals"`
}

// parseManagedPolicy builds a ManagedPolicy from the policy endpoint payload.
func parseManagedPolicy(version, agentsYAML string, keys []AgentKeyEntry) (*ManagedPolicy, error) {
	var my managedYAML
	if strings.TrimSpace(agentsYAML) != "" {
		if err := yaml.Unmarshal([]byte(agentsYAML), &my); err != nil {
			return nil, fmt.Errorf("parsing agents_yaml: %w", err)
		}
	}
	m := &ManagedPolicy{Version: version, Agents: my.Agents, Keys: keys}
	if m.Agents == nil {
		m.Agents = map[string]AgentPolicy{}
	}
	for _, r := range my.Approvals.Rules {
		switch {
		case strings.EqualFold(r.Action, "hold") && proxyHoldCapable:
			m.HoldRules = append(m.HoldRules, r)
		case strings.EqualFold(r.Action, "hold"), strings.EqualFold(r.Action, "flag"):
			// No hold support in this build: degrade to flag (never silently allow).
			r.Action = "flag"
			m.FlagRules = append(m.FlagRules, r)
		}
	}
	return m, nil
}

// ── key store ──

// AgentKeyStore maps sha256(key) -> entry, plus agent name -> has-keys.
type AgentKeyStore struct {
	mu      sync.RWMutex
	byHash  map[string]AgentKeyEntry
	byAgent map[string]int // number of keys (live or revoked) per agent
	// live keys with a SCRAM verifier, per agent (SCRAM picks by agent name:
	// the proxy never sees the raw key, so it can't look it up by hash).
	scramByAgent map[string][]AgentKeyEntry
}

// agentKeys is the process-global store (empty until the first sync/cache load).
var agentKeys = NewAgentKeyStore()

func NewAgentKeyStore() *AgentKeyStore {
	return &AgentKeyStore{byHash: map[string]AgentKeyEntry{}, byAgent: map[string]int{}, scramByAgent: map[string][]AgentKeyEntry{}}
}

// HashAgentKey is the same sha256-hex scheme the control plane stores.
func HashAgentKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Replace swaps the whole key set atomically.
func (s *AgentKeyStore) Replace(entries []AgentKeyEntry) {
	byHash := make(map[string]AgentKeyEntry, len(entries))
	byAgent := map[string]int{}
	for _, e := range entries {
		h := strings.ToLower(strings.TrimSpace(e.KeySHA256))
		if h == "" || e.Agent == "" {
			continue
		}
		e.KeySHA256 = h
		// A hash seen twice: revoked wins (fail closed).
		if prev, ok := byHash[h]; ok && prev.Revoked {
			e.Revoked = true
		}
		byHash[h] = e
		byAgent[e.Agent]++
	}
	scramBy := map[string][]AgentKeyEntry{}
	for _, e := range byHash {
		if !e.Revoked && e.Scram.valid() {
			scramBy[e.Agent] = append(scramBy[e.Agent], e)
		}
	}
	s.mu.Lock()
	s.byHash, s.byAgent, s.scramByAgent = byHash, byAgent, scramBy
	s.mu.Unlock()
}

// Lookup resolves a raw key. ok=false means the key is unknown.
func (s *AgentKeyStore) Lookup(raw string) (AgentKeyEntry, bool) {
	if raw == "" {
		return AgentKeyEntry{}, false
	}
	h := HashAgentKey(raw)
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.byHash[h]
	if ok && subtle.ConstantTimeCompare([]byte(e.KeySHA256), []byte(h)) != 1 {
		return AgentKeyEntry{}, false
	}
	return e, ok
}

// ScramKeys returns the live keys of agent that have a SCRAM verifier.
func (s *AgentKeyStore) ScramKeys(agent string) []AgentKeyEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]AgentKeyEntry(nil), s.scramByAgent[agent]...)
}

// LiveKeys reports how many live (unrevoked) keys agent has, and whether
// all of them are revoked.
func (s *AgentKeyStore) agentState(agent string) (live int, any bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.byHash {
		if e.Agent == agent {
			any = true
			if !e.Revoked {
				live++
			}
		}
	}
	return
}

// DBRole returns the db_role of agent's live key(s) ("" = none). Live agent
// names are unique on the control plane, so live keys agree; if they ever
// don't, the lexically smallest non-empty role wins (deterministic).
func (s *AgentKeyStore) DBRole(agent string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	role := ""
	for _, e := range s.byHash {
		if e.Agent == agent && !e.Revoked && e.DBRole != "" && (role == "" || e.DBRole < role) {
			role = e.DBRole
		}
	}
	return role
}

// HasAgent reports whether any key (live or revoked) was issued to name.
func (s *AgentKeyStore) HasAgent(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byAgent[name] > 0
}

// Len is the number of known keys.
func (s *AgentKeyStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byHash)
}

// ── policy sync ──

// policySyncResponse is GET /v1/policy.
type policySyncResponse struct {
	Template            string          `json:"template"`
	Version             int             `json:"version"`
	AgentsVersion       string          `json:"agents_version"`
	AgentsYAML          string          `json:"agents_yaml"`
	AgentKeys           []AgentKeyEntry `json:"agent_keys"`
	HoldCompiledAs      string          `json:"hold_compiled_as"`
	SyncIntervalSeconds int             `json:"sync_interval_seconds"`
}

// PolicySyncer pulls managed agents + keys from the control plane.
type PolicySyncer struct {
	url, token string
	pe         *PolicyEngine
	keys       *AgentKeyStore
	http       *http.Client
	cachePath  string
	interval   time.Duration // 0 = use server-advertised value

	mu         sync.Mutex
	lastSync   time.Time
	lastErr    string
	lastVer    string
	agentNames []string
}

func defaultAgentCachePath() string {
	if p := os.Getenv("FW_AGENT_CACHE"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".faultwall", "managed-agents.json")
}

// NewPolicySyncer builds a syncer. FW_POLICY_SYNC_INTERVAL (Go duration or
// seconds) overrides the server-advertised interval.
func NewPolicySyncer(cpURL, token string, pe *PolicyEngine, keys *AgentKeyStore) *PolicySyncer {
	ps := &PolicySyncer{
		url: strings.TrimRight(cpURL, "/"), token: token, pe: pe, keys: keys,
		http:      &http.Client{Timeout: 10 * time.Second},
		cachePath: defaultAgentCachePath(),
	}
	if v := strings.TrimSpace(os.Getenv("FW_POLICY_SYNC_INTERVAL")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			ps.interval = time.Duration(n) * time.Second
		} else if d, err := time.ParseDuration(v); err == nil && d > 0 {
			ps.interval = d
		}
	}
	return ps
}

func capabilities() string {
	caps := []string{"agent-keys", "flag"}
	if proxyHoldCapable {
		caps = append(caps, "hold")
	}
	return strings.Join(caps, ",")
}

// fetch performs one GET /v1/policy.
func (ps *PolicySyncer) fetch() (*policySyncResponse, error) {
	req, err := http.NewRequest("GET", ps.url+"/v1/policy", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+ps.token)
	req.Header.Set("X-FaultWall-Capabilities", capabilities())
	resp, err := ps.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /v1/policy: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out policySyncResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decoding /v1/policy: %w", err)
	}
	return &out, nil
}

// apply installs a policy response (from the network or the cache). Returns
// changed=true when the agents version differs from what's loaded.
func (ps *PolicySyncer) apply(r *policySyncResponse) (bool, error) {
	ps.mu.Lock()
	same := r.AgentsVersion != "" && r.AgentsVersion == ps.lastVer
	ps.mu.Unlock()
	if same {
		return false, nil
	}
	m, err := parseManagedPolicy(r.AgentsVersion, r.AgentsYAML, r.AgentKeys)
	if err != nil {
		return false, err
	}
	ps.keys.Replace(r.AgentKeys)
	if n := agentSessions.KillRevoked(ps.keys); n > 0 {
		log.Printf("🔑 Ended %d open session(s) of agents whose key was revoked or whose DB role changed", n)
	}
	if ps.pe != nil {
		ps.pe.SetManaged(m)
	}
	names := make([]string, 0, len(m.Agents))
	for n := range m.Agents {
		names = append(names, n)
	}
	ps.mu.Lock()
	ps.lastVer = r.AgentsVersion
	ps.agentNames = names
	ps.mu.Unlock()
	log.Printf("🔑 Agent keys synced: %d agent(s), %d key(s), version %s (ask-first compiled as %s)",
		len(m.Agents), ps.keys.Len(), r.AgentsVersion, nonEmpty(r.HoldCompiledAs, "flag"))
	return true, nil
}

// SyncOnce fetches, applies and caches. Network errors keep the current state.
func (ps *PolicySyncer) SyncOnce() (time.Duration, error) {
	r, err := ps.fetch()
	ps.mu.Lock()
	ps.lastSync = time.Now()
	if err != nil {
		ps.lastErr = err.Error()
	} else {
		ps.lastErr = ""
	}
	ps.mu.Unlock()
	if err != nil {
		return 0, err
	}
	changed, err := ps.apply(r)
	if err != nil {
		return 0, err
	}
	if changed {
		ps.saveCache(r)
	}
	next := ps.interval
	if next == 0 && r.SyncIntervalSeconds > 0 {
		next = time.Duration(r.SyncIntervalSeconds) * time.Second
	}
	if next == 0 {
		next = 30 * time.Second
	}
	return next, nil
}

func (ps *PolicySyncer) saveCache(r *policySyncResponse) {
	if ps.cachePath == "" {
		return
	}
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(ps.cachePath), 0o700)
	tmp := ps.cachePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		_ = os.Rename(tmp, ps.cachePath)
	}
}

// LoadCache installs the last good policy from disk (used before the first
// successful sync, so a restart during a control-plane outage still works).
func (ps *PolicySyncer) LoadCache() bool {
	if ps.cachePath == "" {
		return false
	}
	b, err := os.ReadFile(ps.cachePath)
	if err != nil {
		return false
	}
	var r policySyncResponse
	if json.Unmarshal(b, &r) != nil {
		return false
	}
	if _, err := ps.apply(&r); err != nil {
		return false
	}
	log.Printf("🔑 Loaded cached agent keys from %s", ps.cachePath)
	return true
}

// Start runs an initial sync (falling back to the cache) and then polls.
func (ps *PolicySyncer) Start() {
	next, err := ps.SyncOnce()
	if err != nil {
		log.Printf("⚠️  Agent key sync failed: %v", err)
		ps.LoadCache()
		next = ps.interval
		if next == 0 {
			next = 30 * time.Second
		}
	}
	go func() {
		for {
			time.Sleep(next)
			n, err := ps.SyncOnce()
			if err != nil {
				log.Printf("⚠️  Agent key sync failed (keeping last good copy): %v", err)
				continue
			}
			next = n
		}
	}()
}

// Status is exposed on the local API (/api/agent-keys).
func (ps *PolicySyncer) Status() map[string]interface{} {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return map[string]interface{}{
		"control_plane": ps.url,
		"version":       ps.lastVer,
		"agents":        ps.agentNames,
		"keys":          ps.keys.Len(),
		"last_sync":     ps.lastSync,
		"last_error":    ps.lastErr,
		"hold_capable":  proxyHoldCapable,
	}
}

// policySyncer is the process-global syncer (nil when not configured).
var policySyncer *PolicySyncer

func handleAgentKeysStatus(w http.ResponseWriter, r *http.Request) {
	if policySyncer == nil {
		writeJSON(w, map[string]interface{}{"enabled": false, "keys": agentKeys.Len()})
		return
	}
	st := policySyncer.Status()
	st["enabled"] = true
	writeJSON(w, st)
}

// ── managed policy merge (PolicyEngine) ──

// SetManaged installs control-plane managed agents over the local policy.
// Copy-on-write: a fresh PolicyConfig with a fresh Agents map is swapped in,
// so concurrent readers holding the old pointer are never mutated under.
func (pe *PolicyEngine) SetManaged(m *ManagedPolicy) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.managed = m
	pe.config = pe.overlayManagedLocked(pe.config)
}

// overlayManagedLocked returns cfg with the managed agents applied. Agents a
// previous managed set added (but that are gone now) are removed, and any
// local definition they shadowed is restored. Caller holds pe.mu.
func (pe *PolicyEngine) overlayManagedLocked(cfg *PolicyConfig) *PolicyConfig {
	if cfg == nil {
		cfg = &PolicyConfig{DefaultPolicy: "allow", Unidentified: UnidentifiedPolicy{Policy: "deny"}}
	}
	next := *cfg
	next.Agents = make(map[string]AgentPolicy, len(cfg.Agents))
	for k, v := range cfg.Agents {
		next.Agents[k] = v
	}
	if pe.shadowed == nil {
		pe.shadowed = map[string]*AgentPolicy{}
	}
	// Undo the previous overlay.
	for name, orig := range pe.shadowed {
		if orig != nil {
			next.Agents[name] = *orig
		} else {
			delete(next.Agents, name)
		}
	}
	pe.shadowed = map[string]*AgentPolicy{}
	pe.flagRules = nil
	if pe.managed == nil {
		return &next
	}
	for name, ap := range pe.managed.Agents {
		if orig, ok := next.Agents[name]; ok {
			o := orig
			pe.shadowed[name] = &o
		} else {
			pe.shadowed[name] = nil
		}
		next.Agents[name] = ap
	}
	pe.flagRules = pe.managed.FlagRules
	return &next
}

// isManagedAgent reports whether name currently comes from the control plane.
func (pe *PolicyEngine) isManagedAgent(name string) bool {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	_, ok := pe.shadowed[name]
	return ok
}

// checkFlagRules returns a flag-only violation when a managed "ask first"
// rule matches and this proxy can't hold. It never blocks.
func (pe *PolicyEngine) checkFlagRules(identity *AgentIdentity, pq *ParsedQuery, query string) *PolicyViolation {
	if identity == nil || pq == nil {
		return nil
	}
	pe.mu.RLock()
	rules := pe.flagRules
	pe.mu.RUnlock()
	if len(rules) == 0 {
		return nil
	}
	ops := pq.Operations
	if len(ops) == 0 {
		ops = []string{pq.Operation}
	}
	for _, r := range rules {
		if !ruleHasAgent(r, identity.AgentID) {
			continue
		}
		for _, op := range ops {
			for _, want := range r.Operations {
				if strings.EqualFold(op, want) {
					return &PolicyViolation{
						AgentID:   identity.AgentID,
						MissionID: identity.MissionID,
						Query:     truncateQuery(query),
						Reason:    "needs_approval:" + nonEmpty(r.Name, "ask-first") + " (flag only: this proxy cannot pause yet)",
						Operation: strings.ToUpper(op),
						Action:    "flagged",
						FlagOnly:  true,
						Timestamp: time.Now(),
					}
				}
			}
		}
	}
	return nil
}

func ruleHasAgent(r ManagedRule, agent string) bool {
	if len(r.Agents) == 0 {
		return true
	}
	for _, a := range r.Agents {
		if a == "*" || a == agent {
			return true
		}
	}
	return false
}
