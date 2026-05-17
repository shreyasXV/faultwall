package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// SecurityProfile defines a named security posture
type SecurityProfile struct {
	Name               string   // profile name
	BlockedCategories  []string // e.g. ["DCL", "ADMIN", "EXTENSION", "FUNCTION"]
	BlockedOperations  []string // specific ops blocked within allowed categories
	AllowedOperations  []string // if non-empty, only these ops are allowed (allowlist mode)
	Conditions         []string // e.g. ["DELETE must include WHERE", "UPDATE must include WHERE"]
	AllowUnknown       bool     // whether to allow UNKNOWN operations
}

// Built-in security profiles
var BuiltinProfiles = map[string]SecurityProfile{
	"permissive": {
		Name:         "permissive",
		AllowUnknown: true,
	},
	"standard": {
		Name:              "standard",
		BlockedCategories: []string{"DCL", "DDL", "ADMIN", "EXTENSION", "FUNCTION"},
		BlockedOperations: []string{"COPY", "NOTIFY", "LISTEN", "DISCARD", "LOCK", "LOAD", "EXPLAIN"},
		Conditions:        []string{"DELETE must include WHERE", "UPDATE must include WHERE"},
		AllowUnknown:      false,
	},
	"strict": {
		Name:              "strict",
		AllowedOperations: []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRANSACTION"},
		Conditions:        []string{"DELETE must include WHERE", "UPDATE must include WHERE"},
		AllowUnknown:      false,
	},
}

// ProfileOverrides allows per-agent tweaks on top of a profile
type ProfileOverrides struct {
	Allow []string `yaml:"allow" json:"allow"`
	Block []string `yaml:"block" json:"block"`
}

// CustomProfileConfig is the YAML representation of a custom profile
type CustomProfileConfig struct {
	Extends           string   `yaml:"extends" json:"extends"`
	AllowedOperations []string `yaml:"allowed_operations" json:"allowed_operations"`
	BlockedCategories []string `yaml:"blocked_categories" json:"blocked_categories"`
	BlockedOperations []string `yaml:"blocked_operations" json:"blocked_operations"`
	Conditions        []string `yaml:"conditions" json:"conditions"`
	AllowUnknown      *bool    `yaml:"allow_unknown" json:"allow_unknown"`
}

// PolicyConfig is the top-level policies.yaml structure
type PolicyConfig struct {
	DefaultPolicy    string                         `yaml:"default_policy" json:"default_policy"`
	BlockedFunctions []string                       `yaml:"blocked_functions" json:"blocked_functions"`
	Profiles         map[string]CustomProfileConfig `yaml:"profiles" json:"profiles"`
	Agents           map[string]AgentPolicy         `yaml:"agents" json:"agents"`
	Unidentified     UnidentifiedPolicy             `yaml:"unidentified" json:"unidentified"`
}

// FingerprintRule is one entry in an agent's AllowedFingerprints or PendingReview list.
type FingerprintRule struct {
	Hash    string `yaml:"hash"`             // pg_query.Fingerprint() hex
	SQL     string `yaml:"sql"`              // human-readable canonical form
	Seen    int64  `yaml:"seen"`             // observation count from monitor window
	Verdict string `yaml:"verdict"`          // "safe" | "risky" | "unknown"
	Reason  string `yaml:"reason,omitempty"` // why it was classified this way
}

// AgentPolicy defines rules for a specific agent
type AgentPolicy struct {
	Description        string                   `yaml:"description" json:"description"`
	AuthToken          string                   `yaml:"auth_token" json:"-"`
	Profile            string                   `yaml:"profile" json:"profile"`
	ProfileOverrides   *ProfileOverrides        `yaml:"profile_overrides" json:"profile_overrides"`
	Missions           map[string]MissionPolicy `yaml:"missions" json:"missions"`
	BlockedOperations  []string                 `yaml:"blocked_operations" json:"blocked_operations"`
	BlockedTables      []string                 `yaml:"blocked_tables" json:"blocked_tables"`
	BlockedColumns     map[string][]string      `yaml:"blocked_columns" json:"blocked_columns"` // table -> blocked column names (lowercase). Fires when the listed table is referenced AND any listed column appears in the query.
	AllowedFunctions   []string                 `yaml:"allowed_functions" json:"allowed_functions"`
	AllowedFingerprints []FingerprintRule       `yaml:"allowed_fingerprints,omitempty" json:"allowed_fingerprints,omitempty"`
	PendingReview      []FingerprintRule        `yaml:"pending_review,omitempty" json:"pending_review,omitempty"` // informational only, never enforced
}

// MissionPolicy defines per-mission table/operation access
// MissionPolicy defines per-mission table/operation access.
//
// Enforcement behavior (proxy mode):
//   - max_rows: per-statement circuit breaker. Counts DataRow wire messages;
//     terminates connection when exceeded. Client receives rows up to the limit
//     plus an ErrorResponse. Resets on ReadyForQuery ('Z').
//   - max_query_time_ms: per-statement timeout. Starts when query is forwarded
//     to upstream; kills connection via sync.Once shutdown if exceeded.
//     Resets on ReadyForQuery ('Z'). Per-transaction timing is not yet supported.
type MissionPolicy struct {
	Tables         []string `yaml:"tables" json:"tables"`
	MaxRows        int      `yaml:"max_rows" json:"max_rows"`
	MaxQueryTimeMs int      `yaml:"max_query_time_ms" json:"max_query_time_ms"`
	Conditions     []string `yaml:"conditions" json:"conditions"`
}

// UnidentifiedPolicy handles connections without agent: prefix
// Policy modes:
//   - "deny":    block all queries (strictest)
//   - "log":     allow queries but log all unidentified access as violations (audit trail)
//   - "monitor": allow queries, only log actual violations (blocked tables/functions)
//   - "allow":   allow queries, enforce global blocklists only (most permissive)
//
// Migration note: "monitor" was renamed from the old behavior that logged every query.
// The old "monitor" behavior is now "log". Current "monitor" only logs real violations.
type UnidentifiedPolicy struct {
	Policy        string   `yaml:"policy" json:"policy"` // monitor | deny | allow
	BlockedTables []string `yaml:"blocked_tables" json:"blocked_tables"`
}

// PolicyViolation records a policy breach
type PolicyViolation struct {
	AgentID   string    `json:"agent_id"`
	MissionID string    `json:"mission_id"`
	Query     string    `json:"query"`
	Reason    string    `json:"reason"`
	Table     string    `json:"table"`
	Operation string    `json:"operation"`
	PID       int       `json:"pid"`
	Action    string    `json:"action"` // "blocked" or "monitored"
	Timestamp time.Time `json:"timestamp"`
}

// PolicyEngine manages policy loading, enforcement, and violation tracking
type PolicyEngine struct {
	mu           sync.RWMutex
	config       *PolicyConfig
	violations   []PolicyViolation
	enforcement  string // "enforce" | "monitor"
	filePath     string
	pausedAgents map[string]bool // agents that are paused (all queries blocked)
}

func NewPolicyEngine() *PolicyEngine {
	filePath := os.Getenv("POLICY_FILE")
	if filePath == "" {
		filePath = "./policies.yaml"
	}
	enforcement := os.Getenv("POLICY_ENFORCEMENT")
	if enforcement == "" {
		enforcement = "monitor"
	}

	pe := &PolicyEngine{
		enforcement:  enforcement,
		filePath:     filePath,
		pausedAgents: make(map[string]bool),
	}

	if err := pe.LoadFromFile(filePath); err != nil {
		if enforcement == "enforce" {
			log.Fatalf("FATAL: Policy file required in enforce mode but failed to load (%v). Refusing to start — fail-closed.", err)
		}
		log.Printf("Policy engine: no policies loaded (%v) — running in monitor mode without policy enforcement", err)
		pe.config = &PolicyConfig{
			DefaultPolicy: "allow",
			Agents:        make(map[string]AgentPolicy),
			Unidentified:  UnidentifiedPolicy{Policy: "allow"},
		}
	}

	return pe
}

// LoadFromFile reads and parses a policies.yaml file
func (pe *PolicyEngine) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading policy file: %w", err)
	}

	var cfg PolicyConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parsing policy YAML: %w", err)
	}

	if cfg.Agents == nil {
		cfg.Agents = make(map[string]AgentPolicy)
	}

	pe.mu.Lock()
	pe.config = &cfg
	pe.mu.Unlock()

	log.Printf("Policy engine: loaded %d agent policies from %s (default: %s)", len(cfg.Agents), path, cfg.DefaultPolicy)
	return nil
}

// Reload hot-reloads the policy file
func (pe *PolicyEngine) Reload() error {
	return pe.LoadFromFile(pe.filePath)
}

// SaveToFile writes the current policy config back to the YAML file
func (pe *PolicyEngine) SaveToFile() error {
	pe.mu.RLock()
	cfg := pe.config
	pe.mu.RUnlock()

	if cfg == nil {
		return fmt.Errorf("no config to save")
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling policy config: %w", err)
	}

	if err := os.WriteFile(pe.filePath, data, 0644); err != nil {
		return fmt.Errorf("writing policy file: %w", err)
	}

	log.Printf("Policy engine: saved config to %s", pe.filePath)
	return nil
}

// IsAgentPaused returns whether an agent is currently paused
func (pe *PolicyEngine) IsAgentPaused(agentID string) bool {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return pe.pausedAgents[agentID]
}

// SetAgentPaused sets the paused state for an agent
func (pe *PolicyEngine) SetAgentPaused(agentID string, paused bool) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	if paused {
		pe.pausedAgents[agentID] = true
	} else {
		delete(pe.pausedAgents, agentID)
	}
}

// GetPausedAgents returns all currently paused agent IDs
func (pe *PolicyEngine) GetPausedAgents() []string {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	result := make([]string, 0, len(pe.pausedAgents))
	for id := range pe.pausedAgents {
		result = append(result, id)
	}
	return result
}

// GetFilePath returns the policy file path
func (pe *PolicyEngine) GetFilePath() string {
	return pe.filePath
}

// GetConfig returns the current policy config
func (pe *PolicyEngine) GetConfig() *PolicyConfig {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return pe.config
}

// GetViolations returns all recorded violations
func (pe *PolicyEngine) GetViolations() []PolicyViolation {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	result := make([]PolicyViolation, len(pe.violations))
	copy(result, pe.violations)
	return result
}

// GetViolationsByAgent returns violations for a specific agent
func (pe *PolicyEngine) GetViolationsByAgent(agentID string) []PolicyViolation {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	var result []PolicyViolation
	for _, v := range pe.violations {
		if v.AgentID == agentID {
			result = append(result, v)
		}
	}
	return result
}

func (pe *PolicyEngine) addViolation(v PolicyViolation) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.violations = append(pe.violations, v)
	// Keep last 1000 violations
	if len(pe.violations) > 1000 {
		pe.violations = pe.violations[len(pe.violations)-1000:]
	}
	// Also record in agent tracker if available
	if agentTracker != nil && v.AgentID != "" {
		agentTracker.RecordViolation(v.AgentID)
	}
}

// AddViolation is the exported version of addViolation (for use from proxy and external packages)
func (pe *PolicyEngine) AddViolation(v PolicyViolation) {
	pe.addViolation(v)
}

// ResolveProfile resolves a profile name to a SecurityProfile, checking custom profiles
// in the config first, then built-in profiles. Returns nil if not found.
func ResolveProfile(name string, cfg *PolicyConfig) *SecurityProfile {
	// Check custom profiles in config
	if cfg != nil && cfg.Profiles != nil {
		if custom, ok := cfg.Profiles[name]; ok {
			return buildCustomProfile(name, custom)
		}
	}
	// Check built-in profiles
	if builtin, ok := BuiltinProfiles[name]; ok {
		cp := builtin // copy
		return &cp
	}
	return nil
}

// buildCustomProfile constructs a SecurityProfile from a CustomProfileConfig
func buildCustomProfile(name string, custom CustomProfileConfig) *SecurityProfile {
	profile := &SecurityProfile{Name: name}

	// If extending a built-in, start from that base
	if custom.Extends != "" {
		if base, ok := BuiltinProfiles[custom.Extends]; ok {
			*profile = base
			profile.Name = name
		}
	}

	// Override fields if specified
	if len(custom.AllowedOperations) > 0 {
		profile.AllowedOperations = custom.AllowedOperations
		// Allowlist mode overrides blocked lists
		profile.BlockedCategories = nil
		profile.BlockedOperations = nil
	}
	if len(custom.BlockedCategories) > 0 {
		profile.BlockedCategories = custom.BlockedCategories
	}
	if len(custom.BlockedOperations) > 0 {
		profile.BlockedOperations = custom.BlockedOperations
	}
	if len(custom.Conditions) > 0 {
		profile.Conditions = custom.Conditions
	}
	if custom.AllowUnknown != nil {
		profile.AllowUnknown = *custom.AllowUnknown
	}
	return profile
}

// isOperationBlockedByProfile checks whether an operation is blocked by a resolved profile
// with optional per-agent overrides applied.
func isOperationBlockedByProfile(operation string, profile *SecurityProfile, overrides *ProfileOverrides) bool {
	opUpper := strings.ToUpper(operation)

	// Build effective allow/block sets from overrides
	overrideAllow := make(map[string]bool)
	overrideBlock := make(map[string]bool)
	if overrides != nil {
		for _, op := range overrides.Allow {
			overrideAllow[strings.ToUpper(op)] = true
		}
		for _, op := range overrides.Block {
			overrideBlock[strings.ToUpper(op)] = true
		}
	}

	// Override block always wins
	if overrideBlock[opUpper] {
		return true
	}
	// Override allow exempts from profile blocking
	if overrideAllow[opUpper] {
		return false
	}

	// Allowlist mode: if AllowedOperations is set, only those are allowed
	if len(profile.AllowedOperations) > 0 {
		for _, allowed := range profile.AllowedOperations {
			if strings.EqualFold(allowed, opUpper) {
				return false
			}
		}
		return true // not in allowlist = blocked
	}

	// Blocklist mode: check blocked categories, then blocked operations
	category := OperationCategory[opUpper]
	for _, blockedCat := range profile.BlockedCategories {
		if strings.EqualFold(blockedCat, category) {
			return true
		}
	}
	for _, blockedOp := range profile.BlockedOperations {
		if strings.EqualFold(blockedOp, opUpper) {
			return true
		}
	}

	return false
}

// hasTrivialWhere checks if the WHERE clause is trivially true (e.g. WHERE 1=1, WHERE true)
func hasTrivialWhere(query string) bool {
	upper := strings.ToUpper(query)
	whereIdx := strings.Index(upper, "WHERE")
	if whereIdx < 0 {
		return false
	}
	whereClause := strings.TrimSpace(upper[whereIdx+5:])
	trivialPatterns := []string{
		"1=1", "1 = 1", "TRUE", "'1'='1'", "'A'='A'",
		"1<>0", "1 <> 0", "1!=0", "1 != 0",
		"NOT FALSE", "1 > 0", "1 >= 1", "0 < 1", "0 <= 1",
		"0=0", "0 = 0", "2=2", "2 = 2",
		"(SELECT 1)=1", "(SELECT 1) = 1", "(SELECT TRUE)",
		"'X'='X'", "'T'='T'",
		"1 IS NOT NULL", "'' = ''", "NULL IS NULL",
	}
	for _, pattern := range trivialPatterns {
		if strings.HasPrefix(whereClause, pattern) {
			return true
		}
	}
	return false
}

// checkConditions checks WHERE clause conditions against a query
func checkConditions(conditions []string, operation string, query string, identity *AgentIdentity, pid int) *PolicyViolation {
	for _, cond := range conditions {
		condLower := strings.ToLower(cond)
		if strings.Contains(condLower, "update must include where") {
			if strings.EqualFold(operation, "UPDATE") && (!strings.Contains(strings.ToUpper(query), "WHERE") || hasTrivialWhere(query)) {
				return &PolicyViolation{
					AgentID:   identity.AgentID,
					MissionID: identity.MissionID,
					Query:     truncateQuery(query),
					Reason:    "condition_violated",
					Operation: operation,
					PID:       pid,
					Action:    "pending",
					Timestamp: time.Now(),
				}
			}
		}
		if strings.Contains(condLower, "delete must include where") {
			if strings.EqualFold(operation, "DELETE") && (!strings.Contains(strings.ToUpper(query), "WHERE") || hasTrivialWhere(query)) {
				return &PolicyViolation{
					AgentID:   identity.AgentID,
					MissionID: identity.MissionID,
					Query:     truncateQuery(query),
					Reason:    "condition_violated",
					Operation: operation,
					PID:       pid,
					Action:    "pending",
					Timestamp: time.Now(),
				}
			}
		}
	}
	return nil
}

// CheckQuery evaluates a query against the loaded policies.
// Returns nil if allowed, a PolicyViolation if blocked/flagged.
func (pe *PolicyEngine) CheckQuery(identity *AgentIdentity, query string, pid int) *PolicyViolation {
	pe.mu.RLock()
	cfg := pe.config
	pe.mu.RUnlock()

	if cfg == nil {
		return nil
	}

	// Check if agent is paused (all queries blocked)
	if identity != nil && pe.IsAgentPaused(identity.AgentID) {
		return &PolicyViolation{
			AgentID:   identity.AgentID,
			MissionID: identity.MissionID,
			Query:     truncateQuery(query),
			Reason:    "agent_paused",
			Operation: "ALL",
			PID:       pid,
			Action:    "pending",
			Timestamp: time.Now(),
		}
	}

	// Parse query using AST (falls back to regex automatically)
	parsed := ParseQuery(query)
	operation := parsed.Operation
	operations := parsed.Operations
	if len(operations) == 0 {
		operations = []string{operation}
	}
	tables := parsed.Tables
	functions := parsed.Functions

	// Treat server info functions (current_user, session_user, etc.) as blocked functions
	// on non-permissive profiles — they leak server identity/role information.
	if len(parsed.ServerInfoFuncs) > 0 {
		functions = append(functions, parsed.ServerInfoFuncs...)
	}

	// Block OPERATOR(pg_catalog.*) syntax on non-permissive profiles.
	if parsed.HasPgCatalogOp && identity != nil {
		agentPolicy, agentExists := cfg.Agents[identity.AgentID]
		if agentExists {
			isPermissive := false
			if agentPolicy.Profile != "" {
				profile := ResolveProfile(agentPolicy.Profile, cfg)
				if profile != nil && profile.Name == "permissive" {
					isPermissive = true
				}
			}
			if !isPermissive {
				return &PolicyViolation{
					AgentID:   identity.AgentID,
					MissionID: identity.MissionID,
					Query:     truncateQuery(query),
					Reason:    "pg_catalog_operator",
					Operation: operation,
					PID:       pid,
					Action:    "pending",
					Timestamp: time.Now(),
				}
			}
		}
	}

	// Block system columns (ctid, xmin, xmax, cmin, cmax, tableoid) on non-permissive profiles.
	// These leak internal Postgres metadata (physical row locations, transaction IDs, table OIDs).
	if len(parsed.SystemColumns) > 0 && identity != nil {
		agentPolicy, agentExists := cfg.Agents[identity.AgentID]
		if agentExists {
			isPermissive := false
			if agentPolicy.Profile != "" {
				profile := ResolveProfile(agentPolicy.Profile, cfg)
				if profile != nil && profile.Name == "permissive" {
					isPermissive = true
				}
			}
			if !isPermissive {
				return &PolicyViolation{
					AgentID:   identity.AgentID,
					MissionID: identity.MissionID,
					Query:     truncateQuery(query),
					Reason:    "system_column:" + strings.Join(parsed.SystemColumns, ","),
					Operation: operation,
					PID:       pid,
					Action:    "pending",
					Timestamp: time.Now(),
				}
			}
		}
	}

	// ── AST parse failure: enhanced regex checks + fail-closed for non-permissive ──
	// When the AST parser fails, the query is either invalid SQL (Postgres would
	// reject it anyway) or deliberately obfuscated. Either way, it's suspicious.
	if !parsed.UsedAST && identity != nil {
		// Enhanced regex: detect regproc casts, blocked functions, multi-statement
		if v := regexFallbackCheck(identity, query, operation, cfg, pid); v != nil {
			return v
		}
		// For non-permissive profiles, fail-closed on AST parse failure
		agentPolicy, agentExists := cfg.Agents[identity.AgentID]
		if agentExists {
			isPermissive := false
			if agentPolicy.Profile != "" {
				profile := ResolveProfile(agentPolicy.Profile, cfg)
				if profile != nil && profile.Name == "permissive" {
					isPermissive = true
				}
			}
			if !isPermissive {
				return &PolicyViolation{
					AgentID:   identity.AgentID,
					MissionID: identity.MissionID,
					Query:     truncateQuery(query),
					Reason:    "ast_parse_failed",
					Operation: operation,
					PID:       pid,
					Action:    "pending",
					Timestamp: time.Now(),
				}
			}
		}
	}

	// Unidentified connection — full query analysis, then policy decision
	if identity == nil {
		if cfg.Unidentified.Policy == "deny" {
			return &PolicyViolation{
				AgentID:   "unidentified",
				Query:     truncateQuery(query),
				Reason:    "unidentified_connection",
				Operation: operation,
				PID:       pid,
				Action:    "pending",
				Timestamp: time.Now(),
			}
		}

		// For monitor/allow: run full checks (blocked tables + global blocked functions)
		// Monitor: log specific violations; Allow: still enforce global blocklists

		// Check blocked tables for unidentified connections
		for _, table := range tables {
			if isTableBlocked(table, cfg.Unidentified.BlockedTables) {
				return &PolicyViolation{
					AgentID:   "unidentified",
					Query:     truncateQuery(query),
					Reason:    "blocked_table",
					Table:     table,
					Operation: operation,
					PID:       pid,
					Action:    "pending",
					Timestamp: time.Now(),
				}
			}
		}

		// Check global function blocklist for unidentified connections
		if len(cfg.BlockedFunctions) > 0 && len(functions) > 0 {
			for _, fn := range functions {
				fnLower := strings.ToLower(fn)
				if isFunctionBlocked(fnLower, cfg.BlockedFunctions) {
					return &PolicyViolation{
						AgentID:   "unidentified",
						Query:     truncateQuery(query),
						Reason:    "blocked_function:" + fn,
						Operation: operation,
						PID:       pid,
						Action:    "pending",
						Timestamp: time.Now(),
					}
				}
			}
		}

		// No specific violation found — log generic unidentified only in "log" mode
		// "monitor" mode: only logs actual violations (blocked table/function) above
		// "log" mode: logs every unidentified query for audit trail
		if cfg.Unidentified.Policy == "log" {
			return &PolicyViolation{
				AgentID:   "unidentified",
				Query:     truncateQuery(query),
				Reason:    "unidentified_connection_logged",
				Operation: operation,
				PID:       pid,
				Action:    "logged",
				Timestamp: time.Now(),
			}
		}

		// policy: allow or monitor with no violations
		return nil
	}

	agentPolicy, agentExists := cfg.Agents[identity.AgentID]

	// Agent not in policy
	if !agentExists {
		if cfg.DefaultPolicy == "deny" {
			return &PolicyViolation{
				AgentID:   identity.AgentID,
				MissionID: identity.MissionID,
				Query:     truncateQuery(query),
				Reason:    "agent_not_in_policy",
				Operation: operation,
				PID:       pid,
				Action:    "pending",
				Timestamp: time.Now(),
			}
		}
		return nil
	}

	// ── Profile-based operation checking (check ALL operations) ──
	if agentPolicy.Profile != "" {
		profile := ResolveProfile(agentPolicy.Profile, cfg)
		if profile == nil {
			log.Printf("Policy engine: unknown profile %q for agent %s, treating as permissive", agentPolicy.Profile, identity.AgentID)
		} else {
			for _, op := range operations {
				// Check UNKNOWN handling per profile
				if strings.EqualFold(op, "UNKNOWN") {
					if !profile.AllowUnknown {
						return &PolicyViolation{
							AgentID:   identity.AgentID,
							MissionID: identity.MissionID,
							Query:     truncateQuery(query),
							Reason:    "unrecognized_operation",
							Operation: op,
							PID:       pid,
							Action:    "pending",
							Timestamp: time.Now(),
						}
					}
				} else if isOperationBlockedByProfile(op, profile, agentPolicy.ProfileOverrides) {
					return &PolicyViolation{
						AgentID:   identity.AgentID,
						MissionID: identity.MissionID,
						Query:     truncateQuery(query),
						Reason:    "blocked_operation",
						Operation: op,
						PID:       pid,
						Action:    "pending",
						Timestamp: time.Now(),
					}
				}

				// Check profile conditions for each operation
				if v := checkConditions(profile.Conditions, op, query, identity, pid); v != nil {
					return v
				}
			}
		}
	} else {
		// ── Legacy: blocked_operations list (no profile) — check ALL operations ──
		for _, op := range operations {
			for _, blocked := range agentPolicy.BlockedOperations {
				if strings.EqualFold(op, blocked) {
					return &PolicyViolation{
						AgentID:   identity.AgentID,
						MissionID: identity.MissionID,
						Query:     truncateQuery(query),
						Reason:    "blocked_operation",
						Operation: op,
						PID:       pid,
						Action:    "pending",
						Timestamp: time.Now(),
					}
				}
			}

			// Legacy: default-deny for UNKNOWN when no profile is set
			if strings.EqualFold(op, "UNKNOWN") {
				return &PolicyViolation{
					AgentID:   identity.AgentID,
					MissionID: identity.MissionID,
					Query:     truncateQuery(query),
					Reason:    "unrecognized_operation",
					Operation: op,
					PID:       pid,
					Action:    "pending",
					Timestamp: time.Now(),
				}
			}
		}
	}

	// Check blocked tables (global for agent — applies regardless of profile)
	for _, table := range tables {
		if isTableBlocked(table, agentPolicy.BlockedTables) {
			return &PolicyViolation{
				AgentID:   identity.AgentID,
				MissionID: identity.MissionID,
				Query:     truncateQuery(query),
				Reason:    "blocked_table",
				Table:     table,
				Operation: operation,
				PID:       pid,
				Action:    "pending",
				Timestamp: time.Now(),
			}
		}
	}

	// Check blocked columns (per-table column denylist).
	//
	// Policy semantics: if a query references a table T listed in blocked_columns
	// AND any column name in parsed.Columns appears in blocked_columns[T], the
	// query is denied with reason "blocked_column:<table>.<col>". This catches:
	//
	//   SELECT ssn FROM users          → denied
	//   SELECT u.ssn FROM users u      → denied (parser extracts both "u" and "ssn")
	//   SELECT email FROM users WHERE ssn = ?  → denied (WHERE-clause references)
	//   UPDATE users SET ssn = ?       → denied (SET target)
	//
	// Behavior notes:
	//   - SELECT * does NOT trigger a column-level block by itself; the parser
	//     records no column names for the star target. Pair BlockedColumns with
	//     BlockedTables when the entire table is off-limits.
	//   - Multi-table queries that reference a blocked column name on any of the
	//     listed tables deny the whole query (fail-closed). Schema resolution is
	//     not performed — if an unqualified column name matches a blocklist
	//     entry for a referenced table, the query is denied even if the column
	//     actually originates from a different, un-listed table. This is the
	//     conservative choice for a security product.
	//   - Config keys may be unqualified ("users") or qualified ("public.users").
	//     Matching is case-insensitive and handles either form on either side.
	if len(agentPolicy.BlockedColumns) > 0 && len(parsed.Columns) > 0 {
		for blockedTable, blockedCols := range agentPolicy.BlockedColumns {
			if !isAnyTableReferenced(blockedTable, tables) {
				continue
			}
			for _, bc := range blockedCols {
				bcLower := strings.ToLower(bc)
				for _, qc := range parsed.Columns {
					if qc == bcLower {
						return &PolicyViolation{
							AgentID:   identity.AgentID,
							MissionID: identity.MissionID,
							Query:     truncateQuery(query),
							Reason:    "blocked_column:" + blockedTable + "." + bcLower,
							Table:     blockedTable,
							Operation: operation,
							PID:       pid,
							Action:    "pending",
							Timestamp: time.Now(),
						}
					}
				}
			}
		}
	}

	// Check mission policy
	//
	// Historical note (bug #3 from docs/compatibility.md, fixed Apr 27):
	// this block previously did `return nil` when the agent carried a mission
	// ID not present in their missions map AND default_policy != "deny".
	// That short-circuited the global function blocklist check further down,
	// letting any agent with an unknown mission bypass `blocked_functions`
	// entirely (e.g. SELECT pg_sleep(9999) with PGAPPNAME=agent:x:mission:any:token:Y).
	// Now we only run mission-scoped checks when a mission policy exists;
	// absence of a policy under default-allow just skips mission checks
	// and falls through to global checks (function blocklist, etc).
	if identity.MissionID != "" {
		missionPolicy, missionExists := agentPolicy.Missions[identity.MissionID]
		if !missionExists {
			if cfg.DefaultPolicy == "deny" {
				return &PolicyViolation{
					AgentID:   identity.AgentID,
					MissionID: identity.MissionID,
					Query:     truncateQuery(query),
					Reason:    "no_mission_policy",
					Operation: operation,
					PID:       pid,
					Action:    "pending",
					Timestamp: time.Now(),
				}
			}
			// default_policy=allow: skip mission-scoped checks but CONTINUE
			// through the rest of CheckQuery so global blocklists still apply.
		} else {
			// Check tables against mission allowed list
			if len(missionPolicy.Tables) > 0 {
				for _, table := range tables {
					if !isTableAllowed(table, missionPolicy.Tables) {
						return &PolicyViolation{
							AgentID:   identity.AgentID,
							MissionID: identity.MissionID,
							Query:     truncateQuery(query),
							Reason:    "table_not_in_mission",
							Table:     table,
							Operation: operation,
							PID:       pid,
							Action:    "pending",
							Timestamp: time.Now(),
						}
					}
				}
			}

			// Check mission conditions (for agents without profiles)
			if agentPolicy.Profile == "" {
				for _, op := range operations {
					if v := checkConditions(missionPolicy.Conditions, op, query, identity, pid); v != nil {
						return v
					}
				}
			}
		}
	}

	// ── Regproc cast detection (defense-in-depth: block OID-resolving casts) ──
	// Skip for permissive profile — it allows everything
	// Two-layer check: AST-based HasRegprocCast + raw string scan as fallback
	regprocDetected := parsed.HasRegprocCast
	if !regprocDetected {
		// Raw string fallback — catches deeply nested or obfuscated casts
		queryLower := strings.ToLower(query)
		if strings.Contains(queryLower, "::regproc") || strings.Contains(queryLower, "::regprocedure") {
			regprocDetected = true
		}
	}
	if regprocDetected {
		isPermissive := false
		if agentPolicy.Profile != "" {
			profile := ResolveProfile(agentPolicy.Profile, cfg)
			if profile != nil && profile.Name == "permissive" {
				isPermissive = true
			}
		}
		if !isPermissive {
			return &PolicyViolation{
				AgentID:   identity.AgentID,
				MissionID: identity.MissionID,
				Query:     truncateQuery(query),
				Reason:    "blocked_regproc_cast",
				Operation: operation,
				PID:       pid,
				Action:    "pending",
				Timestamp: time.Now(),
			}
		}
	}

	// ── Global function blocklist (checked last for most specific violation reason) ──
	if len(cfg.BlockedFunctions) > 0 && len(functions) > 0 {
		var agentAllowed map[string]bool
		if ap, ok := cfg.Agents[identity.AgentID]; ok && len(ap.AllowedFunctions) > 0 {
			agentAllowed = make(map[string]bool)
			for _, fn := range ap.AllowedFunctions {
				agentAllowed[strings.ToLower(fn)] = true
			}
		}

		for _, fn := range functions {
			fnLower := strings.ToLower(fn)
			if isFunctionBlocked(fnLower, cfg.BlockedFunctions) {
				if agentAllowed != nil && agentAllowed[fnLower] {
					continue
				}
				return &PolicyViolation{
					AgentID:   identity.AgentID,
					MissionID: identity.MissionID,
					Query:     truncateQuery(query),
					Reason:    "blocked_function:" + fn,
					Operation: operation,
					PID:       pid,
					Action:    "pending",
					Timestamp: time.Now(),
				}
			}
		}
	}

	// ── Allowed-fingerprint shortcut (MUST remain the last check) ──
	// A fingerprint match is additive-allow only: it can only pass a query that
	// cleared every deny check above. Moving this block earlier would let a known
	// fingerprint bypass blocked_tables, blocked_columns, blocked_functions, etc.
	if len(agentPolicy.AllowedFingerprints) > 0 {
		fp := FingerprintQuery(query)
		for _, rule := range agentPolicy.AllowedFingerprints {
			if rule.Hash == fp {
				return nil
			}
		}
	}

	return nil
}

// GetMaxRows returns the max_rows limit for an agent+mission (0 = unlimited).
func (pe *PolicyEngine) GetMaxRows(identity *AgentIdentity) int {
	if identity == nil {
		return 0
	}
	pe.mu.RLock()
	cfg := pe.config
	pe.mu.RUnlock()
	if cfg == nil {
		return 0
	}
	agentPolicy, exists := cfg.Agents[identity.AgentID]
	if !exists {
		return 0
	}
	if identity.MissionID != "" {
		if mission, ok := agentPolicy.Missions[identity.MissionID]; ok && mission.MaxRows > 0 {
			return mission.MaxRows
		}
	}
	// Check default mission
	if mission, ok := agentPolicy.Missions["default"]; ok && mission.MaxRows > 0 {
		return mission.MaxRows
	}
	return 0
}

// GetMaxQueryTimeMs returns the max_query_time_ms limit for an agent+mission (0 = unlimited).
func (pe *PolicyEngine) GetMaxQueryTimeMs(identity *AgentIdentity) int {
	if identity == nil {
		return 0
	}
	pe.mu.RLock()
	cfg := pe.config
	pe.mu.RUnlock()
	if cfg == nil {
		return 0
	}
	agentPolicy, exists := cfg.Agents[identity.AgentID]
	if !exists {
		return 0
	}
	if identity.MissionID != "" {
		if mission, ok := agentPolicy.Missions[identity.MissionID]; ok && mission.MaxQueryTimeMs > 0 {
			return mission.MaxQueryTimeMs
		}
	}
	if mission, ok := agentPolicy.Missions["default"]; ok && mission.MaxQueryTimeMs > 0 {
		return mission.MaxQueryTimeMs
	}
	return 0
}

// GetEnforcement returns the current enforcement mode safely.
func (pe *PolicyEngine) GetEnforcement() string {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return pe.enforcement
}

// EnforceOnConnection checks a live agent connection and takes action if violated
func (pe *PolicyEngine) EnforceOnConnection(db *sql.DB, conn AgentConnection) *PolicyViolation {
	if conn.Query == "" || conn.State != "active" {
		return nil
	}

	// Skip internal/system queries
	if isSystemQuery(conn.Query) {
		return nil
	}

	violation := pe.CheckQuery(conn.Identity, conn.Query, conn.PID)
	if violation == nil {
		return nil
	}

	// Set action based on enforcement mode
	if pe.GetEnforcement() == "enforce" {
		violation.Action = "blocked"
		// Try graceful cancel first
		var cancelled bool
		err := db.QueryRow("SELECT pg_cancel_backend($1)", conn.PID).Scan(&cancelled)
		if err != nil {
			log.Printf("Policy enforcement: pg_cancel_backend failed for pid %d: %v", conn.PID, err)
		} else if cancelled {
			log.Printf("Policy enforcement: cancelled pid %d (agent=%s, reason=%s)", conn.PID, violation.AgentID, violation.Reason)
		}
		// If cancel didn't work, escalate to terminate
		if !cancelled {
			_, err = db.Exec("SELECT pg_terminate_backend($1)", conn.PID)
			if err != nil {
				log.Printf("Policy enforcement: failed to terminate pid %d: %v", conn.PID, err)
			} else {
				log.Printf("Policy enforcement: terminated pid %d (agent=%s, reason=%s)", conn.PID, violation.AgentID, violation.Reason)
			}
		}
	} else {
		violation.Action = "monitored"
		log.Printf("Policy monitor: violation detected pid %d (agent=%s, reason=%s, query=%s)", conn.PID, violation.AgentID, violation.Reason, violation.Query)
	}

	pe.addViolation(*violation)

	return violation
}

// ── SQL Parsing (regex-based fallback for when AST fails) ──

// regprocRe matches regproc/regprocedure/regclass/regtype casts in raw SQL text
var regprocRe = regexp.MustCompile(`(?i)::\s*(?:regproc|regprocedure|regclass|regtype|regoper|regoperator)\b`)

// multiStmtDangerousRe matches a semicolon followed by dangerous operations
var multiStmtDangerousRe = regexp.MustCompile(`(?i);\s*(?:GRANT|REVOKE|DROP|TRUNCATE|ALTER|CREATE|DELETE|UPDATE|INSERT|COPY|DO|CALL)\b`)

// regexFallbackCheck performs enhanced security checks on raw SQL text when AST parsing fails.
// Returns a violation if suspicious patterns are found, nil otherwise.
func regexFallbackCheck(identity *AgentIdentity, query string, operation string, cfg *PolicyConfig, pid int) *PolicyViolation {
	upper := strings.ToUpper(query)

	// Check for regproc/regprocedure casts
	if regprocRe.MatchString(query) {
		return &PolicyViolation{
			AgentID:   identity.AgentID,
			MissionID: identity.MissionID,
			Query:     truncateQuery(query),
			Reason:    "blocked_regproc_cast",
			Operation: operation,
			PID:       pid,
			Action:    "pending",
			Timestamp: time.Now(),
		}
	}

	// Check for multi-statement with dangerous second statement
	if multiStmtDangerousRe.MatchString(query) {
		return &PolicyViolation{
			AgentID:   identity.AgentID,
			MissionID: identity.MissionID,
			Query:     truncateQuery(query),
			Reason:    "multi_statement_blocked",
			Operation: operation,
			PID:       pid,
			Action:    "pending",
			Timestamp: time.Now(),
		}
	}

	// Check for blocked functions in raw query text
	if len(cfg.BlockedFunctions) > 0 {
		// Extract potential function calls using a simple word boundary match
		queryLower := strings.ToLower(query)
		for _, blocked := range cfg.BlockedFunctions {
			blockedLower := strings.ToLower(blocked)
			if strings.HasSuffix(blockedLower, "*") {
				prefix := strings.TrimSuffix(blockedLower, "*")
				if strings.Contains(queryLower, prefix) {
					return &PolicyViolation{
						AgentID:   identity.AgentID,
						MissionID: identity.MissionID,
						Query:     truncateQuery(query),
						Reason:    "blocked_function:" + blocked,
						Operation: operation,
						PID:       pid,
						Action:    "pending",
						Timestamp: time.Now(),
					}
				}
			} else {
				// Check for function name followed by '(' or preceded by '.'
				if strings.Contains(queryLower, blockedLower+"(") ||
					strings.Contains(queryLower, "."+blockedLower+"(") ||
					strings.Contains(queryLower, "."+blockedLower+" ") {
					return &PolicyViolation{
						AgentID:   identity.AgentID,
						MissionID: identity.MissionID,
						Query:     truncateQuery(query),
						Reason:    "blocked_function:" + blocked,
						Operation: operation,
						PID:       pid,
						Action:    "pending",
						Timestamp: time.Now(),
					}
				}
			}
		}
	}

	// Check for blocked tables in raw query text
	agentPolicy, agentExists := cfg.Agents[identity.AgentID]
	if agentExists {
		for _, blocked := range agentPolicy.BlockedTables {
			blockedLower := strings.ToLower(blocked)
			if strings.HasSuffix(blockedLower, ".*") {
				prefix := strings.TrimSuffix(blockedLower, "*")
				if strings.Contains(strings.ToLower(query), prefix) {
					return &PolicyViolation{
						AgentID:   identity.AgentID,
						MissionID: identity.MissionID,
						Query:     truncateQuery(query),
						Reason:    "blocked_table",
						Table:     blocked,
						Operation: operation,
						PID:       pid,
						Action:    "pending",
						Timestamp: time.Now(),
					}
				}
			} else if strings.Contains(upper, strings.ToUpper(blocked)) {
				return &PolicyViolation{
					AgentID:   identity.AgentID,
					MissionID: identity.MissionID,
					Query:     truncateQuery(query),
					Reason:    "blocked_table",
					Table:     blocked,
					Operation: operation,
					PID:       pid,
					Action:    "pending",
					Timestamp: time.Now(),
				}
			}
		}
	}

	return nil
}

// ExtractSQLOperationRegex returns the SQL operation type using regex (fallback)
func ExtractSQLOperationRegex(query string) string {
	normalized := strings.TrimSpace(query)
	// Strip leading comments
	for strings.HasPrefix(normalized, "/*") {
		idx := strings.Index(normalized, "*/")
		if idx < 0 {
			break
		}
		normalized = strings.TrimSpace(normalized[idx+2:])
	}
	// Skip SET statements (e.g., SET application_name = ...; SELECT ...)
	upper := strings.ToUpper(normalized)
	if strings.HasPrefix(upper, "SET ") {
		// Find the next statement after semicolon
		idx := strings.Index(normalized, ";")
		if idx >= 0 && idx+1 < len(normalized) {
			normalized = strings.TrimSpace(normalized[idx+1:])
			upper = strings.ToUpper(normalized)
		}
	}

	for _, op := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE", "GRANT", "REVOKE", "COPY", "REASSIGN", "DO", "CALL", "EXPLAIN", "MERGE", "VACUUM", "REINDEX", "CLUSTER", "CHECKPOINT", "REFRESH", "IMPORT", "LOAD", "SET", "SHOW", "DISCARD", "PREPARE", "EXECUTE", "DEALLOCATE", "LISTEN", "UNLISTEN", "NOTIFY", "LOCK", "FETCH", "CLOSE", "DECLARE", "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT"} {
		if strings.HasPrefix(upper, op) {
			return op
		}
	}
	return "UNKNOWN"
}

var tableExtractRe = regexp.MustCompile(`(?i)\b(?:FROM|JOIN|INTO|UPDATE|TABLE)\s+([a-zA-Z_][a-zA-Z0-9_.]*(?:\s*,\s*[a-zA-Z_][a-zA-Z0-9_.]*)*)`)

// ExtractTablesRegex extracts table names from a SQL query using regex (fallback)
func ExtractTablesRegex(query string) []string {
	matches := tableExtractRe.FindAllStringSubmatch(query, -1)
	seen := make(map[string]bool)
	var tables []string

	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		// Split on commas for "FROM t1, t2" syntax
		parts := strings.Split(m[1], ",")
		for _, part := range parts {
			tbl := strings.TrimSpace(part)
			// Strip alias (take first word only)
			fields := strings.Fields(tbl)
			if len(fields) > 0 {
				tbl = fields[0]
			}
			tbl = strings.ToLower(tbl)
			// Skip known non-tables
			if tbl == "" || tbl == "set" || tbl == "values" || tbl == "(" {
				continue
			}
			if !seen[tbl] {
				seen[tbl] = true
				tables = append(tables, tbl)
			}
		}
	}
	return tables
}

// ── Helpers ──

// isTableBlocked reports whether the referenced table matches any blocked entry.
// Supports three match modes:
//   - Exact match: "public.users" == "public.users"
//   - Wildcard prefix: "pg_catalog.*" matches "pg_catalog.pg_user"
//   - Schema-agnostic bare-name match: "users" matches blocklist "public.users"
//     and "public.users" matches blocklist "users". Prevents the trivial bypass
//     where Postgres search_path resolution hides the schema.
func isTableBlocked(table string, blockedList []string) bool {
	tableLower := strings.ToLower(table)
	// Derive the unqualified leaf ("public.users" → "users", "users" → "users")
	tableLeaf := tableLower
	if idx := strings.LastIndex(tableLower, "."); idx >= 0 {
		tableLeaf = tableLower[idx+1:]
	}

	for _, blocked := range blockedList {
		blockedLower := strings.ToLower(blocked)
		if strings.HasSuffix(blockedLower, ".*") {
			// Wildcard: "pg_catalog.*" matches any pg_catalog.xxx
			prefix := strings.TrimSuffix(blockedLower, "*")
			if strings.HasPrefix(tableLower, prefix) {
				return true
			}
			continue
		}
		if tableLower == blockedLower {
			return true
		}
		// Schema-agnostic match: compare unqualified leaves in both directions.
		// Blocklist "public.users" → bare "users" (matches "FROM users"),
		// Blocklist "users" → bare "users" (matches "FROM public.users").
		blockedLeaf := blockedLower
		if idx := strings.LastIndex(blockedLower, "."); idx >= 0 {
			blockedLeaf = blockedLower[idx+1:]
		}
		if tableLeaf == blockedLeaf {
			return true
		}
	}
	return false
}

// isAnyTableReferenced reports whether the blocked_columns key `target` refers
// to any of the tables extracted from the query. Matching is case-insensitive
// and schema-agnostic: a config key of "users" matches a referenced
// "public.users", and a key of "public.users" matches a referenced "users".
// Used by the BlockedColumns enforcement in CheckQuery.
func isAnyTableReferenced(target string, referenced []string) bool {
	t := strings.ToLower(strings.TrimSpace(target))
	if t == "" {
		return false
	}
	tLeaf := t
	if idx := strings.LastIndex(t, "."); idx >= 0 {
		tLeaf = t[idx+1:]
	}
	for _, r := range referenced {
		rLower := strings.ToLower(r)
		if rLower == t {
			return true
		}
		rLeaf := rLower
		if idx := strings.LastIndex(rLower, "."); idx >= 0 {
			rLeaf = rLower[idx+1:]
		}
		if tLeaf == rLeaf {
			return true
		}
	}
	return false
}

func isTableAllowed(table string, allowedList []string) bool {
	tableLower := strings.ToLower(table)
	for _, allowed := range allowedList {
		// Mission tables use format "schema.table: [ops]" or just "schema.table"
		allowedClean := strings.Split(allowed, ":")[0]
		allowedClean = strings.TrimSpace(strings.ToLower(allowedClean))
		if tableLower == allowedClean {
			return true
		}
		// Also match without schema prefix
		if !strings.Contains(tableLower, ".") && strings.HasSuffix(allowedClean, "."+tableLower) {
			return true
		}
	}
	return false
}

func isSystemQuery(query string) bool {
	upper := strings.ToUpper(strings.TrimSpace(query))
	// For multi-statement queries (SET ...; SELECT ...), check the non-SET part
	if strings.HasPrefix(upper, "SET ") && strings.Contains(upper, ";") {
		idx := strings.Index(upper, ";")
		rest := strings.TrimSpace(upper[idx+1:])
		if rest != "" {
			return false // Has a real query after SET
		}
	}
	systemPrefixes := []string{
		"SET ", "SHOW ", "BEGIN", "COMMIT", "ROLLBACK",
		"RESET", "DEALLOCATE",
	}
	for _, prefix := range systemPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	// Skip pg_stat queries (our own polling)
	if strings.Contains(upper, "PG_STAT_") || strings.Contains(upper, "PG_DATABASE_SIZE") {
		return true
	}
	return false
}

func truncateQuery(q string) string {
	if len(q) > 200 {
		return q[:200] + "..."
	}
	return q
}

// isFunctionBlocked checks if a function name is in the blocklist.
// Supports wildcard prefix matching: "lo_*" matches "lo_export", "lo_import", etc.
func isFunctionBlocked(fn string, blockedList []string) bool {
	fnLower := strings.ToLower(fn)
	// Strip schema prefix for matching (pg_catalog.pg_sleep → pg_sleep)
	bareName := fnLower
	if idx := strings.LastIndex(fnLower, "."); idx >= 0 {
		bareName = fnLower[idx+1:]
	}
	for _, blocked := range blockedList {
		blockedLower := strings.ToLower(blocked)
		if strings.HasSuffix(blockedLower, "*") {
			// Wildcard prefix match: "pg_stat_get_*" matches "pg_stat_get_activity"
			prefix := strings.TrimSuffix(blockedLower, "*")
			if strings.HasPrefix(fnLower, prefix) || strings.HasPrefix(bareName, prefix) {
				return true
			}
		} else {
			// Exact match (existing behavior)
			if fnLower == blockedLower || bareName == blockedLower {
				return true
			}
		}
	}
	return false
}
