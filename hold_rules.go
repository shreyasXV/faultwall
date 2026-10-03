package main

// hold_rules.go — policy `action: hold` (live-query approvals).
//
// A hold rule pauses a matching statement in the proxy until a human approves
// or denies it (dashboard, Slack, or the local API). Matching runs on the
// PARSED query (operation + target table), never on a regex over raw SQL:
//
//	approvals:
//	  timeout: 120s          # no decision in time => deny (default 120s)
//	  rules:
//	    - name: writes-to-orders
//	      action: hold
//	      agents: [support-agent]       # empty or "*" = every agent
//	      operations: [UPDATE, DELETE]  # empty = any operation; WRITE = INSERT/UPDATE/DELETE/MERGE/TRUNCATE
//	      tables: [orders]              # empty = any table; schema-agnostic leaf match
//
// For write statements the table is the statement's TARGET relation (the table
// being written), found by walking the full AST, so writes hidden in a CTE
// (`WITH x AS (UPDATE orders …) SELECT …`) or EXPLAIN ANALYZE are still held.
// Reads match against every referenced table.
//
// Holds apply in enforce mode. `mode: always` also applies them in monitor
// mode (used by `faultwall try --hold`), because an explicit hold rule is an
// opt-in to pausing.

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// ApprovalsConfig is the `approvals:` block of policies.yaml.
type ApprovalsConfig struct {
	Timeout     string     `yaml:"timeout,omitempty" json:"timeout,omitempty"`           // Go duration, e.g. "120s"
	Mode        string     `yaml:"mode,omitempty" json:"mode,omitempty"`                 // "" (enforce mode only) | "always"
	RedactQuery bool       `yaml:"redact_query,omitempty" json:"redact_query,omitempty"` // send only the literal-stripped query to the control plane
	Rules       []HoldRule `yaml:"rules,omitempty" json:"rules,omitempty"`
}

// HoldRule is one approval rule. Action must be "hold".
type HoldRule struct {
	Name       string   `yaml:"name,omitempty" json:"name,omitempty"`
	Action     string   `yaml:"action" json:"action"`
	Agents     []string `yaml:"agents,omitempty" json:"agents,omitempty"`
	Operations []string `yaml:"operations,omitempty" json:"operations,omitempty"`
	Tables     []string `yaml:"tables,omitempty" json:"tables,omitempty"`
}

// HoldMatch is why a statement is being held.
type HoldMatch struct {
	Rule      string   // rule name (or a generated description)
	Operation string   // the operation that matched, e.g. UPDATE
	Tables    []string // the table(s) that matched
}

func (r HoldRule) describe() string {
	if r.Name != "" {
		return r.Name
	}
	ops := "any"
	if len(r.Operations) > 0 {
		ops = strings.Join(r.Operations, ",")
	}
	tbl := "any table"
	if len(r.Tables) > 0 {
		tbl = strings.Join(r.Tables, ",")
	}
	return fmt.Sprintf("hold %s on %s", ops, tbl)
}

// writeOps is what the WRITE alias expands to.
var writeOps = []string{"INSERT", "UPDATE", "DELETE", "MERGE", "TRUNCATE"}

// envHoldRules / envHoldMode come from FW_HOLD_RULES (or `try --hold`).
var (
	envHoldRules []HoldRule
	envHoldMode  string
)

// parseHoldSpec parses the compact rule syntax used by FW_HOLD_RULES and
// `faultwall try --hold`:
//
//	OPS[:TABLES][@AGENTS] ; OPS[:TABLES][@AGENTS] ; ...
//
// e.g. "UPDATE,DELETE:orders"  "WRITE@support-agent"  "DELETE:orders,payments@a,b"
func parseHoldSpec(spec string) ([]HoldRule, error) {
	var out []HoldRule
	for _, part := range strings.Split(spec, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		r := HoldRule{Action: "hold", Name: part}
		if at := strings.LastIndex(part, "@"); at >= 0 {
			r.Agents = splitList(part[at+1:])
			part = part[:at]
		}
		if c := strings.Index(part, ":"); c >= 0 {
			r.Tables = splitList(part[c+1:])
			part = part[:c]
		}
		for _, op := range splitList(part) {
			op = strings.ToUpper(op)
			if op == "*" || op == "ANY" {
				r.Operations = nil
				break
			}
			r.Operations = append(r.Operations, op)
		}
		if len(r.Operations) == 0 && len(r.Tables) == 0 && strings.TrimSpace(part) == "" {
			return nil, fmt.Errorf("hold rule %q: need operations and/or tables", r.Name)
		}
		out = append(out, r)
	}
	return out, nil
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func init() {
	if spec := os.Getenv("FW_HOLD_RULES"); spec != "" {
		rules, err := parseHoldSpec(spec)
		if err == nil {
			envHoldRules = rules
		}
	}
	envHoldMode = os.Getenv("FW_HOLD_MODE")
}

// holdRules returns the active rules (policy file + env) and mode.
func holdRules(pe *PolicyEngine) ([]HoldRule, string) {
	var rules []HoldRule
	mode := envHoldMode
	if pe != nil {
		if cfg := pe.GetConfig(); cfg != nil {
			for _, r := range cfg.Approvals.Rules {
				if strings.EqualFold(r.Action, "hold") {
					rules = append(rules, r)
				}
			}
			if mode == "" {
				mode = cfg.Approvals.Mode
			}
		}
	}
	rules = append(rules, envHoldRules...)
	return rules, mode
}

// holdsEnforced reports whether matching statements are actually paused
// (true) or only logged as "would hold" (false, monitor mode).
func holdsEnforced(pe *PolicyEngine, mode string) bool {
	return strings.EqualFold(mode, "always") || (pe != nil && pe.GetEnforcement() == "enforce")
}

// holdTimeout resolves the decision timeout: FW_HOLD_TIMEOUT > policy > 120s.
func holdTimeout(pe *PolicyEngine) time.Duration {
	parse := func(s string) time.Duration {
		s = strings.TrimSpace(s)
		if s == "" {
			return 0
		}
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			return d
		}
		return 0
	}
	if d := parse(os.Getenv("FW_HOLD_TIMEOUT")); d > 0 {
		return d
	}
	if pe != nil {
		if cfg := pe.GetConfig(); cfg != nil {
			if d := parse(cfg.Approvals.Timeout); d > 0 {
				return d
			}
		}
	}
	return 120 * time.Second
}

func holdRedactQuery(pe *PolicyEngine) bool {
	if v := os.Getenv("FW_HOLD_REDACT_QUERY"); v != "" {
		return v == "1" || strings.EqualFold(v, "true")
	}
	if pe != nil {
		if cfg := pe.GetConfig(); cfg != nil {
			return cfg.Approvals.RedactQuery
		}
	}
	return false
}

// holdAction is one (operation, table) pair a statement performs.
type holdAction struct {
	Op    string
	Table string // "" when the operation touches no table
}

// holdActions lists what a query does, for rule matching. Writes use the
// target relation from a full AST walk (catches data-modifying CTEs, EXPLAIN
// ANALYZE, PREPARE … AS UPDATE); everything else uses the parser's
// operations × referenced tables. If the AST walk fails we fall back to the
// coarse operations × tables product, which can only hold MORE, never less.
func holdActions(query string, pq *ParsedQuery) []holdAction {
	var acts []holdAction
	var tables []string
	var ops []string
	if pq != nil {
		tables = pq.Tables
		ops = pq.Operations
		if len(ops) == 0 && pq.Operation != "" {
			ops = []string{pq.Operation}
		}
	}
	walked := false
	if js, err := pg_query.ParseToJSON(stripLeadingSET(sanitizeQuery(query))); err == nil {
		var tree interface{}
		if json.Unmarshal([]byte(js), &tree) == nil {
			walked = true
			walkWrites(tree, &acts)
		}
	}
	isWrite := map[string]bool{"INSERT": true, "UPDATE": true, "DELETE": true, "MERGE": true}
	for _, op := range ops {
		if walked && isWrite[op] {
			continue // covered by the AST walk with its precise target
		}
		if len(tables) == 0 {
			acts = append(acts, holdAction{Op: op})
			continue
		}
		for _, t := range tables {
			acts = append(acts, holdAction{Op: op, Table: t})
		}
	}
	return acts
}

var writeStmtKeys = map[string]string{
	"InsertStmt": "INSERT", "UpdateStmt": "UPDATE", "DeleteStmt": "DELETE", "MergeStmt": "MERGE",
}

func walkWrites(n interface{}, acts *[]holdAction) {
	switch v := n.(type) {
	case map[string]interface{}:
		for k, child := range v {
			if op, ok := writeStmtKeys[k]; ok {
				tbl := ""
				if m, ok := child.(map[string]interface{}); ok {
					if rel, ok := m["relation"].(map[string]interface{}); ok {
						name, _ := rel["relname"].(string)
						schema, _ := rel["schemaname"].(string)
						tbl = strings.ToLower(name)
						if schema != "" {
							tbl = strings.ToLower(schema) + "." + tbl
						}
					}
				}
				*acts = append(*acts, holdAction{Op: op, Table: tbl})
			}
			walkWrites(child, acts)
		}
	case []interface{}:
		for _, c := range v {
			walkWrites(c, acts)
		}
	}
}

func ruleAppliesToAgent(r HoldRule, agentID string) bool {
	if len(r.Agents) == 0 {
		return true
	}
	for _, a := range r.Agents {
		if a == "*" || strings.EqualFold(a, agentID) {
			return true
		}
	}
	return false
}

func ruleOpMatches(r HoldRule, op string) bool {
	if len(r.Operations) == 0 {
		return true
	}
	for _, want := range r.Operations {
		want = strings.ToUpper(want)
		if want == op || want == "*" || want == "ANY" {
			return true
		}
		if want == "WRITE" {
			for _, w := range writeOps {
				if w == op {
					return true
				}
			}
		}
	}
	return false
}

// matchHoldRules evaluates rules against a query. agentID is the identified
// agent ("" for unidentified connections; those only match agent-less rules
// or "*").
func matchHoldRules(rules []HoldRule, agentID, query string, pq *ParsedQuery) *HoldMatch {
	if len(rules) == 0 || strings.TrimSpace(query) == "" {
		return nil
	}
	var acts []holdAction
	computed := false
	for _, r := range rules {
		if !ruleAppliesToAgent(r, agentID) {
			continue
		}
		if !computed {
			acts = holdActions(query, pq)
			computed = true
		}
		var hit *HoldMatch
		for _, a := range acts {
			if !ruleOpMatches(r, a.Op) {
				continue
			}
			if len(r.Tables) > 0 && (a.Table == "" || !isTableBlocked(a.Table, r.Tables)) {
				continue
			}
			if hit == nil {
				hit = &HoldMatch{Rule: r.describe(), Operation: a.Op}
			}
			if a.Table != "" && !containsStr(hit.Tables, a.Table) {
				hit.Tables = append(hit.Tables, a.Table)
			}
		}
		if hit != nil {
			return hit
		}
	}
	return nil
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
