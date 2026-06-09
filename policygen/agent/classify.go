package agent

import (
	"sort"
	"strings"
)

// ── F3: deterministic observation classifier ──
//
// The proxy writes observations.jsonl; APA reasons over agents.<id>.pending_review
// in the policy. Nothing bridged the two, so `apa run` on a clean install always
// reported "nothing to do". This classifier is that bridge (wired to `apa sync`):
// it turns observed fingerprints into allowed_fingerprints (safe, repeated,
// read-only on non-sensitive tables) or pending_review (everything that needs a
// human/LLM look). It is deterministic — no LLM — so the same input always yields
// the same classification, satisfying the RFC-001 dependency RFC-002 assumes.

// classifyDefaults are the thresholds the classifier uses. Kept as a struct so
// `apa sync` can expose them as flags later without touching call sites.
type classifyDefaults struct {
	// MinSeenToAutoAllow is the minimum aggregate count before a safe read-only
	// SELECT is auto-promoted to allowed_fingerprints. Below this it stays
	// pending (novel / low-confidence).
	MinSeenToAutoAllow int64
}

var defaultClassify = classifyDefaults{MinSeenToAutoAllow: 20}

// writeOps and ddlOps are operations that are never auto-allowed — they always
// route to pending_review for explicit review.
var writeOps = map[string]struct{}{
	"INSERT": {}, "UPDATE": {}, "DELETE": {}, "MERGE": {}, "UPSERT": {},
}
var ddlOps = map[string]struct{}{
	"DROP": {}, "ALTER": {}, "CREATE": {}, "TRUNCATE": {}, "GRANT": {}, "REVOKE": {},
	"COPY": {}, // COPY can exfiltrate to/from files — treat as risky
}

// sensitiveTableHints are substrings that mark a table as PII/credential-bearing.
// A read on one of these is never auto-allowed; it goes to pending_review so a
// human/LLM decides. Deliberately broad — false-positive pending is safe; a
// false-positive allow is not.
var sensitiveTableHints = []string{
	"user", "users", "account", "customer", "payment", "card", "credential",
	"secret", "token", "session", "password", "auth", "ssn", "message",
	"pii", "person", "patient", "employee", "salary", "bank",
}

// Classification is the per-agent output of the classifier: which observed
// fingerprints should be auto-allowed vs. routed to pending_review.
type Classification struct {
	Allowed []FingerprintRule
	Pending []FingerprintRule
}

// ClassifyObservations groups observations by agent and classifies each
// fingerprint deterministically. `current` is the existing per-agent policy so
// we never re-propose already-allowed fingerprints and never duplicate pending
// entries. Returns map[agentID]Classification containing only NEW entries to add.
func ClassifyObservations(obs []Observation, current map[string]agentPolicyYAML) map[string]Classification {
	out := make(map[string]Classification)

	for _, o := range obs {
		ap := current[o.AgentID]

		// Skip anything already approved or already pending — idempotent.
		if fingerprintInRules(o.Fingerprint, ap.AllowedFingerprints) ||
			fingerprintInRules(o.Fingerprint, ap.PendingReview) {
			continue
		}

		rule := FingerprintRule{
			Hash: o.Fingerprint,
			SQL:  o.NormalizedSQL,
			Seen: o.Count,
		}

		c := out[o.AgentID]
		if reason, safe := isAutoAllowable(o); safe {
			rule.Verdict = "allow"
			c.Allowed = append(c.Allowed, rule)
		} else {
			rule.Verdict = "pending"
			rule.Reason = reason
			c.Pending = append(c.Pending, rule)
		}
		out[o.AgentID] = c
	}

	// Deterministic ordering (by hash) so output/diffs are stable.
	for id, c := range out {
		sortRules(c.Allowed)
		sortRules(c.Pending)
		out[id] = c
	}
	return out
}

// isAutoAllowable returns (reason, true) when an observed fingerprint is a safe,
// repeated, read-only SELECT on non-sensitive tables that has never been blocked.
// Otherwise it returns (reason-for-pending, false).
func isAutoAllowable(o Observation) (string, bool) {
	op := strings.ToUpper(strings.TrimSpace(o.Operation))

	if _, isWrite := writeOps[op]; isWrite {
		return "write operation (" + op + ") — requires review", false
	}
	if _, isDDL := ddlOps[op]; isDDL {
		return "DDL/privileged operation (" + op + ") — requires review", false
	}
	if op != "SELECT" {
		return "non-SELECT operation (" + op + ") — requires review", false
	}
	if o.BlockedCount > 0 {
		return "fingerprint has prior blocked executions — requires review", false
	}
	if len(o.Functions) > 0 {
		return "calls function(s) " + strings.Join(o.Functions, ",") + " — requires review", false
	}
	for _, t := range o.Tables {
		if isSensitiveTable(t) {
			return "touches sensitive table " + t + " — requires review", false
		}
	}
	if o.Count < defaultClassify.MinSeenToAutoAllow {
		return "novel / low-frequency read (seen < auto-allow threshold) — requires review", false
	}
	return "", true
}

// isSensitiveTable reports whether a table name (schema-qualified or bare)
// contains a sensitive hint. Match is on the unqualified leaf, substring-based.
func isSensitiveTable(table string) bool {
	t := strings.ToLower(table)
	if idx := strings.LastIndex(t, "."); idx >= 0 {
		t = t[idx+1:]
	}
	for _, hint := range sensitiveTableHints {
		if strings.Contains(t, hint) {
			return true
		}
	}
	return false
}

func fingerprintInRules(hash string, rules []FingerprintRule) bool {
	for _, r := range rules {
		if r.Hash == hash {
			return true
		}
	}
	return false
}

func sortRules(rules []FingerprintRule) {
	sort.Slice(rules, func(i, j int) bool { return rules[i].Hash < rules[j].Hash })
}
