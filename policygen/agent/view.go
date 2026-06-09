package agent

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
)

// ── Local APA visibility (dashboard / GET /api/apa/proposals) ──
//
// The proxy doesn't run APA inline (apa run/sync are separate invocations), so a
// self-host user with no control plane and no PR setup couldn't SEE what APA is
// proposing. These exported readers let the proxy surface APA state from the two
// local artifacts: the policy file (current allowed/pending) and the audit log
// (recent APA runs). No network, no control plane required.

// AgentAPAView is the per-agent APA state exposed to the dashboard/API.
type AgentAPAView struct {
	AgentID             string            `json:"agent_id"`
	AllowedFingerprints []FingerprintView `json:"allowed_fingerprints"`
	PendingReview       []FingerprintView `json:"pending_review"`
	BlockedOperations   []string          `json:"blocked_operations,omitempty"`
	BlockedTables       []string          `json:"blocked_tables,omitempty"`
}

// FingerprintView is a JSON-friendly projection of a FingerprintRule.
type FingerprintView struct {
	Hash    string `json:"hash"`
	SQL     string `json:"sql"`
	Seen    int64  `json:"seen"`
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
}

func toFingerprintViews(rules []FingerprintRule) []FingerprintView {
	out := make([]FingerprintView, 0, len(rules))
	for _, r := range rules {
		out = append(out, FingerprintView{Hash: r.Hash, SQL: r.SQL, Seen: r.Seen, Verdict: r.Verdict, Reason: r.Reason})
	}
	return out
}

// LoadAPAView reads the policy file and returns per-agent APA state, sorted by
// agent id for stable output. Used by the local dashboard.
func LoadAPAView(policyPath string) ([]AgentAPAView, error) {
	agents, err := LoadAgentPolicies(policyPath)
	if err != nil {
		return nil, err
	}
	out := make([]AgentAPAView, 0, len(agents))
	for id, ap := range agents {
		out = append(out, AgentAPAView{
			AgentID:             id,
			AllowedFingerprints: toFingerprintViews(ap.AllowedFingerprints),
			PendingReview:       toFingerprintViews(ap.PendingReview),
			BlockedOperations:   ap.BlockedOperations,
			BlockedTables:       ap.BlockedTables,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AgentID < out[j].AgentID })
	return out, nil
}

// LoadRecentAuditRecords reads up to `limit` most-recent APA run records from the
// JSONL audit log (newest first). Missing file → empty slice, no error.
func LoadRecentAuditRecords(auditPath string, limit int) ([]AuditRecord, error) {
	f, err := os.Open(auditPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []AuditRecord{}, nil
		}
		return nil, err
	}
	defer f.Close()

	var recs []AuditRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var r AuditRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			continue // skip malformed lines
		}
		recs = append(recs, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	// newest first
	sort.Slice(recs, func(i, j int) bool { return recs[i].Timestamp.After(recs[j].Timestamp) })
	if limit > 0 && len(recs) > limit {
		recs = recs[:limit]
	}
	return recs, nil
}
