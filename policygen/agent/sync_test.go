package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// F3: ClassifyObservations must deterministically route fingerprints.
func TestClassifyObservations_RoutesByRisk(t *testing.T) {
	now := time.Now()
	obs := []Observation{
		// Safe, repeated, read-only SELECT on a non-sensitive table → allowed.
		{AgentID: "rb", Fingerprint: "safe1", NormalizedSQL: "SELECT id FROM orders", Operation: "SELECT", Tables: []string{"public.orders"}, Count: 200, LastSeen: now},
		// Write op → pending.
		{AgentID: "rb", Fingerprint: "del1", NormalizedSQL: "DELETE FROM orders WHERE id=$1", Operation: "DELETE", Tables: []string{"public.orders"}, Count: 1, LastSeen: now},
		// Read on a sensitive table → pending.
		{AgentID: "rb", Fingerprint: "pii1", NormalizedSQL: "SELECT ssn FROM users", Operation: "SELECT", Tables: []string{"public.users"}, Count: 50, LastSeen: now},
		// Low-frequency novel read → pending.
		{AgentID: "rb", Fingerprint: "novel1", NormalizedSQL: "SELECT x FROM widgets", Operation: "SELECT", Tables: []string{"public.widgets"}, Count: 2, LastSeen: now},
		// Function call → pending.
		{AgentID: "rb", Fingerprint: "fn1", NormalizedSQL: "SELECT pg_read_file($1)", Operation: "SELECT", Functions: []string{"pg_read_file"}, Count: 99, LastSeen: now},
		// Previously blocked → pending.
		{AgentID: "rb", Fingerprint: "blk1", NormalizedSQL: "SELECT * FROM orders", Operation: "SELECT", Tables: []string{"public.orders"}, Count: 80, BlockedCount: 3, LastSeen: now},
	}

	got := ClassifyObservations(obs, map[string]agentPolicyYAML{})
	c := got["rb"]

	allowedHashes := hashesOf(c.Allowed)
	pendingHashes := hashesOf(c.Pending)

	if !allowedHashes["safe1"] {
		t.Error("safe repeated read should be auto-allowed")
	}
	for _, h := range []string{"del1", "pii1", "novel1", "fn1", "blk1"} {
		if !pendingHashes[h] {
			t.Errorf("%s should be routed to pending_review", h)
		}
		if allowedHashes[h] {
			t.Errorf("%s must NOT be auto-allowed", h)
		}
	}
}

// F3: already-classified fingerprints are not duplicated (idempotent).
func TestClassifyObservations_Idempotent(t *testing.T) {
	now := time.Now()
	obs := []Observation{
		{AgentID: "rb", Fingerprint: "safe1", Operation: "SELECT", Tables: []string{"public.orders"}, Count: 200, LastSeen: now},
	}
	current := map[string]agentPolicyYAML{
		"rb": {AllowedFingerprints: []FingerprintRule{{Hash: "safe1"}}},
	}
	got := ClassifyObservations(obs, current)
	if len(got) != 0 {
		t.Errorf("already-allowed fingerprint must not be re-proposed, got %+v", got)
	}
}

// F3 end-to-end: SyncPolicy writes pending_review/allowed_fingerprints into the
// policy file, and a follow-up sync is a no-op (idempotent).
func TestSyncPolicy_WritesAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policies.yaml")
	obsPath := filepath.Join(dir, "observations.jsonl")

	if err := os.WriteFile(policyPath, []byte("version: 1\ndefault_policy: deny\nagents: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	lines := strings.Join([]string{
		`{"schema":"faultwall.observation.v1","agent_id":"rb","fingerprint":"safe1","normalized_sql":"SELECT id FROM orders","operation":"SELECT","tables":["public.orders"],"count":200,"first_seen":"` + now + `","last_seen":"` + now + `"}`,
		`{"schema":"faultwall.observation.v1","agent_id":"rb","fingerprint":"del1","normalized_sql":"DELETE FROM orders","operation":"DELETE","tables":["public.orders"],"count":1,"first_seen":"` + now + `","last_seen":"` + now + `"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(obsPath, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := SyncPolicy(policyPath, obsPath, 24*time.Hour, false)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !res.Changed {
		t.Fatal("expected policy to change")
	}
	if res.AddedAllowed["rb"] != 1 || res.AddedPending["rb"] != 1 {
		t.Errorf("expected +1 allowed +1 pending, got allowed=%d pending=%d", res.AddedAllowed["rb"], res.AddedPending["rb"])
	}

	// The written policy must now parse with rb having both lists populated.
	policies, err := LoadAgentPolicies(policyPath)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(policies["rb"].AllowedFingerprints) != 1 {
		t.Errorf("expected 1 allowed fingerprint, got %d", len(policies["rb"].AllowedFingerprints))
	}
	if len(policies["rb"].PendingReview) != 1 {
		t.Errorf("expected 1 pending entry, got %d", len(policies["rb"].PendingReview))
	}

	// Second sync over the same observations is a no-op.
	res2, err := SyncPolicy(policyPath, obsPath, 24*time.Hour, false)
	if err != nil {
		t.Fatalf("sync2: %v", err)
	}
	if res2.Changed {
		t.Error("second sync over identical observations should be a no-op")
	}
}

func hashesOf(rules []FingerprintRule) map[string]bool {
	m := map[string]bool{}
	for _, r := range rules {
		m[r.Hash] = true
	}
	return m
}
