package agent

import (
	"strings"
	"testing"
)

// TestApplyPatchAutoPrunesPromotedFromPending — invariant: if a fingerprint
// appears in the patch's allowed_fingerprints, it must be removed from that
// agent's pending_review (otherwise the merged YAML carries a stale duplicate).
//
// Surfaced by the RFC-002 E2E run on 2026-05-17 — the patch added
// abc123novel to allowed_fingerprints but the original pending_review entry
// remained, leaving the same hash in two lists at once.
func TestApplyPatchAutoPrunesPromotedFromPending(t *testing.T) {
	src := `agents:
  analytics:
    description: x
    blocked_operations:
      - DROP
    pending_review:
      - hash: keep1
        sql: "SELECT password_hash FROM users"
        seen: 5
        verdict: risky
      - hash: promoted
        sql: "SELECT count(*) FROM events GROUP BY day"
        seen: 78
        verdict: unknown
      - hash: keep2
        sql: "DROP TABLE events"
        seen: 1
        verdict: risky
`
	policyPath := writeTempPolicy(t, src)
	patch := `agents:
  analytics:
    allowed_fingerprints:
      - hash: promoted
        sql: "SELECT count(*) FROM events GROUP BY day"
        seen: 78
        verdict: safe
        reason: "auto-promoted by APA"
`
	merged, err := ApplyPatch(policyPath, patch)
	if err != nil {
		t.Fatalf("ApplyPatch: %v", err)
	}
	got := string(merged)
	t.Logf("merged:\n%s", got)

	// allowed_fingerprints must include the promoted hash.
	if !strings.Contains(got, "auto-promoted by APA") {
		t.Error("promoted entry missing from allowed_fingerprints")
	}

	// pending_review must NOT include the promoted hash anymore.
	// We do this by counting occurrences of "promoted" — should be exactly 1
	// (in allowed_fingerprints), not 2 (one in each list).
	if strings.Count(got, "hash: promoted") != 1 {
		t.Errorf("promoted hash should appear once (in allowed_fingerprints) — found %d occurrences\n%s",
			strings.Count(got, "hash: promoted"), got)
	}

	// The other pending entries must survive.
	if !strings.Contains(got, "hash: keep1") {
		t.Error("keep1 dropped from pending_review")
	}
	if !strings.Contains(got, "hash: keep2") {
		t.Error("keep2 dropped from pending_review")
	}
}

// TestApplyPatchAutoPruneDoesNotTouchOtherAgents — promoting a hash for agent A
// must not affect agent B's pending_review even if (extremely unlikely) the
// same hash exists for both.
func TestApplyPatchAutoPruneDoesNotTouchOtherAgents(t *testing.T) {
	src := `agents:
  agentA:
    pending_review:
      - hash: shared
        sql: "SELECT 1"
        seen: 5
        verdict: unknown
  agentB:
    pending_review:
      - hash: shared
        sql: "SELECT 1"
        seen: 5
        verdict: unknown
`
	policyPath := writeTempPolicy(t, src)
	patch := `agents:
  agentA:
    allowed_fingerprints:
      - hash: shared
        sql: "SELECT 1"
        seen: 5
        verdict: safe
`
	merged, err := ApplyPatch(policyPath, patch)
	if err != nil {
		t.Fatalf("ApplyPatch: %v", err)
	}
	got := string(merged)

	// agentA: shared was promoted → pending should be empty list (or section dropped).
	// agentB: shared must STILL be in pending_review.
	// Easiest assertion: shared appears exactly twice — once in agentA's allowed
	// and once in agentB's pending.
	if c := strings.Count(got, "hash: shared"); c != 2 {
		t.Errorf("expected 2 occurrences of 'hash: shared' (1 in agentA.allowed, 1 in agentB.pending), got %d\n%s", c, got)
	}
}
