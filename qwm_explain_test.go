package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shreyasXV/faultwall/policygen/agent"
)

// QWM flag explanation: under-load world-model path mentions predicted latency
// and the driving conditions, so the user sees what's wrong with their DB.
func TestExplainQWMFlag_LoadDriven(t *testing.T) {
	infra := QWMInfraState{ActiveBackends: 8, Utilization: 0.9, BlockedBackends: 2, LongestActiveMs: 6000}
	rec := QWMFlagRecord{
		PredictedMs: 22000, PBreach: 0.99,
		Conditions: &FlagConditions{BaseServiceMs: 150, CongestionX: 10},
	}
	pq := &ParsedQuery{Operation: "SELECT", Tables: []string{"public.orders"}}
	got := explainQWMFlag(pq, infra, rec, true)

	for _, want := range []string{"predicted", "22.0s", "lock", "busy"} {
		if !strings.Contains(strings.ToLower(got), strings.ToLower(want)) {
			t.Errorf("explanation missing %q; got: %s", want, got)
		}
	}
}

// Shape-fallback path explains the query shape when no world-model base exists.
func TestExplainQWMFlag_ShapeDriven(t *testing.T) {
	infra := QWMInfraState{ActiveBackends: 1, Utilization: 0.1}
	rec := QWMFlagRecord{}
	pq := &ParsedQuery{Operation: "DROP", Tables: []string{"public.users"}}
	got := explainQWMFlag(pq, infra, rec, false)
	if !strings.Contains(strings.ToLower(got), "shape") {
		t.Errorf("shape-driven explanation expected, got: %s", got)
	}
	if !strings.Contains(got, "DROP") {
		t.Errorf("explanation should name the operation, got: %s", got)
	}
}

// The flag record round-trips the conditions block (dashboard reads it).
func TestQWMFlagRecord_CarriesConditions(t *testing.T) {
	qwmFlagsMu.Lock()
	qwmFlags = nil
	qwmFlagsMu.Unlock()
	recordQWMFlag(QWMFlagRecord{
		Agent: "a", Query: "q", Score: 0.9,
		Reason:     "Database is busy",
		Conditions: &FlagConditions{ActiveBackends: 5, Utilization: 0.8, BlockedBackends: 1},
	})
	got := GetQWMFlags("")
	if len(got) != 1 || got[0].Conditions == nil {
		t.Fatal("conditions not preserved on flag record")
	}
	if got[0].Conditions.BlockedBackends != 1 {
		t.Errorf("blocked backends not preserved: %+v", got[0].Conditions)
	}
}

// Verify the local APA-proposals handler reads pending_review + audit from disk.
func TestHandleAPAProposals_ReadsLocalState(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policies.yaml")
	auditPath := filepath.Join(dir, "apa_audit.jsonl")
	os.Setenv("POLICY_FILE", policyPath)
	os.Setenv("APA_AUDIT_LOG", auditPath)
	defer os.Unsetenv("POLICY_FILE")
	defer os.Unsetenv("APA_AUDIT_LOG")

	policy := `version: 1
agents:
  rb:
    pending_review:
      - hash: deadbeef
        sql: "DELETE FROM orders"
        seen: 1
        verdict: pending
        reason: "write op"
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	audit := `{"run_id":"r1","timestamp":"2026-06-09T00:00:00Z","agent_id":"rb","provider":"litellm:bedrock-opus","pending_count":1,"confidence":0.82,"pr_url":"https://github.com/x/y/pull/1"}` + "\n"
	if err := os.WriteFile(auditPath, []byte(audit), 0o600); err != nil {
		t.Fatal(err)
	}

	// Exercise via the agent loaders the handler uses.
	view, err := agent.LoadAPAView(policyPath)
	if err != nil || len(view) != 1 || len(view[0].PendingReview) != 1 {
		t.Fatalf("expected 1 agent with 1 pending, got %v err=%v", view, err)
	}
	if view[0].PendingReview[0].Reason != "write op" {
		t.Errorf("pending reason not loaded: %+v", view[0].PendingReview[0])
	}
	runs, rerr := agent.LoadRecentAuditRecords(auditPath, 10)
	if rerr != nil || len(runs) != 1 || runs[0].PRURL == "" {
		t.Fatalf("expected 1 audit run with PR url, got %v err=%v", runs, rerr)
	}
}
