package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/shreyasXV/faultwall/policygen/agent"
)

// TestAPAProposalPayloadRedaction is the privacy guard for the APA propose
// client: the JSON shipped to /v1/apa/propose must carry ONLY a proposed YAML
// diff (a human-review artifact) plus metadata. No observations, query text,
// bound params, or row data may appear.
func TestAPAProposalPayloadRedaction(t *testing.T) {
	p := apaProposalPayload{
		InstallationID: "inst-1",
		AgentID:        "analytics",
		Title:          "promote 2 fingerprints",
		YAMLDiff:       "--- a/policies.yaml\n+++ b/policies.yaml\n+    allowed_fingerprints: [abc]",
		Confidence:     0.88,
		DiffLines:      3,
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	allowed := map[string]bool{
		"installation_id": true, "agent_id": true, "title": true,
		"yaml_diff": true, "confidence": true, "diff_lines": true,
	}
	for k := range m {
		if !allowed[k] {
			t.Errorf("UNEXPECTED apa proposal field %q — proposals must be metadata + diff only", k)
		}
	}

	// Defense in depth: no observation/query content fields.
	for _, forbidden := range []string{"query", "sql", "params", "rows", "row_data", "observations", "fingerprints", "sample"} {
		if _, ok := m[forbidden]; ok {
			t.Errorf("forbidden field %q present in apa proposal payload", forbidden)
		}
	}
}

// TestAPAProposalClientNilSafe ensures an unconfigured control plane yields a
// no-op sink (no panic, no network).
func TestAPAProposalClientNilSafe(t *testing.T) {
	c := NewAPAProposalClient(ControlPlaneConfig{}) // no url/token
	if c != nil {
		t.Fatal("expected nil client when control plane unconfigured")
	}
	sink := c.Sink() // must be safe on nil receiver
	// Must not panic.
	sink(agent.ProposalReport{AgentID: "x", YAMLDiff: "diff"})
}

// TestAPAProposalClientConfigured verifies a configured client builds a usable
// sink (we don't hit the network here; just exercise construction).
func TestAPAProposalClientConfigured(t *testing.T) {
	c := NewAPAProposalClient(ControlPlaneConfig{URL: "http://example.invalid", Token: "x", InstallationID: "i"})
	if c == nil {
		t.Fatal("expected non-nil client when url+token set")
	}
	if c.Sink() == nil {
		t.Fatal("sink should be non-nil")
	}
}

// TestProposalReportNoQueryFields confirms the agent->main report contract
// carries only diff + metadata.
func TestProposalReportNoQueryFields(t *testing.T) {
	rep := agent.ProposalReport{
		AgentID: "a", Title: "t", YAMLDiff: "diff", Confidence: 0.5, DiffLines: 2,
	}
	b, _ := json.Marshal(rep)
	for _, forbidden := range []string{"query", "sql", "observations", "rows"} {
		if strings.Contains(strings.ToLower(string(b)), "\""+forbidden+"\"") {
			t.Errorf("forbidden field %q present in ProposalReport", forbidden)
		}
	}
}
