package agent

import (
	"strings"
	"testing"
	"time"
)

func TestPromptSystemDefendsInjection(t *testing.T) {
	if !strings.Contains(systemPrompt, "prompt injection") {
		t.Error("system prompt must explicitly defend against prompt injection")
	}
	if !strings.Contains(systemPrompt, "untrusted") {
		t.Error("system prompt must label SQL strings as untrusted")
	}
}

func TestPromptRequiresHumanReviewInstructions(t *testing.T) {
	if !strings.Contains(systemPrompt, "requires_human_review") {
		t.Error("system prompt must mention requires_human_review")
	}
	if !strings.Contains(systemPrompt, "true") {
		t.Error("system prompt must instruct the LLM to always set requires_human_review=true")
	}
}

func TestBuildPromptContainsPendingFingerprints(t *testing.T) {
	ap := agentPolicyYAML{
		PendingReview: []FingerprintRule{
			{Hash: "abc123", SQL: "SELECT 1", Seen: 10, Verdict: "unknown"},
			{Hash: "def456", SQL: "DELETE FROM t WHERE id = $1", Seen: 2, Verdict: "risky"},
		},
	}
	now := time.Now()
	p := BuildPrompt("analytics", ap, nil, now.Add(-time.Hour), now, 4000)

	if !strings.Contains(p.User, "abc123") {
		t.Error("user prompt should contain fingerprint hash abc123")
	}
	if !strings.Contains(p.User, "def456") {
		t.Error("user prompt should contain fingerprint hash def456")
	}
	if !strings.Contains(p.User, "analytics") {
		t.Error("user prompt should contain agent_id")
	}
	if p.MaxTokens != 4000 {
		t.Errorf("max tokens: got %d, want 4000", p.MaxTokens)
	}
	if p.Temperature != defaultTemperature {
		t.Errorf("temperature: got %f, want %f", p.Temperature, defaultTemperature)
	}
}

// TestBuildPromptPopulatesCurrentPolicy verifies P0.2 fix: current_policy is
// non-empty when the agent has existing allowed_fingerprints or blocked_operations.
func TestBuildPromptPopulatesCurrentPolicy(t *testing.T) {
	ap := agentPolicyYAML{
		AllowedFingerprints: []FingerprintRule{
			{Hash: "existingfp", SQL: "SELECT 1", Verdict: "safe"},
		},
		BlockedOperations: []string{"DELETE"},
		PendingReview: []FingerprintRule{
			{Hash: "newpending", SQL: "SELECT 2", Verdict: "unknown"},
		},
	}
	now := time.Now()
	p := BuildPrompt("agent1", ap, nil, now.Add(-time.Hour), now, 4000)

	// The existing allowed fingerprint and blocked op must appear in current_policy.
	if !strings.Contains(p.User, "existingfp") {
		t.Error("current_policy.allowed_fingerprints should include existing fp hash")
	}
	if !strings.Contains(p.User, "DELETE") {
		t.Error("current_policy.blocked_operations should include DELETE")
	}
	// The pending review entry should also be present.
	if !strings.Contains(p.User, "newpending") {
		t.Error("pending_review should include the new fingerprint")
	}
}

func TestBuildPromptEnrichesFromObsIndex(t *testing.T) {
	ap := agentPolicyYAML{
		PendingReview: []FingerprintRule{
			{Hash: "aaa", SQL: "SELECT 1", Seen: 5, Verdict: "unknown"},
		},
	}
	obsIndex := map[string]Observation{
		"aaa": {
			Fingerprint: "aaa",
			Operation:   "SELECT",
			Tables:      []string{"events"},
			Count:       100,
		},
	}
	now := time.Now()
	p := BuildPrompt("agent1", ap, obsIndex, now.Add(-time.Hour), now, 4000)

	if !strings.Contains(p.User, "events") {
		t.Error("user prompt should contain table name from observation index")
	}
}

func TestSummarizePrompt(t *testing.T) {
	pending := []FingerprintRule{
		{Hash: "a", Verdict: "unknown"},
		{Hash: "b", Verdict: "unknown"},
		{Hash: "c", Verdict: "risky"},
	}
	s := SummarizePrompt("myagent", pending)
	if !strings.Contains(s, "myagent") {
		t.Error("summary should contain agent id")
	}
	if !strings.Contains(s, "3") {
		t.Error("summary should contain pending count")
	}
}
