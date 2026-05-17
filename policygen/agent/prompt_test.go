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
	pending := []FingerprintRule{
		{Hash: "abc123", SQL: "SELECT 1", Seen: 10, Verdict: "unknown"},
		{Hash: "def456", SQL: "DELETE FROM t WHERE id = $1", Seen: 2, Verdict: "risky"},
	}
	now := time.Now()
	p := BuildPrompt("analytics", pending, nil, now.Add(-time.Hour), now, 4000)

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

func TestBuildPromptEnrichesFromObsIndex(t *testing.T) {
	pending := []FingerprintRule{
		{Hash: "aaa", SQL: "SELECT 1", Seen: 5, Verdict: "unknown"},
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
	p := BuildPrompt("agent1", pending, obsIndex, now.Add(-time.Hour), now, 4000)

	// Observation data should appear in the user prompt
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
