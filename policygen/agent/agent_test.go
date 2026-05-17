package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestParseProposalValid verifies that the golden proposal file parses correctly.
func TestParseProposalValid(t *testing.T) {
	data, err := os.ReadFile("testdata/golden_proposal.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	p, err := parseProposal(string(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.AgentID != "analytics" {
		t.Errorf("agent_id: got %q, want %q", p.AgentID, "analytics")
	}
	if len(p.Clusters) != 2 {
		t.Errorf("clusters: got %d, want 2", len(p.Clusters))
	}
	if !p.RequiresHumanReview {
		t.Error("requires_human_review must be true")
	}
	if p.Confidence < 0 || p.Confidence > 1 {
		t.Errorf("confidence %f out of [0,1]", p.Confidence)
	}
}

func TestParseProposalWrongSchema(t *testing.T) {
	bad := `{"schema":"faultwall.apa.proposal.v99","agent_id":"x","summary":"x","requires_human_review":true}`
	_, err := parseProposal(bad)
	if err == nil {
		t.Error("expected error for wrong schema version")
	}
}

func TestParseProposalMissingAgentID(t *testing.T) {
	bad := `{"schema":"faultwall.apa.proposal.v1","summary":"x","requires_human_review":true}`
	_, err := parseProposal(bad)
	if err == nil {
		t.Error("expected error for missing agent_id")
	}
}

func TestParseProposalRequiresHumanReviewFalse(t *testing.T) {
	bad := `{"schema":"faultwall.apa.proposal.v1","agent_id":"x","summary":"x","requires_human_review":false}`
	_, err := parseProposal(bad)
	if err == nil {
		t.Error("expected error when requires_human_review=false")
	}
}

func TestParseProposalInvalidJSON(t *testing.T) {
	_, err := parseProposal("not json at all")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// TestFakeProviderReturnsValidProposal checks that the fake provider returns a
// proposal that passes schema validation.
func TestFakeProviderReturnsValidProposal(t *testing.T) {
	f := &FakeProvider{}
	pending := []FingerprintRule{
		{Hash: "abc", SQL: "SELECT 1", Seen: 5, Verdict: "unknown"},
	}
	now := time.Now()
	prompt := BuildPrompt("testAgent", pending, nil, now.Add(-time.Hour), now, 4000)
	resp, err := f.Reason(context.Background(), prompt)
	if err != nil {
		t.Fatalf("fake provider error: %v", err)
	}
	p, err := parseProposal(resp.Text)
	if err != nil {
		t.Fatalf("parse fake response: %v\nraw: %s", err, resp.Text)
	}
	if p.AgentID != "testAgent" {
		t.Errorf("agent_id: got %q, want %q", p.AgentID, "testAgent")
	}
	if !p.RequiresHumanReview {
		t.Error("requires_human_review must be true")
	}
}

// TestFakeProviderRecordsLastPrompt checks that LastPrompt is set after Reason().
func TestFakeProviderRecordsLastPrompt(t *testing.T) {
	f := &FakeProvider{}
	now := time.Now()
	prompt := BuildPrompt("agent1", nil, nil, now.Add(-time.Hour), now, 100)
	_, _ = f.Reason(context.Background(), prompt)
	if f.LastPrompt.MaxTokens != 100 {
		t.Errorf("LastPrompt.MaxTokens: got %d, want 100", f.LastPrompt.MaxTokens)
	}
}

// TestFakeProviderErrorPropagation checks that Err is returned.
func TestFakeProviderErrorPropagation(t *testing.T) {
	f := &FakeProvider{Err: fmt.Errorf("simulated failure")}
	_, err := f.Reason(context.Background(), Prompt{})
	if err == nil || !strings.Contains(err.Error(), "simulated failure") {
		t.Errorf("expected simulated failure, got %v", err)
	}
}

// TestRunOnceNoPending verifies that RunOnce returns empty when no agents have pending_review.
func TestRunOnceNoPending(t *testing.T) {
	policyPath := writeTempPolicy(t, `
default_policy: standard
agents:
  clean:
    profile: standard
apa:
  enabled: true
  provider: fake
  policy_repo: github.com/test/fw-policy
`)
	obsPath := filepath.Join(t.TempDir(), "observations.jsonl")
	cfg := APAConfig{
		Provider:             "fake",
		PolicyPath:           policyPath,
		ObservationPath:      obsPath,
		MaxTokensPerRun:      1000,
		PerAgentMaxDiffLines: 200,
		Window:               time.Hour,
		PolicyRepo:           "github.com/test/fw-policy",
	}
	urls, err := RunOnce(context.Background(), cfg)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(urls) != 0 {
		t.Errorf("expected no PRs, got %v", urls)
	}
}

// TestRunOnceFakePatchEmpty verifies that RunOnce with a fake provider that returns
// an empty patch does not attempt to open a PR.
func TestRunOnceFakePatchEmpty(t *testing.T) {
	policyPath := writeTempPolicy(t, `
default_policy: standard
agents:
  analytics:
    pending_review:
      - hash: "aaa"
        sql: "SELECT 1"
        seen: 5
        verdict: unknown
apa:
  enabled: true
  provider: fake
  policy_repo: github.com/test/fw-policy
`)
	cfg := APAConfig{
		Provider:             "fake",
		PolicyPath:           policyPath,
		ObservationPath:      filepath.Join(t.TempDir(), "observations.jsonl"),
		MaxTokensPerRun:      1000,
		PerAgentMaxDiffLines: 200,
		Window:               time.Hour,
		PolicyRepo:           "github.com/test/fw-policy",
	}
	// Fake provider returns empty patch by default → no PR opened.
	urls, err := RunOnce(context.Background(), cfg)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(urls) != 0 {
		t.Errorf("expected no PRs for empty patch, got %v", urls)
	}
}

// TestLoadAgentPolicies checks that pending_review entries are read correctly.
func TestLoadAgentPolicies(t *testing.T) {
	ap, err := LoadAgentPolicies("testdata/policies_base.yaml")
	if err != nil {
		t.Fatalf("LoadAgentPolicies: %v", err)
	}
	analytics, ok := ap["analytics"]
	if !ok {
		t.Fatal("expected analytics agent")
	}
	if len(analytics.PendingReview) != 3 {
		t.Errorf("pending_review: got %d, want 3", len(analytics.PendingReview))
	}
}

// TestParseWindowShorthand checks that "7d" is parsed as 7*24h.
func TestParseWindowShorthand(t *testing.T) {
	d, err := ParseWindow("7d")
	if err != nil {
		t.Fatalf("ParseWindow: %v", err)
	}
	if d != 7*24*time.Hour {
		t.Errorf("got %v, want %v", d, 7*24*time.Hour)
	}
}

func TestParseWindowStandardDuration(t *testing.T) {
	d, err := ParseWindow("2h30m")
	if err != nil {
		t.Fatalf("ParseWindow: %v", err)
	}
	if d != 2*time.Hour+30*time.Minute {
		t.Errorf("got %v, want 2h30m", d)
	}
}

// TestDiffTextEmpty checks that a file diffed against itself returns no changes.
func TestDiffTextNoDiff(t *testing.T) {
	policyPath := writeTempPolicy(t, "agents: {}\n")
	current, _ := os.ReadFile(policyPath)
	diff, err := DiffText(policyPath, current)
	if err != nil {
		t.Fatalf("DiffText: %v", err)
	}
	if CountDiffLines(diff) != 0 {
		t.Errorf("expected 0 diff lines for identical content, got %d\ndiff:\n%s", CountDiffLines(diff), diff)
	}
}

// TestBranchName checks branch name format and sanitisation.
func TestBranchName(t *testing.T) {
	t1 := time.Date(2026, 5, 17, 9, 30, 0, 0, time.UTC)
	name := BranchName("analytics", t1)
	if !strings.HasPrefix(name, "apa/proposal-") {
		t.Errorf("unexpected prefix: %s", name)
	}
	if strings.Contains(name, " ") {
		t.Errorf("branch name must not contain spaces: %s", name)
	}
}

// TestNewProviderFake checks that "fake" provider is constructable without env vars.
func TestNewProviderFake(t *testing.T) {
	p, err := NewProvider(APAConfig{Provider: "fake"})
	if err != nil {
		t.Fatalf("NewProvider fake: %v", err)
	}
	if p.Name() != "fake" {
		t.Errorf("expected name 'fake', got %q", p.Name())
	}
}

// TestNewProviderUnknown checks that an unknown provider string returns an error.
func TestNewProviderUnknown(t *testing.T) {
	_, err := NewProvider(APAConfig{Provider: "gopher"})
	if err == nil {
		t.Error("expected error for unknown provider")
	}
}

// writeTempPolicy creates a temp policies.yaml file and returns its path.
func writeTempPolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp policy: %v", err)
	}
	return path
}
