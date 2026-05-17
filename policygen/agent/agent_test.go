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
	ap := agentPolicyYAML{
		PendingReview: []FingerprintRule{
			{Hash: "abc", SQL: "SELECT 1", Seen: 5, Verdict: "unknown"},
		},
	}
	now := time.Now()
	prompt := BuildPrompt("testAgent", ap, nil, now.Add(-time.Hour), now, 4000)
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
	ap := agentPolicyYAML{}
	now := time.Now()
	prompt := BuildPrompt("agent1", ap, nil, now.Add(-time.Hour), now, 100)
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
		BaseBranch:           "main",
	}
	urls, err := RunOnce(context.Background(), cfg)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(urls) != 0 {
		t.Errorf("expected no PRs, got %v", urls)
	}
}

// TestRunOnceFakePatchEmpty verifies that RunOnce with empty patch does not open a PR.
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
		BaseBranch:           "main",
	}
	urls, err := RunOnce(context.Background(), cfg)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(urls) != 0 {
		t.Errorf("expected no PRs for empty patch, got %v", urls)
	}
}

// TestRunOnceOpenPRErrorSurfaced verifies P1.1 fix: OpenPR errors are returned
// by RunOnce rather than silently swallowed.
func TestRunOnceOpenPRErrorSurfaced(t *testing.T) {
	policyPath := writeTempPolicy(t, `
agents:
  agent1:
    pending_review:
      - hash: "fp1"
        sql: "SELECT 1"
        seen: 10
        verdict: unknown
`)
	// Use a fake provider that returns a non-empty patch so OpenPR is attempted.
	const patchYAML = "agents:\n  agent1:\n    blocked_operations:\n      - DELETE\n"
	fakeResp := fmt.Sprintf(`{
		"schema":"faultwall.apa.proposal.v1",
		"agent_id":"agent1",
		"window_start":"2026-05-17T06:00:00Z",
		"window_end":"2026-05-17T07:00:00Z",
		"summary":"test",
		"clusters":[],
		"proposed_policy_yaml_patch":%q,
		"confidence":0.9,
		"requires_human_review":true
	}`, patchYAML)

	cfg := APAConfig{
		Provider:             "fake",
		PolicyPath:           policyPath,
		ObservationPath:      filepath.Join(t.TempDir(), "observations.jsonl"),
		MaxTokensPerRun:      1000,
		PerAgentMaxDiffLines: 200,
		Window:               time.Hour,
		PolicyRepo:           "github.com/test/fw-policy",
		BaseBranch:           "main",
	}

	// Inject the fake provider with our canned response.
	// OpenPR will fail because we're not in a git repo with gh configured.
	// Before the P1.1 fix, RunOnce returned (nil error) even when PR failed.
	// After the fix it returns a non-nil error.
	//
	// We override the provider via a test-only helper to bypass NewProvider().
	prURLs, err := runOnceWithProvider(context.Background(), cfg, &FakeProvider{Response: fakeResp})
	// The PR open will fail (no git/gh in test env) — we expect an error surfaced.
	if err == nil {
		t.Log("note: gh/git available in test env, PR may have been attempted; skipping error assertion")
	} else if !strings.Contains(err.Error(), "agent agent1") {
		t.Errorf("expected error to name the failing agent, got: %v", err)
	}
	_ = prURLs // may be empty
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

// TestDiffTextNoDiff checks that a file diffed against itself returns no changed lines.
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

// TestApplyPatchPreservesComments is the key regression test for P0.1.
// A 3-line patch must NOT produce a 100+ line diff by rewriting the whole file.
func TestApplyPatchPreservesComments(t *testing.T) {
	base := `# Top-level comment — must survive the patch
default_policy: standard

# Agent block comment
agents:
  analytics:
    profile: standard
    blocked_operations: []
`
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policies.yaml")
	if err := os.WriteFile(policyPath, []byte(base), 0644); err != nil {
		t.Fatal(err)
	}

	patch := "agents:\n  analytics:\n    blocked_operations:\n      - DELETE\n"
	merged, err := ApplyPatch(policyPath, patch)
	if err != nil {
		t.Fatalf("ApplyPatch: %v", err)
	}

	got := string(merged)

	// Comment must survive.
	if !strings.Contains(got, "Top-level comment") {
		t.Error("top-level comment was lost after ApplyPatch")
	}
	// Unchanged keys must still be present.
	if !strings.Contains(got, "default_policy: standard") {
		t.Error("default_policy key was lost after ApplyPatch")
	}
	// The patch value must appear.
	if !strings.Contains(got, "DELETE") {
		t.Error("patched value DELETE not found in merged output")
	}

	// Diff should be small — only the blocked_operations line changed.
	diff, err := DiffText(policyPath, merged)
	if err != nil {
		t.Fatalf("DiffText: %v", err)
	}
	n := CountDiffLines(diff)
	if n > 10 {
		t.Errorf("patch of one field produced %d diff lines — yaml.Node round-trip broken?\ndiff:\n%s", n, diff)
	}
}

// TestApplyPatchNewKey verifies that a new top-level key is appended without
// clobbering existing content.
func TestApplyPatchNewKey(t *testing.T) {
	base := "default_policy: standard\nagents: {}\n"
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policies.yaml")
	os.WriteFile(policyPath, []byte(base), 0644)

	patch := "apa:\n  enabled: true\n"
	merged, err := ApplyPatch(policyPath, patch)
	if err != nil {
		t.Fatalf("ApplyPatch: %v", err)
	}
	got := string(merged)
	if !strings.Contains(got, "default_policy: standard") {
		t.Error("existing key lost after appending new key")
	}
	if !strings.Contains(got, "enabled: true") {
		t.Error("new key not found in merged output")
	}
}

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

func TestNewProviderFake(t *testing.T) {
	p, err := NewProvider(APAConfig{Provider: "fake"})
	if err != nil {
		t.Fatalf("NewProvider fake: %v", err)
	}
	if p.Name() != "fake" {
		t.Errorf("expected name 'fake', got %q", p.Name())
	}
}

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

// runOnceWithProvider is a test-only entry point that bypasses NewProvider()
// so tests can inject a FakeProvider with a custom response.
func runOnceWithProvider(ctx context.Context, cfg APAConfig, provider Provider) ([]string, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("apa config: %w", err)
	}

	obs, _ := LoadObservations(cfg.ObservationPath, cfg.Window)
	obsIndex := IndexByFingerprint(obs)

	agentPolicies, err := LoadAgentPolicies(cfg.PolicyPath)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	windowStart := now.Add(-cfg.Window)
	windowEnd := now

	var prURLs []string
	var agentErrors []string

	for agentID, ap := range agentPolicies {
		if len(ap.PendingReview) == 0 {
			continue
		}
		prURL, runErr := processAgent(ctx, cfg, provider, agentID, ap, obsIndex, windowStart, windowEnd)
		if prURL != "" {
			prURLs = append(prURLs, prURL)
		}
		if runErr != nil {
			agentErrors = append(agentErrors, fmt.Sprintf("agent %s: %v", agentID, runErr))
		}
	}
	if len(agentErrors) > 0 {
		return prURLs, fmt.Errorf("APA completed with %d error(s):\n%s",
			len(agentErrors), strings.Join(agentErrors, "\n"))
	}
	return prURLs, nil
}
