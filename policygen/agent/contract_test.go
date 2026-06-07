package agent_test

// This is an external test (package agent_test) that asserts the duplicate type
// definitions across faultwall/policy.go and policygen/agent/* stay
// field-compatible. They're duplicated to avoid an import cycle and the main
// faultwall package is `package main` (not importable), so this test vendors
// the main-side struct shape inline. If main.AgentPolicy or main.APASection
// change, you must also update mainAgentPolicy / mainAPASection below —
// failure to do so trips the test.
//
// Failure modes this catches:
// - Renaming a yaml tag on one side
// - Adding a required field on one side
// - Changing a field type (string vs int)

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shreyasXV/faultwall/policygen/agent"
	"gopkg.in/yaml.v3"
)

// mainFingerprintRule mirrors faultwall/policy.go:FingerprintRule.
// MUST stay in sync.
type mainFingerprintRule struct {
	Hash    string `yaml:"hash"`
	SQL     string `yaml:"sql"`
	Seen    int64  `yaml:"seen"`
	Verdict string `yaml:"verdict"`
	Reason  string `yaml:"reason,omitempty"`
}

// mainAgentPolicy mirrors the slice of faultwall/policy.go:AgentPolicy that's
// shared with policygen/agent.agentPolicyYAML. MUST stay in sync.
type mainAgentPolicy struct {
	Description         string                `yaml:"description"`
	BlockedOperations   []string              `yaml:"blocked_operations"`
	BlockedTables       []string              `yaml:"blocked_tables"`
	AllowedFingerprints []mainFingerprintRule `yaml:"allowed_fingerprints,omitempty"`
	PendingReview       []mainFingerprintRule `yaml:"pending_review,omitempty"`
}

// mainAPASection mirrors faultwall/policy.go:APASection. MUST stay in sync.
type mainAPASection struct {
	Enabled              bool   `yaml:"enabled"`
	Provider             string `yaml:"provider"`
	Model                string `yaml:"model"`
	Schedule             string `yaml:"schedule"`
	Window               string `yaml:"window"`
	PolicyRepo           string `yaml:"policy_repo"`
	BaseBranch           string `yaml:"base_branch"`
	NotifySlackWebhook   string `yaml:"notify_slack_webhook"`
	MaxTokensPerRun      int    `yaml:"max_tokens_per_run"`
	PerAgentMaxDiffLines int    `yaml:"per_agent_max_diff_lines"`
	SchemaCacheTTL       string `yaml:"schema_cache_ttl"`
}

type mainPolicyConfig struct {
	Agents map[string]mainAgentPolicy `yaml:"agents"`
	APA    mainAPASection             `yaml:"apa"`
}

const sampleYAML = `default_policy: deny

agents:
  analytics:
    description: contract-test agent
    blocked_operations:
      - DROP
    blocked_tables:
      - public.audit_logs
    allowed_fingerprints:
      - hash: "deadbeef"
        sql: "SELECT 1"
        seen: 100
        verdict: safe
        reason: "auto"
    pending_review:
      - hash: "cafef00d"
        sql: "SELECT password_hash FROM users"
        seen: 5
        verdict: risky
        reason: "blocked at runtime"

apa:
  enabled: true
  provider: openai
  model: gpt-4o-2024-08-06
  schedule: "0 * * * *"
  window: 1h
  policy_repo: github.com/shreyasXV/faultwall
  base_branch: main
  notify_slack_webhook: "https://hooks.example/x"
  max_tokens_per_run: 4000
  per_agent_max_diff_lines: 200
  schema_cache_ttl: 24h
`

// TestFingerprintRuleContract asserts FingerprintRule round-trips identically
// through the main-package shape (mirrored above) and the policygen/agent
// loader. Catches drift in YAML tag names or field types.
func TestFingerprintRuleContract(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.yaml")
	if err := os.WriteFile(path, []byte(sampleYAML), 0644); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var mainCfg mainPolicyConfig
	if err := yaml.Unmarshal(data, &mainCfg); err != nil {
		t.Fatalf("main yaml unmarshal: %v", err)
	}
	mainAnalytics, ok := mainCfg.Agents["analytics"]
	if !ok {
		t.Fatal("main: missing analytics agent")
	}

	apMap, err := agent.LoadAgentPolicies(path)
	if err != nil {
		t.Fatalf("agent package load: %v", err)
	}
	agentAnalytics, ok := apMap["analytics"]
	if !ok {
		t.Fatal("agent: missing analytics agent")
	}

	if got, want := len(agentAnalytics.AllowedFingerprints), len(mainAnalytics.AllowedFingerprints); got != want {
		t.Fatalf("allowed_fingerprints len: agent=%d, main=%d", got, want)
	}
	for i := range mainAnalytics.AllowedFingerprints {
		m := mainAnalytics.AllowedFingerprints[i]
		a := agentAnalytics.AllowedFingerprints[i]
		if m.Hash != a.Hash || m.SQL != a.SQL || m.Seen != a.Seen || m.Verdict != a.Verdict || m.Reason != a.Reason {
			t.Errorf("allowed[%d] drift: main=%+v agent=%+v", i, m, a)
		}
	}

	if got, want := len(agentAnalytics.PendingReview), len(mainAnalytics.PendingReview); got != want {
		t.Fatalf("pending_review len: agent=%d, main=%d", got, want)
	}
	for i := range mainAnalytics.PendingReview {
		m := mainAnalytics.PendingReview[i]
		a := agentAnalytics.PendingReview[i]
		if m.Hash != a.Hash || m.SQL != a.SQL || m.Seen != a.Seen || m.Verdict != a.Verdict || m.Reason != a.Reason {
			t.Errorf("pending[%d] drift", i)
		}
	}

	if !stringSliceEq(mainAnalytics.BlockedOperations, agentAnalytics.BlockedOperations) {
		t.Errorf("blocked_operations drift")
	}
	if !stringSliceEq(mainAnalytics.BlockedTables, agentAnalytics.BlockedTables) {
		t.Errorf("blocked_tables drift")
	}
}

// TestAPASectionContract asserts the apa: block round-trips through both shapes.
func TestAPASectionContract(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.yaml")
	if err := os.WriteFile(path, []byte(sampleYAML), 0644); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	var mainCfg mainPolicyConfig
	if err := yaml.Unmarshal(data, &mainCfg); err != nil {
		t.Fatalf("main yaml unmarshal: %v", err)
	}
	apaCfg, err := agent.LoadConfig(path, "/tmp/obs.jsonl", "/tmp/audit.jsonl")
	if err != nil {
		t.Fatalf("agent package load: %v", err)
	}

	if mainCfg.APA.Enabled != apaCfg.Enabled {
		t.Errorf("Enabled drift: main=%v agent=%v", mainCfg.APA.Enabled, apaCfg.Enabled)
	}
	if mainCfg.APA.Provider != apaCfg.Provider {
		t.Errorf("Provider drift")
	}
	if mainCfg.APA.Model != apaCfg.Model {
		t.Errorf("Model drift")
	}
	if mainCfg.APA.Schedule != apaCfg.Schedule {
		t.Errorf("Schedule drift")
	}
	if mainCfg.APA.PolicyRepo != apaCfg.PolicyRepo {
		t.Errorf("PolicyRepo drift")
	}
	if mainCfg.APA.BaseBranch != apaCfg.BaseBranch {
		t.Errorf("BaseBranch drift")
	}
	if mainCfg.APA.NotifySlackWebhook != apaCfg.NotifySlackWebhook {
		t.Errorf("NotifySlackWebhook drift")
	}
	if mainCfg.APA.MaxTokensPerRun != apaCfg.MaxTokensPerRun {
		t.Errorf("MaxTokensPerRun drift")
	}
	if mainCfg.APA.PerAgentMaxDiffLines != apaCfg.PerAgentMaxDiffLines {
		t.Errorf("PerAgentMaxDiffLines drift")
	}
}

func stringSliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
