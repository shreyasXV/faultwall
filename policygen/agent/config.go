package agent

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultMaxTokens    = 8000
	defaultDiffLines    = 200
	defaultSchemaCacheTTL = 24 * time.Hour
	defaultWindow       = time.Hour
	defaultSchedule     = "0 * * * *"
	defaultTemperature  = 0.2
)

// ProposalReport is the metadata + diff handed to a ProposalSink after APA
// computes a policy diff. It carries ONLY the proposed diff (a human-review
// artifact) plus metadata — never observation/query/row content.
type ProposalReport struct {
	AgentID    string
	Title      string
	YAMLDiff   string
	Confidence float64
	DiffLines  int
}

// ProposalSink, when set, is invoked (best-effort, off the hot path) with each
// computed proposal so an external system (e.g. the control plane) can record
// it for human review. It must never block APA or mutate policy. Errors are
// the sink's own concern; RunOnce ignores them.
type ProposalSink func(ProposalReport)

// APAConfig is the runtime configuration for one APA run or cron loop.
type APAConfig struct {
	Enabled              bool
	Provider             string        // "openai" | "anthropic" | "fake"
	Model                string
	Schedule             string        // cron expression, default hourly
	Window               time.Duration // observation look-back window
	PolicyRepo           string        // git repo APA opens PRs against
	BaseBranch           string        // PR target branch, default "main"
	NotifySlackWebhook   string
	MaxTokensPerRun      int
	PerAgentMaxDiffLines int
	SchemaCacheTTL       time.Duration
	ObservationPath      string // path to observations.jsonl
	PolicyPath           string // path to policies.yaml to diff against
	AuditLogPath         string

	// Sink, when non-nil, receives each computed proposal for external
	// recording (e.g. control-plane review queue). Set by the caller; not
	// loaded from YAML. Best-effort, off the hot path.
	Sink ProposalSink `yaml:"-"`
}

// apaYAML is the on-disk representation of the apa: section.
type apaYAML struct {
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

// policyFileAPA is the minimal slice of policies.yaml we need to read the apa: section.
type policyFileAPA struct {
	APA apaYAML `yaml:"apa"`
}

// LoadConfig reads the apa: section from policyPath and fills in defaults.
func LoadConfig(policyPath, observationPath, auditLogPath string) (APAConfig, error) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return APAConfig{}, fmt.Errorf("read policy file: %w", err)
	}
	var pf policyFileAPA
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return APAConfig{}, fmt.Errorf("parse policy yaml: %w", err)
	}
	s := pf.APA
	cfg := APAConfig{
		Enabled:              s.Enabled,
		Provider:             s.Provider,
		Model:                s.Model,
		Schedule:             s.Schedule,
		PolicyRepo:           s.PolicyRepo,
		BaseBranch:           s.BaseBranch,
		NotifySlackWebhook:   s.NotifySlackWebhook,
		MaxTokensPerRun:      s.MaxTokensPerRun,
		PerAgentMaxDiffLines: s.PerAgentMaxDiffLines,
		ObservationPath:      observationPath,
		PolicyPath:           policyPath,
		AuditLogPath:         auditLogPath,
	}
	if cfg.Schedule == "" {
		cfg.Schedule = defaultSchedule
	}
	if cfg.BaseBranch == "" {
		cfg.BaseBranch = "main"
	}
	if cfg.MaxTokensPerRun == 0 {
		cfg.MaxTokensPerRun = defaultMaxTokens
	}
	if cfg.PerAgentMaxDiffLines == 0 {
		cfg.PerAgentMaxDiffLines = defaultDiffLines
	}
	if s.Window != "" {
		cfg.Window, err = ParseWindow(s.Window)
		if err != nil {
			return APAConfig{}, fmt.Errorf("parse apa.window: %w", err)
		}
	} else {
		cfg.Window = defaultWindow
	}
	if s.SchemaCacheTTL != "" {
		cfg.SchemaCacheTTL, err = ParseWindow(s.SchemaCacheTTL)
		if err != nil {
			return APAConfig{}, fmt.Errorf("parse apa.schema_cache_ttl: %w", err)
		}
	} else {
		cfg.SchemaCacheTTL = defaultSchemaCacheTTL
	}
	return cfg, nil
}

// ParseWindow accepts Go duration strings ("1h", "30m") plus a "Nd" shorthand for N days.
func ParseWindow(s string) (time.Duration, error) {
	if len(s) > 1 && s[len(s)-1] == 'd' {
		var n int
		if _, err := fmt.Sscanf(s[:len(s)-1], "%d", &n); err == nil {
			return time.Duration(n) * 24 * time.Hour, nil
		}
	}
	return time.ParseDuration(s)
}
