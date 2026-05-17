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

// APAConfig is the runtime configuration for one APA run or cron loop.
type APAConfig struct {
	Enabled              bool
	Provider             string        // "openai" | "anthropic" | "fake"
	Model                string
	Schedule             string        // cron expression, default hourly
	Window               time.Duration // observation look-back window
	PolicyRepo           string        // git repo APA opens PRs against
	NotifySlackWebhook   string
	MaxTokensPerRun      int
	PerAgentMaxDiffLines int
	SchemaCacheTTL       time.Duration
	ObservationPath      string // path to observations.jsonl
	PolicyPath           string // path to policies.yaml to diff against
	AuditLogPath         string
}

// apaYAML is the on-disk representation of the apa: section.
type apaYAML struct {
	Enabled              bool   `yaml:"enabled"`
	Provider             string `yaml:"provider"`
	Model                string `yaml:"model"`
	Schedule             string `yaml:"schedule"`
	Window               string `yaml:"window"`
	PolicyRepo           string `yaml:"policy_repo"`
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
