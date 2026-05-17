package agent

import "gopkg.in/yaml.v3"

// FingerprintRule mirrors faultwall/policy.go:FingerprintRule.
// Field names and YAML tags must stay in sync with the main package.
type FingerprintRule struct {
	Hash    string `yaml:"hash"`
	SQL     string `yaml:"sql"`
	Seen    int64  `yaml:"seen"`
	Verdict string `yaml:"verdict"`
	Reason  string `yaml:"reason,omitempty"`
}

// agentPolicyYAML is the minimal slice of an AgentPolicy we need to read
// pending_review and allowed_fingerprints for APA reasoning.
type agentPolicyYAML struct {
	AllowedFingerprints []FingerprintRule `yaml:"allowed_fingerprints"`
	PendingReview       []FingerprintRule `yaml:"pending_review"`
	BlockedOperations   []string          `yaml:"blocked_operations"`
	BlockedTables       []string          `yaml:"blocked_tables"`
}

// policyFileAgents is the slice of policies.yaml we parse to find agent sections.
type policyFileAgents struct {
	Agents map[string]agentPolicyYAML `yaml:"agents"`
}

// LoadAgentPolicies reads policyPath and returns a map of agentID → agentPolicyYAML.
func LoadAgentPolicies(policyPath string) (map[string]agentPolicyYAML, error) {
	data, err := readFileBytes(policyPath)
	if err != nil {
		return nil, err
	}
	var pf policyFileAgents
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, err
	}
	if pf.Agents == nil {
		pf.Agents = make(map[string]agentPolicyYAML)
	}
	return pf.Agents, nil
}
