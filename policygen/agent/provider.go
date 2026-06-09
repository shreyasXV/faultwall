package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Provider is the minimal contract any LLM backend must satisfy.
// Concrete implementations live in openai.go / anthropic.go / fake.go.
type Provider interface {
	// Name returns a label used in logs and audit records.
	Name() string

	// Reason runs one inference call. The prompt is fully constructed by the
	// caller. No retries — the agent loop owns retry/backoff logic.
	Reason(ctx context.Context, p Prompt) (Response, error)
}

// Prompt is the fully-assembled input to a Provider.
type Prompt struct {
	System      string
	User        string
	MaxTokens   int
	Temperature float64
}

// Response is the raw result from a single Provider call.
type Response struct {
	Text         string
	InputTokens  int
	OutputTokens int
	LatencyMs    int
	ProviderID   string // e.g. "openai:gpt-4o-2024-08-06"
}

// ProposalSchema is the version sentinel every LLM response must carry.
const ProposalSchema = "faultwall.apa.proposal.v1"

// Proposal is the structured JSON the LLM must return.
// Anything that doesn't parse into this shape is rejected.
type Proposal struct {
	Schema              string    `json:"schema"`
	AgentID             string    `json:"agent_id"`
	WindowStart         time.Time `json:"window_start"`
	WindowEnd           time.Time `json:"window_end"`
	Summary             string    `json:"summary"`
	Clusters            []Cluster `json:"clusters"`
	ProposedPolicyPatch string    `json:"proposed_policy_yaml_patch"`
	Confidence          float64   `json:"confidence"`
	RequiresHumanReview bool      `json:"requires_human_review"`
}

// Cluster is one group of semantically similar fingerprints.
type Cluster struct {
	Label          string   `json:"label"`
	Fingerprints   []string `json:"fingerprints"`
	Recommendation string   `json:"recommendation"` // "approve_all_safe" | "deny" | "pending"
	Reasoning      string   `json:"reasoning"`
}

// parseProposal decodes and validates raw LLM text into a Proposal.
// Returns an error if the schema sentinel is wrong or required fields are empty.
func parseProposal(text string) (Proposal, error) {
	var p Proposal
	if err := json.Unmarshal([]byte(text), &p); err != nil {
		return Proposal{}, err
	}
	if p.Schema != ProposalSchema {
		return Proposal{}, fmt.Errorf("unexpected proposal schema %q (want %q)", p.Schema, ProposalSchema)
	}
	if p.AgentID == "" {
		return Proposal{}, fmt.Errorf("proposal missing agent_id")
	}
	if p.Summary == "" {
		return Proposal{}, fmt.Errorf("proposal missing summary")
	}
	// v1 hard constraint: requires_human_review must be true
	if !p.RequiresHumanReview {
		return Proposal{}, fmt.Errorf("proposal has requires_human_review=false — rejected in v1")
	}
	return p, nil
}

// NewProvider constructs the right Provider from the config.
func NewProvider(cfg APAConfig) (Provider, error) {
	switch cfg.Provider {
	case "openai":
		return newOpenAIProvider(cfg)
	case "litellm":
		return newLiteLLMProvider(cfg)
	case "anthropic":
		return newAnthropicProvider(cfg)
	case "fake", "":
		return newFakeProvider(cfg), nil
	default:
		return nil, fmt.Errorf("unknown provider %q — valid: openai, litellm, anthropic, fake", cfg.Provider)
	}
}
