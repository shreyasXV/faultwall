package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
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
	// Real LLM responses (esp. Claude Opus via Bedrock/Anthropic) often wrap the
	// JSON in a ```json … ``` fence or surrounding prose. Extract the outermost
	// JSON object before unmarshalling. No-op for already-clean JSON.
	cleaned := extractJSONObject(text)
	if err := json.Unmarshal([]byte(cleaned), &p); err != nil {
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
	// F5: the proposed YAML patch must conform to the real policy schema, or a
	// reviewer could approve a proposal that silently fails to enforce.
	if p.ProposedPolicyPatch != "" {
		if err := validateProposalPatch(p.ProposedPolicyPatch); err != nil {
			return Proposal{}, fmt.Errorf("proposed_policy_yaml_patch rejected: %w", err)
		}
	}
	return p, nil
}

// extractJSONObject strips Markdown code fences and any surrounding prose,
// returning the substring from the first "{" to the last "}". If no braces are
// found it returns the trimmed input unchanged (json.Unmarshal then reports the
// real error). Safe for input that is already a bare JSON object.
func extractJSONObject(s string) string {
	trimmed := strings.TrimSpace(s)
	// Strip a leading ```json / ``` fence and its closing fence if present.
	if strings.HasPrefix(trimmed, "```") {
		if nl := strings.IndexByte(trimmed, '\n'); nl >= 0 {
			trimmed = trimmed[nl+1:]
		}
		if idx := strings.LastIndex(trimmed, "```"); idx >= 0 {
			trimmed = trimmed[:idx]
		}
		trimmed = strings.TrimSpace(trimmed)
	}
	start := strings.IndexByte(trimmed, '{')
	end := strings.LastIndexByte(trimmed, '}')
	if start >= 0 && end > start {
		return trimmed[start : end+1]
	}
	return trimmed
}

// proposalPatchSchema is the strict shape APA is allowed to emit in
// proposed_policy_yaml_patch. It mirrors the engine's AgentPolicy exactly.
// Unknown keys (e.g. the invented "blocked_fingerprints") are rejected by
// KnownFields(true), and fingerprint entries must be objects, not bare strings —
// both failure modes observed in the 2026-06-08 E2E run (finding F5).
type proposalPatchSchema struct {
	Agents map[string]struct {
		AllowedFingerprints []FingerprintRule `yaml:"allowed_fingerprints"`
		PendingReview       []FingerprintRule `yaml:"pending_review"`
		BlockedOperations   []string          `yaml:"blocked_operations"`
		BlockedTables       []string          `yaml:"blocked_tables"`
		Profile             string            `yaml:"profile"`
		AuthToken           string            `yaml:"auth_token"`
		Missions            map[string]struct {
			Tables []string `yaml:"tables"`
		} `yaml:"missions"`
	} `yaml:"agents"`
}

// validateProposalPatch parses the YAML patch with strict key checking so a
// proposal that invents fields or uses bare-string fingerprints is rejected
// loudly rather than merged into a policy that silently does not enforce.
func validateProposalPatch(patch string) error {
	var s proposalPatchSchema
	dec := yaml.NewDecoder(strings.NewReader(patch))
	dec.KnownFields(true) // reject unknown keys like blocked_fingerprints
	if err := dec.Decode(&s); err != nil {
		// io.EOF means an empty patch — treated as no-op upstream, allow it.
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("patch does not match AgentPolicy schema (bare-string fingerprints or unknown field?): %w", err)
	}
	// Belt-and-suspenders: every fingerprint entry must carry a non-empty hash.
	for agentID, ap := range s.Agents {
		for _, fp := range append(ap.AllowedFingerprints, ap.PendingReview...) {
			if strings.TrimSpace(fp.Hash) == "" {
				return fmt.Errorf("agent %q has a fingerprint entry with no hash — must be {hash, sql, seen, verdict}", agentID)
			}
		}
	}
	return nil
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
