package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// FakeProvider is a deterministic Provider that returns a canned proposal.
// Used in tests and in --dry-run mode. Never makes network calls.
type FakeProvider struct {
	// Response allows callers to inject a custom response body.
	// If empty, the fake returns a valid minimal proposal for the first pending fingerprint.
	Response string
	// Err, if non-nil, is returned instead of generating a response.
	Err error
	// LastPrompt is set on every Reason() call for assertions in tests.
	LastPrompt Prompt
}

func newFakeProvider(_ APAConfig) *FakeProvider {
	return &FakeProvider{}
}

func (f *FakeProvider) Name() string { return "fake" }

func (f *FakeProvider) Reason(_ context.Context, p Prompt) (Response, error) {
	f.LastPrompt = p
	if f.Err != nil {
		return Response{}, f.Err
	}
	text := f.Response
	if text == "" {
		text = f.buildDefaultResponse(p)
	}
	return Response{
		Text:         text,
		InputTokens:  len(p.User) / 4,
		OutputTokens: len(text) / 4,
		LatencyMs:    1,
		ProviderID:   "fake",
	}, nil
}

func (f *FakeProvider) buildDefaultResponse(p Prompt) string {
	// Parse the agent_id from the prompt JSON so the response is consistent.
	var input struct {
		AgentID       string              `json:"agent_id"`
		WindowStart   time.Time           `json:"window_start"`
		WindowEnd     time.Time           `json:"window_end"`
		PendingReview []fingerprintEntry  `json:"pending_review"`
	}
	_ = json.Unmarshal([]byte(p.User), &input)
	agentID := input.AgentID
	if agentID == "" {
		agentID = "unknown"
	}

	fps := make([]string, 0, len(input.PendingReview))
	for _, e := range input.PendingReview {
		fps = append(fps, e.Hash)
	}

	wStart := input.WindowStart
	wEnd := input.WindowEnd
	if wStart.IsZero() {
		wStart = time.Now().Add(-time.Hour)
	}
	if wEnd.IsZero() {
		wEnd = time.Now()
	}

	prop := map[string]any{
		"schema":      ProposalSchema,
		"agent_id":    agentID,
		"window_start": wStart.Format(time.RFC3339),
		"window_end":   wEnd.Format(time.RFC3339),
		"summary":     fmt.Sprintf("Fake APA analysis for agent %s. All %d pending fingerprints reviewed. No anomalies detected by fake provider.", agentID, len(fps)),
		"clusters": []map[string]any{
			{
				"label":          "Pending fingerprints",
				"fingerprints":   fps,
				"recommendation": "pending",
				"reasoning":      "Fake provider: deferred to human review.",
			},
		},
		"proposed_policy_yaml_patch": "",
		"confidence":                 0.5,
		"requires_human_review":      true,
	}
	b, _ := json.Marshal(prop)
	return string(b)
}
