package main

// Control-plane APA proposal client.
//
// PRIVACY CONTRACT: this client ships ONLY a proposed policy YAML diff (a
// human-review artifact, never query/row data) plus metadata (agent id, title,
// confidence, diff line count) to the control plane's POST /v1/apa/propose.
// It deliberately has no field carrying observations, query text, bound params,
// or row data. apa_client_test.go asserts this via JSON marshaling.
//
// PERFORMANCE CONTRACT: APA is already an out-of-band reasoning loop (never on
// the query hot path). Even so, proposal upload happens on a background
// goroutine with a bounded timeout so a slow/hung control plane can't stall the
// APA cron cycle. Errors are logged and swallowed (fire-and-forget).

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/shreyasXV/faultwall/policygen/agent"
)

// apaProposalPayload is the request body for POST /v1/apa/propose.
// NOTE: there is intentionally NO field carrying observations or query content.
type apaProposalPayload struct {
	InstallationID string  `json:"installation_id"`
	AgentID        string  `json:"agent_id"`
	Title          string  `json:"title"`
	YAMLDiff       string  `json:"yaml_diff"`
	MergedYAML     string  `json:"merged_yaml"`
	Confidence     float64 `json:"confidence"`
	DiffLines      int     `json:"diff_lines"`
}

// APAProposalClient ships APA proposals to the control plane. It reuses the
// same ControlPlaneConfig (url + token) the telemetry client uses.
type APAProposalClient struct {
	cfg  ControlPlaneConfig
	http *http.Client
}

// NewAPAProposalClient builds a proposal client. Returns nil when the control
// plane is not configured (no url/token) so the sink becomes a no-op.
func NewAPAProposalClient(cfg ControlPlaneConfig) *APAProposalClient {
	if cfg.URL == "" || cfg.Token == "" {
		return nil
	}
	return &APAProposalClient{
		cfg:  cfg,
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

// Sink returns an agent.ProposalSink that uploads each proposal in the
// background. Safe to call on a nil client (returns a no-op sink).
func (c *APAProposalClient) Sink() agent.ProposalSink {
	if c == nil {
		return func(agent.ProposalReport) {}
	}
	return func(rep agent.ProposalReport) {
		// Off the cron-cycle goroutine; never blocks APA.
		go c.post(rep)
	}
}

// post ships a single proposal. Fire-and-forget: errors are logged, not returned.
func (c *APAProposalClient) post(rep agent.ProposalReport) {
	if c == nil {
		return
	}
	body, err := json.Marshal(apaProposalPayload{
		InstallationID: c.cfg.InstallationID,
		AgentID:        rep.AgentID,
		Title:          rep.Title,
		YAMLDiff:       rep.YAMLDiff,
		MergedYAML:     rep.MergedYAML,
		Confidence:     rep.Confidence,
		DiffLines:      rep.DiffLines,
	})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(c.cfg.URL, "/")+"/v1/apa/propose", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		log.Printf("apa propose upload failed (agent=%s): %v", rep.AgentID, err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		log.Printf("apa propose upload rejected (agent=%s): HTTP %d", rep.AgentID, resp.StatusCode)
	}
}
