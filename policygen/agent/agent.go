// Package agent implements RFC-002 Autonomous Policy Agent (APA).
//
// APA is an out-of-band reasoning loop that watches observations.jsonl, clusters
// pending_review fingerprints, and proposes policy diffs as git PRs for human review.
//
// The proxy hot-path is never touched. LLMs are only called from this package,
// never from policy.go or proxy.go.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RunOnce executes one full APA cycle: load → reason → diff → PR → audit.
// It processes every agent that has non-empty pending_review entries.
// Returns the list of PR URLs opened (may be empty if nothing was pending).
func RunOnce(ctx context.Context, cfg APAConfig) ([]string, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("apa config: %w", err)
	}

	provider, err := NewProvider(cfg)
	if err != nil {
		return nil, fmt.Errorf("create provider: %w", err)
	}
	log.Printf("[apa] provider=%s policy=%s observations=%s", provider.Name(), cfg.PolicyPath, cfg.ObservationPath)

	// Load observations within the window.
	obs, err := LoadObservations(cfg.ObservationPath, cfg.Window)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("load observations: %w", err)
	}
	obsIndex := IndexByFingerprint(obs)

	// Load current agent policies (pending_review + allowed_fingerprints).
	agentPolicies, err := LoadAgentPolicies(cfg.PolicyPath)
	if err != nil {
		return nil, fmt.Errorf("load agent policies: %w", err)
	}

	now := time.Now().UTC()
	windowStart := now.Add(-cfg.Window)
	windowEnd := now

	var prURLs []string
	var agentErrors []string
	anyPending := false

	for agentID, ap := range agentPolicies {
		if len(ap.PendingReview) == 0 {
			continue
		}
		anyPending = true

		log.Printf("[apa] processing agent=%s pending=%d", agentID, len(ap.PendingReview))

		prURL, runErr := processAgent(ctx, cfg, provider, agentID, ap, obsIndex, windowStart, windowEnd)
		if prURL != "" {
			prURLs = append(prURLs, prURL)
		}
		if runErr != nil {
			log.Printf("[apa] agent=%s error: %v", agentID, runErr)
			agentErrors = append(agentErrors, fmt.Sprintf("agent %s: %v", agentID, runErr))
		}
	}

	if !anyPending {
		log.Println("[apa] nothing to do — no agents have pending_review entries")
	}
	if len(agentErrors) > 0 {
		return prURLs, fmt.Errorf("APA completed with %d error(s):\n%s",
			len(agentErrors), strings.Join(agentErrors, "\n"))
	}
	return prURLs, nil
}

// processAgent runs one agent through the full reason → diff → PR → audit cycle.
func processAgent(
	ctx context.Context,
	cfg APAConfig,
	provider Provider,
	agentID string,
	ap agentPolicyYAML,
	obsIndex map[string]Observation,
	windowStart, windowEnd time.Time,
) (prURL string, _ error) {
	runID := RunID(agentID, time.Now())
	rec := AuditRecord{
		RunID:        runID,
		Timestamp:    time.Now().UTC(),
		AgentID:      agentID,
		Provider:     provider.Name(),
		WindowStart:  windowStart,
		WindowEnd:    windowEnd,
		PendingCount: len(ap.PendingReview),
	}
	defer func() {
		if err := AuditLog(cfg.AuditLogPath, rec); err != nil {
			log.Printf("[apa] audit log error: %v", err)
		}
	}()

	// Build and send prompt.
	prompt := BuildPrompt(agentID, ap, obsIndex, windowStart, windowEnd, cfg.MaxTokensPerRun)
	log.Printf("[apa] calling provider for %s", SummarizePrompt(agentID, ap.PendingReview))

	resp, err := provider.Reason(ctx, prompt)
	if err != nil {
		rec.Error = err.Error()
		return "", fmt.Errorf("provider.Reason: %w", err)
	}
	rec.InputTokens = resp.InputTokens
	rec.OutputTokens = resp.OutputTokens
	rec.LatencyMs = resp.LatencyMs

	// Parse and validate LLM output. Retry once on parse failure with a
	// corrective instruction appended — the original code re-sent the identical
	// prompt, so a model that ignored the schema failed identically twice
	// (E2E finding F4). Echoing the parse error nudges the model to comply.
	proposal, err := parseProposal(resp.Text)
	if err != nil {
		log.Printf("[apa] parse failed (attempt 1): %v — retrying with corrective prompt", err)
		retryPrompt := prompt
		retryPrompt.System = prompt.System + fmt.Sprintf(
			"\n\nYOUR PREVIOUS RESPONSE FAILED TO PARSE: %v\n"+
				"Respond with ONE raw JSON object and nothing else (no code fence, no prose). "+
				"\"schema\" MUST be the string value \"%s\" (a value, not a key). "+
				"Follow the OUTPUT FORMAT and patch schema rules exactly.",
			err, ProposalSchema)
		resp, err = provider.Reason(ctx, retryPrompt)
		if err != nil {
			rec.Error = "retry: " + err.Error()
			return "", fmt.Errorf("provider.Reason retry: %w", err)
		}
		rec.InputTokens += resp.InputTokens
		rec.OutputTokens += resp.OutputTokens
		proposal, err = parseProposal(resp.Text)
		if err != nil {
			rec.Error = "parse: " + err.Error()
			return "", fmt.Errorf("parse proposal: %w", err)
		}
	}
	rec.Confidence = proposal.Confidence

	// Skip PR if the patch is empty.
	if proposal.ProposedPolicyPatch == "" {
		log.Printf("[apa] agent=%s confidence=%.2f — no patch proposed (all pending)", agentID, proposal.Confidence)
		return "", nil
	}

	// Apply patch and compute diff.
	merged, err := ApplyPatch(cfg.PolicyPath, proposal.ProposedPolicyPatch)
	if err != nil {
		rec.Error = "patch: " + err.Error()
		return "", fmt.Errorf("apply patch: %w", err)
	}

	diffText, err := DiffText(cfg.PolicyPath, merged)
	if err != nil {
		log.Printf("[apa] diff generation warning: %v", err)
		diffText = ""
	}

	if n := CountDiffLines(diffText); n > cfg.PerAgentMaxDiffLines {
		rec.Error = fmt.Sprintf("diff too large (%d lines > %d limit)", n, cfg.PerAgentMaxDiffLines)
		return "", fmt.Errorf("diff too large for agent %s: %d lines (limit %d)", agentID, n, cfg.PerAgentMaxDiffLines)
	}

	// Report the proposal to an external sink (e.g. control-plane review queue)
	// if one is configured. Best-effort and decoupled: we ship ONLY the diff (a
	// human-review artifact) + metadata, never observations/query content. A
	// panicking or slow sink must not break the APA run, so we guard it.
	if cfg.Sink != nil {
		title := fmt.Sprintf("apa: policy proposal for agent %s (confidence %.0f%%)", agentID, proposal.Confidence*100)
		reportProposalSafe(cfg.Sink, ProposalReport{
			AgentID:    agentID,
			Title:      title,
			YAMLDiff:   diffText,
			Confidence: proposal.Confidence,
			DiffLines:  CountDiffLines(diffText),
			MergedYAML: string(merged),
		})
	}

	// File-drop mode: when no git repo is configured, APA does not open a PR.
	// The proposal has already been persisted via the sink above (a downloadable,
	// apply-ready YAML for review). This is the self-host, no-git review path.
	if cfg.PolicyRepo == "" {
		log.Printf("[apa] agent=%s confidence=%.2f — proposal recorded (file-drop mode, no PR)", agentID, proposal.Confidence)
		return "", nil
	}

	// Open git PR.
	branch := BranchName(agentID, time.Now())
	title := fmt.Sprintf("apa: policy proposal for agent %s (confidence %.0f%%)", agentID, proposal.Confidence*100)
	body := PRBody(proposal, resp, runID, diffText)

	prResult, err := OpenPR(PRRequest{
		BranchName: branch,
		Title:      title,
		Body:       body,
		PolicyPath: cfg.PolicyPath,
		NewContent: merged,
		BaseBranch: cfg.BaseBranch,
		RepoDir:    cfg.PolicyRepo,
	})
	if err != nil {
		rec.Error = "pr: " + err.Error()
		return "", fmt.Errorf("open PR for agent %s: %w", agentID, err)
	}

	rec.PRURL = prResult.URL
	log.Printf("[apa] PR opened: %s (agent=%s confidence=%.2f)", prResult.URL, agentID, proposal.Confidence)

	if cfg.NotifySlackWebhook != "" {
		notifySlack(cfg.NotifySlackWebhook, agentID, prResult.URL, proposal.Confidence)
	}

	return prResult.URL, nil
}

// validateConfig checks that the required config fields are present.
func validateConfig(cfg APAConfig) error {
	if cfg.PolicyPath == "" {
		return fmt.Errorf("policy_path is required")
	}
	// APA needs a review destination: either a git repo (PR mode) or a
	// proposal directory (file-drop mode). File-drop satisfies RFC-002 §3.8's
	// intent (no silent in-place mutation; every change is a reviewable
	// artifact) without requiring gh/git.
	if cfg.PolicyRepo == "" && cfg.ProposalDir == "" && cfg.Provider != "fake" {
		return fmt.Errorf("apa needs a review destination: set policy_repo (PR mode) or proposal_dir (file-drop mode) in the apa: section")
	}
	return nil
}

// notifySlack sends a one-line Slack notification about a new APA PR.
func notifySlack(webhookURL, agentID, prURL string, confidence float64) {
	msg := fmt.Sprintf(`{"text":"🤖 APA proposal for agent *%s* (confidence %.0f%%): <%s>"}`,
		agentID, confidence*100, prURL)
	// Fire-and-forget; errors are logged but don't fail the run.
	if err := postJSON(webhookURL, []byte(msg)); err != nil {
		log.Printf("[apa] slack notify error: %v", err)
	}
}

// readFileBytes is a small helper used by multiple files in this package.
func readFileBytes(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// reportProposalSafe invokes a ProposalSink, recovering from any panic so a
// misbehaving sink can never break an APA run.
func reportProposalSafe(sink ProposalSink, rep ProposalReport) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[apa] proposal sink panicked (ignored): %v", r)
		}
	}()
	sink(rep)
}

// dirOf returns the directory part of a file path.
func dirOf(path string) string {
	return filepath.Dir(path)
}
