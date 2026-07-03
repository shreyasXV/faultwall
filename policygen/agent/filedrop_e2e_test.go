package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestRunOnceFileDropMode is the end-to-end proof of the no-git review path:
// RunOnce with the fake provider + a FileSink + no git repo must produce a
// downloadable, apply-ready proposal and open zero PRs.
func TestRunOnceFileDropMode(t *testing.T) {
	// Copy the base policy into a temp file so ApplyPatch/Diff have a real path.
	base, err := os.ReadFile(filepath.Join("testdata", "policies_base.yaml"))
	if err != nil {
		t.Fatalf("read base policy: %v", err)
	}
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policies.yaml")
	if err := os.WriteFile(policyPath, base, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	proposalDir := filepath.Join(tmp, "faultwall")
	sink := NewFileSink(proposalDir)

	// Drive the fake provider with a real non-empty patch (the golden proposal)
	// so the full patch → diff → sink path runs.
	golden, err := os.ReadFile(filepath.Join("testdata", "golden_proposal.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	fakeProviderResponse = string(golden)
	t.Cleanup(func() { fakeProviderResponse = "" })

	cfg := APAConfig{
		Provider:             "fake",
		PolicyPath:           policyPath,
		ObservationPath:      filepath.Join(tmp, "observations.jsonl"), // absent → empty
		AuditLogPath:         filepath.Join(tmp, "audit.jsonl"),
		Window:               defaultWindow,
		MaxTokensPerRun:      defaultMaxTokens,
		PerAgentMaxDiffLines: 1000,
		ProposalDir:          proposalDir,
		// No PolicyRepo → file-drop mode.
		Sink: sink.Sink(),
	}

	urls, err := RunOnce(context.Background(), cfg)
	if err != nil {
		t.Fatalf("RunOnce (file-drop): %v", err)
	}
	if len(urls) != 0 {
		t.Errorf("file-drop mode must open zero PRs, got %v", urls)
	}

	props, err := ListProposals(proposalDir)
	if err != nil {
		t.Fatalf("ListProposals: %v", err)
	}
	if len(props) == 0 {
		t.Fatal("expected at least one file-drop proposal, got none")
	}
	for _, p := range props {
		if p.MergedYAML == "" {
			t.Errorf("proposal %s has empty MergedYAML (not downloadable)", p.ID)
		}
		if p.Status != "pending" {
			t.Errorf("proposal %s status = %q, want pending", p.ID, p.Status)
		}
	}
}
