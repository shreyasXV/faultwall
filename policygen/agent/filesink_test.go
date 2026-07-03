package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileSinkWriteAndList(t *testing.T) {
	dir := t.TempDir()
	s := NewFileSink(dir)
	sink := s.Sink()

	sink(ProposalReport{
		AgentID:    "cursor-ai",
		Title:      "apa: policy proposal for agent cursor-ai (confidence 90%)",
		YAMLDiff:   "--- a\n+++ b\n+allowed_tables:\n+  - public.users\n",
		Confidence: 0.9,
		DiffLines:  3,
		MergedYAML: "default_policy: standard\nagents:\n  cursor-ai:\n    allowed_tables:\n      - public.users\n",
	})

	props, err := ListProposals(dir)
	if err != nil {
		t.Fatalf("ListProposals: %v", err)
	}
	if len(props) != 1 {
		t.Fatalf("expected 1 proposal, got %d", len(props))
	}
	p := props[0]
	if p.AgentID != "cursor-ai" {
		t.Errorf("AgentID = %q, want cursor-ai", p.AgentID)
	}
	if p.Status != "pending" {
		t.Errorf("Status = %q, want pending", p.Status)
	}
	if p.MergedYAML == "" {
		t.Error("MergedYAML must be persisted for download")
	}

	// Download-by-id path.
	got, err := GetProposal(dir, p.ID)
	if err != nil {
		t.Fatalf("GetProposal: %v", err)
	}
	if got.MergedYAML != p.MergedYAML {
		t.Error("GetProposal MergedYAML mismatch")
	}

	// Status transition.
	if err := SetProposalStatus(dir, p.ID, "applied"); err != nil {
		t.Fatalf("SetProposalStatus: %v", err)
	}
	got, _ = GetProposal(dir, p.ID)
	if got.Status != "applied" {
		t.Errorf("Status after apply = %q, want applied", got.Status)
	}
}

func TestFileSinkListEmptyDir(t *testing.T) {
	props, err := ListProposals(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("ListProposals on missing dir should not error: %v", err)
	}
	if len(props) != 0 {
		t.Fatalf("expected 0 proposals, got %d", len(props))
	}
}

func TestGetProposalRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"../secret", "a/b", "..", ""} {
		if _, err := GetProposal(dir, bad); err == nil {
			t.Errorf("GetProposal(%q) should be rejected", bad)
		}
	}
}

func TestValidateConfigFileDropMode(t *testing.T) {
	// No git repo, but a proposal dir set → valid (file-drop mode).
	err := validateConfig(APAConfig{
		PolicyPath:  "policies.yaml",
		Provider:    "openai",
		ProposalDir: "/tmp/faultwall",
	})
	if err != nil {
		t.Errorf("file-drop config should be valid, got: %v", err)
	}

	// No git repo, no proposal dir, real provider → invalid.
	err = validateConfig(APAConfig{
		PolicyPath: "policies.yaml",
		Provider:   "openai",
	})
	if err == nil {
		t.Error("config with no review destination should be rejected")
	}
}

func TestWriteProposalCreatesDir(t *testing.T) {
	base := filepath.Join(t.TempDir(), "nested", "faultwall")
	s := NewFileSink(base)
	if err := s.Write(ProposalReport{AgentID: "x", MergedYAML: "y: 1\n"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "proposals")); err != nil {
		t.Errorf("proposals dir not created: %v", err)
	}
}
