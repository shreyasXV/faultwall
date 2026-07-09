package agent

import (
	"os/exec"
	"strings"
	"testing"
)

// TestOpenPR_MissingOrigin reproduces the production failure:
// "fatal: 'origin' does not appear to be a git repository". APA must fail
// early with an actionable message and must NOT leave a dangling branch behind.
func TestOpenPR_MissingOrigin(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	if _, err := exec.LookPath("gh"); err != nil {
		t.Skip("gh not on PATH")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if out, err := gitRunDir(dir, args...); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "test")
	// A committed base so checkout -b works.
	if out, err := gitRunDir(dir, "commit", "--allow-empty", "-m", "base"); err != nil {
		t.Fatalf("base commit: %v\n%s", err, out)
	}

	_, err := OpenPR(PRRequest{
		BranchName: "apa/test-branch",
		Title:      "t",
		Body:       "b",
		PolicyPath: dir + "/policies.yaml",
		NewContent: []byte("agents: {}\n"),
		RepoDir:    dir,
	})
	if err == nil {
		t.Fatal("expected error when origin remote is missing, got nil")
	}
	if !strings.Contains(err.Error(), "origin") {
		t.Fatalf("error should mention the missing origin remote, got: %v", err)
	}

	// Regression guard: the early check must fire BEFORE any branch is created,
	// so we should still be on the default branch with no apa/* branch present.
	out, _ := gitRunDir(dir, "branch", "--list", "apa/test-branch")
	if strings.TrimSpace(out) != "" {
		t.Fatalf("dangling branch created despite early failure: %q", out)
	}
}

// TestCheckRepo_NotARepo verifies a plain directory (the old process-cwd case)
// produces the actionable file-drop-mode hint rather than a raw git message.
func TestCheckRepo_NotARepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	err := checkRepo(dir)
	if err == nil {
		t.Fatal("expected error for non-repo dir")
	}
	if !strings.Contains(err.Error(), "proposal_dir") {
		t.Fatalf("error should hint at file-drop mode, got: %v", err)
	}
}
