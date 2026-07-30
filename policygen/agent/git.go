package agent

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// PRRequest holds everything needed to open a GitHub PR.
type PRRequest struct {
	BranchName string
	Title      string
	Body       string
	PolicyPath string
	NewContent []byte
	BaseBranch string // PR target branch; defaults to "main" if empty
	// RepoDir is the git working tree APA operates in. All git/gh commands run
	// with this as their working directory. When empty, commands fall back to
	// the process cwd (legacy behavior) — but that is almost always wrong when
	// APA runs as a service, which produced the classic
	// "fatal: 'origin' does not appear to be a git repository" failure.
	RepoDir string
}

// PRResult is returned after opening (or attempting to open) a PR.
type PRResult struct {
	URL        string
	BranchName string
}

// OpenPR creates a branch, commits the new policy file, pushes, and opens a PR
// via the gh CLI. It requires git and gh to be on PATH and the working directory
// to be a git repository.
func OpenPR(req PRRequest) (PRResult, error) {
	if err := checkGHPresent(); err != nil {
		return PRResult{}, err
	}

	dir := req.RepoDir

	// Fail loudly and early if the working directory is not a git repo with an
	// "origin" remote. Otherwise the first push dies deep in the flow with the
	// opaque "fatal: 'origin' does not appear to be a git repository" message
	// after a branch + commit have already been created.
	if err := checkRepo(dir); err != nil {
		return PRResult{}, err
	}

	// Create branch
	if out, err := gitRunDir(dir, "checkout", "-b", req.BranchName); err != nil {
		return PRResult{}, fmt.Errorf("git checkout -b: %w\n%s", err, out)
	}

	// Write the new policy content
	if err := os.WriteFile(req.PolicyPath, req.NewContent, 0644); err != nil {
		gitRunDir(dir, "checkout", "-") //nolint — best-effort cleanup
		return PRResult{}, fmt.Errorf("write policy file: %w", err)
	}

	// Stage and commit
	if out, err := gitRunDir(dir, "add", req.PolicyPath); err != nil {
		gitRunDir(dir, "checkout", "-")
		return PRResult{}, fmt.Errorf("git add: %w\n%s", err, out)
	}
	if out, err := gitRunDir(dir, "commit", "-m", req.Title+"\n\n"+req.Body); err != nil {
		gitRunDir(dir, "checkout", "-")
		return PRResult{}, fmt.Errorf("git commit: %w\n%s", err, out)
	}

	// Push
	if out, err := gitRunDir(dir, "push", "origin", req.BranchName); err != nil {
		gitRunDir(dir, "checkout", "-")
		return PRResult{}, fmt.Errorf("git push: %w\n%s", err, out)
	}

	base := req.BaseBranch
	if base == "" {
		base = "main"
	}
	url, err := ghCreatePR(dir, req.Title, req.Body, base)
	if err != nil {
		return PRResult{BranchName: req.BranchName}, fmt.Errorf("gh pr create: %w", err)
	}

	// Return to original branch
	gitRunDir(dir, "checkout", "-") //nolint — best-effort

	return PRResult{URL: url, BranchName: req.BranchName}, nil
}

// BranchName builds the PR branch name for a given agent and timestamp.
func BranchName(agentID string, t time.Time) string {
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, agentID)
	return fmt.Sprintf("apa/proposal-%s-%s", t.UTC().Format("2006-01-02-1504"), safe)
}

// PRBody renders the standard APA PR body from a proposal and run metadata.
func PRBody(p Proposal, resp Response, runID string, diffText string) string {
	var sb strings.Builder
	sb.WriteString("## Autonomous Policy Agent — Proposal\n\n")
	fmt.Fprintf(&sb, "**Agent:** `%s`  \n", p.AgentID)
	fmt.Fprintf(&sb, "**Window:** %s → %s  \n",
		p.WindowStart.UTC().Format("2006-01-02 15:04 UTC"),
		p.WindowEnd.UTC().Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(&sb, "**Provider:** %s (%d in / %d out tokens, %.1fs)  \n",
		resp.ProviderID, resp.InputTokens, resp.OutputTokens, float64(resp.LatencyMs)/1000)
	fmt.Fprintf(&sb, "**Confidence:** %.2f  \n\n", p.Confidence)

	sb.WriteString("### Summary\n")
	sb.WriteString(p.Summary)
	sb.WriteString("\n\n")

	sb.WriteString("### Proposed clusters\n")
	for i, c := range p.Clusters {
		fmt.Fprintf(&sb, "%d. **%s** (%s) — %d fingerprints  \n", i+1, c.Label, c.Recommendation, len(c.Fingerprints))
	}
	sb.WriteString("\n")

	if diffText != "" {
		sb.WriteString("### Diff\n```diff\n")
		sb.WriteString(diffText)
		sb.WriteString("\n```\n\n")
	}

	sb.WriteString("<details><summary>Reasoning trace</summary>\n\n```json\n")
	for _, c := range p.Clusters {
		fmt.Fprintf(&sb, "// %s\n%s\n\n", c.Label, c.Reasoning)
	}
	sb.WriteString("```\n</details>\n\n")

	fmt.Fprintf(&sb, "### Audit\n- Run ID: `%s`\n\n", runID)

	sb.WriteString("---\n**This PR will not auto-merge.** Reviewer must explicitly approve before any policy change reaches the proxy.\n\n")
	sb.WriteString("Generated with [FaultWall APA](https://github.com/shreyasXV/faultwall)\n")
	return sb.String()
}

func gitRun(args ...string) (string, error) {
	return gitRunDir("", args...)
}

// gitRunDir runs git with the given working directory. An empty dir falls back
// to the process cwd.
func gitRunDir(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// checkRepo verifies dir is inside a git work tree and has an "origin" remote,
// returning an actionable error instead of the raw git message.
func checkRepo(dir string) error {
	if out, err := gitRunDir(dir, "rev-parse", "--is-inside-work-tree"); err != nil {
		loc := dir
		if loc == "" {
			loc = "(process working directory)"
		}
		return fmt.Errorf("apa PR mode requires a git repo but %s is not one — set apa.policy_repo in policies.yaml, or use file-drop mode (apa.proposal_dir); git said: %s", loc, strings.TrimSpace(out))
	}
	if out, err := gitRunDir(dir, "remote", "get-url", "origin"); err != nil {
		return fmt.Errorf("apa PR mode requires an 'origin' remote in %q but none is configured — add one with `git remote add origin <url>` or switch to file-drop mode (apa.proposal_dir); git said: %s", dir, strings.TrimSpace(out))
	}
	return nil
}

func ghCreatePR(dir, title, body, baseBranch string) (string, error) {
	cmd := exec.Command("gh", "pr", "create",
		"--title", title,
		"--body", body,
		"--base", baseBranch,
	)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func checkGHPresent() error {
	if _, err := exec.LookPath("gh"); err != nil {
		return fmt.Errorf("gh CLI not found on PATH — install from https://cli.github.com")
	}
	return nil
}
