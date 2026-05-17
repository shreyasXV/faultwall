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

	// Create branch
	if out, err := gitRun("checkout", "-b", req.BranchName); err != nil {
		return PRResult{}, fmt.Errorf("git checkout -b: %w\n%s", err, out)
	}

	// Write the new policy content
	if err := os.WriteFile(req.PolicyPath, req.NewContent, 0644); err != nil {
		gitRun("checkout", "-") //nolint — best-effort cleanup
		return PRResult{}, fmt.Errorf("write policy file: %w", err)
	}

	// Stage and commit
	if out, err := gitRun("add", req.PolicyPath); err != nil {
		gitRun("checkout", "-")
		return PRResult{}, fmt.Errorf("git add: %w\n%s", err, out)
	}
	if out, err := gitRun("commit", "-m", req.Title+"\n\n"+req.Body); err != nil {
		gitRun("checkout", "-")
		return PRResult{}, fmt.Errorf("git commit: %w\n%s", err, out)
	}

	// Push
	if out, err := gitRun("push", "origin", req.BranchName); err != nil {
		gitRun("checkout", "-")
		return PRResult{}, fmt.Errorf("git push: %w\n%s", err, out)
	}

	base := req.BaseBranch
	if base == "" {
		base = "main"
	}
	url, err := ghCreatePR(req.Title, req.Body, base)
	if err != nil {
		return PRResult{BranchName: req.BranchName}, fmt.Errorf("gh pr create: %w", err)
	}

	// Return to original branch
	gitRun("checkout", "-") //nolint — best-effort

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
	sb.WriteString("🤖 Generated with [FaultWall APA](https://github.com/shreyasXV/faultwall)\n")
	return sb.String()
}

func gitRun(args ...string) (string, error) {
	out, err := exec.Command("git", args...).CombinedOutput()
	return string(out), err
}

func ghCreatePR(title, body, baseBranch string) (string, error) {
	out, err := exec.Command("gh", "pr", "create",
		"--title", title,
		"--body", body,
		"--base", baseBranch,
	).Output()
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
