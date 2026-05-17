package agent

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v3"
)

// ApplyPatch merges a YAML patch string into the policies.yaml at policyPath.
// The patch is expected to contain only the agent's section:
//
//	agents:
//	  <agentID>:
//	    blocked_operations: [...]
//
// Returns the full merged YAML bytes.
func ApplyPatch(policyPath, patch string) ([]byte, error) {
	current, err := readFileBytes(policyPath)
	if err != nil {
		return nil, fmt.Errorf("read current policy: %w", err)
	}

	// Decode both as generic maps so we can deep-merge.
	var base map[string]any
	if err := yaml.Unmarshal(current, &base); err != nil {
		return nil, fmt.Errorf("parse current policy: %w", err)
	}
	if base == nil {
		base = make(map[string]any)
	}

	var overlay map[string]any
	if err := yaml.Unmarshal([]byte(patch), &overlay); err != nil {
		return nil, fmt.Errorf("parse patch yaml: %w", err)
	}

	deepMerge(base, overlay)

	merged, err := yaml.Marshal(base)
	if err != nil {
		return nil, fmt.Errorf("marshal merged policy: %w", err)
	}
	return merged, nil
}

// deepMerge merges src into dst recursively. Lists are replaced, not appended.
func deepMerge(dst, src map[string]any) {
	for k, sv := range src {
		if sm, ok := sv.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				deepMerge(dm, sm)
				continue
			}
		}
		dst[k] = sv
	}
}

// DiffText generates a unified diff between the original policy file and the
// merged bytes. Uses git diff --no-index if available, falls back to a simple
// line-level diff.
func DiffText(originalPath string, mergedBytes []byte) (string, error) {
	tmp, err := os.CreateTemp("", "apa-proposed-*.yaml")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(mergedBytes); err != nil {
		tmp.Close()
		return "", err
	}
	tmp.Close()

	out, err := exec.Command("git", "diff", "--no-index", "--", originalPath, tmp.Name()).CombinedOutput()
	// git diff --no-index exits 1 when there are differences — that's normal.
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return "", fmt.Errorf("git diff: %w", err)
		}
	}
	// Replace tmp path with a readable label in the diff header.
	diff := strings.ReplaceAll(string(out), tmp.Name(), "policies.yaml.proposed")
	return diff, nil
}

// CountDiffLines returns the number of changed lines (+ or -) in a unified diff.
func CountDiffLines(diff string) int {
	n := 0
	for _, line := range strings.Split(diff, "\n") {
		if len(line) == 0 {
			continue
		}
		if line[0] == '+' || line[0] == '-' {
			if !strings.HasPrefix(line, "+++") && !strings.HasPrefix(line, "---") {
				n++
			}
		}
	}
	return n
}
