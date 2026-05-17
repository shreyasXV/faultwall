package agent

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v3"
)

// ApplyPatch merges a YAML patch string into the policies.yaml at policyPath
// using yaml.Node to preserve comments, key order, and indentation style in the
// unchanged parts of the document.
//
// Before (map[string]any round-trip):
//
//	# my comment — LOST
//	agents:
//	  analytics:
//	    blocked_operations: []
//
// After (yaml.Node merge):
//
//	# my comment — preserved
//	agents:
//	  analytics:
//	    blocked_operations: [DELETE]   ← only the patched value changes
func ApplyPatch(policyPath, patch string) ([]byte, error) {
	current, err := readFileBytes(policyPath)
	if err != nil {
		return nil, fmt.Errorf("read current policy: %w", err)
	}

	var baseDoc yaml.Node
	if err := yaml.Unmarshal(current, &baseDoc); err != nil {
		return nil, fmt.Errorf("parse current policy: %w", err)
	}
	// yaml.Unmarshal wraps everything in a DocumentNode; unwrap for merging.
	if baseDoc.Kind == 0 {
		// Empty file — start with an empty mapping.
		baseDoc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{
			{Kind: yaml.MappingNode, Tag: "!!map"},
		}}
	}

	var overlayDoc yaml.Node
	if err := yaml.Unmarshal([]byte(patch), &overlayDoc); err != nil {
		return nil, fmt.Errorf("parse patch yaml: %w", err)
	}
	if overlayDoc.Kind == 0 || len(overlayDoc.Content) == 0 {
		return current, nil // empty patch → nothing to do
	}

	if baseDoc.Kind == yaml.DocumentNode && overlayDoc.Kind == yaml.DocumentNode {
		mergeNodes(baseDoc.Content[0], overlayDoc.Content[0])
	}

	merged, err := yaml.Marshal(&baseDoc)
	if err != nil {
		return nil, fmt.Errorf("marshal merged policy: %w", err)
	}
	return merged, nil
}

// mergeNodes merges overlay into base, preserving base's comments and key ordering.
// For mapping nodes: existing keys are updated in-place (recursing into nested maps),
// new keys are appended after the last existing key.
// For all other node kinds (scalar, sequence): the base value is replaced outright.
func mergeNodes(base, overlay *yaml.Node) {
	if base.Kind != yaml.MappingNode || overlay.Kind != yaml.MappingNode {
		return
	}

	// Build index: key string → index of its value node in base.Content.
	// base.Content is [key0, val0, key1, val1, ...]
	baseIdx := make(map[string]int, len(base.Content)/2)
	for i := 0; i < len(base.Content)-1; i += 2 {
		baseIdx[base.Content[i].Value] = i + 1
	}

	for i := 0; i < len(overlay.Content)-1; i += 2 {
		ok := overlay.Content[i]
		ov := overlay.Content[i+1]
		if idx, exists := baseIdx[ok.Value]; exists {
			// Key already exists — recurse into nested mappings, replace everything else.
			if ov.Kind == yaml.MappingNode && base.Content[idx].Kind == yaml.MappingNode {
				mergeNodes(base.Content[idx], ov)
			} else {
				base.Content[idx] = ov
			}
		} else {
			// New key — append after existing keys (predictable, reviewable ordering).
			base.Content = append(base.Content, ok, ov)
			baseIdx[ok.Value] = len(base.Content) - 1
		}
	}
}

// DiffText generates a unified diff between the original policy file and the
// merged bytes using git diff --no-index.
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
	// git diff --no-index exits 1 when there are differences — that's expected.
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return "", fmt.Errorf("git diff: %w", err)
		}
	}
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
