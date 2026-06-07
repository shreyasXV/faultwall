package agent

import (
	"bytes"
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
// As a correctness invariant, any fingerprint hash that appears in the patch's
// allowed_fingerprints (for any agent) is auto-removed from that agent's
// pending_review. This prevents stale pending entries from surviving an APA
// promotion. Surfaced by the RFC-002 E2E run (2026-05-17).
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
		// Pre-merge: collect promoted fingerprint hashes from the overlay so we
		// can prune them from pending_review after the merge.
		promotedByAgent := promotedHashesPerAgent(overlayDoc.Content[0])

		mergeNodes(baseDoc.Content[0], overlayDoc.Content[0])

		// Post-merge: walk base and remove any pending_review entry whose hash
		// was promoted in this patch.
		prunePromotedFromPending(baseDoc.Content[0], promotedByAgent)
	}

	// Use SetIndent(2) to match FaultWall's policy file convention.
	// yaml.Marshal defaults to 4-space indent, which would rewrite every
	// nested line and turn a 3-line semantic patch into a 100+ line diff.
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&baseDoc); err != nil {
		return nil, fmt.Errorf("marshal merged policy: %w", err)
	}
	enc.Close()
	return buf.Bytes(), nil
}

// promotedHashesPerAgent walks the patch's agents.<id>.allowed_fingerprints
// section and returns map[agentID]set-of-hashes. Used to drive auto-prune.
func promotedHashesPerAgent(patchRoot *yaml.Node) map[string]map[string]struct{} {
	out := make(map[string]map[string]struct{})
	if patchRoot == nil || patchRoot.Kind != yaml.MappingNode {
		return out
	}
	agents := findMappingValue(patchRoot, "agents")
	if agents == nil || agents.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i < len(agents.Content)-1; i += 2 {
		agentID := agents.Content[i].Value
		agentNode := agents.Content[i+1]
		if agentNode.Kind != yaml.MappingNode {
			continue
		}
		allowed := findMappingValue(agentNode, "allowed_fingerprints")
		if allowed == nil || allowed.Kind != yaml.SequenceNode {
			continue
		}
		hashes := make(map[string]struct{})
		for _, entry := range allowed.Content {
			if entry.Kind != yaml.MappingNode {
				continue
			}
			hashNode := findMappingValue(entry, "hash")
			if hashNode != nil && hashNode.Value != "" {
				hashes[hashNode.Value] = struct{}{}
			}
		}
		if len(hashes) > 0 {
			out[agentID] = hashes
		}
	}
	return out
}

// prunePromotedFromPending removes any pending_review entry whose hash matches
// a promoted hash for that agent. Agents not in promotedByAgent are untouched.
func prunePromotedFromPending(baseRoot *yaml.Node, promotedByAgent map[string]map[string]struct{}) {
	if baseRoot == nil || baseRoot.Kind != yaml.MappingNode || len(promotedByAgent) == 0 {
		return
	}
	agents := findMappingValue(baseRoot, "agents")
	if agents == nil || agents.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i < len(agents.Content)-1; i += 2 {
		agentID := agents.Content[i].Value
		agentNode := agents.Content[i+1]
		if agentNode.Kind != yaml.MappingNode {
			continue
		}
		promoted, ok := promotedByAgent[agentID]
		if !ok {
			continue
		}
		pending := findMappingValue(agentNode, "pending_review")
		if pending == nil || pending.Kind != yaml.SequenceNode {
			continue
		}
		kept := pending.Content[:0]
		for _, entry := range pending.Content {
			if entry.Kind != yaml.MappingNode {
				kept = append(kept, entry)
				continue
			}
			hashNode := findMappingValue(entry, "hash")
			if hashNode == nil {
				kept = append(kept, entry)
				continue
			}
			if _, isPromoted := promoted[hashNode.Value]; isPromoted {
				continue // drop — promoted to allowed_fingerprints
			}
			kept = append(kept, entry)
		}
		pending.Content = kept
	}
}

// findMappingValue returns the value Node for the given key in a MappingNode,
// or nil if not present. Helper for the patch-walking helpers above.
func findMappingValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(m.Content)-1; i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
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
