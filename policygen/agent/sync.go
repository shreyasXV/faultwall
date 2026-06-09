package agent

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// ── F3: observations → pending_review/allowed_fingerprints bridge ──
//
// SyncPolicy is the implementation behind `faultwall apa sync`. It reads
// observations.jsonl, classifies each fingerprint deterministically
// (ClassifyObservations), and writes the resulting allowed_fingerprints /
// pending_review entries back into the policy YAML — preserving comments, key
// order, and indentation by reusing the yaml.Node merge in ApplyPatch.
//
// Without this, `apa run` always reports "nothing to do" because nothing ever
// populates pending_review. This makes the APA loop runnable on a clean install.

// SyncResult summarizes what a sync added, for human-readable CLI output.
type SyncResult struct {
	AddedAllowed map[string]int // agentID → count promoted to allowed_fingerprints
	AddedPending map[string]int // agentID → count routed to pending_review
	MergedYAML   []byte         // the new policy file contents
	Changed      bool
}

// SyncPolicy classifies observations in the window and merges new
// allowed_fingerprints/pending_review entries into the policy file at
// policyPath. If dryRun is true the file is not written, only MergedYAML is set.
func SyncPolicy(policyPath, observationPath string, window time.Duration, dryRun bool) (SyncResult, error) {
	res := SyncResult{
		AddedAllowed: map[string]int{},
		AddedPending: map[string]int{},
	}

	obs, err := LoadObservations(observationPath, window)
	if err != nil {
		return res, fmt.Errorf("load observations: %w", err)
	}
	current, err := LoadAgentPolicies(policyPath)
	if err != nil {
		return res, fmt.Errorf("load agent policies: %w", err)
	}

	classified := ClassifyObservations(obs, current)
	if len(classified) == 0 {
		// Nothing new to add — return the file unchanged.
		cur, rerr := os.ReadFile(policyPath)
		if rerr != nil {
			return res, fmt.Errorf("read policy: %w", rerr)
		}
		res.MergedYAML = cur
		return res, nil
	}

	// Build a minimal YAML patch (agents.<id>.{allowed_fingerprints,pending_review})
	// containing existing + new entries, then merge it. We include existing
	// entries because mergeNodes replaces sequence nodes wholesale rather than
	// appending — so we must hand it the complete list.
	patch := buildSyncPatch(classified, current, &res)

	merged, err := ApplyPatch(policyPath, patch)
	if err != nil {
		return res, fmt.Errorf("apply sync patch: %w", err)
	}
	res.MergedYAML = merged
	res.Changed = true

	if !dryRun {
		if err := writeFileAtomic(policyPath, merged); err != nil {
			return res, fmt.Errorf("write policy: %w", err)
		}
	}
	return res, nil
}

// buildSyncPatch constructs the YAML patch string. For each agent with new
// classifications it emits the FULL (existing + new) allowed_fingerprints and
// pending_review lists. Counts of newly-added entries are recorded in res.
func buildSyncPatch(classified map[string]Classification, current map[string]agentPolicyYAML, res *SyncResult) string {
	type agentOut struct {
		AllowedFingerprints []FingerprintRule `yaml:"allowed_fingerprints,omitempty"`
		PendingReview       []FingerprintRule `yaml:"pending_review,omitempty"`
	}
	root := struct {
		Agents map[string]agentOut `yaml:"agents"`
	}{Agents: map[string]agentOut{}}

	for agentID, c := range classified {
		existing := current[agentID]

		allowed := append([]FingerprintRule{}, existing.AllowedFingerprints...)
		allowed = append(allowed, c.Allowed...)

		pending := append([]FingerprintRule{}, existing.PendingReview...)
		pending = append(pending, c.Pending...)

		root.Agents[agentID] = agentOut{
			AllowedFingerprints: allowed,
			PendingReview:       pending,
		}
		if len(c.Allowed) > 0 {
			res.AddedAllowed[agentID] = len(c.Allowed)
		}
		if len(c.Pending) > 0 {
			res.AddedPending[agentID] = len(c.Pending)
		}
	}

	out, _ := yaml.Marshal(root)
	return string(out)
}

// writeFileAtomic writes data to path via a temp file + rename, preserving the
// existing file mode when possible.
func writeFileAtomic(path string, data []byte) error {
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp := path + ".apa-sync.tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
