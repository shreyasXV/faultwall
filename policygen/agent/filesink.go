package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// FileProposal is the on-disk record for one file-drop APA proposal. It carries
// ONLY human-review artifacts (a diff + the full proposed policy YAML) plus
// metadata — never observations, query text, or row content. This is the
// self-host, no-git review path (Soumya request): APA writes an apply-ready
// YAML you can download and diff, instead of opening a PR.
type FileProposal struct {
	ID         string    `json:"id"`
	AgentID    string    `json:"agent_id"`
	Title      string    `json:"title"`
	Confidence float64   `json:"confidence"`
	DiffLines  int       `json:"diff_lines"`
	YAMLDiff   string    `json:"yaml_diff"`
	MergedYAML string    `json:"merged_yaml"`
	CreatedAt  time.Time `json:"created_at"`
	Status     string    `json:"status"` // "pending" | "applied" | "dismissed"
}

// FileSink persists APA proposals to a directory as JSON records so the
// dashboard/API can list them and offer the proposed YAML for download. It is a
// drop-in ProposalSink: best-effort, off the APA hot path, never blocks or
// mutates policy. Concurrency-safe for the (rare) parallel-run case.
type FileSink struct {
	dir string
	mu  sync.Mutex
}

// NewFileSink returns a FileSink writing into dir/proposals (created on first
// use). dir is typically APAConfig.ProposalDir.
func NewFileSink(dir string) *FileSink {
	return &FileSink{dir: dir}
}

func (s *FileSink) proposalsDir() string { return filepath.Join(s.dir, "proposals") }

// Sink returns the ProposalSink closure to hand to APAConfig.Sink.
func (s *FileSink) Sink() ProposalSink {
	return func(rep ProposalReport) {
		if err := s.Write(rep); err != nil {
			// Best-effort: surface via error return path is not available in a
			// sink, so we swallow after a stderr note. APA must not break.
			fmt.Fprintf(os.Stderr, "[apa] file sink write error: %v\n", err)
		}
	}
}

// Write persists one proposal record atomically (temp + rename).
func (s *FileSink) Write(rep ProposalReport) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := s.proposalsDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir proposal dir: %w", err)
	}

	now := time.Now().UTC()
	id := fmt.Sprintf("%s-%s", sanitizeID(rep.AgentID), now.Format("20060102T150405.000Z"))
	id = strings.ReplaceAll(id, ".", "-")
	p := FileProposal{
		ID:         id,
		AgentID:    rep.AgentID,
		Title:      rep.Title,
		Confidence: rep.Confidence,
		DiffLines:  rep.DiffLines,
		YAMLDiff:   rep.YAMLDiff,
		MergedYAML: rep.MergedYAML,
		CreatedAt:  now,
		Status:     "pending",
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal proposal: %w", err)
	}
	path := filepath.Join(dir, id+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write proposal: %w", err)
	}
	return os.Rename(tmp, path)
}

// ListProposals returns all stored proposals, newest first. Missing dir → empty.
func ListProposals(dir string) ([]FileProposal, error) {
	pdir := filepath.Join(dir, "proposals")
	entries, err := os.ReadDir(pdir)
	if err != nil {
		if os.IsNotExist(err) {
			return []FileProposal{}, nil
		}
		return nil, err
	}
	var out []FileProposal
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(pdir, e.Name()))
		if err != nil {
			continue
		}
		var p FileProposal
		if err := json.Unmarshal(b, &p); err != nil {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// GetProposal loads a single proposal by ID.
func GetProposal(dir, id string) (FileProposal, error) {
	if !safeID(id) {
		return FileProposal{}, fmt.Errorf("invalid proposal id")
	}
	path := filepath.Join(dir, "proposals", id+".json")
	b, err := os.ReadFile(path)
	if err != nil {
		return FileProposal{}, err
	}
	var p FileProposal
	if err := json.Unmarshal(b, &p); err != nil {
		return FileProposal{}, err
	}
	return p, nil
}

// SetProposalStatus updates the status field of a stored proposal ("applied",
// "dismissed", etc.) atomically.
func SetProposalStatus(dir, id, status string) error {
	if !safeID(id) {
		return fmt.Errorf("invalid proposal id")
	}
	p, err := GetProposal(dir, id)
	if err != nil {
		return err
	}
	p.Status = status
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "proposals", id+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// sanitizeID makes an agent id safe for use in a filename.
func sanitizeID(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	if out == "" {
		return "agent"
	}
	return out
}

// safeID guards the proposal-lookup path against traversal.
func safeID(id string) bool {
	if id == "" || strings.Contains(id, "/") || strings.Contains(id, "\\") || strings.Contains(id, "..") {
		return false
	}
	return true
}
