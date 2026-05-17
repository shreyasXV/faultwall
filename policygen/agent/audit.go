package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// AuditRecord is written to the audit log after every APA run.
type AuditRecord struct {
	RunID        string    `json:"run_id"`
	Timestamp    time.Time `json:"timestamp"`
	AgentID      string    `json:"agent_id"`
	Provider     string    `json:"provider"`
	InputTokens  int       `json:"input_tokens"`
	OutputTokens int       `json:"output_tokens"`
	LatencyMs    int       `json:"latency_ms"`
	WindowStart  time.Time `json:"window_start"`
	WindowEnd    time.Time `json:"window_end"`
	PendingCount int       `json:"pending_count"`
	PRURL        string    `json:"pr_url,omitempty"`
	Error        string    `json:"error,omitempty"`
	Confidence   float64   `json:"confidence"`
}

// AuditLog appends a record to the audit log file as a JSONL line.
func AuditLog(path string, rec AuditRecord) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(dirOf(path), 0755); err != nil {
		return fmt.Errorf("audit log mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("audit log open: %w", err)
	}
	defer f.Close()
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("audit log encode: %w", err)
	}
	_, err = f.Write(append(line, '\n'))
	return err
}

// RunID generates a deterministic run identifier from the agent and time.
func RunID(agentID string, t time.Time) string {
	return fmt.Sprintf("apa-%s-%s", t.UTC().Format("2006-01-02-15-04-05"), agentID)
}
