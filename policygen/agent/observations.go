package agent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

const observationSchema = "faultwall.observation.v1"

// rawObservation mirrors faultwall/observation.go:FingerprintObservation.
// Field names must stay in sync with the JSONL written by the proxy.
type rawObservation struct {
	Schema        string    `json:"schema"`
	AgentID       string    `json:"agent_id"`
	Fingerprint   string    `json:"fingerprint"`
	NormalizedSQL string    `json:"normalized_sql"`
	Operation     string    `json:"operation"`
	Tables        []string  `json:"tables"`
	Functions     []string  `json:"functions"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Count         int64     `json:"count"`
	BlockedCount  int64     `json:"blocked_count"`
}

// Observation is one (agentID, fingerprint) group after merging JSONL records
// that fall inside the requested time window.
type Observation struct {
	AgentID       string
	Fingerprint   string
	NormalizedSQL string
	Operation     string
	Tables        []string
	Functions     []string
	FirstSeen     time.Time
	LastSeen      time.Time
	Count         int64
	BlockedCount  int64
}

// LoadObservations reads path, skips records outside the window or with wrong schema,
// and returns one Observation per (agentID, fingerprint) pair.
func LoadObservations(path string, window time.Duration) ([]Observation, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open observations: %w", err)
	}
	defer f.Close()

	cutoff := time.Now().Add(-window)
	type key struct{ agent, fp string }
	grouped := make(map[key]*Observation)
	skipped, total := 0, 0

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		total++
		var raw rawObservation
		if err := json.Unmarshal(scanner.Bytes(), &raw); err != nil {
			skipped++
			continue
		}
		if raw.Schema != observationSchema {
			log.Printf("[apa] skipping record with unknown schema %q", raw.Schema)
			skipped++
			continue
		}
		if raw.LastSeen.Before(cutoff) {
			skipped++
			continue
		}
		k := key{raw.AgentID, raw.Fingerprint}
		agg, ok := grouped[k]
		if !ok {
			agg = &Observation{
				AgentID:       raw.AgentID,
				Fingerprint:   raw.Fingerprint,
				NormalizedSQL: raw.NormalizedSQL,
				Operation:     raw.Operation,
				Tables:        raw.Tables,
				Functions:     raw.Functions,
				FirstSeen:     raw.FirstSeen,
				LastSeen:      raw.LastSeen,
			}
			grouped[k] = agg
		}
		agg.Count += raw.Count
		agg.BlockedCount += raw.BlockedCount
		if raw.FirstSeen.Before(agg.FirstSeen) {
			agg.FirstSeen = raw.FirstSeen
		}
		if raw.LastSeen.After(agg.LastSeen) {
			agg.LastSeen = raw.LastSeen
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan observations: %w", err)
	}
	if skipped > 0 {
		log.Printf("[apa] loaded %d/%d observation records (%d skipped)", total-skipped, total, skipped)
	}

	out := make([]Observation, 0, len(grouped))
	for _, agg := range grouped {
		out = append(out, *agg)
	}
	return out, nil
}

// IndexByFingerprint builds a map keyed by fingerprint for O(1) lookup.
func IndexByFingerprint(obs []Observation) map[string]Observation {
	m := make(map[string]Observation, len(obs))
	for _, o := range obs {
		m[o.Fingerprint] = o
	}
	return m
}
