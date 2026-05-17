package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const observationSchema = "faultwall.observation.v1"
const observationMaxBytes = 100 * 1024 * 1024 // 100 MB
const observationMaxRecords = 10_000          // force-flush before map grows beyond this

// FingerprintObservation is one record per (agentID, fingerprint) pair, written
// to disk as JSONL and read by the policygen CLI to generate draft policies.
type FingerprintObservation struct {
	Schema        string    `json:"schema"`         // always observationSchema — version sentinel
	AgentID       string    `json:"agent_id"`
	Fingerprint   string    `json:"fingerprint"`    // pg_query.Fingerprint() hex
	NormalizedSQL string    `json:"normalized_sql"` // first query seen, for human review
	Operation     string    `json:"operation"`
	Tables        []string  `json:"tables"`
	Functions     []string  `json:"functions"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Count         int64     `json:"count"`
	BlockedCount  int64     `json:"blocked_count"`
	Verdict       string    `json:"verdict"` // "", "safe", "risky", "unknown"
}

// ObservationStore accumulates per-(agent, fingerprint) observations in memory
// and flushes them to a JSONL file. The file rotates when it exceeds 100 MB.
type ObservationStore struct {
	mu      sync.Mutex
	records map[string]*FingerprintObservation // key: agentID+"|"+fingerprint
	path    string
}

// NewObservationStore creates a store that writes to path.
// If path is empty, it defaults to ~/.faultwall/observations.jsonl.
func NewObservationStore(path string) *ObservationStore {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		path = filepath.Join(home, ".faultwall", "observations.jsonl")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		// Non-fatal: Flush() will surface the error when it tries to write.
		_ = err
	}
	return &ObservationStore{
		records: make(map[string]*FingerprintObservation),
		path:    path,
	}
}

// Record upserts an observation for the given (agentID, parsed query) pair.
// Uses pq.Fingerprint (set once by ParseQuery) — never calls FingerprintQuery again.
// If the in-memory map exceeds observationMaxRecords it drains inline to disk
// before adding the new record, preventing unbounded memory growth.
func (s *ObservationStore) Record(agentID string, pq *ParsedQuery, rawSQL string, blocked bool) {
	if pq == nil {
		return
	}
	fp := pq.Fingerprint // P0.2: use cached value, no second CGO call
	key := agentID + "|" + fp

	s.mu.Lock()

	// P1.1: force-drain if map is too large, while still holding the lock
	var overflow []*FingerprintObservation
	if len(s.records) >= observationMaxRecords {
		overflow = make([]*FingerprintObservation, 0, len(s.records))
		for _, obs := range s.records {
			overflow = append(overflow, obs)
		}
		s.records = make(map[string]*FingerprintObservation)
	}

	obs, ok := s.records[key]
	if !ok {
		obs = &FingerprintObservation{
			Schema:        observationSchema,
			AgentID:       agentID,
			Fingerprint:   fp,
			NormalizedSQL: rawSQL,
			Operation:     pq.Operation,
			Tables:        pq.Tables,
			Functions:     pq.Functions,
			FirstSeen:     time.Now(),
		}
		s.records[key] = obs
	}
	obs.LastSeen = time.Now()
	obs.Count++
	if blocked {
		obs.BlockedCount++
	}
	s.mu.Unlock()

	// Write the overflow snapshot to disk outside the lock
	if overflow != nil {
		if err := s.writeSnapshot(overflow); err != nil {
			log.Printf("observation force-flush: %v", err)
		}
	}
}

// Flush appends all in-memory records to the JSONL file, then clears the map.
// It rotates the file to observations.jsonl.YYYYMMDD when the file exceeds
// observationMaxBytes, so the active file never grows unboundedly.
func (s *ObservationStore) Flush() error {
	s.mu.Lock()
	if len(s.records) == 0 {
		s.mu.Unlock()
		return nil
	}
	snapshot := make([]*FingerprintObservation, 0, len(s.records))
	for _, obs := range s.records {
		snapshot = append(snapshot, obs)
	}
	s.records = make(map[string]*FingerprintObservation)
	s.mu.Unlock()

	return s.writeSnapshot(snapshot)
}

// writeSnapshot appends a slice of observations to disk, rotating first if needed.
// Safe to call without holding the mutex.
func (s *ObservationStore) writeSnapshot(snapshot []*FingerprintObservation) error {
	if len(snapshot) == 0 {
		return nil
	}
	if err := s.rotateIfNeeded(); err != nil {
		return fmt.Errorf("observation rotate: %w", err)
	}

	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("observation flush open: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, obs := range snapshot {
		if err := enc.Encode(obs); err != nil {
			return fmt.Errorf("observation flush encode: %w", err)
		}
	}
	return nil
}

func (s *ObservationStore) rotateIfNeeded() error {
	info, err := os.Stat(s.path)
	if err != nil {
		return nil // file doesn't exist yet — nothing to rotate
	}
	if info.Size() < observationMaxBytes {
		return nil
	}
	rotated := s.path + "." + time.Now().Format("20060102")
	return os.Rename(s.path, rotated)
}
