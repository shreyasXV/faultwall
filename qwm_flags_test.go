package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// F11: the QWM flag store records flags and the API serves them newest-first,
// with an agent filter. This is observe-only telemetry — recording a flag must
// never affect enforcement.
func TestQWMFlagStore_RecordAndServe(t *testing.T) {
	// Reset the ring for a deterministic test.
	qwmFlagsMu.Lock()
	qwmFlags = nil
	qwmFlagsMu.Unlock()

	recordQWMFlag(QWMFlagRecord{Agent: "a1", Query: "SELECT 1", Score: 0.81, Operation: "SELECT", Timestamp: time.Now()})
	recordQWMFlag(QWMFlagRecord{Agent: "a2", Query: "DELETE FROM x", Score: 0.95, Operation: "DELETE", Timestamp: time.Now()})

	// Newest-first ordering.
	all := GetQWMFlags("")
	if len(all) != 2 {
		t.Fatalf("expected 2 flags, got %d", len(all))
	}
	if all[0].Agent != "a2" {
		t.Errorf("expected newest (a2) first, got %s", all[0].Agent)
	}

	// Agent filter.
	if got := GetQWMFlags("a1"); len(got) != 1 || got[0].Agent != "a1" {
		t.Errorf("agent filter failed, got %+v", got)
	}

	// HTTP handler shape.
	req := httptest.NewRequest(http.MethodGet, "/api/qwm/flags", nil)
	rec := httptest.NewRecorder()
	handleQWMFlags(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var resp struct {
		Count       int             `json:"count"`
		ObserveOnly bool            `json:"observe_only"`
		Flags       []QWMFlagRecord `json:"flags"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 2 {
		t.Errorf("count: got %d want 2", resp.Count)
	}
	if !resp.ObserveOnly {
		t.Error("observe_only must be true — QWM never blocks")
	}
}

// F11: the ring buffer is bounded.
func TestQWMFlagStore_Bounded(t *testing.T) {
	qwmFlagsMu.Lock()
	qwmFlags = nil
	qwmFlagsMu.Unlock()

	for i := 0; i < qwmFlagRingSize+50; i++ {
		recordQWMFlag(QWMFlagRecord{Agent: "a", Query: "q", Score: 0.8, Timestamp: time.Now()})
	}
	if got := len(GetQWMFlags("")); got != qwmFlagRingSize {
		t.Errorf("ring should cap at %d, got %d", qwmFlagRingSize, got)
	}
}
