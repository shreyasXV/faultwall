package main

import (
	"testing"
)

// TestShadowQWMScorer_CrossesThresholdForDestructiveAndSensitive verifies the
// cold-start weights flag the obvious bad cases without training. If this test
// regresses, retune NewShadowQWMScorer weights or update the threshold.
func TestShadowQWMScorer_CrossesThresholdForDestructiveAndSensitive(t *testing.T) {
	scorer := NewShadowQWMScorer()
	infra := QWMInfraState{}

	cases := []struct {
		name      string
		query     string
		shouldFlag bool
	}{
		{"benign-select-count", "SELECT count(*) FROM events WHERE event_name = 'login'", false},
		{"benign-select-by-id", "SELECT id, email, name FROM users WHERE id = 42", false},
		{"sensitive-column-pii", "SELECT id, password_hash FROM users LIMIT 5", true},
		{"sensitive-column-via-join", "SELECT u.email, u.password_hash FROM users u JOIN events e ON e.user_id = u.id LIMIT 5", true},
		{"drop-table", "DROP TABLE users", true},
		{"truncate", "TRUNCATE events", true},
		{"delete-no-where", "DELETE FROM events", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pq := ParseQuery(tc.query)
			score := scorer.Score(pq, infra)
			flagged := score > qwmFlagThreshold
			if flagged != tc.shouldFlag {
				t.Errorf("query=%q score=%.3f flagged=%v, want flagged=%v",
					tc.query, score, flagged, tc.shouldFlag)
			}
		})
	}
}

// TestQWMSensitiveColumns_DirectlyVerifyHelper guards the new column-aware path.
func TestQWMSensitiveColumns_DirectlyVerifyHelper(t *testing.T) {
	if !qwmSensitiveColumns([]string{"password_hash"}) {
		t.Error("password_hash should be flagged as sensitive")
	}
	if !qwmSensitiveColumns([]string{"u.api_key"}) {
		t.Error("api_key (qualified) should be flagged as sensitive")
	}
	if qwmSensitiveColumns([]string{"id", "email", "name"}) {
		t.Error("plain non-sensitive columns should not be flagged")
	}
	if qwmSensitiveColumns(nil) {
		t.Error("nil columns slice must not flag")
	}
}
