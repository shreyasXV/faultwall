package main

import (
	"log"
	"math"
	"strings"
	"sync"
	"time"
)

// QWMScorer is a minimal interface so the proxy can call the Query Weight Model
// without importing the qwm package directly. In production the faultwall-ebpf
// binary provides a trained model; the proxy loads its weights via LoadQWMModel.
type QWMScorer interface {
	// Score returns a harm probability in [0,1] for the query.
	Score(pq *ParsedQuery, infra QWMInfraState) float64
	// TopFeatures returns the names of the top-N features driving the score.
	TopFeatures(pq *ParsedQuery, infra QWMInfraState, n int) []string
}

// QWMInfraState carries the runtime signals the model needs from the proxy.
type QWMInfraState struct {
	ActiveConnections   int
	MaxConnections      int
	AvgQueryTime60sMs   float64
	BaselineQueryTimeMs float64
	LockContentionMs    float64
	AnomalyRateAgent    float64
}

// shadowQWMScorer is the built-in logistic regression scorer used in shadow mode.
// Weights are loaded from a JSON file produced by `schemaghost qwm train`.
type shadowQWMScorer struct {
	mu      sync.RWMutex
	weights [12]float64
	bias    float64
	known   map[string]int64 // fingerprint → observation count
}

// NewShadowQWMScorer returns a scorer initialised with conservative cold-start weights.
func NewShadowQWMScorer() *shadowQWMScorer {
	return &shadowQWMScorer{
		weights: [12]float64{
			1.8,  // is_novel_fingerprint
			0.9,  // op_type
			1.4,  // touches_sensitive_table
			0.5,  // n_joins
			0.6,  // has_subquery
			0.4,  // active_connections_norm
			0.3,  // avg_query_time_norm
			-0.1, // time_of_day_bucket
			0.0,  // agent_id_hash
			1.2,  // recent_anomaly_rate
			0.8,  // lock_contention_norm
			-0.7, // fingerprint_frequency
		},
		bias:  -2.0,
		known: make(map[string]int64),
	}
}

var qwmFeatureNames = [12]string{
	"is_novel_fingerprint", "op_type", "touches_sensitive_table",
	"n_joins", "has_subquery", "active_connections_norm",
	"avg_query_time_norm", "time_of_day_bucket", "agent_id_hash",
	"recent_anomaly_rate", "lock_contention_norm", "fingerprint_frequency",
}

func (s *shadowQWMScorer) extract(pq *ParsedQuery, infra QWMInfraState) [12]float64 {
	var fv [12]float64
	fp := FingerprintQuery(pq.Operation + strings.Join(pq.Tables, ","))

	s.mu.RLock()
	count := s.known[fp]
	s.mu.RUnlock()

	// 0: is_novel_fingerprint
	if count == 0 {
		fv[0] = 1
	}
	// 1: op_type normalised
	fv[1] = qwmOpType(pq.Operation) / 3.0
	// 2: touches_sensitive_table
	if qwmSensitiveTables(pq.Tables) {
		fv[2] = 1
	}
	// 3: n_joins (not tracked in ParsedQuery yet — placeholder 0)
	fv[3] = 0
	// 4: has_subquery (placeholder)
	fv[4] = 0
	// 5: active_connections_norm
	if infra.MaxConnections > 0 {
		fv[5] = math.Min(float64(infra.ActiveConnections)/float64(infra.MaxConnections), 1)
	}
	// 6: avg_query_time_norm
	if infra.BaselineQueryTimeMs > 0 {
		fv[6] = math.Min(infra.AvgQueryTime60sMs/infra.BaselineQueryTimeMs, 5) / 5.0
	}
	// 7: time_of_day_bucket
	fv[7] = float64(time.Now().UTC().Hour()/6) / 3.0
	// 8: agent_id_hash (placeholder)
	fv[8] = 0
	// 9: recent_anomaly_rate
	fv[9] = math.Min(infra.AnomalyRateAgent, 1)
	// 10: lock_contention_norm
	fv[10] = math.Min(infra.LockContentionMs/2000.0, 1)
	// 11: fingerprint_frequency
	fv[11] = math.Log(float64(count)+1) / math.Log(10001)

	return fv
}

func (s *shadowQWMScorer) Score(pq *ParsedQuery, infra QWMInfraState) float64 {
	fv := s.extract(pq, infra)
	s.mu.RLock()
	w := s.weights
	b := s.bias
	s.mu.RUnlock()
	var dot float64
	for i, wi := range w {
		dot += wi * fv[i]
	}
	return 1.0 / (1.0 + math.Exp(-(dot + b)))
}

func (s *shadowQWMScorer) TopFeatures(pq *ParsedQuery, infra QWMInfraState, n int) []string {
	fv := s.extract(pq, infra)
	s.mu.RLock()
	w := s.weights
	s.mu.RUnlock()

	type contrib struct {
		name  string
		value float64
	}
	contribs := make([]contrib, 12)
	for i := range w {
		contribs[i] = contrib{qwmFeatureNames[i], math.Abs(w[i] * fv[i])}
	}
	// simple selection sort for top-N (N is at most 3)
	out := make([]string, 0, n)
	used := make([]bool, 12)
	for range n {
		best, bestIdx := -1.0, -1
		for j, c := range contribs {
			if !used[j] && c.value > best {
				best, bestIdx = c.value, j
			}
		}
		if bestIdx >= 0 && best > 0 {
			out = append(out, contribs[bestIdx].name)
			used[bestIdx] = true
		}
	}
	return out
}

// RecordKnownFingerprint updates the scorer's fingerprint frequency map.
// Called by the observation store flush path so the scorer stays current.
func (s *shadowQWMScorer) RecordKnownFingerprint(fp string, count int64) {
	s.mu.Lock()
	s.known[fp] += count
	s.mu.Unlock()
}

var sensitiveQWMNames = []string{
	"password", "passwd", "secret", "token", "api_key", "apikey", "ssn",
}

func qwmSensitiveTables(tables []string) bool {
	for _, tbl := range tables {
		tblL := strings.ToLower(tbl)
		for _, pat := range sensitiveQWMNames {
			if strings.Contains(tblL, pat) {
				return true
			}
		}
	}
	return false
}

func qwmOpType(op string) float64 {
	switch strings.ToUpper(op) {
	case "SELECT":
		return 0
	case "INSERT":
		return 1
	case "UPDATE":
		return 2
	case "DELETE", "DROP", "TRUNCATE", "ALTER":
		return 3
	default:
		return 1.5
	}
}

// logQWMFlag writes a shadow-mode flag to the proxy log without blocking the query.
func logQWMFlag(agent, query string, score float64, topFeatures []string) {
	log.Printf("%s%s[QWM-FLAG]%s agent=%-20s score=%.3f features=%v query=%s",
		colorYellow, colorBold, colorReset, agent, score, topFeatures, querySnippet(query))
}
