package main

import (
	"encoding/json"
	"math"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"
)

// ── RFC-003: QWM Query World Model — state-conditioned admission control ──
//
// IAM answers "is this agent allowed to run this query?". The world model
// answers the gray-zone question: "given the LIVE state of the database, will
// running this query breach the latency SLO?"
//
//	predicted_ms = base_service_ms(q) * congestion_factor(utilization ρ)
//	             = base_fp            * 1/(1-ρ)            (M/M/c queuing prior)
//	P_breach     = sigmoid(a * log(predicted_ms / SLO) + b)   (Platt-calibrated)
//	decision     = reject iff P_breach > p_threshold
//
// Two hard lessons from the prototype, encoded here:
//  1. base_service_ms is the query's own OBSERVED UNLOADED latency keyed by
//     fingerprint — NOT the planner cost (Postgres mis-costs functions ~20×).
//  2. utilization must be a FAST signal (active backends / cores), never the
//     1-min loadavg, which lags real load by ~a minute → stale rejections.
//
// This file is the pure algorithm + model artifact + base-service store. The
// live-state plumbing is in qwm_state.go; the proxy wiring is in proxy.go.

// WorldModelArtifact is the on-disk model (schema faultwall.qwm.worldmodel.v1).
type WorldModelArtifact struct {
	Schema      string             `json:"schema"`
	SLOms       float64            `json:"slo_ms"`
	PThreshold  float64            `json:"p_threshold"`
	Platt       PlattParams        `json:"platt"`
	Servers     float64            `json:"servers"`
	LowUtil     float64            `json:"low_util"`
	BaseMsByFP  map[string]float64 `json:"base_ms_by_fp"`
	Meta        map[string]any     `json:"meta,omitempty"`
}

// PlattParams are the logistic-calibration coefficients mapping the log-ratio of
// predicted latency to SLO into a calibrated breach probability.
type PlattParams struct {
	A float64 `json:"a"`
	B float64 `json:"b"`
}

// defaultWorldModel returns sane cold-start parameters so the scorer is useful
// before any artifact is trained. These mirror the prototype's defaults: an 8s
// SLO, reject at P>=0.5, and a Platt curve that puts P~0.5 right around
// predicted==SLO (a·log(1)+b small) and saturates as predicted exceeds it.
func defaultWorldModel() *WorldModelArtifact {
	return &WorldModelArtifact{
		Schema:     "faultwall.qwm.worldmodel.v1",
		SLOms:      8000,
		PThreshold: 0.5,
		Platt:      PlattParams{A: 5.32, B: 1.72},
		Servers:    1.0,
		LowUtil:    0.35,
		BaseMsByFP: map[string]float64{},
	}
}

// LoadWorldModel reads an artifact from disk, filling defaults for any missing
// field so a partial artifact (e.g. only platt + slo) still works.
func LoadWorldModel(path string) (*WorldModelArtifact, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	wm := defaultWorldModel()
	if err := json.Unmarshal(data, wm); err != nil {
		return nil, err
	}
	if wm.SLOms <= 0 {
		wm.SLOms = 8000
	}
	if wm.PThreshold <= 0 {
		wm.PThreshold = 0.5
	}
	if wm.Servers <= 0 {
		wm.Servers = 1.0
	}
	if wm.LowUtil <= 0 {
		wm.LowUtil = 0.35
	}
	if wm.BaseMsByFP == nil {
		wm.BaseMsByFP = map[string]float64{}
	}
	return wm, nil
}

// ── Pure algorithm (unit-tested independently of the proxy) ──

// congestionFactor is the M/M/c-style queuing multiplier 1/(1-ρ). It clamps ρ
// into [0, ρmax] so a saturated/over-subscribed DB (ρ>=1) yields a large-but-
// finite inflation rather than +Inf, and an idle DB yields ~1.0 (no inflation).
func congestionFactor(utilization, servers float64) float64 {
	rho := utilization
	if servers > 1 {
		rho = utilization / servers
	}
	if rho < 0 {
		rho = 0
	}
	// Clamp just below 1 so the factor is finite; ρ>=1 means "unstable", which
	// we represent as a very large inflation (caps predicted_ms high → P→1).
	const rhoMax = 0.995
	if rho > rhoMax {
		rho = rhoMax
	}
	return 1.0 / (1.0 - rho)
}

// predictedLatencyMs estimates how long query q will take given current load:
// its unloaded base service time inflated by the congestion factor.
func predictedLatencyMs(baseServiceMs, utilization, servers float64) float64 {
	if baseServiceMs <= 0 {
		return 0
	}
	return baseServiceMs * congestionFactor(utilization, servers)
}

// breachProbability maps predicted latency vs SLO into a calibrated P(breach)
// via the Platt sigmoid. predicted<=0 (unknown base) → 0 (defer to fallback).
func breachProbability(predictedMs, sloMs float64, p PlattParams) float64 {
	if predictedMs <= 0 || sloMs <= 0 {
		return 0
	}
	z := p.A*math.Log(predictedMs/sloMs) + p.B
	return 1.0 / (1.0 + math.Exp(-z))
}

// ── Per-fingerprint base-service store (EWMA of unloaded latency) ──

// baseServiceStore maintains an exponentially-weighted moving average of each
// fingerprint's UNLOADED service time. Base is only updated when the DB is below
// the low-utilization threshold, so it stays a clean "unloaded" estimate.
type baseServiceStore struct {
	mu    sync.RWMutex
	ewma  map[string]float64
	alpha float64 // EWMA weight for the new sample (0..1)
}

func newBaseServiceStore(alpha float64) *baseServiceStore {
	if alpha <= 0 || alpha > 1 {
		alpha = 0.2
	}
	return &baseServiceStore{ewma: map[string]float64{}, alpha: alpha}
}

// Observe records a measured latency for a fingerprint. It only updates the
// unloaded base when utilization is below lowUtil (per RFC §4.1B); under load the
// sample is inflated and would poison the base estimate, so it is ignored.
func (b *baseServiceStore) Observe(fp string, latencyMs, utilization, lowUtil float64) {
	if fp == "" || latencyMs <= 0 {
		return
	}
	if utilization >= lowUtil {
		return // not "unloaded" — don't pollute the base estimate
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if cur, ok := b.ewma[fp]; ok {
		b.ewma[fp] = b.alpha*latencyMs + (1-b.alpha)*cur
	} else {
		b.ewma[fp] = latencyMs
	}
}

// Base returns the EWMA base service time for a fingerprint, or (0,false) if the
// fingerprint has never been observed under low load.
func (b *baseServiceStore) Base(fp string) (float64, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	v, ok := b.ewma[fp]
	return v, ok
}

// Seed installs known base latencies from a model artifact (does not overwrite a
// live-learned value that is already present).
func (b *baseServiceStore) Seed(seed map[string]float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for fp, ms := range seed {
		if _, exists := b.ewma[fp]; !exists && ms > 0 {
			b.ewma[fp] = ms
		}
	}
}

// ── worldModelScorer: implements QWMScorer ──

// worldModelScorer is the RFC-003 scorer. It is state-conditioned: the same
// query scores low at idle and high under load. On cold start (no base-service
// data for a fingerprint) it falls back to the supplied shape-based scorer so we
// never regress below the shipped behavior.
type worldModelScorer struct {
	artifact *WorldModelArtifact
	base     *baseServiceStore
	fallback QWMScorer // shape-based shadow scorer for unseen fingerprints
}

// NewWorldModelScorer builds a world-model scorer around an artifact + fallback.
func NewWorldModelScorer(artifact *WorldModelArtifact, fallback QWMScorer) *worldModelScorer {
	if artifact == nil {
		artifact = defaultWorldModel()
	}
	bs := newBaseServiceStore(0.2)
	bs.Seed(artifact.BaseMsByFP)
	return &worldModelScorer{artifact: artifact, base: bs, fallback: fallback}
}

// Predict returns the predicted latency and calibrated breach probability for a
// query under the given state. usedModel is false when we fell back to shape.
func (w *worldModelScorer) Predict(pq *ParsedQuery, infra QWMInfraState) (predictedMs, pBreach float64, usedModel bool) {
	if pq == nil {
		return 0, 0, false
	}
	baseMs, known := w.base.Base(pq.Fingerprint)
	if !known {
		return 0, 0, false
	}
	predictedMs = predictedLatencyMs(baseMs, infra.Utilization, w.artifact.Servers)
	pBreach = breachProbability(predictedMs, w.artifact.SLOms, w.artifact.Platt)
	return predictedMs, pBreach, true
}

// Score implements QWMScorer. Returns P_breach when the world model has a base
// for the fingerprint; otherwise defers to the shape-based fallback so unseen
// queries still get a (shape) risk score during cold start.
func (w *worldModelScorer) Score(pq *ParsedQuery, infra QWMInfraState) float64 {
	if _, p, ok := w.Predict(pq, infra); ok {
		return p
	}
	if w.fallback != nil {
		return w.fallback.Score(pq, infra)
	}
	return 0
}

// TopFeatures implements QWMScorer with the world-model explainability triple.
func (w *worldModelScorer) TopFeatures(pq *ParsedQuery, infra QWMInfraState, n int) []string {
	predictedMs, _, ok := w.Predict(pq, infra)
	if !ok {
		if w.fallback != nil {
			return w.fallback.TopFeatures(pq, infra, n)
		}
		return nil
	}
	baseMs, _ := w.base.Base(pq.Fingerprint)
	cong := congestionFactor(infra.Utilization, w.artifact.Servers)
	feats := []struct {
		name string
		mag  float64
	}{
		{"utilization", infra.Utilization},
		{"congestion_factor", cong},
		{"base_service_ms", baseMs / 1000.0},
		{"predicted_ms", predictedMs / 1000.0},
	}
	sort.Slice(feats, func(i, j int) bool { return feats[i].mag > feats[j].mag })
	if n > len(feats) {
		n = len(feats)
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, feats[i].name)
	}
	return out
}

// Observe forwards a measured latency to the base-service store.
func (w *worldModelScorer) Observe(fp string, latencyMs, utilization float64) {
	w.base.Observe(fp, latencyMs, utilization, w.artifact.LowUtil)
}

// SLO/threshold accessors used by the decision logic in proxy.go.
func (w *worldModelScorer) SLOms() float64      { return w.artifact.SLOms }
func (w *worldModelScorer) PThreshold() float64 { return w.artifact.PThreshold }

// worldModelStartTime anchors any time-based meta; kept for future use.
var worldModelStartTime = time.Now()

// loadWorldModelArtifact loads a trained artifact from FW_QWM_MODEL or
// ~/.faultwall/qwm_world_model.json, falling back to cold-start defaults. Never
// fails the proxy: a bad/missing artifact just yields the default model.
func loadWorldModelArtifact() *WorldModelArtifact {
	path := os.Getenv("FW_QWM_MODEL")
	if path == "" {
		if home, err := os.UserHomeDir(); err == nil {
			path = home + "/.faultwall/qwm_world_model.json"
		}
	}
	if path == "" {
		return defaultWorldModel()
	}
	wm, err := LoadWorldModel(path)
	if err != nil {
		return defaultWorldModel()
	}
	return wm
}

// qwmConfiguredCores returns the core count used as the utilization denominator.
// FW_QWM_CORES overrides; otherwise runtime.NumCPU(). Min 1.
func qwmConfiguredCores() float64 {
	if v := os.Getenv("FW_QWM_CORES"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil && n >= 1 {
			return n
		}
	}
	if n := runtime.NumCPU(); n >= 1 {
		return float64(n)
	}
	return 1
}
