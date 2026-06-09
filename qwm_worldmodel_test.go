package main

import (
	"math"
	"testing"
)

// RFC-003 §8: same query admitted at idle, rejected under load.
func TestWorldModel_SameQueryIdleVsHot(t *testing.T) {
	wm := NewWorldModelScorer(defaultWorldModel(), nil)
	fp := "abc123"
	// Establish an unloaded base of 3s for this fingerprint (observed at idle).
	wm.Observe(fp, 3000, 0.0)
	if b, ok := wm.base.Base(fp); !ok || math.Abs(b-3000) > 1 {
		t.Fatalf("base not learned: %v %v", b, ok)
	}

	pq := &ParsedQuery{Fingerprint: fp, Operation: "SELECT"}

	// Idle: utilization ~0 → predicted ~= base (3s) which is < 8s SLO → low P.
	idle := QWMInfraState{Utilization: 0.05}
	predIdle, pbIdle, ok := wm.Predict(pq, idle)
	if !ok {
		t.Fatal("expected world model to apply (base known)")
	}
	if pbIdle > 0.3 {
		t.Errorf("idle: expected low breach prob, got %.3f (predicted %.0fms)", pbIdle, predIdle)
	}

	// Hot: utilization 0.9 → congestion 1/(1-0.9)=10× → predicted ~30s ≫ 8s → P→1.
	hot := QWMInfraState{Utilization: 0.9}
	predHot, pbHot, _ := wm.Predict(pq, hot)
	if pbHot < 0.9 {
		t.Errorf("hot: expected high breach prob, got %.3f (predicted %.0fms)", pbHot, predHot)
	}
	if predHot <= predIdle {
		t.Errorf("predicted latency must rise with load: idle=%.0f hot=%.0f", predIdle, predHot)
	}
}

// RFC-003 §8: query×state aware — under identical high load a cheap query is
// admitted while a heavy one is rejected.
func TestWorldModel_CheapVsHeavyUnderSameLoad(t *testing.T) {
	wm := NewWorldModelScorer(defaultWorldModel(), nil)
	cheap := &ParsedQuery{Fingerprint: "cheap"}
	heavy := &ParsedQuery{Fingerprint: "heavy"}
	wm.Observe("cheap", 50, 0.0)   // 50ms unloaded
	wm.Observe("heavy", 5000, 0.0) // 5s unloaded

	load := QWMInfraState{Utilization: 0.8} // 5× inflation

	_, pCheap, _ := wm.Predict(cheap, load)
	_, pHeavy, _ := wm.Predict(heavy, load)

	if pCheap > wm.PThreshold() {
		t.Errorf("cheap query should be admitted under load, P=%.3f", pCheap)
	}
	if pHeavy < wm.PThreshold() {
		t.Errorf("heavy query should be rejected under load, P=%.3f", pHeavy)
	}
}

// Base service must only be learned at low utilization (unloaded), per §4.1B.
func TestBaseServiceStore_OnlyLearnsUnloaded(t *testing.T) {
	bs := newBaseServiceStore(0.5)
	// Under load: ignored.
	bs.Observe("fp", 9999, 0.9, 0.35)
	if _, ok := bs.Base("fp"); ok {
		t.Error("base should not be learned under load")
	}
	// Unloaded: learned.
	bs.Observe("fp", 100, 0.1, 0.35)
	if v, ok := bs.Base("fp"); !ok || v != 100 {
		t.Errorf("base should be 100, got %v %v", v, ok)
	}
	// EWMA blends subsequent unloaded samples.
	bs.Observe("fp", 200, 0.1, 0.35)
	if v, _ := bs.Base("fp"); v != 150 { // 0.5*200 + 0.5*100
		t.Errorf("EWMA expected 150, got %v", v)
	}
}

// Congestion factor: idle ~1, saturated finite-large, ρ>=1 clamped.
func TestCongestionFactor(t *testing.T) {
	if c := congestionFactor(0, 1); math.Abs(c-1) > 1e-9 {
		t.Errorf("idle congestion should be 1, got %v", c)
	}
	if c := congestionFactor(0.5, 1); math.Abs(c-2) > 1e-9 {
		t.Errorf("ρ=0.5 → 2×, got %v", c)
	}
	if c := congestionFactor(1.5, 1); math.IsInf(c, 1) || c <= 0 {
		t.Errorf("ρ>=1 must clamp to finite large, got %v", c)
	}
}

// Cold start: unknown fingerprint falls back to the shape scorer, no panic.
func TestWorldModel_ColdStartFallsBack(t *testing.T) {
	fallback := NewShadowQWMScorer()
	wm := NewWorldModelScorer(defaultWorldModel(), fallback)
	pq := &ParsedQuery{Fingerprint: "never-seen", Operation: "DROP", Tables: []string{"users"}}
	// No base for this fp → must use fallback (which scores DROP high), not 0.
	got := wm.Score(pq, QWMInfraState{Utilization: 0.1})
	want := fallback.Score(pq, QWMInfraState{Utilization: 0.1})
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("cold start should defer to fallback: got %.3f want %.3f", got, want)
	}
}

// Breach probability is monotonic in predicted latency.
func TestBreachProbabilityMonotonic(t *testing.T) {
	p := PlattParams{A: 5.32, B: 1.72}
	prev := -1.0
	for _, ms := range []float64{1000, 4000, 8000, 16000, 32000} {
		pb := breachProbability(ms, 8000, p)
		if pb < prev {
			t.Errorf("P_breach must be monotonic; dropped at %vms", ms)
		}
		prev = pb
	}
}
