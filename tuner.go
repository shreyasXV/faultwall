package main

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
	"time"
)

// TunerConfig holds the tunable parameters for anomaly detection + throttling
type TunerConfig struct {
	// Anomaly detection
	AnomalyWindowSize  int     `json:"anomaly_window_size"`
	AnomalySensitivity float64 `json:"anomaly_sensitivity"` // z-score threshold
	AnomalyMinSamples  int     `json:"anomaly_min_samples"`

	// Predictor
	PredictThresholdMs float64 `json:"predict_threshold_ms"`
	PredictWindowSize  int     `json:"predict_window_size"`
	PredictConfidence  float64 `json:"predict_confidence"` // min R² to act on prediction

	// Throttle
	ThrottleMaxQueryMs  float64 `json:"throttle_max_query_ms"`
	ThrottleMaxConns    int     `json:"throttle_max_conns"`
	ThrottleGracePeriod float64 `json:"throttle_grace_period_ms"`

	// Scoring weights (internal — how much each metric matters)
	WeightDetection     float64 `json:"weight_detection"`      // reward for catching anomalies
	WeightSpeed         float64 `json:"weight_speed"`          // reward for fast detection
	WeightFalsePositive float64 `json:"weight_false_positive"` // penalty for false alarms
	WeightCollateral    float64 `json:"weight_collateral"`     // penalty for throttling healthy tenants
}

// IncidentScenario represents a known test case
type IncidentScenario struct {
	Name          string  `json:"name"`
	TenantID      string  `json:"tenant_id"`
	StartSec      int     `json:"start_sec"`
	EndSec        int     `json:"end_sec"`
	QPSMultiplier float64 `json:"qps_multiplier"`
	ExpectAnomaly bool    `json:"expect_anomaly"` // should detection fire?
	Severity      string  `json:"severity"`       // "warning" or "critical"
}

// TunerResult captures the score of a single evaluation
type TunerResult struct {
	Config         TunerConfig `json:"config"`
	Score          float64     `json:"score"`
	DetectionRate  float64     `json:"detection_rate"` // % of real incidents caught
	FalsePositives int         `json:"false_positives"`
	AvgDetectTime  float64     `json:"avg_detect_time"` // seconds to detect
	Generation     int         `json:"generation"`
}

// GroundTruth defines what SHOULD happen during the load simulation
var groundTruth = []IncidentScenario{
	{Name: "Acme analytics export", TenantID: "acme_corp", StartSec: 45, EndSec: 75, QPSMultiplier: 3, ExpectAnomaly: true, Severity: "warning"},
	{Name: "Wayne batch reporting", TenantID: "wayne_enterprises", StartSec: 120, EndSec: 150, QPSMultiplier: 4, ExpectAnomaly: true, Severity: "warning"},
	{Name: "Initech CROSS JOIN", TenantID: "initech", StartSec: 170, EndSec: 190, QPSMultiplier: 20, ExpectAnomaly: true, Severity: "critical"},
	{Name: "Acme flash sale", TenantID: "acme_corp", StartSec: 220, EndSec: 300, QPSMultiplier: 5, ExpectAnomaly: true, Severity: "critical"},
	{Name: "Multi-tenant storm", TenantID: "acme_corp", StartSec: 330, EndSec: 360, QPSMultiplier: 3, ExpectAnomaly: true, Severity: "warning"},
	// These should NOT trigger
	{Name: "Hooli normal traffic", TenantID: "hooli", StartSec: 0, EndSec: 400, QPSMultiplier: 1, ExpectAnomaly: false, Severity: ""},
	{Name: "Globex light usage", TenantID: "globex_inc", StartSec: 0, EndSec: 400, QPSMultiplier: 1, ExpectAnomaly: false, Severity: ""},
	{Name: "Pied Piper startup", TenantID: "pied_piper", StartSec: 0, EndSec: 400, QPSMultiplier: 1, ExpectAnomaly: false, Severity: ""},
}

// DefaultConfig returns the hand-tuned baseline
func DefaultTunerConfig() TunerConfig {
	return TunerConfig{
		AnomalyWindowSize:   30,
		AnomalySensitivity:  2.0,
		AnomalyMinSamples:   10,
		PredictThresholdMs:  30000,
		PredictWindowSize:   20,
		PredictConfidence:   0.7,
		ThrottleMaxQueryMs:  30000,
		ThrottleMaxConns:    50,
		ThrottleGracePeriod: 5000,
		WeightDetection:     10.0,
		WeightSpeed:         2.0,
		WeightFalsePositive: -8.0,
		WeightCollateral:    -5.0,
	}
}

// Mutate creates a slightly modified version of the config
func (c TunerConfig) Mutate(mutationRate float64) TunerConfig {
	m := c

	if rand.Float64() < mutationRate {
		m.AnomalyWindowSize = clampInt(m.AnomalyWindowSize+rand.Intn(21)-10, 5, 120)
	}
	if rand.Float64() < mutationRate {
		m.AnomalySensitivity = clampFloat(m.AnomalySensitivity+(rand.Float64()-0.5)*1.0, 0.5, 5.0)
	}
	if rand.Float64() < mutationRate {
		m.AnomalyMinSamples = clampInt(m.AnomalyMinSamples+rand.Intn(11)-5, 3, 50)
	}
	if rand.Float64() < mutationRate {
		m.PredictThresholdMs = clampFloat(m.PredictThresholdMs+(rand.Float64()-0.5)*20000, 1000, 120000)
	}
	if rand.Float64() < mutationRate {
		m.PredictWindowSize = clampInt(m.PredictWindowSize+rand.Intn(11)-5, 5, 60)
	}
	if rand.Float64() < mutationRate {
		m.PredictConfidence = clampFloat(m.PredictConfidence+(rand.Float64()-0.5)*0.3, 0.3, 0.99)
	}
	if rand.Float64() < mutationRate {
		m.ThrottleMaxQueryMs = clampFloat(m.ThrottleMaxQueryMs+(rand.Float64()-0.5)*20000, 1000, 120000)
	}
	if rand.Float64() < mutationRate {
		m.ThrottleMaxConns = clampInt(m.ThrottleMaxConns+rand.Intn(31)-15, 5, 200)
	}
	if rand.Float64() < mutationRate {
		m.ThrottleGracePeriod = clampFloat(m.ThrottleGracePeriod+(rand.Float64()-0.5)*5000, 500, 30000)
	}

	return m
}

// Crossover blends two configs
func Crossover(a, b TunerConfig) TunerConfig {
	child := TunerConfig{
		WeightDetection:     a.WeightDetection,
		WeightSpeed:         a.WeightSpeed,
		WeightFalsePositive: a.WeightFalsePositive,
		WeightCollateral:    a.WeightCollateral,
	}

	// Uniform crossover — pick each param from either parent
	if rand.Float64() < 0.5 {
		child.AnomalyWindowSize = a.AnomalyWindowSize
	} else {
		child.AnomalyWindowSize = b.AnomalyWindowSize
	}
	if rand.Float64() < 0.5 {
		child.AnomalySensitivity = a.AnomalySensitivity
	} else {
		child.AnomalySensitivity = b.AnomalySensitivity
	}
	if rand.Float64() < 0.5 {
		child.AnomalyMinSamples = a.AnomalyMinSamples
	} else {
		child.AnomalyMinSamples = b.AnomalyMinSamples
	}
	if rand.Float64() < 0.5 {
		child.PredictThresholdMs = a.PredictThresholdMs
	} else {
		child.PredictThresholdMs = b.PredictThresholdMs
	}
	if rand.Float64() < 0.5 {
		child.PredictWindowSize = a.PredictWindowSize
	} else {
		child.PredictWindowSize = b.PredictWindowSize
	}
	if rand.Float64() < 0.5 {
		child.PredictConfidence = a.PredictConfidence
	} else {
		child.PredictConfidence = b.PredictConfidence
	}
	if rand.Float64() < 0.5 {
		child.ThrottleMaxQueryMs = a.ThrottleMaxQueryMs
	} else {
		child.ThrottleMaxQueryMs = b.ThrottleMaxQueryMs
	}
	if rand.Float64() < 0.5 {
		child.ThrottleMaxConns = a.ThrottleMaxConns
	} else {
		child.ThrottleMaxConns = b.ThrottleMaxConns
	}
	if rand.Float64() < 0.5 {
		child.ThrottleGracePeriod = a.ThrottleGracePeriod
	} else {
		child.ThrottleGracePeriod = b.ThrottleGracePeriod
	}

	return child
}

// Score evaluates a config against the ground truth using simulated detection
func (c TunerConfig) Score() TunerResult {
	detected := 0
	totalExpected := 0
	falsePositives := 0
	totalDetectTime := 0.0
	detections := 0

	for _, incident := range groundTruth {
		if incident.ExpectAnomaly {
			totalExpected++

			incidentDuration := float64(incident.EndSec - incident.StartSec)
			// Time to detect after incident starts
			collectInterval := 10.0 // seconds per sample
			// But we might already have baseline data from before the incident
			// So actual detection time = max(minSamples * interval - preExistingData, interval)
			preExistingSamples := float64(incident.StartSec) / collectInterval
			effectiveWait := collectInterval // at least one collection cycle
			if preExistingSamples < float64(c.AnomalyMinSamples) {
				effectiveWait = (float64(c.AnomalyMinSamples) - preExistingSamples) * collectInterval
			}
			if effectiveWait < collectInterval {
				effectiveWait = collectInterval
			}

			// Z-score simulation: model the statistical signal strength
			// Base noise ~ 1/sqrt(windowSize), signal ~ (multiplier - 1)
			baseNoise := 1.0 / math.Sqrt(math.Max(float64(c.AnomalyWindowSize), 1.0))
			signalStrength := (incident.QPSMultiplier - 1.0)
			estimatedZScore := signalStrength / (baseNoise*3.0 + 0.5) // noise floor + variance

			// Detection: z-score exceeds threshold AND we detect within incident window
			if estimatedZScore > c.AnomalySensitivity && effectiveWait < incidentDuration {
				detected++
				totalDetectTime += effectiveWait
				detections++
			}
		} else {
			// Normal traffic — false positive check
			// Random variance in normal traffic: smaller window = more noise
			noiseVariance := 2.5 / math.Sqrt(math.Max(float64(c.AnomalyWindowSize), 1.0))
			// If sensitivity is too low, noise can trigger false positives
			if noiseVariance > c.AnomalySensitivity*0.5 {
				falsePositives++
			}
		}
	}

	detectionRate := 0.0
	if totalExpected > 0 {
		detectionRate = float64(detected) / float64(totalExpected)
	}

	avgDetectTime := 0.0
	if detections > 0 {
		avgDetectTime = totalDetectTime / float64(detections)
	}

	// Speed score: 10s = perfect, 120s = zero
	speedScore := math.Max(0, 1.0-avgDetectTime/120.0)

	score := detectionRate*c.WeightDetection +
		speedScore*c.WeightSpeed +
		float64(falsePositives)*c.WeightFalsePositive

	// Reward balanced throttle params
	throttleBalance := 0.0
	if c.ThrottleMaxQueryMs >= 5000 && c.ThrottleMaxQueryMs <= 60000 {
		throttleBalance += 1.0
	}
	if c.ThrottleMaxConns >= 10 && c.ThrottleMaxConns <= 100 {
		throttleBalance += 1.0
	}
	if c.ThrottleGracePeriod >= 1000 && c.ThrottleGracePeriod <= 15000 {
		throttleBalance += 0.5
	}
	score += throttleBalance * 0.5

	return TunerResult{
		Config:         c,
		Score:          score,
		DetectionRate:  detectionRate,
		FalsePositives: falsePositives,
		AvgDetectTime:  avgDetectTime,
	}
}

// RunTuner executes the genetic algorithm
func RunTuner(generations, populationSize int, mutationRate float64) TunerResult {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║           FaultWall AutoResearch Tuner v1.0                  ║")
	fmt.Println("║         Genetic Algorithm Parameter Optimization             ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Generations: %-4d  Population: %-4d  Mutation: %.0f%%          ║\n", generations, populationSize, mutationRate*100)
	fmt.Printf("║  Ground truth incidents: %d (expect: %d anomalies)             ║\n", len(groundTruth), countExpected())
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Initialize population with default + random variants
	population := make([]TunerConfig, populationSize)
	population[0] = DefaultTunerConfig() // always include the hand-tuned baseline
	for i := 1; i < populationSize; i++ {
		population[i] = DefaultTunerConfig().Mutate(0.8) // high mutation for diversity
	}

	var bestEver TunerResult
	baselineResult := DefaultTunerConfig().Score()
	bestEver = baselineResult
	bestEver.Generation = 0

	fmt.Printf("Baseline (hand-tuned): score=%.2f detect=%.0f%% fp=%d speed=%.1fs\n\n",
		baselineResult.Score, baselineResult.DetectionRate*100, baselineResult.FalsePositives, baselineResult.AvgDetectTime)

	for gen := 0; gen < generations; gen++ {
		// Evaluate all
		results := make([]TunerResult, len(population))
		for i, cfg := range population {
			results[i] = cfg.Score()
			results[i].Generation = gen
		}

		// Sort by score (descending)
		sort.Slice(results, func(i, j int) bool {
			return results[i].Score > results[j].Score
		})

		// Track best
		if results[0].Score > bestEver.Score {
			bestEver = results[0]
			bestEver.Generation = gen
			fmt.Printf("Gen %3d: NEW BEST score=%.2f detect=%.0f%% fp=%d speed=%.1fs\n",
				gen, results[0].Score, results[0].DetectionRate*100, results[0].FalsePositives, results[0].AvgDetectTime)
		} else if gen%10 == 0 {
			fmt.Printf("Gen %3d: best=%.2f detect=%.0f%% fp=%d\n",
				gen, results[0].Score, results[0].DetectionRate*100, results[0].FalsePositives)
		}

		// Selection: top 20% survive
		survivors := populationSize / 5
		if survivors < 2 {
			survivors = 2
		}

		// Build next generation
		nextGen := make([]TunerConfig, populationSize)

		// Elitism: keep top performers
		for i := 0; i < survivors; i++ {
			nextGen[i] = results[i].Config
		}

		// Fill rest with crossover + mutation
		for i := survivors; i < populationSize; i++ {
			parentA := results[rand.Intn(survivors)].Config
			parentB := results[rand.Intn(survivors)].Config
			child := Crossover(parentA, parentB)
			child = child.Mutate(mutationRate)
			nextGen[i] = child
		}

		population = nextGen
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("OPTIMIZATION COMPLETE")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  Best score:      %.2f (baseline: %.2f) → %.1f%% improvement\n",
		bestEver.Score, baselineResult.Score,
		(bestEver.Score-baselineResult.Score)/math.Abs(baselineResult.Score)*100)
	fmt.Printf("  Detection rate:  %.0f%% (baseline: %.0f%%)\n",
		bestEver.DetectionRate*100, baselineResult.DetectionRate*100)
	fmt.Printf("  False positives: %d (baseline: %d)\n",
		bestEver.FalsePositives, baselineResult.FalsePositives)
	fmt.Printf("  Avg detect time: %.1fs (baseline: %.1fs)\n",
		bestEver.AvgDetectTime, baselineResult.AvgDetectTime)
	fmt.Printf("  Found in gen:    %d\n", bestEver.Generation)
	fmt.Println()

	// Show optimized params vs baseline
	base := DefaultTunerConfig()
	best := bestEver.Config
	fmt.Println("  Parameter Changes:")
	fmt.Println("  ─────────────────────────────────────────────")
	printDiff("AnomalyWindowSize", base.AnomalyWindowSize, best.AnomalyWindowSize)
	printDiffF("AnomalySensitivity", base.AnomalySensitivity, best.AnomalySensitivity)
	printDiff("AnomalyMinSamples", base.AnomalyMinSamples, best.AnomalyMinSamples)
	printDiffF("PredictThresholdMs", base.PredictThresholdMs, best.PredictThresholdMs)
	printDiff("PredictWindowSize", base.PredictWindowSize, best.PredictWindowSize)
	printDiffF("PredictConfidence", base.PredictConfidence, best.PredictConfidence)
	printDiffF("ThrottleMaxQueryMs", base.ThrottleMaxQueryMs, best.ThrottleMaxQueryMs)
	printDiff("ThrottleMaxConns", base.ThrottleMaxConns, best.ThrottleMaxConns)
	printDiffF("ThrottleGracePeriod", base.ThrottleGracePeriod, best.ThrottleGracePeriod)
	fmt.Println()

	return bestEver
}

func printDiff(name string, old, new int) {
	arrow := "→"
	marker := "  "
	if old != new {
		marker = "* "
	}
	fmt.Printf("  %s%-22s %5d %s %-5d\n", marker, name, old, arrow, new)
}

func printDiffF(name string, old, new float64) {
	arrow := "→"
	marker := "  "
	if math.Abs(old-new) > 0.01 {
		marker = "* "
	}
	fmt.Printf("  %s%-22s %8.1f %s %-8.1f\n", marker, name, old, arrow, new)
}

func countExpected() int {
	n := 0
	for _, inc := range groundTruth {
		if inc.ExpectAnomaly {
			n++
		}
	}
	return n
}

func clampInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func clampFloat(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// SaveResult writes the best config to a JSON file
func SaveTunerResult(result TunerResult, path string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
