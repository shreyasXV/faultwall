package main

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Classifier contracts (a)–(d)
// ─────────────────────────────────────────────────────────────────────────────

// (a) A proxy-owned backend is NOT flagged.
func TestRealF9_Classifier_ProxyOwnedNotFlagged(t *testing.T) {
	reg := NewProxyBackendRegistry()
	reg.Register(101)
	v := ClassifySession(SessionRow{
		PID:             101,
		ApplicationName: "agent:billing:mission:read",
		BackendType:     "client backend",
	}, reg)
	if v != VerdictProxyOwned {
		t.Errorf("contract (a): proxy-owned PID 101 must classify as VerdictProxyOwned, got %v", v)
	}
}

// (b) An agent-looking session NOT in the tracked set IS flagged.
func TestRealF9_Classifier_AgentNotInRegistryFlagged(t *testing.T) {
	reg := NewProxyBackendRegistry() // empty
	v := ClassifySession(SessionRow{
		PID:             999,
		ApplicationName: "agent:billing:mission:read",
		BackendType:     "client backend",
		ClientAddr:      "10.0.0.7",
	}, reg)
	if v != VerdictBypassSuspected {
		t.Errorf("contract (b): unregistered agent-like session must classify as VerdictBypassSuspected, got %v", v)
	}
}

// (c) System / replication / autovacuum sessions are NOT flagged.
func TestRealF9_Classifier_SystemNotFlagged(t *testing.T) {
	reg := NewProxyBackendRegistry()
	cases := []SessionRow{
		{PID: 1, BackendType: "autovacuum worker"},
		{PID: 2, BackendType: "walsender"},
		{PID: 3, BackendType: "logical replication launcher"},
		{PID: 4, BackendType: "checkpointer"},
		{PID: 5, BackendType: "background writer"},
		{PID: 6, BackendType: "archiver"},
		{PID: 7, Username: "rdsadmin"},
		{PID: 8, Username: "cloudsqladmin", BackendType: "client backend"},
	}
	for i, row := range cases {
		v := ClassifySession(row, reg)
		if v != VerdictSystem {
			t.Errorf("contract (c) case %d: %+v must classify as VerdictSystem, got %v", i, row, v)
		}
	}
}

// (d) Empty / garbage rows must not panic and must classify as Unknown.
func TestRealF9_Classifier_EmptyAndGarbageNoPanic(t *testing.T) {
	reg := NewProxyBackendRegistry()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("classifier panicked on garbage input: %v", r)
		}
	}()
	if v := ClassifySession(SessionRow{}, reg); v != VerdictUnknown {
		t.Errorf("contract (d): empty row must classify Unknown, got %v", v)
	}
	if v := ClassifySession(SessionRow{
		PID:             -1,
		ApplicationName: "\x00\x01garbage",
		BackendType:     "\x00",
		Username:        "\x7f",
	}, reg); v != VerdictUnknown {
		t.Errorf("contract (d): garbage row must classify Unknown, got %v", v)
	}
}

// Non-agent client backends (psql admin, monitoring) are NOT flagged.
func TestRealF9_Classifier_NonAgentClientBackendIsUnknown(t *testing.T) {
	reg := NewProxyBackendRegistry()
	v := ClassifySession(SessionRow{
		PID:             50,
		ApplicationName: "psql",
		BackendType:     "client backend",
		Username:        "alice",
	}, reg)
	if v != VerdictUnknown {
		t.Errorf("non-agent client backend must classify Unknown (no false positive), got %v", v)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Registry
// ─────────────────────────────────────────────────────────────────────────────

func TestRealF9_Registry_RegisterDeregister(t *testing.T) {
	reg := NewProxyBackendRegistry()
	if reg.Has(42) {
		t.Error("fresh registry should not have PID 42")
	}
	reg.Register(42)
	if !reg.Has(42) {
		t.Error("after Register, registry must Have the PID")
	}
	reg.Deregister(42)
	if reg.Has(42) {
		t.Error("after Deregister, registry must not Have the PID")
	}
	// Defensive: 0 / negative are no-ops.
	reg.Register(0)
	reg.Register(-1)
	if reg.Size() != 0 {
		t.Error("PID 0 and negative must be ignored")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Detector dedupe + error handling
// ─────────────────────────────────────────────────────────────────────────────

// fakeRowSource is a test BypassRowSource. Returns the configured rows or
// the configured error.
type fakeRowSource struct {
	rows []SessionRow
	err  error
}

func (f *fakeRowSource) Snapshot() ([]SessionRow, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.rows, nil
}

// Same suspect PID across two consecutive ticks = warn ONCE.
func TestRealF9_Detector_DedupeAcrossTicks(t *testing.T) {
	prev := IsBypassDetectionOn()
	defer setBypassDetection(prev)
	setBypassDetection(true)

	reg := NewProxyBackendRegistry()
	src := &fakeRowSource{rows: []SessionRow{
		{PID: 999, ApplicationName: "agent:x:mission:m", BackendType: "client backend"},
	}}
	d := NewBypassDetector(reg, src, time.Second)
	out := captureLog(t, func() {
		d.Tick() // first observation → warn
		d.Tick() // same row, same tick → no second warn
	})
	if c := strings.Count(out, "BYPASS SUSPECTED"); c != 1 {
		t.Errorf("dedupe: expected exactly 1 warning across 2 ticks for same pid, got %d. log:\n%s", c, out)
	}
}

// Suspect PID disappears, then returns: warn AGAIN.
func TestRealF9_Detector_RewarnAfterDisappearance(t *testing.T) {
	prev := IsBypassDetectionOn()
	defer setBypassDetection(prev)
	setBypassDetection(true)

	reg := NewProxyBackendRegistry()
	src := &fakeRowSource{}
	d := NewBypassDetector(reg, src, time.Second)

	// Round 1: suspect present
	src.rows = []SessionRow{
		{PID: 999, ApplicationName: "agent:x:mission:m", BackendType: "client backend"},
	}
	out1 := captureLog(t, func() { d.Tick() })
	if !strings.Contains(out1, "BYPASS SUSPECTED") {
		t.Fatalf("round 1: expected warning, got: %s", out1)
	}

	// Round 2: suspect gone
	src.rows = nil
	captureLog(t, func() { d.Tick() })

	// Round 3: same suspect returns → must warn again
	src.rows = []SessionRow{
		{PID: 999, ApplicationName: "agent:x:mission:m", BackendType: "client backend"},
	}
	out3 := captureLog(t, func() { d.Tick() })
	if !strings.Contains(out3, "BYPASS SUSPECTED") {
		t.Errorf("round 3: returning suspect must be warned again, got: %s", out3)
	}
}

// FW_BYPASS_DETECTION=false disables the detector entirely.
func TestRealF9_Env_FalseDisablesDetection(t *testing.T) {
	prevEnv, hadEnv := os.LookupEnv("FW_BYPASS_DETECTION")
	prevGate := IsBypassDetectionOn()
	defer func() {
		if hadEnv {
			os.Setenv("FW_BYPASS_DETECTION", prevEnv)
		} else {
			os.Unsetenv("FW_BYPASS_DETECTION")
		}
		setBypassDetection(prevGate)
	}()
	os.Setenv("FW_BYPASS_DETECTION", "false")

	out := captureLog(t, func() { InitBypassDetectionGuard() })
	if IsBypassDetectionOn() {
		t.Errorf("FW_BYPASS_DETECTION=false must disable the gate, got ON")
	}
	if !strings.Contains(out, "DISABLED") {
		t.Errorf("expected DISABLED log when env disables detection, got: %s", out)
	}
}

// pg_stat_activity query error → log warning, continue without crash.
func TestRealF9_Detector_QueryErrorIsNonFatal(t *testing.T) {
	prev := IsBypassDetectionOn()
	defer setBypassDetection(prev)
	setBypassDetection(true)

	reg := NewProxyBackendRegistry()
	src := &fakeRowSource{err: errors.New("synthetic snapshot error")}
	d := NewBypassDetector(reg, src, time.Second)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Tick must not panic on snapshot error, got: %v", r)
		}
	}()
	out := captureLog(t, func() { d.Tick() })
	if !strings.Contains(out, "snapshot failed") {
		t.Errorf("expected snapshot-failed warning, got: %s", out)
	}
	if !strings.Contains(out, "non-fatal") {
		t.Errorf("warning should describe error as non-fatal, got: %s", out)
	}
}

// Self-check engages the gate on the canonical happy case.
func TestRealF9_SelfCheckEngagesGuard(t *testing.T) {
	prev := IsBypassDetectionOn()
	prevEnv, hadEnv := os.LookupEnv("FW_BYPASS_DETECTION")
	defer func() {
		setBypassDetection(prev)
		if hadEnv {
			os.Setenv("FW_BYPASS_DETECTION", prevEnv)
		} else {
			os.Unsetenv("FW_BYPASS_DETECTION")
		}
	}()
	os.Unsetenv("FW_BYPASS_DETECTION")
	setBypassDetection(false)

	out := captureLog(t, func() { InitBypassDetectionGuard() })
	if !IsBypassDetectionOn() {
		t.Errorf("self-check should pass on canonical case — guard expected ON. log: %s", out)
	}
	if !strings.Contains(out, "REAL-F9 guard active") {
		t.Errorf("expected REAL-F9 guard-active log, got: %s", out)
	}
}

// Self-check failure path: inject a broken classifier seam → guard OFF.
func TestRealF9_SelfCheckFailureFallsBack(t *testing.T) {
	prev := IsBypassDetectionOn()
	prevEnv, hadEnv := os.LookupEnv("FW_BYPASS_DETECTION")
	prevSeam := bypassClassifierSelfCheckFn
	defer func() {
		setBypassDetection(prev)
		if hadEnv {
			os.Setenv("FW_BYPASS_DETECTION", prevEnv)
		} else {
			os.Unsetenv("FW_BYPASS_DETECTION")
		}
		bypassClassifierSelfCheckFn = prevSeam
	}()
	os.Unsetenv("FW_BYPASS_DETECTION")
	bypassClassifierSelfCheckFn = func() bool { return false }
	setBypassDetection(true) // start ON to prove fallback flips it OFF

	out := captureLog(t, func() { InitBypassDetectionGuard() })
	if IsBypassDetectionOn() {
		t.Errorf("broken self-check must DISABLE detection, got ON. log: %s", out)
	}
	if !strings.Contains(out, "REAL-F9 self-check FAILED") {
		t.Errorf("expected REAL-F9 self-check FAILED warning, got: %s", out)
	}
}

// Gate OFF → tick is a no-op (no warning, no snapshot read).
type panicSource struct{}

func (panicSource) Snapshot() ([]SessionRow, error) {
	panic("snapshot must not be called when gate is OFF")
}

func TestRealF9_Detector_GateOffSkipsSnapshot(t *testing.T) {
	prev := IsBypassDetectionOn()
	defer setBypassDetection(prev)
	setBypassDetection(false)

	reg := NewProxyBackendRegistry()
	d := NewBypassDetector(reg, panicSource{}, time.Second)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("gate OFF must short-circuit Tick (no source call), but it panicked: %v", r)
		}
	}()
	d.Tick()
}
