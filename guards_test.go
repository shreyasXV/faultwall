package main

import (
	"bytes"
	"errors"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// captureLog redirects the standard logger output for the duration of fn so
// we can assert on the WARNING text. The default *log.Logger is the one our
// production code uses (log.Printf), so this captures it correctly.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	oldOut := log.Writer()
	oldFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(oldOut)
		log.SetFlags(oldFlags)
	}()
	fn()
	return buf.String()
}

// ─────────────────────────────────────────────────────────────────────────────
// F2 — unqualified-name allow-path normalization
// ─────────────────────────────────────────────────────────────────────────────

// (a) Healthy path: with the guard ON, bare "feedback" is allowed under
// "public.*" — the original bug.
func TestF2_HealthyPath_BareFeedbackAllowedUnderPublicStar(t *testing.T) {
	prev := IsUnqualifiedAllowNormalizationOn()
	defer setUnqualifiedAllowNormalization(prev)
	setUnqualifiedAllowNormalization(true)

	if !isTableAllowed("feedback", []string{"public.*"}) {
		t.Errorf("F2 ON: bare unqualified \"feedback\" must match allow=[public.*], got false")
	}
}

// (b) Fallback path: with the guard OFF (self-check failed), the prior
// behavior is preserved — bare "feedback" is NOT allowed under "public.*".
// This is fail-safe: deny rather than silently flip to a possibly-broken
// allow.
func TestF2_FallbackPath_BareFeedbackBlockedUnderPublicStar(t *testing.T) {
	prev := IsUnqualifiedAllowNormalizationOn()
	defer setUnqualifiedAllowNormalization(prev)
	setUnqualifiedAllowNormalization(false)

	if isTableAllowed("feedback", []string{"public.*"}) {
		t.Errorf("F2 OFF: must preserve pre-fix behavior — bare \"feedback\" should NOT match allow=[public.*]")
	}
}

// (c) Outside-allow-list table is still denied even with the guard ON.
// This is the regression-protection check the prompt called out: a table
// not in the allow list must remain blocked.
func TestF2_HealthyPath_TableOutsideAllowListStillDenied(t *testing.T) {
	prev := IsUnqualifiedAllowNormalizationOn()
	defer setUnqualifiedAllowNormalization(prev)
	setUnqualifiedAllowNormalization(true)

	// allow only public.users — bare "feedback" must NOT match
	if isTableAllowed("feedback", []string{"public.users"}) {
		t.Error("F2 ON: bare \"feedback\" must NOT match allow=[public.users]")
	}
	// schema-qualified table outside the allowed schema must still be blocked
	if isTableAllowed("secret.keys", []string{"public.*"}) {
		t.Error("F2 ON: \"secret.keys\" must NOT match allow=[public.*]")
	}
}

// (d) Block path is unaffected by the F2 guard. isTableBlocked must still
// flag a blocked table whether the guard is on or off — the fix is only in
// the ALLOW path.
func TestF2_BlockPathUnchanged(t *testing.T) {
	for _, on := range []bool{true, false} {
		prev := IsUnqualifiedAllowNormalizationOn()
		setUnqualifiedAllowNormalization(on)
		if !isTableBlocked("public.users", []string{"public.users"}) {
			t.Errorf("isTableBlocked must remain true (guard=%v)", on)
		}
		if !isTableBlocked("users", []string{"public.users"}) {
			t.Errorf("isTableBlocked schema-agnostic match must still fire (guard=%v)", on)
		}
		if isTableBlocked("public.allowed", []string{"public.users"}) {
			t.Errorf("isTableBlocked must not over-match (guard=%v)", on)
		}
		setUnqualifiedAllowNormalization(prev)
	}
}

// (e) Self-check engages the guard on the canonical happy case.
func TestF2_SelfCheckEngagesGuard(t *testing.T) {
	prev := IsUnqualifiedAllowNormalizationOn()
	defer setUnqualifiedAllowNormalization(prev)
	setUnqualifiedAllowNormalization(false)

	out := captureLog(t, func() { InitUnqualifiedAllowGuard() })
	if !IsUnqualifiedAllowNormalizationOn() {
		t.Fatalf("self-check should pass on the canonical case — guard expected ON. log: %s", out)
	}
	if !strings.Contains(out, "F2 guard active") {
		t.Errorf("expected F2 guard-active log, got: %s", out)
	}
}

// (f) Self-check failure path: simulate by swapping the default schema to a
// value that breaks expectation (1) of the self-check. The guard must stay
// OFF and a clear WARNING must be logged. Restores the original schema.
func TestF2_SelfCheckFailureFallsBack(t *testing.T) {
	prevSchema := defaultSchemaForAllowMatch
	prevGate := IsUnqualifiedAllowNormalizationOn()
	defer func() {
		defaultSchemaForAllowMatch = prevSchema
		setUnqualifiedAllowNormalization(prevGate)
	}()

	// Force the self-check to fail by pointing at a schema that won't
	// match "public.*" — bare "feedback" → "wrongschema.feedback" doesn't
	// hit the public.* prefix, so check (1) returns false.
	defaultSchemaForAllowMatch = "wrongschema"
	setUnqualifiedAllowNormalization(true) // start ON to prove fallback flips it OFF

	out := captureLog(t, func() { InitUnqualifiedAllowGuard() })
	if IsUnqualifiedAllowNormalizationOn() {
		t.Fatalf("self-check should fail — guard expected OFF. log: %s", out)
	}
	if !strings.Contains(out, "F2 self-check FAILED") {
		t.Errorf("expected F2 self-check FAILED warning, got: %s", out)
	}
}

// (g) End-to-end through CheckQuery: with F2 ON, an agent that emits an
// unqualified "FROM feedback" under a public.* mission must NOT get
// table_not_in_mission.
func TestF2_EndToEnd_CheckQueryUnqualifiedUnderPublicStar(t *testing.T) {
	prev := IsUnqualifiedAllowNormalizationOn()
	defer setUnqualifiedAllowNormalization(prev)
	setUnqualifiedAllowNormalization(true)

	pe := &PolicyEngine{
		config: &PolicyConfig{
			DefaultPolicy: "allow",
			Agents: map[string]AgentPolicy{
				"orm-agent": {
					AuthToken: "tok",
					Missions: map[string]MissionPolicy{
						"read": {Tables: []string{"public.*"}},
					},
				},
			},
			Unidentified: UnidentifiedPolicy{Policy: "deny"},
		},
		enforcement: "enforce",
	}
	id := &AgentIdentity{AgentID: "orm-agent", MissionID: "read", Token: "tok"}
	if v := pe.CheckQuery(id, "SELECT * FROM feedback", 0); v != nil && v.Reason == "table_not_in_mission" {
		t.Errorf("F2 ON: unqualified FROM feedback under public.* must not be table_not_in_mission, got %+v", v)
	}
}

// And with F2 OFF, the prior over-blocking behavior is preserved.
func TestF2_EndToEnd_FallbackOverblocksLikeBefore(t *testing.T) {
	prev := IsUnqualifiedAllowNormalizationOn()
	defer setUnqualifiedAllowNormalization(prev)
	setUnqualifiedAllowNormalization(false)

	pe := &PolicyEngine{
		config: &PolicyConfig{
			DefaultPolicy: "allow",
			Agents: map[string]AgentPolicy{
				"orm-agent": {
					AuthToken: "tok",
					Missions: map[string]MissionPolicy{
						"read": {Tables: []string{"public.*"}},
					},
				},
			},
			Unidentified: UnidentifiedPolicy{Policy: "deny"},
		},
		enforcement: "enforce",
	}
	id := &AgentIdentity{AgentID: "orm-agent", MissionID: "read", Token: "tok"}
	v := pe.CheckQuery(id, "SELECT * FROM feedback", 0)
	if v == nil || v.Reason != "table_not_in_mission" {
		t.Errorf("F2 OFF: must reproduce the pre-fix table_not_in_mission for unqualified ORM names, got %+v", v)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// F3 — spoofable identity warning + optional enforcement
// ─────────────────────────────────────────────────────────────────────────────

// (a) Warning emitted when at least one agent is tokenless.
func TestF3_WarningWhenTokenlessAgentExists(t *testing.T) {
	cfg := &PolicyConfig{
		Agents: map[string]AgentPolicy{
			"good": {AuthToken: "tok"},
			"bad":  {}, // no token → spoofable
		},
	}
	out := captureLog(t, func() { LogIdentitySpoofWarning(cfg) })
	if !strings.Contains(out, "IDENTITY SPOOFING WARNING") {
		t.Errorf("expected spoofing warning when tokenless agent exists, got: %s", out)
	}
	if !strings.Contains(out, "bad") {
		t.Errorf("warning should name the tokenless agent, got: %s", out)
	}
	if strings.Count(out, "IDENTITY SPOOFING WARNING") != 1 {
		t.Errorf("warning should be emitted exactly once (no per-connection spam), got: %s", out)
	}
}

// (b) No warning when every agent has a token.
func TestF3_NoWarningWhenAllTokensSet(t *testing.T) {
	cfg := &PolicyConfig{
		Agents: map[string]AgentPolicy{
			"a": {AuthToken: "tok-a"},
			"b": {AuthToken: "tok-b"},
		},
	}
	out := captureLog(t, func() { LogIdentitySpoofWarning(cfg) })
	if strings.Contains(out, "IDENTITY SPOOFING WARNING") {
		t.Errorf("no warning expected when all agents have tokens, got: %s", out)
	}
}

// (c) Healthy enforcement: require_auth_token=true blocks tokenless
// identity. We exercise the enforcement-decision function directly so we
// don't need to spin up a full proxy.
func TestF3_RequireAuthToken_BlocksTokenlessAgent(t *testing.T) {
	prev := IsRequireAuthTokenOn()
	defer requireAuthTokenOn.Store(prev)
	requireAuthTokenOn.Store(true)

	tokenless := &AgentIdentity{AgentID: "x", Token: ""}
	if !requireAuthTokenEnforce(tokenless, false, false) {
		t.Error("require_auth_token ON: tokenless identity must be rejected")
	}
}

// (d) Self-check failure path: simulate by stubbing the gate so that the
// enforcement function rejects nothing (a "broken enforcer"). The guard
// must fall back to warn-only and the operator gets a clear WARNING.
//
// We model the broken enforcer by setting FW_REQUIRE_AUTH_TOKEN=true but
// then poisoning the gate — emulated here by having the self-check observe
// a stubbed state. The cleanest way is to give the self-check a function
// hook for tests (or alternatively, swap the env var path).
func TestF3_SelfCheckFailureFallsBackToWarnOnly(t *testing.T) {
	prevEnv, hadEnv := os.LookupEnv("FW_REQUIRE_AUTH_TOKEN")
	defer func() {
		if hadEnv {
			os.Setenv("FW_REQUIRE_AUTH_TOKEN", prevEnv)
		} else {
			os.Unsetenv("FW_REQUIRE_AUTH_TOKEN")
		}
		requireAuthTokenOn.Store(false)
	}()
	os.Setenv("FW_REQUIRE_AUTH_TOKEN", "true")

	// Inject a broken enforcer for the duration of the test by overriding
	// the package-level decision function. The self-check then observes
	// "tokenless identity not rejected" and must fall back.
	prevDecision := requireAuthTokenEnforceFn
	defer func() { requireAuthTokenEnforceFn = prevDecision }()
	requireAuthTokenEnforceFn = func(id *AgentIdentity, hasToken, match bool) bool {
		// Broken: never reject anything.
		return false
	}

	out := captureLog(t, func() { InitRequireAuthTokenGuard() })
	if IsRequireAuthTokenOn() {
		t.Fatalf("broken enforcer self-check must DISABLE require_auth_token. log: %s", out)
	}
	if !strings.Contains(out, "F3 self-check FAILED") {
		t.Errorf("expected F3 self-check FAILED warning, got: %s", out)
	}
}

// (e) Self-check pass path: env on + real enforcer → guard activates.
func TestF3_SelfCheckPassEnablesEnforcement(t *testing.T) {
	prevEnv, hadEnv := os.LookupEnv("FW_REQUIRE_AUTH_TOKEN")
	defer func() {
		if hadEnv {
			os.Setenv("FW_REQUIRE_AUTH_TOKEN", prevEnv)
		} else {
			os.Unsetenv("FW_REQUIRE_AUTH_TOKEN")
		}
		requireAuthTokenOn.Store(false)
	}()
	os.Setenv("FW_REQUIRE_AUTH_TOKEN", "true")

	out := captureLog(t, func() { InitRequireAuthTokenGuard() })
	if !IsRequireAuthTokenOn() {
		t.Fatalf("self-check should pass and enable F3 enforcement. log: %s", out)
	}
	if !strings.Contains(out, "F3 guard active") {
		t.Errorf("expected F3 guard-active log, got: %s", out)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// F9 — DB-port isolation startup self-probe
// ─────────────────────────────────────────────────────────────────────────────

// (a) Probe runs and reports REACHABLE against a real test listener. The
// loud isolation warning must fire. We stand up a localhost listener so we
// don't depend on any external host.
func TestF9_ProbeReachableAgainstTestListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("test setup: failed to listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	out := captureLog(t, func() {
		res := RunDBIsolationProbe(addr)
		if !res.Reachable {
			t.Errorf("expected reachable=true, got %+v", res)
		}
	})
	if !strings.Contains(out, "DIRECTLY REACHABLE") {
		t.Errorf("expected DIRECTLY REACHABLE warning, got: %s", out)
	}
	if !strings.Contains(out, "HARD REQUIREMENT") {
		t.Errorf("expected HARD REQUIREMENT in warning, got: %s", out)
	}
}

// (b) Probe runs against an unreachable port. Connection-refused is
// reported as a positive local signal (not reachable from this host) but
// still flags isolation as a hard requirement.
func TestF9_ProbeUnreachablePort(t *testing.T) {
	// Bind and immediately close to grab a port that's then refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("test setup: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	out := captureLog(t, func() {
		res := RunDBIsolationProbe(addr)
		if res.Reachable {
			t.Errorf("expected reachable=false for closed port, got %+v", res)
		}
		if res.ProbeError != "" {
			t.Errorf("connection refused should not be a probe error, got: %q", res.ProbeError)
		}
	})
	if !strings.Contains(out, "NOT reachable") {
		t.Errorf("expected NOT reachable log, got: %s", out)
	}
}

// (c) Probe failure (probe-itself errors) does NOT crash and DOES log a
// warning. We force this by overriding the dialer with one that returns a
// non-refused error.
func TestF9_ProbeErrorDoesNotCrash(t *testing.T) {
	prev := dbIsolationDialer
	defer func() { dbIsolationDialer = prev }()
	dbIsolationDialer = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		return nil, errors.New("simulated DNS failure")
	}

	out := captureLog(t, func() {
		// Must not panic.
		res := RunDBIsolationProbe("does-not-resolve.invalid:5432")
		if res.ProbeError == "" {
			t.Error("expected ProbeError to be set on dialer failure")
		}
		if res.Reachable {
			t.Error("dialer failure must not flip Reachable=true")
		}
	})
	if !strings.Contains(out, "could not run") {
		t.Errorf("expected probe-could-not-run warning, got: %s", out)
	}
	if !strings.Contains(out, "non-fatal") {
		t.Errorf("warning should describe probe as non-fatal, got: %s", out)
	}
}

// (d) Disabled by config: the probe is skipped and a single line is
// logged so the operator sees that they turned it off intentionally.
func TestF9_DisabledByConfig(t *testing.T) {
	prev, had := os.LookupEnv("FW_DB_ISOLATION_CHECK")
	defer func() {
		if had {
			os.Setenv("FW_DB_ISOLATION_CHECK", prev)
		} else {
			os.Unsetenv("FW_DB_ISOLATION_CHECK")
		}
	}()
	os.Setenv("FW_DB_ISOLATION_CHECK", "false")

	out := captureLog(t, func() {
		res := RunDBIsolationProbe("127.0.0.1:1") // would otherwise be refused
		if !res.Disabled {
			t.Errorf("expected Disabled=true when FW_DB_ISOLATION_CHECK=false, got %+v", res)
		}
		if res.Reachable {
			t.Error("must not run dial when disabled")
		}
	})
	if !strings.Contains(out, "DISABLED") {
		t.Errorf("expected disabled-log, got: %s", out)
	}
}
