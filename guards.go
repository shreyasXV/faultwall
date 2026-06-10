package main

// Self-disabling feature guards.
//
// Each new behavior in this file is gated behind an explicit enable plus a
// startup self-check. If the self-check disagrees with what the new behavior
// is supposed to do, the feature disables itself and the proxy falls back to
// the prior, safe path with a logged WARNING. The rule is: never silently
// ship a broken fix; for security, fail-safe means closed (deny / preserve
// existing block / preserve warn-only).
//
// Three features live here:
//
//   F2 — unqualified-name allow-path normalization
//        (isTableAllowed treats bare "feedback" as "public.feedback" for
//        ALLOW matching only; never loosens BLOCK matching)
//
//   F3 — spoofable-identity startup warning + optional require_auth_token
//        enforcement
//
//   F9 — best-effort DB-port isolation self-probe (warn-only)

import (
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// F2 — unqualified-name allow-path normalization guard
// ─────────────────────────────────────────────────────────────────────────────

// unqualifiedAllowNormalizationOn is the runtime gate consulted by
// isTableAllowed. It defaults to 0 (off / current behavior) and is only
// flipped to 1 if InitUnqualifiedAllowGuard's self-check passes.
//
// When OFF: isTableAllowed behaves exactly as before; an unqualified bare
// table name like "feedback" does not match an allow entry of "public.*",
// so the agent gets table_not_in_mission. (This is the pre-fix state.)
//
// When ON: an unqualified bare reference is normalized to the configured
// default schema (almost always "public") for the ALLOW match, so that
// "feedback" matches an allow entry of "public.*" or "public.feedback".
// Schema-qualified references are unaffected. The BLOCK path is never
// touched.
var unqualifiedAllowNormalizationOn atomic.Bool

// defaultSchemaForAllowMatch is the schema prepended to unqualified table
// references when the allow-path normalization is on. Postgres' default
// search_path puts "public" first, so this is the operationally correct
// choice. We keep it as a package-level so tests can swap it.
var defaultSchemaForAllowMatch = "public"

// IsUnqualifiedAllowNormalizationOn reports whether the F2 normalization
// guard is currently enabled. Exposed for tests and diagnostic logging.
func IsUnqualifiedAllowNormalizationOn() bool {
	return unqualifiedAllowNormalizationOn.Load()
}

// setUnqualifiedAllowNormalization is for tests to toggle the gate without
// going through the self-check.
func setUnqualifiedAllowNormalization(on bool) {
	unqualifiedAllowNormalizationOn.Store(on)
}

// InitUnqualifiedAllowGuard runs the F2 self-check and engages the guard if
// the check confirms the normalization is correct. The contract checked is:
//
//   1. Bare "feedback" must match an allow list of {"public.*"}.
//      (The bug: pre-fix this returned false because "feedback" doesn't
//      have the "public." prefix. The fix: normalize to "public.feedback"
//      for the allow match.)
//
//   2. Bare "feedback" must NOT match an allow list of {"public.users"}.
//      (Verifies the normalization didn't slip into a "match anything in
//      the schema" wildcard.)
//
//   3. A schema-qualified reference outside the allow list must still be
//      blocked: "secret.keys" must not match {"public.*"}. This guards
//      against an over-eager normalization that loses the schema.
//
// If any check disagrees, we log a clear WARNING, leave the guard OFF, and
// the proxy falls back to the original (stricter) isTableAllowed behavior.
func InitUnqualifiedAllowGuard() {
	if !unqualifiedAllowNormalizationCandidatePass() {
		log.Printf("⚠️  F2 self-check FAILED: unqualified-name allow-path normalization disabled. "+
			"isTableAllowed will fall back to the prior (block-on-bare-name) behavior. "+
			"Agents emitting unqualified ORM table names may be over-blocked under public.* allow lists. "+
			"This is a fail-safe (closed) state, not a security regression.")
		unqualifiedAllowNormalizationOn.Store(false)
		return
	}
	unqualifiedAllowNormalizationOn.Store(true)
	log.Printf("✅ F2 guard active: unqualified table names will be normalized to %q for ALLOW matching only "+
		"(BLOCK matching is unchanged).", defaultSchemaForAllowMatch+".<name>")
}

// unqualifiedAllowNormalizationCandidatePass exercises the three contract
// cases against a simulated isTableAllowed-with-normalization. We do this in
// a sandboxed local function so the self-check is decoupled from the live
// gate (no chicken-and-egg).
func unqualifiedAllowNormalizationCandidatePass() bool {
	check := func(table string, allowed []string) bool {
		return isTableAllowedWithNormalization(table, allowed, true)
	}
	// (1) bare "feedback" under "public.*" must match
	if !check("feedback", []string{"public.*"}) {
		return false
	}
	// (2) bare "feedback" under {"public.users"} must NOT match
	if check("feedback", []string{"public.users"}) {
		return false
	}
	// (3) qualified "secret.keys" under "public.*" must NOT match
	if check("secret.keys", []string{"public.*"}) {
		return false
	}
	// (4) bare "feedback" under "public.feedback" must match
	if !check("feedback", []string{"public.feedback"}) {
		return false
	}
	// (5) bare "*" still allows any
	if !check("anything", []string{"*"}) {
		return false
	}
	return true
}

// ─────────────────────────────────────────────────────────────────────────────
// F3 — spoofable identity warning + optional require_auth_token enforcement
// ─────────────────────────────────────────────────────────────────────────────

// requireAuthTokenOn is the runtime gate consulted by the proxy's auth
// block. When ON, agents that present an identity but no token (or whose
// agent definition has no auth_token configured) are rejected at startup
// of the connection. When OFF (default), behavior is unchanged: the proxy
// only enforces tokens for agents that have one configured.
var requireAuthTokenOn atomic.Bool

// IsRequireAuthTokenOn reports whether F3 enforcement is currently enabled.
func IsRequireAuthTokenOn() bool {
	return requireAuthTokenOn.Load()
}

// requireAuthTokenEnforceFn is the enforcement-decision function. Tests
// can swap it to simulate a broken enforcer (the F3 self-check then
// catches the broken state and falls back to warn-only). Production uses
// requireAuthTokenEnforceImpl.
var requireAuthTokenEnforceFn = requireAuthTokenEnforceImpl

// requireAuthTokenEnforce is the public seam used by the proxy. It calls
// through requireAuthTokenEnforceFn so the self-check sees the same
// implementation the proxy will use.
func requireAuthTokenEnforce(identity *AgentIdentity, agentHasToken bool, tokensMatch bool) bool {
	return requireAuthTokenEnforceFn(identity, agentHasToken, tokensMatch)
}

// requireAuthTokenEnforceImpl is the production decision. Returns true if
// the connection should be REJECTED (closed/fail-safe) under
// require_auth_token=true. The function captures the spec: if F3
// enforcement is off, never reject from this path (the proxy's existing
// per-agent token check still runs separately).
//
//   - identity == nil: not our path; defer to existing unidentified policy.
//   - identity != nil but token missing: reject.
//   - identity has agent with no auth_token configured: reject (spoofable).
//   - identity matches an agent with token configured and tokens differ:
//     reject (this is also caught by the existing per-agent check; we
//     duplicate it here so the self-check sees an enforcement signal).
func requireAuthTokenEnforceImpl(identity *AgentIdentity, agentHasToken bool, tokensMatch bool) bool {
	if !requireAuthTokenOn.Load() {
		return false
	}
	if identity == nil {
		return false
	}
	if identity.Token == "" {
		return true
	}
	if !agentHasToken {
		// Identity carries a token but the policy file has no token for
		// this agent — we can't verify, treat as spoofable.
		return true
	}
	if !tokensMatch {
		return true
	}
	return false
}

// InitRequireAuthTokenGuard runs the F3 self-check. If the env var
// FW_REQUIRE_AUTH_TOKEN is "true" the operator is asking for enforce mode.
// We then verify the enforcement decision function actually rejects a
// known-tokenless identity. If the check disagrees, we fall back to
// warn-only (turn the gate OFF) with a logged WARNING. The startup warning
// itself (count of tokenless agents) is always emitted by
// LogIdentitySpoofWarning, regardless of this gate.
func InitRequireAuthTokenGuard() {
	want := strings.ToLower(strings.TrimSpace(os.Getenv("FW_REQUIRE_AUTH_TOKEN"))) == "true"
	if !want {
		requireAuthTokenOn.Store(false)
		return
	}
	// Tentatively enable, then probe the enforcement function.
	requireAuthTokenOn.Store(true)
	if !requireAuthTokenSelfCheckPass() {
		requireAuthTokenOn.Store(false)
		log.Printf("⚠️  F3 self-check FAILED: require_auth_token enforcement could not be verified " +
			"(known-tokenless identity was not rejected by the enforcement check). " +
			"Falling back to WARN-ONLY mode so a buggy enforcer does not give a false sense of " +
			"security. Set auth_token on every agent and investigate before re-enabling.")
		return
	}
	log.Printf("🔐 F3 guard active: require_auth_token=true — agents without a verified token will be REJECTED.")
}

// requireAuthTokenSelfCheckPass verifies the enforcement function rejects
// the obvious failure cases. Run only when require_auth_token is requested.
func requireAuthTokenSelfCheckPass() bool {
	// (a) tokenless identity must be rejected
	tokenless := &AgentIdentity{AgentID: "selfcheck", Token: ""}
	if !requireAuthTokenEnforce(tokenless, false, false) {
		return false
	}
	// (b) identity with token but agent has no token configured: rejected
	withToken := &AgentIdentity{AgentID: "selfcheck", Token: "x"}
	if !requireAuthTokenEnforce(withToken, false, false) {
		return false
	}
	// (c) identity with matching token must NOT be rejected
	if requireAuthTokenEnforce(withToken, true, true) {
		return false
	}
	// (d) gate off → never reject
	requireAuthTokenOn.Store(false)
	if requireAuthTokenEnforce(tokenless, false, false) {
		// restore and fail
		requireAuthTokenOn.Store(true)
		return false
	}
	requireAuthTokenOn.Store(true)
	return true
}

// LogIdentitySpoofWarning emits a single, loud startup warning if any agent
// in the policy config has no auth_token set. The warning is always
// printed (independent of the require_auth_token gate). Returns true if a
// warning was emitted (used by tests).
func LogIdentitySpoofWarning(cfg *PolicyConfig) bool {
	if cfg == nil {
		return false
	}
	tokenless := make([]string, 0, len(cfg.Agents))
	for id, ap := range cfg.Agents {
		if strings.TrimSpace(ap.AuthToken) == "" {
			tokenless = append(tokenless, id)
		}
	}
	if len(tokenless) == 0 {
		return false
	}
	log.Printf("⚠️  IDENTITY SPOOFING WARNING: %d agent(s) have NO auth_token configured: %s. "+
		"Agent identity is derived from PostgreSQL application_name, which is fully spoofable. "+
		"Without an auth_token, any client can impersonate these agent IDs and inherit their "+
		"mission permissions. Set 'auth_token: <secret>' under each agent in policies.yaml, then "+
		"have the agent send 'agent:<id>:mission:<m>:token:<secret>' as application_name. "+
		"To make tokenless agents fail-closed, set FW_REQUIRE_AUTH_TOKEN=true.",
		len(tokenless), strings.Join(tokenless, ", "))
	return true
}

// ─────────────────────────────────────────────────────────────────────────────
// F9 — DB-port isolation startup self-probe (warn-only, non-fatal)
// ─────────────────────────────────────────────────────────────────────────────

// dbIsolationProbeResult captures what the probe observed. Returned for
// tests; the production path only logs.
type dbIsolationProbeResult struct {
	Disabled    bool   // probe was disabled by config — nothing was tried
	ProbeError  string // probe itself errored (DNS, etc) — non-fatal
	Address     string // upstream address that was probed
	Reachable   bool   // TCP-dial from the proxy host succeeded
	DurationMs  int64  // wall-clock for the dial attempt
}

// dbIsolationDialer is overridable for tests so they don't depend on real
// network listeners. Production uses net.DialTimeout.
var dbIsolationDialer = func(network, addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, addr, timeout)
}

// nowFunc is overridable for tests of the F9 probe; production uses
// time.Now. We keep it package-local so the rest of the codebase isn't
// affected.
var nowFunc = time.Now

// RunDBIsolationProbe performs a best-effort TCP-dial against the upstream
// Postgres address from the proxy host. It is non-fatal: a probe error
// (DNS resolution failure, etc) is logged as a WARNING and the proxy
// continues. The probe never blocks startup beyond its dial timeout.
//
// Behavior matrix:
//   db_isolation_check=false       → skip silently, return Disabled=true
//   reachable & probe ok           → loud WARN: DB port directly reachable
//                                    from proxy host, isolation NOT proven
//   unreachable & probe ok         → INFO: DB port not reachable from proxy
//                                    host (good signal, not a guarantee)
//   probe errored                  → WARN: probe could not run, continue
func RunDBIsolationProbe(upstreamAddr string) dbIsolationProbeResult {
	if strings.ToLower(strings.TrimSpace(os.Getenv("FW_DB_ISOLATION_CHECK"))) == "false" {
		log.Printf("F9 DB-port isolation probe DISABLED via FW_DB_ISOLATION_CHECK=false. " +
			"Operators must verify externally that agents cannot reach the upstream Postgres " +
			"port directly; FaultWall enforces SQL only via the proxy.")
		return dbIsolationProbeResult{Disabled: true, Address: upstreamAddr}
	}

	res := dbIsolationProbeResult{Address: upstreamAddr}
	if upstreamAddr == "" {
		log.Printf("⚠️  F9 DB-port isolation probe SKIPPED: no upstream address configured. " +
			"This is a hard-isolation REQUIREMENT regardless: agents must only reach the proxy, " +
			"not the database port directly.")
		res.ProbeError = "no upstream address"
		return res
	}

	start := nowFunc()
	conn, err := dbIsolationDialer("tcp", upstreamAddr, 2*time.Second)
	res.DurationMs = nowFunc().Sub(start).Milliseconds()
	if err != nil {
		// Distinguish a "connection refused" (good — port not reachable)
		// from a probe-itself-error (DNS, permission, timeout). Both are
		// non-fatal; we just log differently so the operator gets the
		// right signal.
		errStr := err.Error()
		if strings.Contains(errStr, "refused") {
			res.Reachable = false
			log.Printf("F9 DB-port isolation probe: upstream %s NOT reachable from proxy host (connection refused). "+
				"This is a *positive* local signal but NOT proof of network isolation — agents on other hosts "+
				"or in other namespaces may still have direct access. DB-port isolation is a HARD REQUIREMENT: "+
				"FaultWall enforces SQL only via the proxy; if agents can reach the DB port directly, the "+
				"entire security promise is void. Verify network policy / security groups / firewall rules.",
				upstreamAddr)
			return res
		}
		// Probe-itself-error: must NOT crash the proxy.
		res.ProbeError = errStr
		log.Printf("⚠️  F9 DB-port isolation probe could not run for %s: %v. "+
			"Continuing startup — this check is best-effort and non-fatal. DB-port isolation remains a "+
			"HARD REQUIREMENT: agents must only be able to reach the proxy listener, not the upstream "+
			"database port directly. Verify network policy / security groups / firewall rules manually.",
			upstreamAddr, err)
		return res
	}
	conn.Close()
	res.Reachable = true
	log.Printf("⚠️  F9 DB-port isolation probe: upstream %s IS DIRECTLY REACHABLE from the proxy host. "+
		"This is best-effort topology info: it CONFIRMS the proxy can reach the DB (good), but it does "+
		"NOT prove that other hosts/agents are blocked. DB-port isolation is a HARD REQUIREMENT — if "+
		"agents can reach %s without going through the proxy, all SQL-level enforcement is bypassed and "+
		"PII is exposed. Verify network policy / security groups / firewall rules so that ONLY the "+
		"FaultWall proxy can reach the upstream Postgres port.",
		upstreamAddr, upstreamAddr)
	return res
}
