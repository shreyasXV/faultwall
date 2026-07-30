package main

// REAL F2 — per-connection search_path tracking.
//
// The shipped F2 (see guards.go: unqualifiedAllowNormalizationOn) hard-codes
// "public" as the default schema for unqualified ALLOW matches. That is
// correct only when the agent never changes search_path. If an agent issues
// `SET search_path TO myschema` (or a multi-schema list), an unqualified
// `feedback` resolves server-side to `myschema.feedback`, but the shipped
// path normalizes to `public.feedback` — which either over-blocks (a
// `myschema.*` mission) or under-validates (a `public.*` mission would
// allow it even though Postgres will run it against `myschema`).
//
// This file tracks search_path PER CONNECTION (the proxyQueryLoop scope is
// already one goroutine per connection — the right granularity) and threads
// the current list into CheckQuery. The behavior is gated by
// `searchPathAwareAllowOn`. Self-check failure → gate stays OFF and the
// proxy falls back to the shipped, public-only F2 normalization (which is
// itself guarded). Fail-safe = closed.

import (
	"log"
	"strings"
	"sync/atomic"
)

// ─────────────────────────────────────────────────────────────────────────────
// Per-connection state
// ─────────────────────────────────────────────────────────────────────────────

// SearchPathState is the per-connection search_path the proxy has observed.
// It is updated as the connection issues `SET search_path`/`RESET
// search_path` statements; the policy check reads it on every query.
//
// Default (no SET seen): []string{"public"} — Postgres' factory default for
// most setups. We deliberately do not try to read the role's
// configured-default search_path: that would require querying the DB at
// connect time and a stale answer is worse than this conservative default.
// (See caveats in the report.)
type SearchPathState struct {
	schemas []string
}

// NewSearchPathState returns the connection's initial search_path.
func NewSearchPathState() *SearchPathState {
	return &SearchPathState{schemas: []string{"public"}}
}

// Schemas returns a copy-safe view of the current search_path. We return the
// underlying slice (callers must NOT mutate); the parser always allocates a
// fresh slice when it updates the state, so reads are stable.
func (s *SearchPathState) Schemas() []string {
	if s == nil {
		return []string{"public"}
	}
	return s.schemas
}

// Reset returns the search_path to the default. Mirrors `RESET search_path`
// or `SET search_path TO DEFAULT`.
func (s *SearchPathState) Reset() {
	s.schemas = []string{"public"}
}

// Set installs a new ordered schema list. A nil/empty list resets to default.
func (s *SearchPathState) Set(schemas []string) {
	if len(schemas) == 0 {
		s.Reset()
		return
	}
	cp := make([]string, 0, len(schemas))
	for _, sc := range schemas {
		sc = strings.TrimSpace(sc)
		if sc == "" {
			continue
		}
		cp = append(cp, sc)
	}
	if len(cp) == 0 {
		s.Reset()
		return
	}
	s.schemas = cp
}

// ─────────────────────────────────────────────────────────────────────────────
// SET search_path parser
// ─────────────────────────────────────────────────────────────────────────────

// ApplySearchPathStatement inspects a query for `SET search_path …` or
// `RESET search_path` semantics. If the query is a search_path mutation,
// the receiver is updated in place and the function returns true. Otherwise
// the receiver is unchanged and the function returns false.
//
// Behavior:
//   - `SET search_path TO a, b;`         → ["a", "b"]
//   - `SET search_path = "MyS", public;` → ["MyS", "public"] (quoted ident
//                                          preserves case)
//   - `SET search_path TO DEFAULT`       → reset
//   - `RESET search_path`                → reset
//   - `SET LOCAL search_path TO …`       → applied (we treat LOCAL the same;
//                                          the proxy isn't transaction-aware
//                                          enough to scope it; conservative)
//   - `$user` token                      → kept as-is. We don't know the
//                                          server's `current_user`, so we
//                                          can't expand it; matching falls
//                                          through to the next entry.
//   - any other query                    → returns false, no change.
//
// Identifiers fold to lowercase Postgres-style when unquoted; quoted
// identifiers preserve case (we only strip the surrounding quotes). Schema
// matching downstream is case-insensitive, so the case preservation is
// cosmetic for the policy decision but kept so logs reflect what was
// actually requested.
func (s *SearchPathState) ApplySearchPathStatement(query string) bool {
	if s == nil {
		return false
	}
	trimmed := strings.TrimSpace(query)
	// Strip any trailing semicolons/whitespace.
	trimmed = strings.TrimRight(trimmed, "; \t\r\n")
	if trimmed == "" {
		return false
	}
	upper := strings.ToUpper(trimmed)

	// `RESET search_path`
	if strings.HasPrefix(upper, "RESET ") {
		rest := strings.TrimSpace(trimmed[len("RESET "):])
		if strings.EqualFold(rest, "search_path") {
			s.Reset()
			return true
		}
		return false
	}

	if !strings.HasPrefix(upper, "SET ") {
		return false
	}
	// Drop "SET " (case-preserving).
	rest := strings.TrimSpace(trimmed[4:])
	upRest := strings.ToUpper(rest)
	// Optional LOCAL/SESSION qualifier.
	if strings.HasPrefix(upRest, "LOCAL ") {
		rest = strings.TrimSpace(rest[len("LOCAL "):])
	} else if strings.HasPrefix(upRest, "SESSION ") {
		rest = strings.TrimSpace(rest[len("SESSION "):])
	}
	upRest = strings.ToUpper(rest)
	if !strings.HasPrefix(upRest, "SEARCH_PATH") {
		return false
	}
	rest = strings.TrimSpace(rest[len("SEARCH_PATH"):])
	// Allow either `TO` or `=` between the name and the value.
	upRest = strings.ToUpper(rest)
	switch {
	case strings.HasPrefix(upRest, "TO "):
		rest = strings.TrimSpace(rest[3:])
	case strings.HasPrefix(upRest, "TO\t"):
		rest = strings.TrimSpace(rest[3:])
	case strings.HasPrefix(rest, "="):
		rest = strings.TrimSpace(rest[1:])
	default:
		// `SET search_path` with no value is malformed — leave state alone.
		return false
	}

	// `DEFAULT` keyword resets the path.
	if strings.EqualFold(rest, "DEFAULT") {
		s.Reset()
		return true
	}

	schemas := parseSearchPathList(rest)
	s.Set(schemas)
	return true
}

// parseSearchPathList splits the right-hand side of a `SET search_path TO`
// statement into individual schema tokens. Handles quoted identifiers
// ("Foo Bar"), the special `$user` placeholder, and stray whitespace.
func parseSearchPathList(s string) []string {
	out := []string{}
	i := 0
	for i < len(s) {
		// skip whitespace + commas
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == ',') {
			i++
		}
		if i >= len(s) {
			break
		}
		if s[i] == '"' {
			// Quoted identifier — read until the matching unescaped quote.
			i++
			start := i
			for i < len(s) && s[i] != '"' {
				i++
			}
			out = append(out, s[start:i])
			if i < len(s) {
				i++ // consume closing quote
			}
			continue
		}
		// Unquoted token — read until comma/whitespace.
		start := i
		for i < len(s) && s[i] != ',' && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		tok := s[start:i]
		if tok == "" {
			continue
		}
		// `$user` is a placeholder we cannot expand without querying the
		// DB; preserve it as-is (callers skip it during matching).
		if !strings.EqualFold(tok, "$user") {
			tok = strings.ToLower(tok) // unquoted identifiers fold to lower
		}
		out = append(out, tok)
	}
	return out
}

// IsSearchPathStatement is a cheap predicate the proxy uses to decide
// whether to bother feeding a query to ApplySearchPathStatement. It only
// peeks at the leading keyword. False positives are fine; false negatives
// would silently miss a mutation.
func IsSearchPathStatement(query string) bool {
	q := strings.TrimSpace(query)
	if q == "" {
		return false
	}
	q = strings.ToUpper(q)
	// We must catch SET LOCAL/SESSION search_path forms too.
	if strings.HasPrefix(q, "RESET ") {
		return strings.Contains(q, "SEARCH_PATH")
	}
	if !strings.HasPrefix(q, "SET ") {
		return false
	}
	return strings.Contains(q, "SEARCH_PATH")
}

// ─────────────────────────────────────────────────────────────────────────────
// Guard for the search-path-aware ALLOW match
// ─────────────────────────────────────────────────────────────────────────────

// searchPathAwareAllowOn gates the search-path-aware ALLOW path. Default
// OFF; flipped ON only after InitSearchPathAwareAllowGuard's self-check
// agrees with the contract.
//
// When OFF: the proxy falls back to the shipped F2 normalization (always
// "public.<name>" for unqualified ALLOW matches). That fallback is itself
// guarded by unqualifiedAllowNormalizationOn — so a search-path-aware
// self-check failure does NOT regress to the pre-F2 over-block; it just
// loses the per-connection precision.
//
// When ON: isTableAllowedWithContext (in policy.go) normalizes an
// unqualified table name against the connection's CURRENT search_path:
// for each schema in order, try `<schema>.<name>` against the allow list;
// if any matches, allow.
var searchPathAwareAllowOn atomic.Bool

// IsSearchPathAwareAllowOn reports the current gate state.
func IsSearchPathAwareAllowOn() bool { return searchPathAwareAllowOn.Load() }

// setSearchPathAwareAllow is the test-only seam for flipping the gate
// without going through the self-check.
func setSearchPathAwareAllow(on bool) { searchPathAwareAllowOn.Store(on) }

// searchPathAwareAllowSelfCheckPassFn is the test-only seam used by the
// failure-path test in searchpath_test.go. Production assigns the real
// candidate-pass function below.
var searchPathAwareAllowSelfCheckPassFn = searchPathAwareAllowSelfCheckPass

// InitSearchPathAwareAllowGuard runs the self-check and engages the gate
// only on contract agreement. Six contracts (mirror of the spec):
//
//  1. search_path=["public"], bare "feedback" matches allow ["public.*"]
//  2. search_path=["myschema"], bare "feedback" matches allow ["myschema.*"]
//  3. search_path=["myschema"], bare "feedback" does NOT match allow
//     ["public.users"]
//  4. search_path=["myschema","public"], bare "feedback" matches allow
//     ["public.feedback"] (resolves via the second entry)
//  5. BLOCK: search_path=["secret"], bare "keys" is BLOCKED when blocklist
//     has "secret.keys" (we do not loosen blocking)
//  6. parser: `SET search_path TO a, b;` → ["a","b"]; `RESET search_path`
//     → default; `SET search_path TO DEFAULT` → default.
//
// Failure → gate OFF + WARNING + fall back to the shipped public-only F2
// (which is itself a guarded improvement over pre-F2). Never crashes.
func InitSearchPathAwareAllowGuard() {
	// The self-check itself flips the gate ON during contract probing
	// (because isTableAllowedWithContext only consults search_path when
	// IsSearchPathAwareAllowOn() is true). We tentatively enable, run
	// the probe, and either confirm or revert.
	prev := searchPathAwareAllowOn.Load()
	searchPathAwareAllowOn.Store(true)
	if !searchPathAwareAllowSelfCheckPassFn() {
		searchPathAwareAllowOn.Store(false)
		_ = prev
		log.Printf("WARN: REAL-F2 self-check FAILED: per-connection search_path tracking disabled. "+
			"Falling back to shipped F2 (public-only ALLOW normalization, guard=%v). "+
			"Agents that issue `SET search_path TO <non-public>` may be over-blocked or "+
			"under-validated. This is fail-safe (closed): we keep the prior, validated behavior "+
			"rather than silently shipping a broken search_path-aware path.",
			IsUnqualifiedAllowNormalizationOn())
		return
	}
	searchPathAwareAllowOn.Store(true)
	log.Printf("REAL-F2 guard active: per-connection search_path is tracked and used for "+
		"unqualified ALLOW matching (BLOCK matching is unchanged — still considers all " +
		"schemas in search_path). Default search_path is [\"public\"] until the agent " +
		"issues SET search_path.")
}

// searchPathAwareAllowSelfCheckPass exercises the six contracts. We use
// the policy package's isTableAllowedWithContext directly (see policy.go),
// passing normalize=true and a synthetic schema context, so the self-check
// validates the production matcher rather than a stub.
func searchPathAwareAllowSelfCheckPass() bool {
	// (1)
	if !isTableAllowedWithContext("feedback", []string{"public.*"}, true, []string{"public"}) {
		return false
	}
	// (2)
	if !isTableAllowedWithContext("feedback", []string{"myschema.*"}, true, []string{"myschema"}) {
		return false
	}
	// (3)
	if isTableAllowedWithContext("feedback", []string{"public.users"}, true, []string{"myschema"}) {
		return false
	}
	// (4)
	if !isTableAllowedWithContext("feedback", []string{"public.feedback"}, true, []string{"myschema", "public"}) {
		return false
	}
	// (5) BLOCK path is unchanged but we double-check: search_path can
	// include a schema that the blocklist names; an unqualified bare name
	// must still be caught when it could resolve to that blocked schema.
	if !isTableBlockedWithContext("keys", []string{"secret.keys"}, []string{"secret"}) {
		return false
	}
	// (6) parser smoke tests
	st := NewSearchPathState()
	if ok := st.ApplySearchPathStatement("SET search_path TO a, b;"); !ok ||
		len(st.Schemas()) != 2 || st.Schemas()[0] != "a" || st.Schemas()[1] != "b" {
		return false
	}
	if ok := st.ApplySearchPathStatement("RESET search_path"); !ok ||
		len(st.Schemas()) != 1 || st.Schemas()[0] != "public" {
		return false
	}
	st.Set([]string{"x"})
	if ok := st.ApplySearchPathStatement("SET search_path TO DEFAULT"); !ok ||
		len(st.Schemas()) != 1 || st.Schemas()[0] != "public" {
		return false
	}
	return true
}
